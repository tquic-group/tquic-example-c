// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "tquic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

// Global variable to store the HTTP path
static const char *g_http_path = "/";

// A simple client that supports HTTP/3 over QUIC
struct simple_client {
    struct quic_endpoint_t *quic_endpoint;
    ev_timer timer;
    int sock;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct quic_tls_config_t *tls_config;
    struct quic_conn_t *conn;
    struct ev_loop *loop;
    struct http3_conn_t * h3_conn;
    struct http3_config_t *h3_config; // Store HTTP/3 config to avoid early cleanup
};

void client_on_conn_created(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    client->conn = conn;
}

// Forward declarations for HTTP/3 event handlers
static void http3_on_stream_headers(void *ctx, uint64_t stream_id,
                                    const struct http3_headers_t *headers, bool fin);
static void http3_on_stream_data(void *ctx, uint64_t stream_id);
static void http3_on_stream_finished(void *ctx, uint64_t stream_id);
static void http3_on_stream_reset(void *ctx, uint64_t stream_id, uint64_t error_code);
static void http3_on_stream_priority_update(void *ctx, uint64_t stream_id);
static void http3_on_conn_goaway(void *ctx, uint64_t stream_id);

// HTTP/3 event handlers structure
static const struct http3_methods_t http3_methods = {
    .on_stream_headers = http3_on_stream_headers,
    .on_stream_data = http3_on_stream_data,
    .on_stream_finished = http3_on_stream_finished,
    .on_stream_reset = http3_on_stream_reset,
    .on_stream_priority_update = http3_on_stream_priority_update,
    .on_conn_goaway = http3_on_conn_goaway,
};

void client_on_conn_established(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    // Get the negotiated protocol
    const uint8_t *proto;
    size_t proto_len;
    quic_conn_application_proto(conn, &proto, &proto_len);
    
    printf("Negotiated protocol: %.*s\n", (int)proto_len, proto);
    
    if (proto_len == 2 && memcmp(proto, "h3", 2) == 0) {
        printf("Using HTTP/3 protocol\n");
        
        // Create HTTP/3 config and connection
        client->h3_config = http3_config_new();
        if (client->h3_config == NULL) {
            printf("Failed to create HTTP/3 config\n");
            return;
        }
        
        client->h3_conn = http3_conn_new(conn, client->h3_config);
        if (client->h3_conn == NULL) {
            printf("Failed to create HTTP/3 connection\n");
            http3_config_free(client->h3_config);
            client->h3_config = NULL;
            return;
        }
        
        // Set HTTP/3 event handlers
        http3_conn_set_events_handler(client->h3_conn, &http3_methods, client);
    } else {
        printf("Expected HTTP/3 protocol but got: %.*s\n", (int)proto_len, proto);
        const char *reason = "unsupported protocol";
        quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
    }
}

void client_on_conn_closed(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    
    // Clean up HTTP/3 resources when connection is closed
    if (client->h3_conn != NULL) {
        http3_conn_free(client->h3_conn);
        client->h3_conn = NULL;
    }
    if (client->h3_config != NULL) {
        http3_config_free(client->h3_config);
        client->h3_config = NULL;
    }
    
    // Clear the connection reference
    client->conn = NULL;
    
    ev_break(client->loop, EVBREAK_ALL);
}

void client_on_stream_created(void *tctx, struct quic_conn_t *conn,
                              uint64_t stream_id) {}

void client_on_stream_readable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id) {
    struct simple_client *client = tctx;
    
    // Only handle HTTP/3 connections
    if (client->h3_conn != NULL && client->conn != NULL && client->conn == conn) {
        // Process the stream through HTTP/3 - this will trigger the HTTP/3 event handlers
        http3_conn_process_streams(client->h3_conn, conn);
    } else {
        fprintf(stderr, "Received stream data but no HTTP/3 connection available\n");
    }
}

void client_on_stream_writable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id) {
    quic_stream_wantwrite(conn, stream_id, false);
}

void client_on_stream_closed(void *tctx, struct quic_conn_t *conn,
                             uint64_t stream_id) {}

int client_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count) {
    struct simple_client *client = psctx;

    unsigned int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(client->sock, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            sent_count++;
        }
    }

    return sent_count;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = client_on_conn_created,
    .on_conn_established = client_on_conn_established,
    .on_conn_closed = client_on_conn_closed,
    .on_stream_created = client_on_stream_created,
    .on_stream_readable = client_on_stream_readable,
    .on_stream_writable = client_on_stream_writable,
    .on_stream_closed = client_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = client_on_packets_send,
};

static void debug_log(const uint8_t *data, size_t data_len, void *argp) {
    fwrite(data, sizeof(uint8_t), data_len, stderr);
}

// Forward declaration
static void process_h3_events(struct simple_client *client);

static void process_connections(struct simple_client *client) {
    // Process HTTP/3 events first, before processing connections
    // This ensures we don't access freed memory after quic_endpoint_process_connections
    if (client->h3_conn != NULL && client->conn != NULL) {
        // Process HTTP/3 streams
        http3_conn_process_streams(client->h3_conn, client->conn);
        process_h3_events(client);
    }
    
    quic_endpoint_process_connections(client->quic_endpoint);
    
    double timeout = quic_endpoint_timeout(client->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    client->timer.repeat = timeout;
    ev_timer_again(client->loop, &client->timer);
}

static void read_callback(EV_P_ ev_io *w, int revents) {
    struct simple_client *client = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(client->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *)&client->local_addr,
            .dst_len = client->local_addr_len,
        };

        int r = quic_endpoint_recv(client->quic_endpoint, buf, read,
                                   &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
            continue;
        }
    }

    process_connections(client);
}

static void timeout_callback(EV_P_ ev_timer *w, int revents) {
    struct simple_client *client = w->data;
    quic_endpoint_on_timeout(client->quic_endpoint);
    process_connections(client);
}

static void process_h3_events(struct simple_client *client) {
    static bool request_sent = false;
    
    // Try to send request if not sent yet and we have a valid HTTP/3 connection
    if (!request_sent && client->h3_conn != NULL && client->conn != NULL) {
        // First, create a new HTTP/3 stream
        int64_t stream_id = http3_stream_new(client->h3_conn, client->conn);
        if (stream_id < 0) {
            printf("Failed to create HTTP/3 stream: %ld\n", stream_id);
            return;
        }
        
        // Create HTTP/3 headers using the global path variable
        struct http3_header_t headers[] = {
            {.name = (uint8_t *)":method", .name_len = 7, .value = (uint8_t *)"GET", .value_len = 3},
            {.name = (uint8_t *)":scheme", .name_len = 7, .value = (uint8_t *)"https", .value_len = 5},
            {.name = (uint8_t *)":authority", .name_len = 10, .value = (uint8_t *)"127.0.0.1", .value_len = 9},
            {.name = (uint8_t *)":path", .name_len = 5, .value = (uint8_t *)g_http_path, .value_len = strlen(g_http_path)},
            {.name = (uint8_t *)"user-agent", .name_len = 10, .value = (uint8_t *)"tquic", .value_len = 5}
        };
        
        // Send headers on the created stream
        int result = http3_send_headers(client->h3_conn, client->conn, (uint64_t)stream_id,
                           headers, sizeof(headers) / sizeof(headers[0]),
                           true);
        
        if (result >= 0) {
            request_sent = true;
            printf("HTTP/3 request sent successfully on stream %ld for path: %s\n", stream_id, g_http_path);
        } else {
            printf("Failed to send HTTP/3 request: %d\n", result);
        }
    }
}

static int create_socket(const char *host, const char *port,
                         struct addrinfo **peer, struct simple_client *client) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    if (getaddrinfo(host, port, &hints, peer) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    int sock = socket((*peer)->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        return -1;
    }
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        return -1;
    }

    client->local_addr_len = sizeof(client->local_addr);
    if (getsockname(sock, (struct sockaddr *)&client->local_addr,
                    &client->local_addr_len) != 0) {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };
    client->sock = sock;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <dest_addr> <dest_port> [path]\n", argv[0]);
        fprintf(stderr, "  path: optional HTTP path (default: /)\n");
        return -1;
    }

    // Set logger.
    quic_set_logger(debug_log, NULL, "TRACE");

    // Create client.
    struct simple_client client;
    client.quic_endpoint = NULL;
    client.tls_config = NULL;
    client.conn = NULL;
    client.h3_conn = NULL;
    client.h3_config = NULL;
    client.loop = NULL;
    quic_config_t *config = NULL;
    int ret = 0;

    // Create socket.
    const char *host = argv[1];
    const char *port = argv[2];
    g_http_path = (argc >= 4) ? argv[3] : "/";  // Set global path variable
    printf("Using HTTP path: %s\n", g_http_path);
    struct addrinfo *peer = NULL;
    if (create_socket(host, port, &peer, &client) != 0) {
        ret = -1;
        goto EXIT;
    }

    // Create quic config.
    config = quic_config_new();
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        ret = -1;
        goto EXIT;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);

    // Create and set tls config with HTTP/3 protocol support.
    const char *const protos[1] = {"h3"};
    client.tls_config = quic_tls_config_new_client_config(protos, 1, true);
    if (client.tls_config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_tls_config(config, client.tls_config);

    // Create quic endpoint
    client.quic_endpoint =
        quic_endpoint_new(config, false, &quic_transport_methods, &client,
                          &quic_packet_send_methods, &client);
    if (client.quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        ret = -1;
        goto EXIT;
    }

    // Init event loop.
    client.loop = ev_default_loop(0);
    ev_init(&client.timer, timeout_callback);
    client.timer.data = &client;

    // Connect to server.
    ret = quic_endpoint_connect(
        client.quic_endpoint, (struct sockaddr *)&client.local_addr,
        client.local_addr_len, peer->ai_addr, peer->ai_addrlen,
        NULL /* server_name */, NULL /* session */, 0 /* session_len */,
        NULL /* token */, 0 /* token_len */, NULL /* config */,
        NULL /* index */);
    if (ret < 0) {
        fprintf(stderr, "failed to connect to client: %d\n", ret);
        ret = -1;
        goto EXIT;
    }
    process_connections(&client);

    // Start event loop.
    ev_io watcher;
    ev_io_init(&watcher, read_callback, client.sock, EV_READ);
    ev_io_start(client.loop, &watcher);
    watcher.data = &client;
    ev_loop(client.loop, 0);

EXIT:
    if (peer != NULL) {
        freeaddrinfo(peer);
    }
    // Note: h3_conn and h3_config may already be freed in client_on_conn_closed
    if (client.h3_conn != NULL) {
        http3_conn_free(client.h3_conn);
        client.h3_conn = NULL;
    }
    if (client.h3_config != NULL) {
        http3_config_free(client.h3_config);
        client.h3_config = NULL;
    }
    if (client.tls_config != NULL) {
        quic_tls_config_free(client.tls_config);
    }
    if (client.sock > 0) {
        close(client.sock);
    }
    if (client.quic_endpoint != NULL) {
        quic_endpoint_free(client.quic_endpoint);
    }
    if (client.loop != NULL) {
        ev_loop_destroy(client.loop);
    }
    if (config != NULL) {
        quic_config_free(config);
    }

    return ret;
}

// HTTP/3 event handler implementations
static int print_header_callback(const uint8_t *name, size_t name_len,
                                  const uint8_t *value, size_t value_len, void *argp) {
    printf("  %.*s: %.*s\n", (int)name_len, (const char *)name, 
           (int)value_len, (const char *)value);
    return 0;
}

static void http3_on_stream_headers(void *ctx, uint64_t stream_id,
                                    const struct http3_headers_t *headers, bool fin) {
    (void)ctx; // Suppress unused parameter warning
    printf("Received HTTP/3 headers on stream %ld:\n", stream_id);
    http3_for_each_header(headers, print_header_callback, NULL);
}

static void http3_on_stream_data(void *ctx, uint64_t stream_id) {
    struct simple_client *client = ctx;
    
    if (client->h3_conn == NULL || client->conn == NULL) {
        printf("HTTP/3 connection not available for stream %ld\n", stream_id);
        return;
    }
    
    static uint8_t buf[READ_BUF_SIZE];
    
    // Loop to read all available data on this stream
    while (true) {
        ssize_t read = http3_recv_body(client->h3_conn, client->conn, stream_id, buf, sizeof(buf));
        
        if (read > 0) {
            // Successfully read data, print it
            printf("%.*s", (int)read, buf);
        } else if (read == 0) {
            // No more data available right now, break the loop
            break;
        } else {
            // Error occurred
            printf("Error reading HTTP/3 data from stream %ld: %zd\n", stream_id, read);
            break;
        }
    }
}

static void http3_on_stream_finished(void *ctx, uint64_t stream_id) {
    struct simple_client *client = ctx;
    printf("HTTP/3 stream %ld finished\n", stream_id);
    
    // Check if connection is still valid before closing
    if (client->conn != NULL) {
        const char *reason = "ok";
        quic_conn_close(client->conn, true, 0, (const uint8_t *)reason, strlen(reason));
    }
}

static void http3_on_stream_reset(void *ctx, uint64_t stream_id, uint64_t error_code) {
    printf("HTTP/3 stream %ld reset with error code %ld\n", stream_id, error_code);
}

static void http3_on_stream_priority_update(void *ctx, uint64_t stream_id) {
    printf("HTTP/3 stream %ld priority updated\n", stream_id);
}

static void http3_on_conn_goaway(void *ctx, uint64_t stream_id) {
    printf("HTTP/3 connection received GOAWAY with stream_id %ld\n", stream_id);
}
