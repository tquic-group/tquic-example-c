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

#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "tquic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

// Global variable to store the document root directory
static const char *g_document_root = ".";

// A simple server that supports HTTP/3 over QUIC
struct simple_server {
    struct quic_endpoint_t *quic_endpoint;
    ev_timer timer;
    int sock;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct quic_tls_config_t *tls_config;
    struct ev_loop *loop;
    struct http3_config_t *h3_config;
};

// Connection context to track H3 state per connection
struct connection_context {
    struct http3_conn_t *h3_conn;
    struct quic_conn_t *quic_conn;  // Store quic connection for HTTP3 callbacks
    // For handling large file transfers
    char *pending_data;          // Remaining data to send
    size_t pending_data_len;     // Length of remaining data
    uint64_t pending_stream_id;  // Stream ID for pending data
};

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

void server_on_conn_created(void *tctx, struct quic_conn_t *conn) {
    fprintf(stderr, "new connection created\n");
    
    // Create connection context
    struct connection_context *ctx = malloc(sizeof(struct connection_context));
    if (ctx) {
        ctx->h3_conn = NULL;
        ctx->quic_conn = conn;
        ctx->pending_data = NULL;
        ctx->pending_data_len = 0;
        ctx->pending_stream_id = 0;
        quic_conn_set_context(conn, ctx);
    }
}

void server_on_conn_established(void *tctx, struct quic_conn_t *conn) {
    struct simple_server *server = tctx;
    struct connection_context *ctx = quic_conn_context(conn);
    if (!ctx) return;
    
    fprintf(stderr, "connection established\n");
    
    // Get the negotiated protocol
    const uint8_t *proto;
    size_t proto_len;
    quic_conn_application_proto(conn, &proto, &proto_len);
    
    if (proto_len > 0) {
        fprintf(stderr, "Negotiated protocol: %.*s (length: %zu)\n", (int)proto_len, proto, proto_len);
        
        if (proto_len == 2 && memcmp(proto, "h3", 2) == 0) {
            fprintf(stderr, "Using HTTP/3 protocol\n");
            
            // Create HTTP/3 connection
            ctx->h3_conn = http3_conn_new(conn, server->h3_config);
            if (ctx->h3_conn == NULL) {
                fprintf(stderr, "Failed to create HTTP/3 connection\n");
                const char *reason = "failed to create HTTP/3 connection";
                quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
            } else {
                // Set HTTP/3 event handlers
                http3_conn_set_events_handler(ctx->h3_conn, &http3_methods, ctx);
            }
        } else {
            fprintf(stderr, "Expected HTTP/3 protocol but got: %.*s\n", (int)proto_len, proto);
            const char *reason = "unsupported protocol";
            quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
        }
    } else {
        fprintf(stderr, "No ALPN protocol negotiated, closing connection\n");
        const char *reason = "no ALPN protocol negotiated";
        quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
    }
}

void server_on_conn_closed(void *tctx, struct quic_conn_t *conn) {
    fprintf(stderr, "connection closed\n");
    
    // Cleanup connection context
    struct connection_context *ctx = quic_conn_context(conn);
    if (ctx) {
        if (ctx->h3_conn) {
            http3_conn_free(ctx->h3_conn);
        }
        if (ctx->pending_data) {
            free(ctx->pending_data);
        }
        free(ctx);
        quic_conn_set_context(conn, NULL);
    }
}

void server_on_stream_created(void *tctx, struct quic_conn_t *conn,
                              uint64_t stream_id) {
    fprintf(stderr, "new stream created %ld\n", stream_id);
}

void server_on_stream_readable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id) {
    struct connection_context *ctx = quic_conn_context(conn);
    if (!ctx) return;
    
    if (ctx->h3_conn) {
        // Process HTTP/3 stream - this will trigger the HTTP/3 event handlers
        http3_conn_process_streams(ctx->h3_conn, conn);
    } else {
        fprintf(stderr, "Received stream data but no HTTP/3 connection available\n");
    }
}

void server_on_stream_writable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id) {
    struct connection_context *ctx = quic_conn_context(conn);
    if (!ctx) {
        quic_stream_wantwrite(conn, stream_id, false);
        return;
    }
    
    // Check if we have pending data to send
    if (ctx->pending_data && ctx->pending_data_len > 0 && ctx->pending_stream_id == stream_id) {
        int written = http3_send_body(ctx->h3_conn, conn, stream_id, 
                                    (uint8_t *)ctx->pending_data, ctx->pending_data_len, true);
        if (written > 0) {
            if ((size_t)written < ctx->pending_data_len) {
                // Still have data to send, update pending data
                memmove(ctx->pending_data, ctx->pending_data + written, ctx->pending_data_len - written);
                ctx->pending_data_len -= written;
                fprintf(stderr, "Continued sending HTTP/3 body: %d bytes, %zu bytes remaining\n", 
                        written, ctx->pending_data_len);
                // Keep wanting write events
                quic_stream_wantwrite(conn, stream_id, true);
            } else {
                // All data sent successfully
                fprintf(stderr, "Finished sending HTTP/3 body: %d bytes\n", written);
                free(ctx->pending_data);
                ctx->pending_data = NULL;
                ctx->pending_data_len = 0;
                ctx->pending_stream_id = 0;
                quic_stream_wantwrite(conn, stream_id, false);
            }
        } else if (written < 0) {
            fprintf(stderr, "Failed to continue sending HTTP/3 body: %d\n", written);
            // Clean up pending data on error
            free(ctx->pending_data);
            ctx->pending_data = NULL;
            ctx->pending_data_len = 0;
            ctx->pending_stream_id = 0;
            quic_stream_wantwrite(conn, stream_id, false);
        } else {
            // written == 0, try again later
            fprintf(stderr, "HTTP/3 body send would block, will retry\n");
            quic_stream_wantwrite(conn, stream_id, true);
        }
    } else {
        quic_stream_wantwrite(conn, stream_id, false);
    }
}

void server_on_stream_closed(void *tctx, struct quic_conn_t *conn,
                             uint64_t stream_id) {
    fprintf(stderr, "stream closed %ld\n", stream_id);
}

int server_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count) {
    struct simple_server *server = psctx;

    unsigned int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(server->sock, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            fprintf(stderr, "send packet, length %ld\n", sent);
            sent_count++;
        }
    }

    return sent_count;
}

struct quic_tls_config_t *server_get_default_tls_config(void *ctx) {
    struct simple_server *server = ctx;
    return server->tls_config;
}

struct quic_tls_config_t *server_select_tls_config(void *ctx,
                                                   const uint8_t *server_name,
                                                   size_t server_name_len) {
    struct simple_server *server = ctx;
    return server->tls_config;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = server_on_conn_created,
    .on_conn_established = server_on_conn_established,
    .on_conn_closed = server_on_conn_closed,
    .on_stream_created = server_on_stream_created,
    .on_stream_readable = server_on_stream_readable,
    .on_stream_writable = server_on_stream_writable,
    .on_stream_closed = server_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = server_on_packets_send,
};

const struct quic_tls_config_select_methods_t tls_config_select_method = {
    .get_default = server_get_default_tls_config,
    .select = server_select_tls_config,
};

static void read_callback(EV_P_ ev_io *w, int revents) {
    struct simple_server *server = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(server->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *)&server->local_addr,
            .dst_len = server->local_addr_len,
        };

        int r = quic_endpoint_recv(server->quic_endpoint, buf, read,
                                   &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
            // Don't continue on this error, but don't return either
            continue;
        }
    }

    quic_endpoint_process_connections(server->quic_endpoint);
    double timeout = quic_endpoint_timeout(server->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void timeout_callback(EV_P_ ev_timer *w, int revents) {
    struct simple_server *server = w->data;
    quic_endpoint_on_timeout(server->quic_endpoint);
    quic_endpoint_process_connections(server->quic_endpoint);

    double timeout = quic_endpoint_timeout(server->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void debug_log(const uint8_t *data, size_t data_len, void *argp) {
    fwrite(data, sizeof(uint8_t), data_len, stderr);
}

// Function to read file content and determine content type
static int read_file_content(const char *path, char **content, size_t *content_length, char **content_type) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return -1;  // File not found
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(file);
        return -1;
    }
    
    // Allocate buffer and read file
    *content = malloc(file_size + 1);
    if (!*content) {
        fclose(file);
        return -1;
    }
    
    size_t read_size = fread(*content, 1, file_size, file);
    fclose(file);
    
    if (read_size != (size_t)file_size) {
        free(*content);
        *content = NULL;
        return -1;
    }
    
    (*content)[file_size] = '\0';
    *content_length = file_size;
    
    // Determine content type based on file extension
    const char *ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) {
            *content_type = "text/html";
        } else if (strcmp(ext, ".css") == 0) {
            *content_type = "text/css";
        } else if (strcmp(ext, ".js") == 0) {
            *content_type = "application/javascript";
        } else if (strcmp(ext, ".json") == 0) {
            *content_type = "application/json";
        } else if (strcmp(ext, ".png") == 0) {
            *content_type = "image/png";
        } else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) {
            *content_type = "image/jpeg";
        } else if (strcmp(ext, ".gif") == 0) {
            *content_type = "image/gif";
        } else {
            *content_type = "text/plain";
        }
    } else {
        *content_type = "text/plain";
    }
    
    return 0;  // Success
}

// Function to send HTTP/3 response
static void send_http3_response(struct connection_context *conn_ctx, uint64_t stream_id, 
                               const char *status, const char *content_type, 
                               const char *body, size_t body_len) {
    if (!conn_ctx || !conn_ctx->h3_conn || !conn_ctx->quic_conn) {
        return;
    }
    
    char content_length_str[32];
    snprintf(content_length_str, sizeof(content_length_str), "%zu", body_len);
    
    struct http3_header_t response_headers[] = {
        {.name = (uint8_t *)":status", .name_len = 7, .value = (uint8_t *)status, .value_len = strlen(status)},
        {.name = (uint8_t *)"content-type", .name_len = 12, .value = (uint8_t *)content_type, .value_len = strlen(content_type)},
        {.name = (uint8_t *)"content-length", .name_len = 14, .value = (uint8_t *)content_length_str, .value_len = strlen(content_length_str)}
    };
    
    int ret = http3_send_headers(conn_ctx->h3_conn, conn_ctx->quic_conn, stream_id,
                               response_headers, sizeof(response_headers)/sizeof(response_headers[0]), false);
    if (ret >= 0 && body && body_len > 0) {
        // If the body is large, it needs to be sent continuously using http3_send_body in on_stream_writable.
        int written = http3_send_body(conn_ctx->h3_conn, conn_ctx->quic_conn, stream_id, 
                      (uint8_t *)body, body_len, true);
        if (written >= 0) {
            if ((size_t)written < body_len) {
                // Partial write - store remaining data and continue sending in on_stream_writable
                size_t remaining = body_len - written;
                conn_ctx->pending_data = malloc(remaining);
                if (conn_ctx->pending_data) {
                    memcpy(conn_ctx->pending_data, body + written, remaining);
                    conn_ctx->pending_data_len = remaining;
                    conn_ctx->pending_stream_id = stream_id;
                    quic_stream_wantwrite(conn_ctx->quic_conn, stream_id, true);
                    fprintf(stderr, "HTTP/3 response partially sent: %s (%d/%zu bytes) - will continue in on_stream_writable\n", 
                            status, written, body_len);
                } else {
                    fprintf(stderr, "Failed to allocate memory for pending data\n");
                }
            } else {
                fprintf(stderr, "HTTP/3 response sent: %s (%zu bytes)\n", status, body_len);
            }
        } else {
            fprintf(stderr, "Failed to send HTTP/3 body: %d\n", written);
        }
    } else if (ret >= 0) {
        // Send empty body with fin=true
        http3_send_body(conn_ctx->h3_conn, conn_ctx->quic_conn, stream_id, 
                      (uint8_t *)"", 0, true);
        fprintf(stderr, "HTTP/3 response sent: %s (0 bytes)\n", status);
    } else {
        fprintf(stderr, "Failed to send HTTP/3 headers: %d\n", ret);
    }
}

static int create_socket(const char *host, const char *port,
                         struct addrinfo **local,
                         struct simple_server *server) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    if (getaddrinfo(host, port, &hints, local) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    int sock = socket((*local)->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        return -1;
    }
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        return -1;
    }
    if (bind(sock, (*local)->ai_addr, (*local)->ai_addrlen) < 0) {
        fprintf(stderr, "failed to bind socket\n");
        return -1;
    }

    server->local_addr_len = sizeof(server->local_addr);
    if (getsockname(sock, (struct sockaddr *)&server->local_addr,
                    &server->local_addr_len) != 0) {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };
    server->sock = sock;

    return 0;
}

// HTTP/3 event handler implementations
static int extract_path_callback(const uint8_t *name, size_t name_len,
                                 const uint8_t *value, size_t value_len, void *argp) {
    char **path = (char **)argp;
    
    if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
        *path = malloc(value_len + 1);
        if (*path) {
            memcpy(*path, value, value_len);
            (*path)[value_len] = '\0';
        }
    }
    return 0;
}

static void http3_on_stream_headers(void *ctx, uint64_t stream_id,
                                    const struct http3_headers_t *headers, bool fin) {
    struct connection_context *conn_ctx = ctx;
    fprintf(stderr, "Received HTTP/3 headers on stream %ld\n", stream_id);
    
    if (fin && conn_ctx && conn_ctx->h3_conn && conn_ctx->quic_conn) {
        // Extract the requested path
        char *requested_path = NULL;
        http3_for_each_header(headers, extract_path_callback, &requested_path);
        
        if (!requested_path) {
            // No path found, send 400 Bad Request
            const char *error_body = "Bad Request: No path specified";
            send_http3_response(conn_ctx, stream_id, "400", "text/plain", error_body, strlen(error_body));
            return;
        }
        
        fprintf(stderr, "Requested path: %s\n", requested_path);
        
        // If path is "/", serve index.html
        if (strcmp(requested_path, "/") == 0) {
            free(requested_path);
            requested_path = strdup("/index.html");
        }
        
        // Construct full file path (remove leading slash and combine with document root)
        char *file_path = malloc(strlen(g_document_root) + strlen(requested_path) + 2);
        if (!file_path) {
            free(requested_path);
            const char *error_body = "Internal Server Error: Memory allocation failed";
            send_http3_response(conn_ctx, stream_id, "500", "text/plain", error_body, strlen(error_body));
            return;
        }
        
        // Skip leading slash in requested_path
        const char *path_without_slash = (requested_path[0] == '/') ? requested_path + 1 : requested_path;
        snprintf(file_path, strlen(g_document_root) + strlen(requested_path) + 2, 
                "%s/%s", g_document_root, path_without_slash);
        
        // Try to read the file
        char *content = NULL;
        size_t content_length = 0;
        char *content_type = NULL;
        
        if (read_file_content(file_path, &content, &content_length, &content_type) == 0) {
            // File found, send it
            send_http3_response(conn_ctx, stream_id, "200", content_type, content, content_length);
            free(content);
        } else {
            // File not found, send 404
            const char *error_body = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested file was not found.</p></body></html>";
            send_http3_response(conn_ctx, stream_id, "404", "text/html", error_body, strlen(error_body));
        }
        
        free(requested_path);
        free(file_path);
    }
}

static void http3_on_stream_data(void *ctx, uint64_t stream_id) {
    struct connection_context *conn_ctx = ctx;
    fprintf(stderr, "Received HTTP/3 data on stream %ld\n", stream_id);
    
    // Drain any available data from the stream
    if (conn_ctx && conn_ctx->h3_conn && conn_ctx->quic_conn) {
        static uint8_t buf[READ_BUF_SIZE];
        ssize_t read = http3_recv_body(conn_ctx->h3_conn, conn_ctx->quic_conn, stream_id, buf, sizeof(buf));
        if (read > 0) {
            fprintf(stderr, "Received %zd bytes of HTTP/3 body data\n", read);
        } else if (read < 0) {
            fprintf(stderr, "Error reading HTTP/3 body data: %zd\n", read);
        }
    }
}

static void http3_on_stream_finished(void *ctx, uint64_t stream_id) {
    (void)ctx;
    fprintf(stderr, "HTTP/3 stream %ld finished\n", stream_id);
}

static void http3_on_stream_reset(void *ctx, uint64_t stream_id, uint64_t error_code) {
    fprintf(stderr, "HTTP/3 stream %ld reset with error code %ld\n", stream_id, error_code);
}

static void http3_on_stream_priority_update(void *ctx, uint64_t stream_id) {
    fprintf(stderr, "HTTP/3 stream %ld priority updated\n", stream_id);
}

static void http3_on_conn_goaway(void *ctx, uint64_t stream_id) {
    fprintf(stderr, "HTTP/3 connection received GOAWAY with stream_id %ld\n", stream_id);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <listen_addr> <listen_port> [document_root]\n", argv[0]);
        fprintf(stderr, "  document_root: optional document root directory (default: .)\n");
        return -1;
    }

    // Set logger.
    quic_set_logger(debug_log, NULL, "TRACE");

    // Create simple server.
    struct simple_server server;
    server.quic_endpoint = NULL;
    server.tls_config = NULL;
    server.h3_config = NULL;
    server.loop = NULL;
    quic_config_t *config = NULL;
    int ret = 0;

    // Create socket.
    const char *host = argv[1];
    const char *port = argv[2];
    g_document_root = (argc >= 4) ? argv[3] : ".";  // Set global document root
    printf("Using document root: %s\n", g_document_root);
    struct addrinfo *local = NULL;
    if (create_socket(host, port, &local, &server) != 0) {
        ret = -1;
        goto EXIT;
    }

    // Create quic config.
    config = quic_config_new();
    if (config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);

    // Create and set tls config with HTTP/3 protocol support.
    const char *const protos[1] = {"h3"};
    server.tls_config = quic_tls_config_new_server_config(
        "cert.crt", "cert.key", protos, 1, true);  // Require ALPN for HTTP/3 only
    if (server.tls_config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_tls_selector(config, &tls_config_select_method, &server);

    // Create HTTP/3 config
    server.h3_config = http3_config_new();
    if (server.h3_config == NULL) {
        fprintf(stderr, "failed to create HTTP/3 config\n");
        ret = -1;
        goto EXIT;
    }

    // Create quic endpoint
    server.quic_endpoint =
        quic_endpoint_new(config, true, &quic_transport_methods, &server,
                          &quic_packet_send_methods, &server);
    if (server.quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        ret = -1;
        goto EXIT;
    }

    // Start event loop.
    server.loop = ev_default_loop(0);
    ev_init(&server.timer, timeout_callback);
    server.timer.data = &server;

    ev_io watcher;
    ev_io_init(&watcher, read_callback, server.sock, EV_READ);
    ev_io_start(server.loop, &watcher);
    watcher.data = &server;
    ev_loop(server.loop, 0);

EXIT:
    if (local != NULL) {
        freeaddrinfo(local);
    }
    if (server.h3_config != NULL) {
        http3_config_free(server.h3_config);
    }
    if (server.tls_config != NULL) {
        quic_tls_config_free(server.tls_config);
    }
    if (server.sock > 0) {
        close(server.sock);
    }
    if (server.quic_endpoint != NULL) {
        quic_endpoint_free(server.quic_endpoint);
    }
    if (server.loop != NULL) {
        ev_loop_destroy(server.loop);
    }
    if (config != NULL) {
        quic_config_free(config);
    }

    return ret;
}
