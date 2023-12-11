# tquic-example-c

C examples of using [TQUIC](https://github.com/Tencent/tquic) on Linux.

**simple_server**

A simple http/0.9 server responsing "OK" to any requests.

The certificate and private key are hard coded to "cert.crt" and "cert.key".

The first argument is the listening IP and the second is the listening port.

**simple_client**

A simple http/0.9 client.

The first argument is the destination IP and the second is the destination port.

## Requirements

Refer to the [TQUIC](https://tquic.net/docs/getting_started/installation#prerequisites) prerequisites.

## Build

```shell
make
```

## Run simple_server

```shell
./simple_server 0.0.0.0 4433
```

## Run simple_client

```shell
./simple_client 127.0.0.1 4433
```