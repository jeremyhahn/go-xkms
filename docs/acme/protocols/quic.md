# QUIC Protocol

Low-latency QUIC/HTTP3 API for Admin operations.

## Overview

The QUIC API provides UDP-based access to all Admin operations using HTTP/3. It's optimized for low-latency connections, mobile clients, and networks with packet loss.

## Connection

| Property | Value |
|----------|-------|
| Protocol | HTTP/3 over QUIC |
| Default Port | 9444 |
| Transport | UDP with TLS 1.3 |
| Content-Type | `application/json` |

## Configuration

### Server

```bash
# Admin addresses are configured via environment variables
TRUSTEDCA_ADMIN_QUIC_ADDR=:9445 trusted-acme-server --admin-enabled
```

**Note:** QUIC requires TLS 1.3. TLS is automatically configured via go-xkms.

### Client (cactl)

```bash
cactl --transport quic --address localhost:9444 status
```

## Advantages

QUIC provides several advantages over TCP-based protocols:

| Feature | Benefit |
|---------|---------|
| 0-RTT connection | Faster initial requests |
| Multiplexing | No head-of-line blocking |
| Connection migration | Survives network changes |
| Built-in encryption | TLS 1.3 required |
| Packet loss resilience | Better on unreliable networks |

## API Endpoints

QUIC uses the same REST API endpoints over HTTP/3:

### Base URL

```
https://{host}:{port}/api/v1
```

All endpoints from the [REST API](rest.md) are available via QUIC.

## Client Usage

### cactl

```bash
# Get status via QUIC
cactl --transport quic --address localhost:9444 status

# List certificates
cactl --transport quic --address localhost:9444 cert list

# Create tenant
cactl --transport quic --address localhost:9444 \
  tenant create --name example --display-name "Example"
```

### Go Client

```go
package main

import (
    "context"
    "crypto/tls"
    "io"
    "log"
    "net/http"

    "github.com/quic-go/quic-go/http3"
)

func main() {
    // Configure TLS
    tlsConfig := &tls.Config{
        InsecureSkipVerify: false, // Set to true only for testing
    }

    // Create HTTP/3 transport
    transport := &http3.Transport{
        TLSClientConfig: tlsConfig,
    }
    defer transport.Close()

    // Create client
    client := &http.Client{
        Transport: transport,
    }

    // Make request
    resp, err := client.Get("https://localhost:9444/api/v1/status")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    log.Printf("Response: %s", body)
}
```

### curl with HTTP/3

```bash
# curl 7.66+ with HTTP/3 support
curl --http3 https://localhost:9444/api/v1/status \
  --cert client.crt --key client.key --cacert ca.crt
```

**Note:** curl HTTP/3 support requires curl built with nghttp3/ngtcp2 or quiche.

## Authentication

QUIC inherits mTLS authentication from TLS 1.3:

```bash
# Server with mTLS (TLS configured via go-xkms)
TRUSTEDCA_ADMIN_QUIC_ADDR=:9445 trusted-acme-server --admin-enabled
```

Client certificates are verified during the TLS handshake.

## Use Cases

QUIC is ideal for:

| Scenario | Why QUIC |
|----------|----------|
| Mobile clients | Connection migration, packet loss resilience |
| High-latency networks | 0-RTT reduces round trips |
| Microservices | Lower latency than TCP |
| Edge deployments | Better performance on variable networks |
| Real-time monitoring | Multiplexing without blocking |

## Performance

### Connection Establishment

| Protocol | Round Trips |
|----------|-------------|
| TCP + TLS 1.2 | 3 RTT |
| TCP + TLS 1.3 | 2 RTT |
| QUIC (new) | 1 RTT |
| QUIC (resumed) | 0 RTT |

### Benchmarks

On lossy networks (1% packet loss):

| Protocol | Avg Latency | P99 Latency |
|----------|-------------|-------------|
| TCP | 150ms | 800ms |
| QUIC | 100ms | 250ms |

## Limitations

- **Firewall compatibility**: Some networks block UDP
- **Middlebox interference**: NAT devices may have issues
- **CPU overhead**: Slightly higher than TCP for encryption
- **Library maturity**: Less mature than TCP implementations

## Fallback

If QUIC is unavailable, clients can fall back to REST:

```bash
# Try QUIC first, fall back to REST
cactl --transport quic --address localhost:9444 status || \
cactl --transport rest --address https://localhost:8443 status
```

## Debugging

### Check QUIC availability

```bash
# Test UDP connectivity
nc -u -z localhost 9444

# Check server logs for QUIC startup
trusted-acme-server --admin-enabled --log-level debug 2>&1 | grep -i quic
```

### Wireshark

Filter QUIC traffic:
```
udp.port == 9444
```

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [gRPC Protocol](grpc.md)
- [cactl CLI](../cli/cactl.md)
