# Metrics Package

The metrics package provides comprehensive Prometheus instrumentation for the go-keychain server, enabling detailed monitoring of operations, performance, resource usage, and health.

## Overview

The metrics package exposes:

- **Operational metrics**: Track keychain operations (generate, sign, encrypt, etc.)
- **Performance metrics**: Monitor request latency and throughput
- **Error tracking**: Record and categorize errors by type
- **Resource metrics**: Monitor goroutines, memory, and GC statistics
- **Protocol metrics**: Track HTTP and gRPC request patterns
- **Health metrics**: Monitor backend availability and system health

## Components

### Core Metrics (`metrics.go`)

Defines all Prometheus metrics and provides helper functions for recording events:

- **OperationsTotal**: Counter tracking keychain operations by type, backend, and status
- **OperationDuration**: Histogram tracking operation latency
- **ErrorsTotal**: Counter tracking errors by operation, backend, and error type
- **HTTPRequestsTotal/Duration**: HTTP request metrics
- **GRPCRequestsTotal/Duration**: gRPC request metrics
- **ActiveConnections**: Gauge tracking concurrent connections by protocol
- **Goroutines**: Current number of goroutines
- **MemoryAllocBytes**: Current allocated heap memory
- **MemorySysBytes**: Total memory obtained from OS
- **GCPauseTotalSeconds**: Cumulative GC pause time
- **KeysTotal**: Number of keys per backend
- **CertsTotal**: Number of certificates per backend
- **BackendHealthy**: Backend health status (0=unhealthy, 1=healthy)
- **ServerUptime**: Server uptime in seconds

### Middleware (`middleware.go`)

Provides automatic instrumentation for HTTP and gRPC services:

- **HTTPMiddleware**: Chi router middleware for REST API
- **GRPCUnaryServerInterceptor**: gRPC unary RPC interceptor
- **GRPCStreamServerInterceptor**: gRPC streaming RPC interceptor
- **ConnectionTracker**: Manual connection tracking for protocols without middleware support

### Resource Collector (`collector.go`)

Periodically collects system resource metrics:

- **ResourceCollector**: Goroutine-based collector with configurable interval
- Collects goroutine count, memory usage, GC statistics, and uptime
- Graceful shutdown support via context cancellation

## Usage

### Basic Setup

The metrics package is automatically initialized when the server starts with metrics enabled:

```go
// In internal/server/server.go
if s.config.Metrics.Enabled {
    if err := s.initializeMetrics(); err != nil {
        return err
    }
}
```

The metrics endpoint is exposed at the configured path (default: `/metrics`).

### Recording Operations

Use `RecordOperation` to track keychain operations:

```go
import "github.com/jeremyhahn/go-keychain/pkg/metrics"

start := time.Now()
err := keystore.Generate(ctx, params)
duration := time.Since(start).Seconds()

if err != nil {
    metrics.RecordOperation(metrics.OpGenerate, "pkcs8", metrics.StatusError, duration)
    metrics.RecordError(metrics.OpGenerate, "pkcs8", "generation_failed")
} else {
    metrics.RecordOperation(metrics.OpGenerate, "pkcs8", metrics.StatusSuccess, duration)
}
```

### HTTP Middleware

The HTTP middleware is automatically applied in the REST server:

```go
import "github.com/jeremyhahn/go-keychain/pkg/metrics"

router := chi.NewRouter()
router.Use(metrics.HTTPMiddleware)
```

This tracks:
- Request duration
- Status codes
- Active connections

### gRPC Interceptors

The gRPC interceptors are automatically registered in the gRPC server:

```go
import "github.com/jeremyhahn/go-keychain/pkg/metrics"

opts := []grpc.ServerOption{
    grpc.UnaryInterceptor(metrics.GRPCUnaryServerInterceptor()),
    grpc.StreamInterceptor(metrics.GRPCStreamServerInterceptor()),
}
```

### Resource Collection

The resource collector starts automatically with the server:

```go
import "github.com/jeremyhahn/go-keychain/pkg/metrics"

// Starts collector in background
collector := metrics.StartResourceCollector(ctx, 30*time.Second)

// Collector stops when context is cancelled
```

### Manual Connection Tracking

For protocols without built-in middleware (QUIC, MCP):

```go
import "github.com/jeremyhahn/go-keychain/pkg/metrics"

tracker := metrics.NewConnectionTracker(metrics.ProtocolQUIC)
defer tracker.Close()

// Handle connection...
```

## Configuration

Metrics are configured in the server configuration file:

```yaml
metrics:
  enabled: true
  port: 9090
  path: /metrics
```

## Available Metrics

### Operation Metrics

```
keychain_operations_total{operation="generate",backend="pkcs8",status="success"} 42
keychain_operation_duration_seconds_bucket{operation="generate",backend="pkcs8",le="0.005"} 38
```

### HTTP Metrics

```
keychain_http_requests_total{method="GET",status_code="200"} 156
keychain_http_request_duration_seconds_bucket{method="GET",le="0.1"} 152
```

### gRPC Metrics

```
keychain_grpc_requests_total{method="/keychain.v1.KeychainService/Generate",status_code="OK"} 89
keychain_grpc_request_duration_seconds_bucket{method="/keychain.v1.KeychainService/Generate",le="0.1"} 85
```

### Resource Metrics

```
keychain_goroutines 47
keychain_memory_alloc_bytes 8388608
keychain_memory_sys_bytes 75497472
keychain_gc_pause_total_seconds 0.00234
keychain_server_uptime_seconds 3600
```

### Connection Metrics

```
keychain_active_connections{protocol="http"} 5
keychain_active_connections{protocol="grpc"} 2
```

### Backend Metrics

```
keychain_keys_total{backend="pkcs8"} 15
keychain_certs_total{backend="pkcs8"} 8
keychain_backend_healthy{backend="pkcs8"} 1
```

## Operation Constants

The package defines constants for common operations:

- `OpGenerate`: Key generation
- `OpStore`: Key storage
- `OpGet`: Key retrieval
- `OpDelete`: Key deletion
- `OpList`: Key listing
- `OpSign`: Signing operation
- `OpVerify`: Signature verification
- `OpEncrypt`: Encryption operation
- `OpDecrypt`: Decryption operation
- `OpExport`: Key export
- `OpImport`: Key import
- `OpRotate`: Key rotation
- `OpBackup`: Backup operation
- `OpRestore`: Restore operation
- `OpHealthCheck`: Health check

## Protocol Constants

- `ProtocolHTTP`: HTTP/REST
- `ProtocolGRPC`: gRPC
- `ProtocolQUIC`: QUIC/HTTP3
- `ProtocolMCP`: MCP JSON-RPC

## Label Constants

- `LabelOperation`: Operation type label
- `LabelBackend`: Backend identifier label
- `LabelStatus`: Operation status label
- `LabelErrorType`: Error type label
- `LabelProtocol`: Protocol label
- `LabelMethod`: HTTP/gRPC method label
- `LabelStatusCode`: HTTP/gRPC status code label

## Enabling/Disabling Metrics

Metrics collection can be toggled at runtime:

```go
metrics.Disable() // Stop collecting metrics
metrics.Enable()  // Resume collecting metrics
if metrics.IsEnabled() {
    // ...
}
```

This is primarily useful for testing scenarios.

## Performance

The metrics package is designed for minimal performance impact:

- Zero allocations for most metric updates
- Lock-free atomic operations where possible
- Efficient Prometheus client implementation
- Benchmark results (on Intel Core Ultra 9 285K):
  - `RecordOperation`: 77.51 ns/op, 0 allocs/op
  - `RecordError`: 37.62 ns/op, 0 allocs/op
  - `RecordHTTPRequest`: 80.04 ns/op, 0 allocs/op
  - `IncrementActiveConnections`: 27.90 ns/op, 0 allocs/op

## Testing

The package includes comprehensive tests with 93.2% coverage:

```bash
# Run tests
go test ./pkg/metrics/...

# Run tests with race detector
go test -race ./pkg/metrics/...

# Run benchmarks
go test -bench=. ./pkg/metrics/...

# Check coverage
go test -coverprofile=coverage.out ./pkg/metrics/...
go tool cover -func=coverage.out
```

## Querying Metrics

### Prometheus Queries

Track error rate:
```promql
rate(keychain_errors_total[5m])
```

Operation latency p95:
```promql
histogram_quantile(0.95, rate(keychain_operation_duration_seconds_bucket[5m]))
```

Request rate by protocol:
```promql
sum(rate(keychain_http_requests_total[5m])) + sum(rate(keychain_grpc_requests_total[5m]))
```

### Grafana Dashboard

A sample Grafana dashboard is available in `examples/grafana/keychain-dashboard.json` with:

- Request rate by protocol
- Error rate by operation
- Latency percentiles
- Active connections
- Resource usage (memory, goroutines)
- Backend health status

## Best Practices

1. **Always record both success and error operations**: This provides complete visibility
2. **Use meaningful error types**: Makes debugging easier (e.g., "key_not_found" vs "error")
3. **Set backend health metrics**: Helps identify infrastructure issues
4. **Monitor p95/p99 latencies**: Better indicators of user experience than averages
5. **Alert on error rate increases**: Set up alerts for sustained error rate increases
6. **Track resource trends**: Monitor goroutines and memory for resource leaks

## Integration with Observability Stack

The metrics package integrates seamlessly with standard observability tools:

- **Prometheus**: Native Prometheus exposition format
- **Grafana**: Import provided dashboard templates
- **Alertmanager**: Use Prometheus alerts with keychain metrics
- **OpenTelemetry**: Metrics can be exported via OTLP if needed

## Thread Safety

All metrics operations are thread-safe and designed for concurrent use from multiple goroutines. The package uses:

- Atomic operations for enable/disable state
- Prometheus client's built-in synchronization
- Lock-free algorithms where possible
