# Health Check Package

The `health` package provides comprehensive health checking capabilities following Kubernetes probe semantics.

## Overview

This package implements three types of health probes as defined by Kubernetes:

1. **Liveness Probes** - Determines if the service is alive and should be restarted
2. **Readiness Probes** - Determines if the service can accept traffic
3. **Startup Probes** - Determines if the application has finished initializing

## Features

- Thread-safe health check management
- Flexible check registration and unregistration
- Context-aware health checks with timeout support
- Aggregated status reporting
- Comprehensive test coverage (100%)
- Zero dependencies (besides standard library)

## Usage

### Basic Setup

```go
import "github.com/jeremyhahn/go-keychain/pkg/health"

// Create a new health checker
checker := health.NewChecker()

// Register a health check
checker.RegisterCheck("database", func(ctx context.Context) health.CheckResult {
    // Check database connectivity
    if err := db.Ping(); err != nil {
        return health.CheckResult{
            Name:    "database",
            Status:  health.StatusUnhealthy,
            Message: "Database connection failed",
            Error:   err.Error(),
        }
    }
    return health.CheckResult{
        Name:    "database",
        Status:  health.StatusHealthy,
        Message: "Database is connected",
    }
})

// Mark service as started after initialization
checker.MarkStarted()
```

### Kubernetes Probes

#### Liveness Probe

Checks if the service is alive. Should only fail if the service needs to be restarted.

```go
result := checker.Live(ctx)
// Always returns healthy for a running process
```

#### Readiness Probe

Checks if the service can accept requests. Runs all registered health checks.

```go
results := checker.Ready(ctx)
status := health.AggregateStatus(results)

if status == health.StatusHealthy {
    // Service is ready to accept traffic
}
```

#### Startup Probe

Checks if the service has completed initialization.

```go
result := checker.Startup(ctx)
// Returns unhealthy until MarkStarted() is called
```

## Health Check Best Practices

### Liveness Checks

- Should only fail on unrecoverable errors
- DO NOT include dependency checks (database, cache, etc.)
- Keep checks fast (< 100ms)
- Failing liveness triggers pod restart

### Readiness Checks

- Include dependency health (database, cache, external APIs)
- Can fail temporarily during normal operations
- Failing readiness removes pod from load balancer
- Should complete within timeout (default: 2 seconds)

### Startup Checks

- Used for slow-starting applications
- Prevents liveness/readiness checks during startup
- Call `MarkStarted()` after all initialization is complete

## Status Types

```go
const (
    StatusHealthy   Status = "healthy"    // Component is operating normally
    StatusUnhealthy Status = "unhealthy"  // Component is not functioning
    StatusDegraded  Status = "degraded"   // Component is functioning with reduced capacity
)
```

## Examples

### Backend Health Check

```go
checker.RegisterCheck("backend-pkcs8", func(ctx context.Context) health.CheckResult {
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()

    done := make(chan error, 1)
    go func() {
        _, err := keystore.ListKeys()
        done <- err
    }()

    select {
    case err := <-done:
        if err != nil {
            return health.CheckResult{
                Name:    "backend-pkcs8",
                Status:  health.StatusUnhealthy,
                Message: "Backend is not responding",
                Error:   err.Error(),
            }
        }
        return health.CheckResult{
            Name:    "backend-pkcs8",
            Status:  health.StatusHealthy,
            Message: "Backend is responding",
        }
    case <-ctx.Done():
        return health.CheckResult{
            Name:    "backend-pkcs8",
            Status:  health.StatusUnhealthy,
            Message: "Backend check timed out",
            Error:   "timeout",
        }
    }
})
```

### HTTP Endpoints

The REST API exposes three health endpoints:

- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe
- `GET /health/startup` - Startup probe

#### Liveness Response

```json
{
  "status": "healthy",
  "message": "Service is alive"
}
```

#### Readiness Response

```json
{
  "status": "healthy",
  "message": "All checks passed",
  "checks": [
    {
      "name": "backend-pkcs8",
      "status": "healthy",
      "message": "Backend is responding",
      "latency": 15000000
    }
  ]
}
```

#### Startup Response

```json
{
  "status": "healthy",
  "message": "Service fully initialized (uptime: 5m30s)"
}
```

## Kubernetes Configuration

### Deployment YAML

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: keychain-server
spec:
  containers:
  - name: keychain
    image: keychain-server:latest
    ports:
    - containerPort: 8443

    # Liveness probe - restart if unhealthy
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8443
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 1
      failureThreshold: 3

    # Readiness probe - remove from service if unhealthy
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8443
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 2
      failureThreshold: 2

    # Startup probe - delay other probes until ready
    startupProbe:
      httpGet:
        path: /health/startup
        port: 8443
      initialDelaySeconds: 0
      periodSeconds: 2
      timeoutSeconds: 1
      failureThreshold: 30  # 30 * 2s = 60s max startup time
```

## Testing

Run tests with coverage:

```bash
go test -v -coverprofile=coverage.out ./pkg/health/
go tool cover -html=coverage.out
```

Current test coverage: **100%**

## API Reference

### Types

#### Checker

Main health checker struct that manages health checks.

**Methods:**
- `NewChecker() *Checker` - Creates a new health checker
- `RegisterCheck(name string, check CheckFunc)` - Registers a health check
- `UnregisterCheck(name string)` - Removes a health check
- `MarkStarted()` - Marks service as fully initialized
- `MarkNotStarted()` - Marks service as not started (for testing)
- `Live(ctx context.Context) CheckResult` - Performs liveness check
- `Ready(ctx context.Context) []CheckResult` - Performs readiness checks
- `Startup(ctx context.Context) CheckResult` - Performs startup check
- `IsHealthy(ctx context.Context) bool` - Returns true if all checks pass
- `IsStarted() bool` - Returns true if service is marked as started
- `Uptime() time.Duration` - Returns service uptime
- `GetAllChecks() []string` - Returns names of all registered checks

#### CheckResult

Result of a health check.

**Fields:**
- `Name string` - Check identifier
- `Status Status` - Health status (healthy/unhealthy/degraded)
- `Message string` - Additional context
- `Latency time.Duration` - Check execution time
- `Error string` - Error details if check failed

#### CheckFunc

Function signature for health checks.

```go
type CheckFunc func(ctx context.Context) CheckResult
```

### Functions

#### AggregateStatus

Combines multiple check results into a single status.

```go
func AggregateStatus(results []CheckResult) Status
```

**Rules:**
- If any check is unhealthy, returns `StatusUnhealthy`
- If any check is degraded (and none unhealthy), returns `StatusDegraded`
- Otherwise returns `StatusHealthy`

## Performance

Health checks are designed to be fast and non-blocking:

- Liveness checks: < 1ms
- Readiness checks: < 100ms per check (configurable timeout)
- Concurrent execution: Safe for multiple goroutines
- Zero allocation for simple checks

## Thread Safety

All methods are thread-safe and can be called concurrently from multiple goroutines.

## References

- [Kubernetes Liveness, Readiness, and Startup Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Health Check Response Format for HTTP APIs](https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check)
- [The Twelve-Factor App - Health Checks](https://12factor.net/)
