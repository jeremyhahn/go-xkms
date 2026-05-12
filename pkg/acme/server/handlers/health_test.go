//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHealthService(t *testing.T) {
	hs := NewHealthService("1.0.0")

	assert.NotNil(t, hs)
	assert.Equal(t, "1.0.0", hs.version)
	assert.NotNil(t, hs.checkers)
	assert.False(t, hs.startTime.IsZero())
}

func TestHealthHandler(t *testing.T) {
	hs := NewHealthService("1.0.0")

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	hs.HealthHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusHealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
	assert.NotEmpty(t, response.Timestamp)
}

func TestLiveHandler(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Wait a bit to accumulate some uptime
	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest("GET", "/health/live", nil)
	rec := httptest.NewRecorder()

	hs.LiveHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusHealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
	assert.NotEmpty(t, response.Timestamp)
	assert.Contains(t, response.Components, "uptime")
	assert.Equal(t, HealthStatusHealthy, response.Components["uptime"].Status)
	assert.NotEmpty(t, response.Components["uptime"].Message)
}

func TestReadyHandler(t *testing.T) {
	tests := []struct {
		name               string
		checkers           map[string]HealthChecker
		expectedStatus     HealthStatus
		expectedHTTPStatus int
	}{
		{
			name:               "no checkers - healthy",
			checkers:           map[string]HealthChecker{},
			expectedStatus:     HealthStatusHealthy,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name: "all healthy",
			checkers: map[string]HealthChecker{
				"database": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusHealthy,
						Message: "Database is healthy",
					}
				}),
				"storage": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusHealthy,
						Message: "Storage is healthy",
					}
				}),
			},
			expectedStatus:     HealthStatusHealthy,
			expectedHTTPStatus: http.StatusOK,
		},
		{
			name: "one degraded",
			checkers: map[string]HealthChecker{
				"database": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusHealthy,
						Message: "Database is healthy",
					}
				}),
				"cache": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusDegraded,
						Message: "Cache is slow",
					}
				}),
			},
			expectedStatus:     HealthStatusDegraded,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name: "one unhealthy",
			checkers: map[string]HealthChecker{
				"database": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusHealthy,
						Message: "Database is healthy",
					}
				}),
				"storage": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusUnhealthy,
						Message: "Storage is down",
						Error:   "connection refused",
					}
				}),
			},
			expectedStatus:     HealthStatusUnhealthy,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
		{
			name: "degraded and unhealthy - unhealthy wins",
			checkers: map[string]HealthChecker{
				"cache": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusDegraded,
						Message: "Cache is slow",
					}
				}),
				"database": HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
					return ComponentHealth{
						Status:  HealthStatusUnhealthy,
						Message: "Database is down",
					}
				}),
			},
			expectedStatus:     HealthStatusUnhealthy,
			expectedHTTPStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := NewHealthService("1.0.0")

			// Register checkers
			for name, checker := range tt.checkers {
				hs.RegisterChecker(name, checker)
			}

			req := httptest.NewRequest("GET", "/health/ready", nil)
			rec := httptest.NewRecorder()

			hs.ReadyHandler(rec, req)

			assert.Equal(t, tt.expectedHTTPStatus, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var response HealthResponse
			err := json.NewDecoder(rec.Body).Decode(&response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, response.Status)
			assert.Equal(t, "1.0.0", response.Version)
			assert.NotEmpty(t, response.Timestamp)
			assert.Equal(t, len(tt.checkers), len(response.Components))
		})
	}
}

func TestReadyHandlerTimeout(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Register a slow checker
	hs.RegisterChecker("slow", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		select {
		case <-time.After(10 * time.Second):
			return ComponentHealth{Status: HealthStatusHealthy}
		case <-ctx.Done():
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Timeout",
				Error:   ctx.Err().Error(),
			}
		}
	}))

	req := httptest.NewRequest("GET", "/health/ready", nil)
	rec := httptest.NewRecorder()

	// Should complete within reasonable time due to context timeout
	done := make(chan bool)
	go func() {
		hs.ReadyHandler(rec, req)
		done <- true
	}()

	select {
	case <-done:
		// Success - handler completed
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	case <-time.After(10 * time.Second):
		t.Fatal("ReadyHandler did not complete within timeout")
	}
}

func TestRegisterChecker(t *testing.T) {
	hs := NewHealthService("1.0.0")

	checker := HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Status: HealthStatusHealthy}
	})

	hs.RegisterChecker("test", checker)

	assert.Len(t, hs.checkers, 1)
	assert.Contains(t, hs.checkers, "test")
}

func TestRegisterCheckerConcurrency(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Register checkers concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			checker := HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
				return ComponentHealth{Status: HealthStatusHealthy}
			})
			hs.RegisterChecker(formatInt(n), checker)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Len(t, hs.checkers, 10)
}

func TestHealthCheckerFunc(t *testing.T) {
	t.Run("healthy check", func(t *testing.T) {
		checker := HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{
				Status:  HealthStatusHealthy,
				Message: "All good",
			}
		})

		result := checker.CheckHealth(context.Background())
		assert.Equal(t, HealthStatusHealthy, result.Status)
		assert.Equal(t, "All good", result.Message)
	})

	t.Run("unhealthy check", func(t *testing.T) {
		checker := HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			return ComponentHealth{
				Status:  HealthStatusUnhealthy,
				Message: "Something wrong",
				Error:   "connection failed",
			}
		})

		result := checker.CheckHealth(context.Background())
		assert.Equal(t, HealthStatusUnhealthy, result.Status)
		assert.Equal(t, "Something wrong", result.Message)
		assert.Equal(t, "connection failed", result.Error)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		checker := HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			<-ctx.Done()
			return ComponentHealth{
				Status: HealthStatusUnhealthy,
				Error:  ctx.Err().Error(),
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result := checker.CheckHealth(ctx)
		assert.Equal(t, HealthStatusUnhealthy, result.Status)
		assert.NotEmpty(t, result.Error)
	})
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		seconds  float64
		expected string
	}{
		{
			name:     "seconds only",
			seconds:  30,
			expected: "0m 30s",
		},
		{
			name:     "minutes and seconds",
			seconds:  90,
			expected: "1m 30s",
		},
		{
			name:     "hours, minutes, and seconds",
			seconds:  3661,
			expected: "1h 1m 1s",
		},
		{
			name:     "days, hours, minutes, and seconds",
			seconds:  90061,
			expected: "1d 1h 1m 1s",
		},
		{
			name:     "multiple days",
			seconds:  259200, // 3 days
			expected: "3d 0h 0m",
		},
		{
			name:     "zero",
			seconds:  0,
			expected: "0m 0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatUptime(tt.seconds)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComponentHealthInReadyHandler(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Register a checker that returns detailed component health
	hs.RegisterChecker("database", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Database is operational",
		}
	}))

	hs.RegisterChecker("cache", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{
			Status:  HealthStatusDegraded,
			Message: "Cache is slow",
		}
	}))

	req := httptest.NewRequest("GET", "/health/ready", nil)
	rec := httptest.NewRecorder()

	hs.ReadyHandler(rec, req)

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusDegraded, response.Status)
	assert.Contains(t, response.Components, "database")
	assert.Contains(t, response.Components, "cache")

	assert.Equal(t, HealthStatusHealthy, response.Components["database"].Status)
	assert.Equal(t, "Database is operational", response.Components["database"].Message)

	assert.Equal(t, HealthStatusDegraded, response.Components["cache"].Status)
	assert.Equal(t, "Cache is slow", response.Components["cache"].Message)
}

func TestReadyHandlerConcurrentChecks(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Register multiple checkers
	for i := 0; i < 5; i++ {
		name := "checker" + formatInt(i)
		hs.RegisterChecker(name, HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
			// Simulate some work
			time.Sleep(10 * time.Millisecond)
			return ComponentHealth{Status: HealthStatusHealthy}
		}))
	}

	req := httptest.NewRequest("GET", "/health/ready", nil)
	rec := httptest.NewRecorder()

	start := time.Now()
	hs.ReadyHandler(rec, req)
	duration := time.Since(start)

	// Should complete faster than sequential execution
	// Sequential would be 5 * 10ms = 50ms minimum
	// Concurrent should be ~10ms
	assert.Less(t, duration, 40*time.Millisecond)

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusHealthy, response.Status)
	assert.Len(t, response.Components, 5)
}

func TestHealthResponseJSON(t *testing.T) {
	response := HealthResponse{
		Status:    HealthStatusHealthy,
		Timestamp: "2024-01-01T00:00:00Z",
		Version:   "1.0.0",
		Components: map[string]ComponentHealth{
			"database": {
				Status:  HealthStatusHealthy,
				Message: "OK",
			},
		},
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	var decoded HealthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, response.Status, decoded.Status)
	assert.Equal(t, response.Timestamp, decoded.Timestamp)
	assert.Equal(t, response.Version, decoded.Version)
	assert.Equal(t, len(response.Components), len(decoded.Components))
}

func TestRealWorldHealthCheck(t *testing.T) {
	hs := NewHealthService("1.0.0")

	// Simulate real-world health checks
	hs.RegisterChecker("ca", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		// Simulate CA check
		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "CA is initialized and operational",
		}
	}))

	hs.RegisterChecker("storage", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		// Simulate storage check
		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Storage backend is accessible",
		}
	}))

	hs.RegisterChecker("nonce_store", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		// Simulate nonce store check
		return ComponentHealth{
			Status:  HealthStatusHealthy,
			Message: "Nonce store has sufficient capacity",
		}
	}))

	req := httptest.NewRequest("GET", "/health/ready", nil)
	rec := httptest.NewRecorder()

	hs.ReadyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusHealthy, response.Status)
	assert.Len(t, response.Components, 3)
	assert.Equal(t, HealthStatusHealthy, response.Components["ca"].Status)
	assert.Equal(t, HealthStatusHealthy, response.Components["storage"].Status)
	assert.Equal(t, HealthStatusHealthy, response.Components["nonce_store"].Status)
}

func TestHealthCheckWithError(t *testing.T) {
	hs := NewHealthService("1.0.0")

	hs.RegisterChecker("failing", HealthCheckerFunc(func(ctx context.Context) ComponentHealth {
		err := errors.New("disk full")
		return ComponentHealth{
			Status:  HealthStatusUnhealthy,
			Message: "Storage check failed",
			Error:   err.Error(),
		}
	}))

	req := httptest.NewRequest("GET", "/health/ready", nil)
	rec := httptest.NewRecorder()

	hs.ReadyHandler(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusUnhealthy, response.Status)
	assert.Contains(t, response.Components, "failing")
	assert.Equal(t, "disk full", response.Components["failing"].Error)
}
