// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01/providers"
)

// mockHTTPClient implements HTTPClient for testing.
type mockHTTPClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.doFunc(req)
}

// helper to create a mock response
func mockResponse(statusCode int, body interface{}) *http.Response {
	var bodyReader io.ReadCloser

	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = io.NopCloser(bytes.NewReader(data))
	} else {
		bodyReader = io.NopCloser(bytes.NewReader(nil))
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       bodyReader,
		Header:     make(http.Header),
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid API token",
			config: Config{
				APIToken: "valid-token-123",
			},
			expectError: false,
		},
		{
			name: "valid API key with email",
			config: Config{
				Email:  "user@example.com",
				APIKey: "valid-key-123",
			},
			expectError: false,
		},
		{
			name: "API key without email",
			config: Config{
				APIKey: "valid-key-123",
			},
			expectError: true,
			errorMsg:    "email",
		},
		{
			name:        "no credentials",
			config:      Config{},
			expectError: true,
			errorMsg:    "credentials",
		},
		{
			name: "both API token and key",
			config: Config{
				APIToken: "token-123",
				APIKey:   "key-123",
			},
			expectError: true,
			errorMsg:    "cannot use both",
		},
		{
			name: "API key with newline",
			config: Config{
				Email:  "user@example.com",
				APIKey: "key-with\nnewline",
			},
			expectError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "API token with newline",
			config: Config{
				APIToken: "token-with\nnewline",
			},
			expectError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "zone API token with newline",
			config: Config{
				APIToken:     "valid-token",
				ZoneAPIToken: "zone-token\nwith-newline",
			},
			expectError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "valid with zone API token",
			config: Config{
				APIToken:     "valid-token",
				ZoneAPIToken: "valid-zone-token",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"empty", "", true},
		{"normal", "abc123", true},
		{"with space", "abc 123", true},
		{"with tab", "abc\t123", true},
		{"with newline", "abc\n123", false},
		{"with carriage return", "abc\r123", false},
		{"with null", "abc\x00123", false},
		{"with del", "abc\x7f123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHeaderValue(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	t.Run("valid config", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
		})
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "valid-token", provider.apiToken)
	})

	t.Run("with custom HTTP client", func(t *testing.T) {
		mockClient := &mockHTTPClient{}
		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("default values", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
		})
		require.NoError(t, err)
		assert.Equal(t, defaultAPIURL, provider.baseURL)
		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
		assert.Equal(t, defaultRecordTTL, provider.ttl)
	})

	t.Run("custom values", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken:           "valid-token",
			BaseURL:            "https://custom.api.com",
			PropagationTimeout: 5 * time.Minute,
			PollingInterval:    10 * time.Second,
			TTL:                300,
			HTTPTimeout:        60 * time.Second,
		})
		require.NoError(t, err)
		assert.Equal(t, "https://custom.api.com", provider.baseURL)
		assert.Equal(t, 5*time.Minute, provider.propagationTimeout)
		assert.Equal(t, 10*time.Second, provider.pollingInterval)
		assert.Equal(t, 300, provider.ttl)
	})

	t.Run("with zone ID", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
			ZoneID:   "preconfigured-zone-123",
		})
		require.NoError(t, err)
		assert.Equal(t, "preconfigured-zone-123", provider.zoneID)
	})

	t.Run("with zone API token", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken:     "dns-token",
			ZoneAPIToken: "zone-list-token",
		})
		require.NoError(t, err)
		assert.Equal(t, "dns-token", provider.apiToken)
		assert.Equal(t, "zone-list-token", provider.zoneAPIToken)
	})
}

func TestTimeout(t *testing.T) {
	ctx := context.Background()

	t.Run("default timeout values", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
		})
		require.NoError(t, err)

		timeout, interval := provider.Timeout()
		assert.Equal(t, defaultPropagationTimeout, timeout)
		assert.Equal(t, defaultPollingInterval, interval)
	})

	t.Run("custom timeout values", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken:           "valid-token",
			PropagationTimeout: 5 * time.Minute,
			PollingInterval:    15 * time.Second,
		})
		require.NoError(t, err)

		timeout, interval := provider.Timeout()
		assert.Equal(t, 5*time.Minute, timeout)
		assert.Equal(t, 15*time.Second, interval)
	})

	t.Run("implements ProviderTimeout interface", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
		})
		require.NoError(t, err)

		// Verify interface compliance
		var _ providers.ProviderTimeout = provider
	})
}

func TestPresent(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new record", func(t *testing.T) {
		callCount := 0
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				callCount++
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				// Check dns_records BEFORE zones since path contains both
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					// Record lookup - no existing record
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					// Zone lookup - return zone only for example.com
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					// Return empty for subdomain lookups
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "POST":
					// Create record
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{"id": "rec123"}`),
					}), nil
				default:
					t.Logf("unexpected request: %s %s %s", req.Method, path, query)
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.Greater(t, callCount, 0)
	})

	t.Run("record already exists", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				// Check dns_records BEFORE zones since path contains both
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					// Return existing record with same content
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "rec123", "name": "_acme-challenge.example.com", "content": "token-value", "type": "TXT"}]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					// Zone lookup - return zone only for example.com
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				default:
					t.Logf("unexpected request: %s %s %s", req.Method, path, query)
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
	})

	t.Run("uses configured TTL", func(t *testing.T) {
		var recordTTL int
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "POST":
					// Parse the body to verify TTL
					body, _ := io.ReadAll(req.Body)
					var record cloudflareRecord
					json.Unmarshal(body, &record)
					recordTTL = record.TTL
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{"id": "rec123"}`),
					}), nil
				default:
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
			TTL:        300,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.Equal(t, 300, recordTTL)
	})

	t.Run("caches record ID", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "POST":
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{"id": "cached-rec-id"}`),
					}), nil
				default:
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		// Verify record is cached
		cacheKey := provider.recordCacheKey("_acme-challenge.example.com.", "token-value")
		provider.recordIDsMu.RLock()
		info, found := provider.recordIDs[cacheKey]
		provider.recordIDsMu.RUnlock()

		assert.True(t, found)
		assert.Equal(t, "cached-rec-id", info.recordID)
		assert.Equal(t, "zone123", info.zoneID)
	})

	t.Run("with preconfigured zone ID", func(t *testing.T) {
		zoneRequestMade := false
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path

				if strings.Contains(path, "/zones") && !strings.Contains(path, "/dns_records") {
					zoneRequestMade = true
				}

				switch {
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "POST":
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{"id": "rec123"}`),
					}), nil
				default:
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
			ZoneID:     "preconfigured-zone-id",
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.False(t, zoneRequestMade, "should not make zone lookup request when ZoneID is preconfigured")
	})
}

func TestCleanUp(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes existing record", func(t *testing.T) {
		deleteCalled := false
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				// Check dns_records BEFORE zones since path contains both
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "rec123", "name": "_acme-challenge.example.com", "content": "token-value", "type": "TXT", "zone_id": "zone123"}]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "DELETE":
					deleteCalled = true
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{}`),
					}), nil
				default:
					t.Logf("unexpected request: %s %s %s", req.Method, path, query)
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)
		assert.True(t, deleteCalled)
	})

	t.Run("record not found is not an error", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				switch {
				// Check dns_records BEFORE zones since path contains both
				case req.Method == "GET" && strings.Contains(path, "/dns_records"):
					// No matching records
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				case req.Method == "GET" && strings.Contains(path, "/zones"):
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				default:
					t.Logf("unexpected request: %s %s %s", req.Method, path, query)
					return mockResponse(500, nil), nil
				}
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		assert.NoError(t, err)
	})

	t.Run("uses cached record ID", func(t *testing.T) {
		deleteURL := ""
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method == "DELETE" {
					deleteURL = req.URL.Path
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`{}`),
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		// Pre-populate the cache
		cacheKey := provider.recordCacheKey("_acme-challenge.example.com.", "token-value")
		provider.recordIDsMu.Lock()
		provider.recordIDs[cacheKey] = recordInfo{
			recordID: "cached-record-id",
			zoneID:   "cached-zone-id",
		}
		provider.recordIDsMu.Unlock()

		err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.NoError(t, err)

		assert.Contains(t, deleteURL, "cached-zone-id")
		assert.Contains(t, deleteURL, "cached-record-id")

		// Verify cache is cleared
		provider.recordIDsMu.RLock()
		_, found := provider.recordIDs[cacheKey]
		provider.recordIDsMu.RUnlock()
		assert.False(t, found, "record should be removed from cache after cleanup")
	})

	t.Run("delete error with cache", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				if req.Method == "DELETE" {
					return mockResponse(200, apiResponse{
						Success: false,
						Errors:  []apiError{{Message: "delete failed"}},
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		// Pre-populate the cache
		cacheKey := provider.recordCacheKey("_acme-challenge.example.com.", "token-value")
		provider.recordIDsMu.Lock()
		provider.recordIDs[cacheKey] = recordInfo{
			recordID: "cached-record-id",
			zoneID:   "cached-zone-id",
		}
		provider.recordIDsMu.Unlock()

		err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete failed")
	})
}

func TestAPIErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("API returns error", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				// Check dns_records BEFORE zones since path contains both
				if strings.Contains(path, "/dns_records") {
					// Return error for dns_records lookup
					return mockResponse(200, apiResponse{
						Success: false,
						Errors: []apiError{
							{Code: 1001, Message: "Invalid API key"},
						},
					}), nil
				}
				// Return zone for zone lookups
				if strings.Contains(path, "/zones") {
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				}
				// Return error for other operations
				return mockResponse(200, apiResponse{
					Success: false,
					Errors: []apiError{
						{Code: 1001, Message: "Invalid API key"},
					},
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid API key")
	})

	t.Run("chained errors", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				path := req.URL.Path
				query := req.URL.RawQuery

				// Check dns_records BEFORE zones since path contains both
				if strings.Contains(path, "/dns_records") {
					// Return chained error for dns_records lookup
					return mockResponse(200, apiResponse{
						Success: false,
						Errors: []apiError{
							{
								Code:    1001,
								Message: "Auth error",
								ErrorChain: []apiError{
									{Code: 1002, Message: "Token expired"},
								},
							},
						},
					}), nil
				}
				// Return zone for zone lookups
				if strings.Contains(path, "/zones") {
					if strings.Contains(query, "name=example.com") {
						return mockResponse(200, apiResponse{
							Success: true,
							Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
						}), nil
					}
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				}
				// Return chained error for other operations
				return mockResponse(200, apiResponse{
					Success: false,
					Errors: []apiError{
						{
							Code:    1001,
							Message: "Auth error",
							ErrorChain: []apiError{
								{Code: 1002, Message: "Token expired"},
							},
						},
					},
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Auth error")
		assert.Contains(t, err.Error(), "Token expired")
	})

	t.Run("empty errors returns generic error", func(t *testing.T) {
		err := formatAPIErrors([]apiError{})
		assert.Equal(t, providers.ErrAPIError, err)
	})

	t.Run("multiple errors separated by semicolon", func(t *testing.T) {
		err := formatAPIErrors([]apiError{
			{Message: "Error 1"},
			{Message: "Error 2"},
		})
		assert.Contains(t, err.Error(), "Error 1")
		assert.Contains(t, err.Error(), "; ")
		assert.Contains(t, err.Error(), "Error 2")
	})
}

func TestFindNearestZone(t *testing.T) {
	ctx := context.Background()

	t.Run("finds zone for subdomain", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				fullURL := req.URL.String()

				if strings.Contains(fullURL, "name=_acme-challenge.www.example.com") {
					// No zone for full domain
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				}
				if strings.Contains(fullURL, "name=www.example.com") {
					// No zone for www
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[]`),
					}), nil
				}
				if strings.Contains(fullURL, "name=example.com") {
					// Found zone
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		zone, err := provider.findNearestZone(ctx, "_acme-challenge.www.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "zone123", zone.ID)
		assert.Equal(t, "example.com", zone.Name)
	})

	t.Run("empty fqdn returns error", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: &mockHTTPClient{},
		})
		require.NoError(t, err)

		_, err = provider.findNearestZone(ctx, "")
		require.Error(t, err)
	})

	t.Run("zone not found returns error", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, err = provider.findNearestZone(ctx, "unknown.domain.com.")
		require.Error(t, err)
		assert.Equal(t, providers.ErrZoneNotFound, err)
	})

	t.Run("handles wildcard domains", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				fullURL := req.URL.String()

				if strings.Contains(fullURL, "name=example.com") {
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		zone, err := provider.findNearestZone(ctx, "_acme-challenge.*.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "zone123", zone.ID)
	})
}

func TestRegistration(t *testing.T) {
	// Verify provider is registered
	assert.True(t, providers.Registered(providers.ProviderCloudflare))

	factory := providers.Get(providers.ProviderCloudflare)
	assert.NotNil(t, factory)
}

func TestFactoryInvalidConfig(t *testing.T) {
	factory := providers.Get(providers.ProviderCloudflare)
	require.NotNil(t, factory)

	ctx := context.Background()

	// Pass invalid config type
	_, err := factory(ctx, "invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected cloudflare.Config")
}

func TestAuthHeaders(t *testing.T) {
	ctx := context.Background()

	t.Run("uses API token", func(t *testing.T) {
		var capturedReq *http.Request
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				capturedReq = req
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "my-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, _ = provider.makeRequest(ctx, "GET", "/test", nil, false)

		require.NotNil(t, capturedReq)
		assert.Equal(t, "Bearer my-token", capturedReq.Header.Get("Authorization"))
		assert.Empty(t, capturedReq.Header.Get("X-Auth-Email"))
		assert.Empty(t, capturedReq.Header.Get("X-Auth-Key"))
	})

	t.Run("uses API key and email", func(t *testing.T) {
		var capturedReq *http.Request
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				capturedReq = req
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			Email:      "user@example.com",
			APIKey:     "my-key",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, _ = provider.makeRequest(ctx, "GET", "/test", nil, false)

		require.NotNil(t, capturedReq)
		assert.Equal(t, "user@example.com", capturedReq.Header.Get("X-Auth-Email"))
		assert.Equal(t, "my-key", capturedReq.Header.Get("X-Auth-Key"))
		assert.Empty(t, capturedReq.Header.Get("Authorization"))
	})

	t.Run("uses zone API token for zone requests", func(t *testing.T) {
		var zoneRequestAuth, dnsRequestAuth string
		requestCount := 0
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				requestCount++
				auth := req.Header.Get("Authorization")
				// First request is the zone request (zoneRequest=true)
				// Second request is the DNS request (zoneRequest=false)
				if requestCount == 1 {
					zoneRequestAuth = auth
				} else {
					dnsRequestAuth = auth
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:     "dns-token",
			ZoneAPIToken: "zone-list-token",
			HTTPClient:   mockClient,
		})
		require.NoError(t, err)

		// Make a zone request (zoneRequest=true)
		_, _ = provider.makeRequest(ctx, "GET", "/zones?name=example.com", nil, true)
		assert.Equal(t, "Bearer zone-list-token", zoneRequestAuth)

		// Make a DNS request (zoneRequest=false)
		_, _ = provider.makeRequest(ctx, "GET", "/dns_records", nil, false)
		assert.Equal(t, "Bearer dns-token", dnsRequestAuth)
	})

	t.Run("uses primary token when zone token not set", func(t *testing.T) {
		var capturedAuth string
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				capturedAuth = req.Header.Get("Authorization")
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "primary-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		// Make a zone request without ZoneAPIToken set
		_, _ = provider.makeRequest(ctx, "GET", "/zones?name=example.com", nil, true)
		assert.Equal(t, "Bearer primary-token", capturedAuth)
	})
}

func TestCustomBaseURL(t *testing.T) {
	ctx := context.Background()

	t.Run("uses custom base URL", func(t *testing.T) {
		var capturedURL string
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				capturedURL = req.URL.String()
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			BaseURL:    "https://enterprise.cloudflare.com/v4",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, _ = provider.makeRequest(ctx, "GET", "/zones", nil, false)
		assert.True(t, strings.HasPrefix(capturedURL, "https://enterprise.cloudflare.com/v4"))
	})
}

func TestNewFromEnv(t *testing.T) {
	ctx := context.Background()

	// Helper to clear all Cloudflare env vars
	clearEnv := func() {
		os.Unsetenv(envEmail)
		os.Unsetenv(envAPIKey)
		os.Unsetenv(envDNSAPIToken)
		os.Unsetenv(envZoneAPIToken)
		os.Unsetenv(envZoneID)
		os.Unsetenv(envPropagationTimeout)
		os.Unsetenv(envPollingInterval)
		os.Unsetenv(envTTL)
		os.Unsetenv(envHTTPTimeout)
		os.Unsetenv(envCFEmail)
		os.Unsetenv(envCFAPIKey)
		os.Unsetenv(envCFDNSAPIToken)
		os.Unsetenv(envCFZoneAPIToken)
		os.Unsetenv(envCFZoneID)
		os.Unsetenv(envCFPropagationTimeout)
		os.Unsetenv(envCFPollingInterval)
		os.Unsetenv(envCFTTL)
		os.Unsetenv(envCFHTTPTimeout)
	}

	t.Run("with CLOUDFLARE_* env vars", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envDNSAPIToken, "env-token")
		os.Setenv(envZoneAPIToken, "env-zone-token")
		os.Setenv(envZoneID, "env-zone-id")
		os.Setenv(envPropagationTimeout, "5m")
		os.Setenv(envPollingInterval, "10s")
		os.Setenv(envTTL, "300")
		os.Setenv(envHTTPTimeout, "45s")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, "env-token", provider.apiToken)
		assert.Equal(t, "env-zone-token", provider.zoneAPIToken)
		assert.Equal(t, "env-zone-id", provider.zoneID)
		assert.Equal(t, 5*time.Minute, provider.propagationTimeout)
		assert.Equal(t, 10*time.Second, provider.pollingInterval)
		assert.Equal(t, 300, provider.ttl)
	})

	t.Run("with CF_* alias env vars", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envCFDNSAPIToken, "cf-token")
		os.Setenv(envCFZoneID, "cf-zone-id")
		os.Setenv(envCFPropagationTimeout, "3m")
		os.Setenv(envCFPollingInterval, "5s")
		os.Setenv(envCFTTL, "200")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, "cf-token", provider.apiToken)
		assert.Equal(t, "cf-zone-id", provider.zoneID)
		assert.Equal(t, 3*time.Minute, provider.propagationTimeout)
		assert.Equal(t, 5*time.Second, provider.pollingInterval)
		assert.Equal(t, 200, provider.ttl)
	})

	t.Run("CLOUDFLARE_* takes precedence over CF_*", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envDNSAPIToken, "cloudflare-token")
		os.Setenv(envCFDNSAPIToken, "cf-token")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, "cloudflare-token", provider.apiToken)
	})

	t.Run("with API key auth", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envEmail, "user@example.com")
		os.Setenv(envAPIKey, "api-key-123")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, "user@example.com", provider.email)
		assert.Equal(t, "api-key-123", provider.apiKey)
	})

	t.Run("no credentials returns error", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		_, err := NewFromEnv(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credentials")
	})

	t.Run("invalid duration uses default", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envDNSAPIToken, "valid-token")
		os.Setenv(envPropagationTimeout, "invalid")
		os.Setenv(envPollingInterval, "also-invalid")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, defaultPropagationTimeout, provider.propagationTimeout)
		assert.Equal(t, defaultPollingInterval, provider.pollingInterval)
	})

	t.Run("invalid TTL uses default", func(t *testing.T) {
		clearEnv()
		defer clearEnv()

		os.Setenv(envDNSAPIToken, "valid-token")
		os.Setenv(envTTL, "not-a-number")

		provider, err := NewFromEnv(ctx)
		require.NoError(t, err)

		assert.Equal(t, defaultRecordTTL, provider.ttl)
	})
}

func TestRecordCacheKey(t *testing.T) {
	ctx := context.Background()

	provider, err := New(ctx, Config{
		APIToken: "valid-token",
	})
	require.NoError(t, err)

	key := provider.recordCacheKey("_acme-challenge.example.com.", "token-value")
	assert.Equal(t, "_acme-challenge.example.com.|token-value", key)
}

func TestGetZoneIDWithPreconfigured(t *testing.T) {
	ctx := context.Background()

	t.Run("returns preconfigured zone ID", func(t *testing.T) {
		provider, err := New(ctx, Config{
			APIToken: "valid-token",
			ZoneID:   "preconfigured-zone",
		})
		require.NoError(t, err)

		zoneID, err := provider.getZoneID(ctx, "_acme-challenge.example.com.")
		require.NoError(t, err)
		assert.Equal(t, "preconfigured-zone", zoneID)
	})
}

func TestMakeRequestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("HTTP client error", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				return nil, assert.AnError
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, err = provider.makeRequest(ctx, "GET", "/test", nil, false)
		require.Error(t, err)
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("invalid json")),
					Header:     make(http.Header),
				}, nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, err = provider.makeRequest(ctx, "GET", "/test", nil, false)
		require.Error(t, err)
	})
}

func TestFindTXTRecordErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("zone lookup error propagates", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
		})
		require.NoError(t, err)

		_, err = provider.findTXTRecord(ctx, "unknown.domain.com.", "value")
		require.Error(t, err)
	})

	t.Run("invalid JSON in records response", func(t *testing.T) {
		requestCount := 0
		mockClient := &mockHTTPClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				requestCount++
				path := req.URL.Path

				if strings.Contains(path, "/dns_records") {
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":"invalid"}`)),
						Header:     make(http.Header),
					}, nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[{"id":"zone123","name":"example.com"}]`),
				}), nil
			},
		}

		provider, err := New(ctx, Config{
			APIToken:   "valid-token",
			HTTPClient: mockClient,
			ZoneID:     "zone123",
		})
		require.NoError(t, err)

		_, err = provider.findTXTRecord(ctx, "_acme-challenge.example.com.", "value")
		require.Error(t, err)
	})
}

func TestCleanUpFindRecordError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			query := req.URL.RawQuery

			if strings.Contains(path, "/dns_records") {
				return mockResponse(200, apiResponse{
					Success: false,
					Errors:  []apiError{{Message: "API error during find"}},
				}), nil
			}
			if strings.Contains(path, "/zones") && strings.Contains(query, "name=example.com") {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
				}), nil
			}
			return mockResponse(200, apiResponse{
				Success: true,
				Result:  json.RawMessage(`[]`),
			}), nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "find record")
}

func TestPresentGetZoneError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			// All zone lookups return empty (zone not found)
			return mockResponse(200, apiResponse{
				Success: true,
				Result:  json.RawMessage(`[]`),
			}), nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	err = provider.Present(ctx, "unknown.domain.com", "_acme-challenge.unknown.domain.com.", "token")
	require.Error(t, err)
	// The error contains "zone not found" from the underlying ErrZoneNotFound
	assert.Contains(t, err.Error(), "zone not found")
}

func TestPresentCreateRecordError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			query := req.URL.RawQuery

			if req.Method == "GET" && strings.Contains(path, "/dns_records") {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			}
			if req.Method == "GET" && strings.Contains(path, "/zones") {
				if strings.Contains(query, "name=example.com") {
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			}
			if req.Method == "POST" {
				return mockResponse(200, apiResponse{
					Success: false,
					Errors:  []apiError{{Message: "Record creation failed"}},
				}), nil
			}
			return mockResponse(500, nil), nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	err = provider.Present(ctx, "example.com", "_acme-challenge.example.com.", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create record")
}

func TestFindNearestZoneAPIError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			query := req.URL.RawQuery

			// Return error for first few lookups, then success
			if strings.Contains(query, "name=_acme-challenge.example.com") {
				return mockResponse(200, apiResponse{
					Success: false,
					Errors:  []apiError{{Message: "API error"}},
				}), nil
			}
			if strings.Contains(query, "name=example.com") {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
				}), nil
			}
			return mockResponse(200, apiResponse{
				Success: true,
				Result:  json.RawMessage(`[]`),
			}), nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	zone, err := provider.findNearestZone(ctx, "_acme-challenge.example.com.")
	require.NoError(t, err)
	assert.Equal(t, "zone123", zone.ID)
}

func TestFindNearestZoneJSONUnmarshalError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":"not-an-array"}`)),
				Header:     make(http.Header),
			}, nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	_, err = provider.findNearestZone(ctx, "_acme-challenge.example.com.")
	require.Error(t, err)
}

func TestEnvHelperFunctions(t *testing.T) {
	// Test getEnvWithAlias
	t.Run("getEnvWithAlias primary set", func(t *testing.T) {
		os.Setenv("TEST_PRIMARY", "primary-value")
		os.Setenv("TEST_ALIAS", "alias-value")
		defer os.Unsetenv("TEST_PRIMARY")
		defer os.Unsetenv("TEST_ALIAS")

		result := getEnvWithAlias("TEST_PRIMARY", "TEST_ALIAS")
		assert.Equal(t, "primary-value", result)
	})

	t.Run("getEnvWithAlias falls back to alias", func(t *testing.T) {
		os.Unsetenv("TEST_PRIMARY")
		os.Setenv("TEST_ALIAS", "alias-value")
		defer os.Unsetenv("TEST_ALIAS")

		result := getEnvWithAlias("TEST_PRIMARY", "TEST_ALIAS")
		assert.Equal(t, "alias-value", result)
	})

	t.Run("getEnvWithAlias both empty", func(t *testing.T) {
		os.Unsetenv("TEST_PRIMARY")
		os.Unsetenv("TEST_ALIAS")

		result := getEnvWithAlias("TEST_PRIMARY", "TEST_ALIAS")
		assert.Equal(t, "", result)
	})

	// Test getDurationWithAlias
	t.Run("getDurationWithAlias primary set", func(t *testing.T) {
		os.Setenv("TEST_DUR_PRIMARY", "5m")
		os.Setenv("TEST_DUR_ALIAS", "10m")
		defer os.Unsetenv("TEST_DUR_PRIMARY")
		defer os.Unsetenv("TEST_DUR_ALIAS")

		result := getDurationWithAlias("TEST_DUR_PRIMARY", "TEST_DUR_ALIAS", time.Second)
		assert.Equal(t, 5*time.Minute, result)
	})

	t.Run("getDurationWithAlias falls back to alias", func(t *testing.T) {
		os.Unsetenv("TEST_DUR_PRIMARY")
		os.Setenv("TEST_DUR_ALIAS", "10m")
		defer os.Unsetenv("TEST_DUR_ALIAS")

		result := getDurationWithAlias("TEST_DUR_PRIMARY", "TEST_DUR_ALIAS", time.Second)
		assert.Equal(t, 10*time.Minute, result)
	})

	t.Run("getDurationWithAlias uses default", func(t *testing.T) {
		os.Unsetenv("TEST_DUR_PRIMARY")
		os.Unsetenv("TEST_DUR_ALIAS")

		result := getDurationWithAlias("TEST_DUR_PRIMARY", "TEST_DUR_ALIAS", 30*time.Second)
		assert.Equal(t, 30*time.Second, result)
	})

	// Test getIntWithAlias
	t.Run("getIntWithAlias primary set", func(t *testing.T) {
		os.Setenv("TEST_INT_PRIMARY", "100")
		os.Setenv("TEST_INT_ALIAS", "200")
		defer os.Unsetenv("TEST_INT_PRIMARY")
		defer os.Unsetenv("TEST_INT_ALIAS")

		result := getIntWithAlias("TEST_INT_PRIMARY", "TEST_INT_ALIAS", 50)
		assert.Equal(t, 100, result)
	})

	t.Run("getIntWithAlias falls back to alias", func(t *testing.T) {
		os.Unsetenv("TEST_INT_PRIMARY")
		os.Setenv("TEST_INT_ALIAS", "200")
		defer os.Unsetenv("TEST_INT_ALIAS")

		result := getIntWithAlias("TEST_INT_PRIMARY", "TEST_INT_ALIAS", 50)
		assert.Equal(t, 200, result)
	})

	t.Run("getIntWithAlias uses default", func(t *testing.T) {
		os.Unsetenv("TEST_INT_PRIMARY")
		os.Unsetenv("TEST_INT_ALIAS")

		result := getIntWithAlias("TEST_INT_PRIMARY", "TEST_INT_ALIAS", 50)
		assert.Equal(t, 50, result)
	})
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify compile-time interface compliance
	var _ providers.Provider = (*Provider)(nil)
	var _ providers.ProviderTimeout = (*Provider)(nil)
}

func TestCleanUpDeleteError(t *testing.T) {
	ctx := context.Background()

	mockClient := &mockHTTPClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			query := req.URL.RawQuery

			if req.Method == "GET" && strings.Contains(path, "/dns_records") {
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[{"id": "rec123", "name": "_acme-challenge.example.com", "content": "token-value", "type": "TXT"}]`),
				}), nil
			}
			if req.Method == "GET" && strings.Contains(path, "/zones") {
				if strings.Contains(query, "name=example.com") {
					return mockResponse(200, apiResponse{
						Success: true,
						Result:  json.RawMessage(`[{"id": "zone123", "name": "example.com"}]`),
					}), nil
				}
				return mockResponse(200, apiResponse{
					Success: true,
					Result:  json.RawMessage(`[]`),
				}), nil
			}
			if req.Method == "DELETE" {
				return mockResponse(200, apiResponse{
					Success: false,
					Errors:  []apiError{{Message: "Delete failed"}},
				}), nil
			}
			return mockResponse(500, nil), nil
		},
	}

	provider, err := New(ctx, Config{
		APIToken:   "valid-token",
		HTTPClient: mockClient,
	})
	require.NoError(t, err)

	err = provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.", "token-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete record")
}
