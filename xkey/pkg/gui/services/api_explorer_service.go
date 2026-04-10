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

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

const (
	// maxResponseBodySize is the maximum response body size (10 MB).
	maxResponseBodySize = 10 * 1024 * 1024

	// historyKeyPrefix is the storage key prefix for history entries.
	historyKeyPrefix = "api_explorer_history/"

	// defaultHTTPTimeout is the default HTTP client timeout.
	defaultHTTPTimeout = 30 * time.Second
)

// validMethods provides O(1) lookup for valid HTTP methods.
var validMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"HEAD":    true,
	"OPTIONS": true,
}

// ExplorerRequest describes an HTTP request to execute.
type ExplorerRequest struct {
	Method  string            `json:"method"`  // GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
	URL     string            `json:"url"`     // Full URL including scheme and host
	Headers map[string]string `json:"headers"` // Additional headers to include
	Body    string            `json:"body"`    // Request body (JSON string)
}

// Validate checks the request for required fields and valid values.
func (r *ExplorerRequest) Validate() error {
	if r.Method == "" {
		return ErrExplorerInvalidMethod
	}
	if !validMethods[r.Method] {
		return ErrExplorerInvalidMethod
	}
	if r.URL == "" {
		return ErrExplorerInvalidURL
	}
	parsed, err := url.Parse(r.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ErrExplorerInvalidURL
	}
	return nil
}

// ExplorerResponse captures the HTTP response from an executed request.
type ExplorerResponse struct {
	StatusCode int               `json:"status_code"`
	Status     string            `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	DurationMs int64             `json:"duration_ms"`
	Error      string            `json:"error,omitempty"`
}

// HistoryEntry records a request/response pair for the API explorer history.
type HistoryEntry struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Request   *ExplorerRequest  `json:"request"`
	Response  *ExplorerResponse `json:"response"`
}

// AvailableToken describes a token available for use in API Explorer requests.
type AvailableToken struct {
	ID        string `json:"id"`
	Source    string `json:"source"` // "oidc", "fido2", "bootstrap"
	Label     string `json:"label"`  // human-readable label
	Token     string `json:"token"`  // full JWT value
	ExpiresAt string `json:"expires_at"`
	IsExpired bool   `json:"is_expired"`
}

// ExplorerConfig holds the dependencies for creating an APIExplorerService.
type ExplorerConfig struct {
	Logger       *slog.Logger
	TokenStore   tokenstore.TokenStore
	Registry     serverregistry.ServerRegistry
	TrustStore   storage.Backend
	HistoryStore storage.Backend
	OIDCService  *OIDCService
	FIDO2Service *FIDO2Service
}

// APIExplorerService executes authenticated HTTP requests against xkms servers.
// It automatically injects JWT tokens from the TokenStore and resolves TLS
// configuration via the ServerRegistry and TrustStore.
type APIExplorerService struct {
	ctx          context.Context
	log          *slog.Logger
	tokenStore   tokenstore.TokenStore
	registry     serverregistry.ServerRegistry
	trustStore   storage.Backend
	historyStore storage.Backend
	oidcService  *OIDCService
	fido2Service *FIDO2Service
	httpClient   *http.Client
	closed       atomic.Bool
	mu           sync.RWMutex
}

// NewAPIExplorerService creates a new APIExplorerService with the given
// configuration. All dependencies are validated and a default HTTP client
// is created with a 30-second timeout.
func NewAPIExplorerService(config *ExplorerConfig) (*APIExplorerService, error) {
	if config == nil {
		return nil, ErrExplorerNilConfig
	}
	if config.TokenStore == nil {
		return nil, ErrExplorerNilTokenStore
	}
	if config.Registry == nil {
		return nil, ErrExplorerNilRegistry
	}
	if config.TrustStore == nil {
		return nil, ErrExplorerNilTrustStore
	}
	if config.HistoryStore == nil {
		return nil, ErrExplorerNilHistoryStore
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &APIExplorerService{
		log:          logger.With("component", "api_explorer_service"),
		tokenStore:   config.TokenStore,
		registry:     config.Registry,
		trustStore:   config.TrustStore,
		historyStore: config.HistoryStore,
		oidcService:  config.OIDCService,
		fido2Service: config.FIDO2Service,
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}, nil
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *APIExplorerService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// Execute sends an HTTP request and returns the response. It automatically
// injects a JWT Authorization header when a token is available for the
// target server. The request and response are recorded in history.
//
// User-visible errors (validation failures, network errors, body limits)
// are returned in ExplorerResponse.Error so the frontend can display them.
// Only system-level errors like ErrExplorerClosed are returned as Go errors.
func (s *APIExplorerService) Execute(req *ExplorerRequest) (*ExplorerResponse, error) {
	if s.closed.Load() {
		return nil, ErrExplorerClosed
	}

	if req == nil {
		return &ExplorerResponse{Error: "request is required"}, nil
	}

	if err := req.Validate(); err != nil {
		return &ExplorerResponse{Error: err.Error()}, nil
	}

	// Extract server base URL for token and registry lookups.
	serverURL, err := extractServerURL(req.URL)
	if err != nil {
		return &ExplorerResponse{Error: "invalid URL: scheme and host are required"}, nil
	}

	// Build the HTTP request.
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return &ExplorerResponse{Error: "failed to build HTTP request"}, nil
	}

	// Inject JWT from token store if available.
	token, tokenErr := s.tokenStore.Load(ctx, serverURL)
	if tokenErr == nil && token != nil && token.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token.Token)
	}

	// Set Content-Type for requests with a body.
	if req.Body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Apply custom headers (after defaults so user can override).
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Look up server entry for potential TLS configuration.
	// This is best-effort; failures are logged but do not block the request.
	_, registryErr := s.registry.Lookup(ctx, serverURL)
	if registryErr != nil {
		s.log.Debug("server registry lookup skipped",
			"server", serverURL,
			"reason", registryErr.Error())
	}

	// Execute the request and measure duration.
	start := time.Now()
	resp, err := s.httpClient.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		// Record the failed request in history and return the error response
		// so the frontend can display the error details and duration.
		explorerResp := &ExplorerResponse{
			DurationMs: duration.Milliseconds(),
			Error:      err.Error(),
		}
		s.recordHistory(req, explorerResp)
		return explorerResp, nil
	}
	defer resp.Body.Close()

	// Read the response body with a size limit.
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		explorerResp := &ExplorerResponse{
			DurationMs: duration.Milliseconds(),
			Error:      "failed to read response body",
		}
		s.recordHistory(req, explorerResp)
		return explorerResp, nil
	}

	if int64(len(body)) > maxResponseBodySize {
		explorerResp := &ExplorerResponse{
			DurationMs: duration.Milliseconds(),
			Error:      "response body exceeds 10 MB limit",
		}
		s.recordHistory(req, explorerResp)
		return explorerResp, nil
	}

	// Collect response headers.
	headers := make(map[string]string, len(resp.Header))
	for key := range resp.Header {
		headers[key] = resp.Header.Get(key)
	}

	bodyStr := string(body)

	// Inject a <base> tag into HTML responses so that relative URLs
	// (images, stylesheets, forms) resolve correctly when rendered in
	// the srcdoc iframe.
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		reqURL, parseErr := url.Parse(req.URL)
		if parseErr == nil && reqURL.Host != "" {
			baseTag := fmt.Sprintf(`<base href="%s://%s">`, reqURL.Scheme, reqURL.Host)
			if idx := strings.Index(strings.ToLower(bodyStr), "<head>"); idx >= 0 {
				insertAt := idx + len("<head>")
				bodyStr = bodyStr[:insertAt] + baseTag + bodyStr[insertAt:]
			} else if idx := strings.Index(strings.ToLower(bodyStr), "<html"); idx >= 0 {
				// No <head> tag; insert after <html...>
				closeIdx := strings.Index(bodyStr[idx:], ">")
				if closeIdx >= 0 {
					insertAt := idx + closeIdx + 1
					bodyStr = bodyStr[:insertAt] + "<head>" + baseTag + "</head>" + bodyStr[insertAt:]
				}
			} else {
				// No HTML structure; prepend base tag
				bodyStr = baseTag + bodyStr
			}
		}
	}

	explorerResp := &ExplorerResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    headers,
		Body:       bodyStr,
		DurationMs: duration.Milliseconds(),
	}

	// Record in history.
	s.recordHistory(req, explorerResp)

	return explorerResp, nil
}

// ListAvailableTokens returns all available tokens from the token store and
// OIDC service, suitable for the frontend token picker. Tokens are sorted
// by source then label.
func (s *APIExplorerService) ListAvailableTokens() []AvailableToken {
	if s.closed.Load() {
		return nil
	}

	var tokens []AvailableToken
	seen := make(map[string]struct{})

	// Collect tokens from the token store (fido2, bootstrap sources).
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	entries, err := s.tokenStore.List(ctx)
	if err == nil {
		for _, entry := range entries {
			if entry == nil || entry.Token == "" {
				continue
			}
			id := "ts:" + entry.ServerURL
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}

			label := entry.Source + ": " + entry.ServerURL
			if entry.Subject != "" {
				label = entry.Source + ": " + entry.Subject + " @ " + entry.ServerURL
			}

			expiresAt := ""
			if !entry.ExpiresAt.IsZero() {
				expiresAt = entry.ExpiresAt.Format(time.RFC3339)
			}

			tokens = append(tokens, AvailableToken{
				ID:        id,
				Source:    entry.Source,
				Label:     label,
				Token:     entry.Token,
				ExpiresAt: expiresAt,
				IsExpired: entry.IsExpired(),
			})
		}
	}

	// Collect tokens from the OIDC service.
	if s.oidcService != nil {
		oidcTokens := s.oidcService.GetAllTokens()
		for _, info := range oidcTokens {
			id := "oidc:" + info.Provider
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}

			label := "OIDC: " + info.Provider
			if info.Email != "" {
				label = "OIDC: " + info.Email + " (" + info.Provider + ")"
			} else if info.Name != "" {
				label = "OIDC: " + info.Name + " (" + info.Provider + ")"
			}

			// Retrieve only the access token for use as a bearer token.
			accessToken, err := s.oidcService.GetAccessToken(info.Provider)
			if err != nil || accessToken == "" {
				continue
			}

			tokens = append(tokens, AvailableToken{
				ID:        id,
				Source:    "oidc",
				Label:     label,
				Token:     accessToken,
				ExpiresAt: info.ExpiresAt,
				IsExpired: info.IsExpired,
			})
		}
	}

	// Collect FIDO2 auth response tokens.
	if s.fido2Service != nil {
		for _, resp := range s.fido2Service.GetAuthResponses() {
			if resp.Token == "" {
				continue
			}
			id := "fido2:" + resp.RPID
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}

			expiresAt := ""
			if !resp.ExpiresAt.IsZero() {
				expiresAt = resp.ExpiresAt.Format(time.RFC3339)
			}

			tokens = append(tokens, AvailableToken{
				ID:        id,
				Source:    "fido2",
				Label:     "FIDO2: " + resp.RPID,
				Token:     resp.Token,
				ExpiresAt: expiresAt,
				IsExpired: !resp.ExpiresAt.IsZero() && time.Now().UTC().After(resp.ExpiresAt),
			})
		}
	}

	// Sort by source, then label.
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].Source != tokens[j].Source {
			return tokens[i].Source < tokens[j].Source
		}
		return tokens[i].Label < tokens[j].Label
	})

	return tokens
}

// GetHistory returns all history entries sorted by timestamp descending
// (most recent first).
func (s *APIExplorerService) GetHistory() ([]*HistoryEntry, error) {
	if s.closed.Load() {
		return nil, ErrExplorerClosed
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	keys, err := s.historyStore.List(context.Background(), historyKeyPrefix)
	if err != nil {
		return nil, err
	}

	entries := make([]*HistoryEntry, 0, len(keys))
	for _, key := range keys {
		data, err := s.historyStore.Get(context.Background(), key)
		if err != nil {
			continue
		}

		var entry HistoryEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entries = append(entries, &entry)
	}

	// Sort by timestamp descending (most recent first).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// ClearHistory deletes all history entries from the history store.
func (s *APIExplorerService) ClearHistory() error {
	if s.closed.Load() {
		return ErrExplorerClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	keys, err := s.historyStore.List(context.Background(), historyKeyPrefix)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if deleteErr := s.historyStore.Delete(context.Background(), key); deleteErr != nil {
			s.log.Warn("failed to delete history entry",
				"key", key,
				"error", deleteErr.Error())
		}
	}

	return nil
}

// DeleteHistoryEntry deletes a single history entry by ID.
func (s *APIExplorerService) DeleteHistoryEntry(id string) error {
	if s.closed.Load() {
		return ErrExplorerClosed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := historyKeyPrefix + id + ".json"
	err := s.historyStore.Delete(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrExplorerHistoryNotFound
		}
		return err
	}

	return nil
}

// Close marks the service as closed. Subsequent calls to Execute,
// GetHistory, ClearHistory, and DeleteHistoryEntry will return
// ErrExplorerClosed. Close is idempotent.
func (s *APIExplorerService) Close() error {
	s.closed.Store(true)
	return nil
}

// recordHistory persists a request/response pair to the history store.
// Errors are logged but do not propagate to the caller.
func (s *APIExplorerService) recordHistory(req *ExplorerRequest, resp *ExplorerResponse) {
	entry := &HistoryEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Request:   req,
		Response:  resp,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		s.log.Warn("failed to marshal history entry",
			"error", err.Error())
		return
	}

	key := historyKeyPrefix + entry.ID + ".json"

	s.mu.Lock()
	defer s.mu.Unlock()

	if putErr := s.historyStore.Put(context.Background(), key, data); putErr != nil {
		s.log.Warn("failed to persist history entry",
			"key", key,
			"error", putErr.Error())
	}
}

// extractServerURL parses a raw URL and returns the normalized base URL
// (scheme + host) in lowercase.
func extractServerURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", ErrExplorerInvalidURL
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrExplorerInvalidURL
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host), nil
}
