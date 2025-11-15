// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

// APIKeyAuthenticator authenticates requests using API keys
// API keys can be provided via header or query parameter
type APIKeyAuthenticator struct {
	// validKeys maps API keys to their associated identity
	validKeys map[string]*Identity

	// headerName is the HTTP header name for the API key (default: "X-API-Key")
	headerName string

	// queryParam is the query parameter name for the API key (default: "api_key")
	queryParam string
}

// APIKeyConfig configures the API key authenticator
type APIKeyConfig struct {
	// Keys maps API keys to identities
	Keys map[string]*Identity

	// HeaderName is the HTTP header name (default: "X-API-Key")
	HeaderName string

	// QueryParam is the query parameter name (default: "api_key")
	QueryParam string
}

// NewAPIKeyAuthenticator creates a new API key authenticator
func NewAPIKeyAuthenticator(config *APIKeyConfig) *APIKeyAuthenticator {
	if config == nil {
		config = &APIKeyConfig{}
	}

	if config.HeaderName == "" {
		config.HeaderName = "X-API-Key"
	}

	if config.QueryParam == "" {
		config.QueryParam = "api_key"
	}

	if config.Keys == nil {
		config.Keys = make(map[string]*Identity)
	}

	return &APIKeyAuthenticator{
		validKeys:  config.Keys,
		headerName: config.HeaderName,
		queryParam: config.QueryParam,
	}
}

// AddKey adds a new API key with the given identity
func (a *APIKeyAuthenticator) AddKey(apiKey string, identity *Identity) {
	a.validKeys[apiKey] = identity
}

// RemoveKey removes an API key
func (a *APIKeyAuthenticator) RemoveKey(apiKey string) {
	delete(a.validKeys, apiKey)
}

// AuthenticateHTTP authenticates an HTTP request using an API key
func (a *APIKeyAuthenticator) AuthenticateHTTP(r *http.Request) (*Identity, error) {
	// Try header first
	apiKey := r.Header.Get(a.headerName)

	// Fall back to query parameter
	if apiKey == "" {
		apiKey = r.URL.Query().Get(a.queryParam)
	}

	// Try Authorization header with "Bearer" scheme
	if apiKey == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			apiKey = strings.TrimPrefix(auth, "Bearer ")
		}
	}

	if apiKey == "" {
		return nil, fmt.Errorf("no API key provided")
	}

	identity, ok := a.validKeys[apiKey]
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}

	// Clone the identity to avoid mutations
	cloned := &Identity{
		Subject:    identity.Subject,
		Claims:     make(map[string]interface{}),
		Attributes: make(map[string]string),
	}

	for k, v := range identity.Claims {
		cloned.Claims[k] = v
	}

	for k, v := range identity.Attributes {
		cloned.Attributes[k] = v
	}

	cloned.Attributes["auth_method"] = "apikey"
	cloned.Attributes["remote_addr"] = r.RemoteAddr

	return cloned, nil
}

// AuthenticateGRPC authenticates a gRPC request using an API key from metadata
func (a *APIKeyAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error) {
	// Try to get API key from metadata
	var apiKey string

	// Check custom header (lowercase in gRPC metadata)
	headerKey := strings.ToLower(a.headerName)
	if values := md.Get(headerKey); len(values) > 0 {
		apiKey = values[0]
	}

	// Try authorization header
	if apiKey == "" {
		if values := md.Get("authorization"); len(values) > 0 {
			auth := values[0]
			if strings.HasPrefix(auth, "Bearer ") {
				apiKey = strings.TrimPrefix(auth, "Bearer ")
			}
		}
	}

	if apiKey == "" {
		return nil, fmt.Errorf("no API key provided in metadata")
	}

	identity, ok := a.validKeys[apiKey]
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}

	// Clone the identity
	cloned := &Identity{
		Subject:    identity.Subject,
		Claims:     make(map[string]interface{}),
		Attributes: make(map[string]string),
	}

	for k, v := range identity.Claims {
		cloned.Claims[k] = v
	}

	for k, v := range identity.Attributes {
		cloned.Attributes[k] = v
	}

	cloned.Attributes["auth_method"] = "apikey"

	return cloned, nil
}

// Name returns the authenticator name
func (a *APIKeyAuthenticator) Name() string {
	return "apikey"
}
