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

// Package xkms implements escrow.EscrowAgent for xkms-to-xkms federation.
// It replicates wrapped key material to a remote go-xkms instance over mTLS,
// enabling disaster recovery and geographic key distribution per NIST SP 800-57.
package xkms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

const (
	// apiPrefix is the base path for escrow API endpoints.
	apiPrefix = "/api/v1/escrow/keys"

	// healthPath is the health check endpoint.
	healthPath = "/api/v1/health"

	// defaultTimeout is the default HTTP client timeout.
	defaultTimeout = 30 * time.Second

	// maxResponseBodySize is the maximum response body size (10 MB).
	maxResponseBodySize = 10 * 1024 * 1024
)

// FederationConfig configures the xkms-to-xkms federation agent.
type FederationConfig struct {
	// Endpoint is the remote go-xkms instance URL (e.g., "https://dr-xkms.company.com:8443").
	Endpoint string `json:"endpoint"`

	// ClientCert is the path to the client certificate PEM file for mTLS.
	ClientCert string `json:"client_cert"`

	// ClientKey is the path to the client private key PEM file for mTLS.
	ClientKey string `json:"client_key"`

	// CACert is the path to the CA certificate PEM file for server verification.
	CACert string `json:"ca_cert"`

	// Timeout overrides the default HTTP client timeout. Zero uses defaultTimeout.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Validate checks the configuration for required fields.
func (c *FederationConfig) Validate() error {
	if c.Endpoint == "" {
		return escrow.ErrEmptyEndpoint
	}
	return nil
}

// FederationAgent implements escrow.EscrowAgent by replicating wrapped
// key material to a remote go-xkms instance over mTLS.
type FederationAgent struct {
	endpoint string
	client   *http.Client
	closed   atomic.Bool
}

// Compile-time interface assertion.
var _ escrow.EscrowAgent = (*FederationAgent)(nil)

// NewFederationAgent creates a new xkms-to-xkms federation escrow agent.
// If TLS certificate paths are provided, mTLS is configured. If no TLS
// paths are provided, a plain HTTPS client is used (suitable for testing).
func NewFederationAgent(config *FederationConfig) (*FederationAgent, error) {
	if config == nil {
		return nil, escrow.ErrAgentNotConfigured
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	transport, err := buildTransport(config)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &FederationAgent{
		endpoint: config.Endpoint,
		client:   client,
	}, nil
}

// Type returns the agent type identifier.
func (a *FederationAgent) Type() string {
	return escrow.AgentTypeXKMS
}

// Available reports whether the remote go-xkms instance can be reached.
func (a *FederationAgent) Available(ctx context.Context) bool {
	if a.closed.Load() {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.endpoint+healthPath, nil)
	if err != nil {
		return false
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// EscrowKey sends wrapped key material to the remote go-xkms instance.
func (a *FederationAgent) EscrowKey(ctx context.Context, req *escrow.EscrowRequest) (*escrow.EscrowReceipt, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request: %s", escrow.ErrEscrowFailed, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+apiPrefix, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create HTTP request: %s", escrow.ErrEscrowFailed, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", escrow.ErrAgentUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %s", escrow.ErrEscrowFailed, err)
	}

	if resp.StatusCode == http.StatusConflict {
		return nil, escrow.ErrAlreadyEscrowed
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, escrow.ErrAuthenticationFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: server returned status %d: %s",
			escrow.ErrEscrowFailed, resp.StatusCode, string(respBody))
	}

	var receipt escrow.EscrowReceipt
	if err := json.Unmarshal(respBody, &receipt); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal receipt: %s", escrow.ErrEscrowFailed, err)
	}

	return &receipt, nil
}

// RecoverKey retrieves wrapped key material from the remote go-xkms instance.
func (a *FederationAgent) RecoverKey(ctx context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}
	if req == nil {
		return nil, escrow.ErrNilRequest
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request: %s", escrow.ErrRecoverFailed, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+apiPrefix+"/recover", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create HTTP request: %s", escrow.ErrRecoverFailed, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", escrow.ErrAgentUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %s", escrow.ErrRecoverFailed, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, escrow.ErrKeyNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, escrow.ErrAuthenticationFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: server returned status %d: %s",
			escrow.ErrRecoverFailed, resp.StatusCode, string(respBody))
	}

	var recoverResp escrow.RecoverResponse
	if err := json.Unmarshal(respBody, &recoverResp); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal response: %s", escrow.ErrRecoverFailed, err)
	}

	return &recoverResp, nil
}

// ListEscrowed returns all keys held by the remote go-xkms instance.
func (a *FederationAgent) ListEscrowed(ctx context.Context) ([]escrow.EscrowRecord, error) {
	if a.closed.Load() {
		return nil, escrow.ErrAgentClosed
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+apiPrefix, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create HTTP request: %s", escrow.ErrRecoverFailed, err)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", escrow.ErrAgentUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %s", escrow.ErrRecoverFailed, err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, escrow.ErrAuthenticationFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: server returned status %d: %s",
			escrow.ErrRecoverFailed, resp.StatusCode, string(respBody))
	}

	var records []escrow.EscrowRecord
	if err := json.Unmarshal(respBody, &records); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal response: %s", escrow.ErrRecoverFailed, err)
	}

	return records, nil
}

// RevokeEscrow removes an escrowed key from the remote go-xkms instance.
func (a *FederationAgent) RevokeEscrow(ctx context.Context, escrowID string) error {
	if a.closed.Load() {
		return escrow.ErrAgentClosed
	}
	if escrowID == "" {
		return escrow.ErrEmptyKeyID
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.endpoint+apiPrefix+"/"+escrowID, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to create HTTP request: %s", escrow.ErrRevokeFailed, err)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: %s", escrow.ErrAgentUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return fmt.Errorf("%w: failed to read response: %s", escrow.ErrRevokeFailed, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return escrow.ErrKeyNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return escrow.ErrAuthenticationFailed
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: server returned status %d: %s",
			escrow.ErrRevokeFailed, resp.StatusCode, string(respBody))
	}

	return nil
}

// Close releases resources held by the federation agent.
func (a *FederationAgent) Close() error {
	a.closed.Store(true)
	a.client.CloseIdleConnections()
	return nil
}

// buildTransport creates an http.Transport with optional mTLS configuration.
func buildTransport(config *FederationConfig) (*http.Transport, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load client certificate for mTLS if provided.
	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to load client certificate: %s",
				escrow.ErrAuthenticationFailed, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification if provided.
	if config.CACert != "" {
		caCert, err := os.ReadFile(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read CA certificate: %s",
				escrow.ErrAuthenticationFailed, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("%w: failed to parse CA certificate",
				escrow.ErrAuthenticationFailed)
		}
		tlsConfig.RootCAs = caCertPool
	}

	return &http.Transport{
		TLSClientConfig: tlsConfig,
	}, nil
}
