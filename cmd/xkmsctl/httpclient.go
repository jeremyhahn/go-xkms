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

package main

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

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// serverHTTPClientFactory is a test injection point for creating HTTP
// clients. When non-nil, createServerHTTPClient uses this factory instead of
// building a real TLS client, enabling tests to supply httptest.Server
// clients.
var serverHTTPClientFactory func(cfg *Config) (*http.Client, error)

// serverErrorResponse is the structure of error responses from the server.
type serverErrorResponse struct {
	Error string `json:"error"`
}

// checkServerResponse reads the response body and checks for non-2xx status
// codes. On success, it returns the response body bytes. On failure, it
// returns a typed error.
func checkServerResponse(resp *http.Response) ([]byte, error) {
	defer closeQuietly(resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrHTTPRequestFailed, Detail: "failed to read response body", Err: err}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}

	// Try to extract a server error message
	var serverErr serverErrorResponse
	if json.Unmarshal(respBody, &serverErr) == nil && serverErr.Error != "" {
		return nil, &WrappedDetailError{Sentinel: ErrServerResponseError, Detail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, serverErr.Error)}
	}

	return nil, &WrappedDetailError{Sentinel: ErrServerResponseError, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

// createServerHTTPClient creates the HTTP client the REST-only commands use.
// With requireSPKI it uses SPKI-pinned TLS; otherwise it uses mTLS.
func createServerHTTPClient(cfg *Config, requireSPKI bool) (*http.Client, error) {
	// Allow test injection
	if serverHTTPClientFactory != nil {
		return serverHTTPClientFactory(cfg)
	}

	if requireSPKI {
		if cfg.SPKIPin == "" {
			return nil, ErrSPKIPinRequired
		}
		return newSPKIHTTPClient(cfg.SPKIPin), nil
	}

	// mTLS client
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return nil, &WrappedDetailError{Sentinel: ErrCertFileRead, Detail: "--tls-cert and --tls-key are required for mTLS"}
	}
	return newMTLSHTTPClient(cfg.TLSCert, cfg.TLSKey, cfg.TLSCACert)
}

// newSPKIHTTPClient creates an HTTP client that pins the server's SPKI.
func newSPKIHTTPClient(pin string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: client.NewSPKIPinnedTLSConfig(pin),
		},
	}
}

// newMTLSHTTPClient creates an HTTP client that uses mTLS.
func newMTLSHTTPClient(certFile, keyFile, caFile string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: err}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Load CA certificate if provided
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrCertFileRead, Err: err}
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, ErrInvalidCA
		}

		tlsConfig.RootCAs = caPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{Transport: transport}, nil
}

// doServerRequest makes a JSON request to the server.
func doServerRequest(client *http.Client, method, url string, body interface{}) (*http.Response, error) {
	return doServerRequestContext(context.Background(), client, method, url, body)
}

// doServerRequestContext is doServerRequest with a caller-supplied context,
// so a cancelled command stops its in-flight request instead of waiting out
// the transport timeout.
func doServerRequestContext(ctx context.Context, client *http.Client, method, url string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrHTTPRequestFailed, Err: err}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return client.Do(req)
}

// outputJSON marshals v as indented JSON and writes it to stdout.
func outputJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err}
	}
	fmt.Println(string(data))
	return nil
}

// createSDKClient creates and connects a client, returning the client and a
// cleanup function. The caller MUST call cleanup when done.
func createSDKClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cleanup := func() { closeQuietly(cl) }
	return cl, cleanup, nil
}
