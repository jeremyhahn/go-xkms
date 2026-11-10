// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkmsdtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// retryInterval paces the barrier helpers' retries.
const retryInterval = 250 * time.Millisecond

// unifiedCABundleFile is the CA bundle xkmsd persists beside its bootstrap
// certificate once it swaps to the certificate its CA issued (pkg/server
// persistUnifiedCABundle).
const unifiedCABundleFile = "ca-bundle.pem"

// bootstrapCertPath is where xkmsd persists its bootstrap TLS certificate
// under its datastore path data.
func bootstrapCertPath(data string) string {
	return filepath.Join(data, "unified-tls", "cert.pem")
}

// ErrBarrierUninitialized reports a sealed node whose barrier was never
// initialized: `xkmsd init` did not run, or did not complete, over its data.
var ErrBarrierUninitialized = errors.New("xkmsdtest: the barrier was never initialized; run xkmsd init over the node's data first")

// ErrNoAnchor reports a persisted trust anchor that is missing or holds no
// certificate.
var ErrNoAnchor = errors.New("xkmsdtest: no trust anchor")

// AnchorError names the persisted trust anchor that could not be used. It
// matches ErrNoAnchor.
type AnchorError struct {
	Path string
	Err  error
}

func (e *AnchorError) Error() string {
	if e.Err == nil {
		return "xkmsdtest: " + e.Path + " holds no certificate"
	}
	return "xkmsdtest: cannot read trust anchor " + e.Path + ": " + e.Err.Error()
}

func (e *AnchorError) Unwrap() []error { return []error{ErrNoAnchor, e.Err} }

// UnansweredError reports a request no verified server answered: the node is
// not listening, or presented a certificate the persisted anchors do not
// verify.
type UnansweredError struct {
	URL string
	Err error
}

func (e *UnansweredError) Error() string {
	return "xkmsdtest: no verified answer from " + e.URL + ": " + e.Err.Error()
}

func (e *UnansweredError) Unwrap() error { return e.Err }

// BarrierState is what a node's sealed window reports about its barrier.
type BarrierState struct {
	Sealed        bool   `json:"sealed"`
	InitializedAt string `json:"initialized_at"`
}

// Initialized reports whether the barrier has a root key.
func (s BarrierState) Initialized() bool { return s.InitializedAt != "" }

// SealedWindowClient returns a client for an xkmsd node, trusting only the
// anchors the node persisted: the bootstrap TLS certificate at certPath
// ("<data>/unified-tls/cert.pem" under its datastore path), which its sealed
// window presents, and the CA bundle beside it, which verifies the
// certificate its CA issued once it is unsealed. The anchors are read afresh
// on every connection, so the client follows the node across that swap. It
// waits until the node has written the bootstrap certificate.
func SealedWindowClient(ctx context.Context, certPath string) (*http.Client, error) {
	for {
		_, err := loadAnchors(certPath)
		if err == nil {
			return &http.Client{
				Timeout:   15 * time.Second,
				Transport: &http.Transport{DialTLSContext: anchoredDialer(certPath)},
			}, nil
		}
		if ctxErr := pause(ctx); ctxErr != nil {
			return nil, errors.Join(ctxErr, err)
		}
	}
}

// anchoredDialer dials TLS 1.3, verifying the server against the anchors
// persisted beside certPath as they are at the time of the dial.
func anchoredDialer(certPath string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		pool, err := loadAnchors(certPath)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		dialer := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13}}
		return dialer.DialContext(ctx, network, addr)
	}
}

// loadAnchors returns a pool of the bootstrap certificate at certPath and,
// when the node has persisted one, the CA bundle beside it.
func loadAnchors(certPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := appendAnchor(pool, certPath); err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(filepath.Dir(certPath), unifiedCABundleFile)
	if _, err := os.Stat(bundlePath); errors.Is(err, os.ErrNotExist) {
		return pool, nil
	}
	if err := appendAnchor(pool, bundlePath); err != nil {
		return nil, err
	}
	return pool, nil
}

// appendAnchor adds the PEM certificates in path to pool.
func appendAnchor(pool *x509.CertPool, path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return &AnchorError{Path: path, Err: err}
	}
	if !pool.AppendCertsFromPEM(pem) {
		return &AnchorError{Path: path}
	}
	return nil
}

// ReadBarrierState returns the barrier state the node at url reports on GET
// /v1/barrier/status, retrying until the listener answers.
func ReadBarrierState(ctx context.Context, client *http.Client, url string) (BarrierState, error) {
	for {
		state, err := readBarrierStateOnce(ctx, client, url)
		var unanswered *UnansweredError
		if !errors.As(err, &unanswered) {
			return state, err
		}
		if err := pause(ctx); err != nil {
			return BarrierState{}, err
		}
	}
}

// readBarrierStateOnce reads the barrier state once. A request no verified
// server answers fails with an *UnansweredError; any status but 200 with a
// *StatusError.
func readBarrierStateOnce(ctx context.Context, client *http.Client, url string) (BarrierState, error) {
	route := url + "/v1/barrier/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return BarrierState{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return BarrierState{}, &UnansweredError{URL: route, Err: err}
	}
	var state BarrierState
	decodeErr := json.NewDecoder(resp.Body).Decode(&state)
	closeErr := resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return BarrierState{}, &StatusError{URL: route, Code: resp.StatusCode}
	}
	return state, errors.Join(decodeErr, closeErr)
}

// probeHealth reports whether the node at url answers GET /health with a 2xx
// status, which only the unsealed server does: the sealed window refuses it
// with 503. A request no verified server answers fails with an
// *UnansweredError.
func probeHealth(ctx context.Context, client *http.Client, url string) (bool, error) {
	route := url + "/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, &UnansweredError{URL: route, Err: err}
	}
	if err := resp.Body.Close(); err != nil {
		return false, err
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// UnsealBarrier unseals the initialized, sealed node at url with passphrase,
// through its sealed window, retrying until the listener answers.
func UnsealBarrier(ctx context.Context, client *http.Client, url string, passphrase []byte) error {
	return postSecret(ctx, client, url+"/v1/barrier/unseal", passphrase)
}

// OpenBarrier brings the node at url past its sealed window, as an operator
// does after `xkmsd init`: it unseals the sealed barrier init initialized and
// leaves an unsealed node alone. A node that answers /health is unsealed --
// the full server refuses the anonymous status read with 401, so the status
// is read only from a node that does not. It never initializes -- the sealed
// window refuses that (HTTP 409) -- so a barrier init never initialized fails
// with ErrBarrierUninitialized. It retries while no verified server answers,
// or while the node is between its sealed window and the full server; when
// ctx ends the error carries the last failure.
func OpenBarrier(ctx context.Context, client *http.Client, url string, passphrase []byte) error {
	var last error
	for {
		state, err := readOpenState(ctx, client, url)
		if err == nil {
			switch {
			case !state.Sealed:
				return nil
			case !state.Initialized():
				return ErrBarrierUninitialized
			default:
				return UnsealBarrier(ctx, client, url, passphrase)
			}
		}
		var unanswered *UnansweredError
		var status *StatusError
		if !errors.As(err, &unanswered) && !errors.As(err, &status) {
			return err
		}
		if ctx.Err() == nil {
			last = err
		}
		if ctxErr := pause(ctx); ctxErr != nil {
			return errors.Join(ctxErr, last)
		}
	}
}

// readOpenState reports an unsealed barrier for a node that answers /health,
// and otherwise the state its sealed window reports.
func readOpenState(ctx context.Context, client *http.Client, url string) (BarrierState, error) {
	healthy, err := probeHealth(ctx, client, url)
	if err != nil {
		return BarrierState{}, err
	}
	if healthy {
		return BarrierState{}, nil
	}
	return readBarrierStateOnce(ctx, client, url)
}

// postSecret posts {"secret": secret} to a barrier route, retrying until the
// listener answers, and requires 204 No Content.
func postSecret(ctx context.Context, client *http.Client, route string, secret []byte) error {
	body, err := json.Marshal(map[string][]byte{"secret": secret})
	if err != nil {
		return err
	}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, route, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			return drain(resp, http.StatusNoContent)
		}
		if err := pause(ctx); err != nil {
			return err
		}
	}
}

// pause waits retryInterval, or fails when ctx ends.
func pause(ctx context.Context) error {
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
