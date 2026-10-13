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
	"net/http"
	"os"
	"time"
)

// retryInterval paces the barrier helpers' retries.
const retryInterval = 250 * time.Millisecond

// ErrBarrierUninitialized reports a sealed node whose barrier was never
// initialized: `xkmsd init` did not run, or did not complete, over its data.
var ErrBarrierUninitialized = errors.New("xkmsdtest: the barrier was never initialized; run xkmsd init over the node's data first")

// BarrierState is what a node's sealed window reports about its barrier.
type BarrierState struct {
	Sealed        bool   `json:"sealed"`
	InitializedAt string `json:"initialized_at"`
}

// Initialized reports whether the barrier has a root key.
func (s BarrierState) Initialized() bool { return s.InitializedAt != "" }

// SealedWindowClient returns a client for a sealed xkmsd's pre-boot
// sealed-window listener, trusting the TLS certificate the node persisted at
// certPath before any CA exists ("<data>/unified-tls/cert.pem" under its
// datastore path). It waits until the node has written the certificate.
func SealedWindowClient(ctx context.Context, certPath string) (*http.Client, error) {
	for {
		if pem, err := os.ReadFile(certPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				return &http.Client{
					Timeout:   15 * time.Second,
					Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
				}, nil
			}
		}
		if err := pause(ctx); err != nil {
			return nil, err
		}
	}
}

// ReadBarrierState returns the barrier state the node at url reports on GET
// /v1/barrier/status, retrying until the listener answers.
func ReadBarrierState(ctx context.Context, client *http.Client, url string) (BarrierState, error) {
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/v1/barrier/status", nil)
		if err != nil {
			return BarrierState{}, err
		}
		resp, err := client.Do(req)
		if err == nil {
			var state BarrierState
			decodeErr := json.NewDecoder(resp.Body).Decode(&state)
			closeErr := resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return BarrierState{}, &StatusError{URL: url + "/v1/barrier/status", Code: resp.StatusCode}
			}
			return state, errors.Join(decodeErr, closeErr)
		}
		if err := pause(ctx); err != nil {
			return BarrierState{}, err
		}
	}
}

// UnsealBarrier unseals the initialized, sealed node at url with passphrase,
// through its sealed window, retrying until the listener answers.
func UnsealBarrier(ctx context.Context, client *http.Client, url string, passphrase []byte) error {
	return postSecret(ctx, client, url+"/v1/barrier/unseal", passphrase)
}

// OpenBarrier brings the node at url past its sealed window, as an operator
// does after `xkmsd init`: it unseals the sealed barrier init initialized and
// leaves an unsealed node alone. It never initializes -- the sealed window
// refuses that (HTTP 409) -- so a barrier init never initialized fails with
// ErrBarrierUninitialized.
func OpenBarrier(ctx context.Context, client *http.Client, url string, passphrase []byte) error {
	state, err := ReadBarrierState(ctx, client, url)
	if err != nil {
		return err
	}
	switch {
	case !state.Sealed:
		return nil
	case !state.Initialized():
		return ErrBarrierUninitialized
	default:
		return UnsealBarrier(ctx, client, url, passphrase)
	}
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
