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

//go:build integration

package oidccredentials

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// barrierPassphrase initializes the test server's passphrase barrier.
const barrierPassphrase = "oidc-credentials-integration"

// errServerExitedSealed is returned when xkmsd exits while its barrier is
// still sealed.
var errServerExitedSealed = errors.New("xkmsd exited while sealed")

// initializeThroughSealedWindow initializes xkmsd's passphrase barrier
// through the pre-boot sealed-window listener, the operator path on a fresh
// deployment: xkmsd blocks start-up behind the window until the barrier is
// unsealed. The window serves the unified TLS certificate xkmsd persisted
// in its data directory before any CA exists, which is what the client
// trusts here.
func initializeThroughSealedWindow(restURL, dataDir string, exited <-chan struct{}, waitErr *error) error {
	certPath := filepath.Join(dataDir, "unified-tls", "cert.pem")
	deadline := time.Now().Add(60 * time.Second)
	var client *http.Client
	for client == nil {
		pemBytes, err := os.ReadFile(certPath)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				client = &http.Client{
					Timeout:   15 * time.Second,
					Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
				}
				break
			}
		}
		if err := waitTick(deadline, exited, waitErr); err != nil {
			return err
		}
	}

	body, err := json.Marshal(map[string][]byte{"secret": []byte(barrierPassphrase)})
	if err != nil {
		return err
	}
	for {
		resp, err := client.Post(restURL+"/v1/barrier/initialize", "application/json", bytes.NewReader(body))
		if err == nil {
			return drain(resp, http.StatusNoContent)
		}
		if err := waitTick(deadline, exited, waitErr); err != nil {
			return err
		}
	}
}

// waitTick waits a moment before the next attempt, failing once deadline
// has passed or xkmsd has exited.
func waitTick(deadline time.Time, exited <-chan struct{}, waitErr *error) error {
	if time.Now().After(deadline) {
		return errSealedWindowTimeout
	}
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-exited:
		return &serverExitError{err: errors.Join(errServerExitedSealed, *waitErr)}
	case <-timer.C:
		return nil
	}
}

// errSealedWindowTimeout is returned when the sealed window never answers.
var errSealedWindowTimeout = errors.New("the sealed-window listener did not answer in time")
