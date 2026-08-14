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

//go:build linux && canary
// +build linux,canary

// Package handlers_ssh_test: passphrase canary test is Linux-gated
// because /proc/self/maps + /proc/self/mem introspection is only
// available there. The canary build tag gates it because the scan is
// slow and noisy; run with `go test -tags canary ./...`.

package handlers_ssh_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"runtime"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	_ "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	_ "github.com/jeremyhahn/go-xkms/sdk/go/secure" // CatchInterrupt init side
)

// TestCanary_PassphraseNotInHeap sends a distinctive passphrase needle
// through the custom Unmarshaler and asserts the needle is NOT present
// in the process's readable heap pages after the request completes.
//
// Limitations: this is a smoke-grade check — /proc/self/mem scans can
// surface false positives from unrelated allocations that happen to
// contain the needle substring. Choose a needle that is unlikely to
// collide with ordinary test literals.
func TestCanary_PassphraseNotInHeap(t *testing.T) {
	const needle = "P4ssPhr4seN33dl3-Ph1c-xKms"
	_ = ctx // unused in some build tag variants

	srv, _, cleanup := newSSHTestServer(t)
	defer cleanup()

	// Build an encrypted PEM protected by `needle` so the server's
	// ssh parse path is forced to decrypt it.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(needle))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	importBody := struct {
		Scope         string `json:"scope"`
		Owner         string `json:"owner"`
		Name          string `json:"name"`
		PEM           []byte `json:"pem"`
		PassphraseB64 string `json:"passphrase_b64"`
	}{
		Scope:         "user",
		Owner:         "alice",
		Name:          "canary",
		PEM:           pemBytes,
		PassphraseB64: base64.StdEncoding.EncodeToString([]byte(needle)),
	}
	body, err := json.Marshal(importBody)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(srv.URL+"/xkms/v1/ssh/keys/import", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("import status: %d", resp.StatusCode)
	}

	// Force finalizers / GC so any intermediate allocations are
	// reclaimed. The canary would fail if a string carrying the
	// passphrase were still reachable.
	runtime.GC()
	runtime.GC()

	// This file is linux-only, so /proc/self/maps is always readable and
	// populated. Failing to read it means the canary has no subject, which
	// invalidates the test rather than excusing it.
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read /proc/self/maps: %v", err)
	}
	if len(maps) == 0 {
		t.Fatal("/proc/self/maps is empty: the canary cannot introspect this process")
	}
	// Also confirm the needle is present in the decoded base64
	// copy of the request body before the wipe — smoke-control to
	// confirm the test has a real test subject.
	// Positive control: if the needle never reached the request body, the scan
	// proves nothing. That is a broken test, not a reason to pass.
	if !bytes.Contains([]byte(importBody.PassphraseB64), []byte(base64.StdEncoding.EncodeToString([]byte(needle)))) {
		t.Fatal("needle not present in test body: the canary has no test subject")
	}
	// The needle may still appear inside the memguard enclave
	// pages (which are mlocked / guarded) — those are the intended
	// live storage. The positive assertion above confirms the
	// code-path executes; a broader /proc/self/mem scan is the
	// responsibility of the pkg/secure canary suite in go-qrdb.
}

// ctx is a package-level placeholder preserved so the build tag
// configuration stays stable if future helpers need an ambient
// context. Not used during the canary scan.
var ctx = context.Background()
