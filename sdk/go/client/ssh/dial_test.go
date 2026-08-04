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

package ssh_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newTLSListServer boots an httptest TLS server answering the SSH keys list
// endpoint, and writes its self-signed certificate as a PEM CA file. It
// returns the server and the CA file path.
func newTLSListServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/xkms/v1/ssh/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"keys":[]}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	})
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return srv, caFile
}

// TestNewClientForServer_HTTPSTrustsCAFile is the regression test for the
// https dispatch dropping tlsCA: a REST call against a server signed by a
// private CA must succeed when the CA file is supplied — exactly as the
// grpcs/quic/mcps schemes already behave.
func TestNewClientForServer_HTTPSTrustsCAFile(t *testing.T) {
	srv, caFile := newTLSListServer(t)

	client, err := sdkssh.NewClientForServer(srv.URL, caFile, "")
	if err != nil {
		t.Fatalf("NewClientForServer: %v", err)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}()

	if _, err := client.Keys().List(context.Background(), sdkssh.ListKeysRequest{}); err != nil {
		t.Fatalf("List over https with --tls-ca: %v", err)
	}
}

// TestNewClientForServer_HTTPSUnknownCAFails pins the negative: without the
// CA file the same server must fail certificate verification (system roots
// do not trust the httptest self-signed cert).
func TestNewClientForServer_HTTPSUnknownCAFails(t *testing.T) {
	srv, _ := newTLSListServer(t)

	client, err := sdkssh.NewClientForServer(srv.URL, "", "")
	if err != nil {
		t.Fatalf("NewClientForServer: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Keys().List(context.Background(), sdkssh.ListKeysRequest{})
	if err == nil {
		t.Fatal("expected certificate verification failure without CA, got nil")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate error, got: %v", err)
	}
}

// TestNewClientForServer_HTTPSBadCAFile verifies the error path: a
// nonexistent CA file fails client construction rather than silently
// falling back to system roots.
func TestNewClientForServer_HTTPSBadCAFile(t *testing.T) {
	if _, err := sdkssh.NewClientForServer("https://example.test", "/nonexistent/ca.crt", ""); err == nil {
		t.Fatal("expected error for missing CA file, got nil")
	}
}
