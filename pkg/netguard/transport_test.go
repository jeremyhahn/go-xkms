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

package netguard

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuardedTransport_DialsAllowedAddress(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: GuardedTransport(TransportConfig{
			Allow:       AllowAll,
			DialTimeout: 2 * time.Second,
		}),
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestGuardedTransport_RefusesReservedAddressByDefault(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a refused destination must never receive a request")
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: GuardedTransport(TransportConfig{DialTimeout: 2 * time.Second}),
		Timeout:   5 * time.Second,
	}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("Get() to a loopback server with the default guard succeeded, want refused")
	}
	var refused *AddressNotPermittedError
	if !errors.As(err, &refused) {
		t.Fatalf("Get() error = %v, want *AddressNotPermittedError in the chain", err)
	}
}
