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

package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTestMemoryBackend creates an in-memory storage.Backend suitable for
// unit tests. The engine-level backend (storage.NewMemory) correctly
// returns ErrNotFound for missing keys, unlike the transport-level
// qrdb.NewMemory backend which returns empty bytes for missing keys.
func newTestMemoryBackend(t *testing.T) storage.Backend {
	t.Helper()
	return storage.NewMemory()
}

// validPin returns a well-formed truststrap.Pin for host:port.
func validPin(host string, port int) *truststrap.Pin {
	return &truststrap.Pin{
		Host:            host,
		Port:            port,
		SPKISHA256:      strings.Repeat("ab", 32), // 64 hex chars
		CertFingerprint: strings.Repeat("cd", 32),
		FirstSeen:       time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		Source:          "tofu",
	}
}

// =============================================================================
// Constructor
// =============================================================================

func TestNewStoragePinStore_NilBackend(t *testing.T) {
	_, err := NewStoragePinStore(nil)
	if err == nil {
		t.Fatal("expected error for nil backend, got nil")
	}
	var nilErr NilBackendError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected NilBackendError, got %T: %v", err, err)
	}
}

func TestNewStoragePinStore_NonNilBackend(t *testing.T) {
	store, err := NewStoragePinStore(newTestMemoryBackend(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil StoragePinStore")
	}
}

// =============================================================================
// Get
// =============================================================================

func TestStoragePinStore_Get_NotFound(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))

	_, err := store.Get(context.Background(), "kms.example.com", 8443)
	if err == nil {
		t.Fatal("expected ErrPinNotFound, got nil")
	}
	var notFound truststrap.ErrPinNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrPinNotFound, got %T: %v", err, err)
	}
	if notFound.Host != "kms.example.com" {
		t.Fatalf("ErrPinNotFound.Host = %q, want %q", notFound.Host, "kms.example.com")
	}
	if notFound.Port != 8443 {
		t.Fatalf("ErrPinNotFound.Port = %d, want %d", notFound.Port, 8443)
	}
}

func TestStoragePinStore_Get_AfterPut(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	pin := validPin("kms.example.com", 8443)
	if err := store.Put(ctx, pin); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, "kms.example.com", 8443)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Host != pin.Host {
		t.Errorf("Host = %q, want %q", got.Host, pin.Host)
	}
	if got.Port != pin.Port {
		t.Errorf("Port = %d, want %d", got.Port, pin.Port)
	}
	if got.SPKISHA256 != pin.SPKISHA256 {
		t.Errorf("SPKISHA256 = %q, want %q", got.SPKISHA256, pin.SPKISHA256)
	}
	if got.CertFingerprint != pin.CertFingerprint {
		t.Errorf("CertFingerprint = %q, want %q", got.CertFingerprint, pin.CertFingerprint)
	}
	if !got.FirstSeen.Equal(pin.FirstSeen) {
		t.Errorf("FirstSeen = %v, want %v", got.FirstSeen, pin.FirstSeen)
	}
	if got.Source != pin.Source {
		t.Errorf("Source = %q, want %q", got.Source, pin.Source)
	}
}

// =============================================================================
// Put
// =============================================================================

func TestStoragePinStore_Put_NilPin(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))

	err := store.Put(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil pin, got nil")
	}
	var nilPin truststrap.ErrNilPin
	if !errors.As(err, &nilPin) {
		t.Fatalf("expected ErrNilPin, got %T: %v", err, err)
	}
}

func TestStoragePinStore_Put_Overwrite(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	first := validPin("kms.example.com", 8443)
	if err := store.Put(ctx, first); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	second := validPin("kms.example.com", 8443)
	second.SPKISHA256 = strings.Repeat("ff", 32)
	if err := store.Put(ctx, second); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	got, err := store.Get(ctx, "kms.example.com", 8443)
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if got.SPKISHA256 != second.SPKISHA256 {
		t.Errorf("SPKISHA256 = %q, want %q", got.SPKISHA256, second.SPKISHA256)
	}
}

// =============================================================================
// Delete
// =============================================================================

func TestStoragePinStore_Delete_Idempotent(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))

	// Delete a key that was never stored — must succeed (idempotent).
	if err := store.Delete(context.Background(), "kms.example.com", 8443); err != nil {
		t.Fatalf("Delete of absent key: %v", err)
	}
}

func TestStoragePinStore_Delete_RemovesPin(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	if err := store.Put(ctx, validPin("kms.example.com", 8443)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, "kms.example.com", 8443); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := store.Get(ctx, "kms.example.com", 8443)
	var notFound truststrap.ErrPinNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrPinNotFound after delete, got %v", err)
	}
}

// =============================================================================
// List
// =============================================================================

func TestStoragePinStore_List_Empty(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))

	pins, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List on empty store: %v", err)
	}
	if len(pins) != 0 {
		t.Fatalf("expected 0 pins, got %d", len(pins))
	}
}

func TestStoragePinStore_List_MultiplePins(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	entries := []*truststrap.Pin{
		validPin("alpha.example.com", 8443),
		validPin("beta.example.com", 9443),
		// IPv6 host — net.JoinHostPort must bracket the address.
		{
			Host:            "::1",
			Port:            8443,
			SPKISHA256:      strings.Repeat("ee", 32),
			CertFingerprint: strings.Repeat("ff", 32),
			FirstSeen:       time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			Source:          "tofu",
		},
	}
	for _, p := range entries {
		if err := store.Put(ctx, p); err != nil {
			t.Fatalf("Put %s:%d: %v", p.Host, p.Port, err)
		}
	}

	pins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pins) != 3 {
		t.Fatalf("List returned %d pins, want 3", len(pins))
	}
}

func TestStoragePinStore_List_IPv6RoundTrip(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	ip6Pin := &truststrap.Pin{
		Host:            "::1",
		Port:            8443,
		SPKISHA256:      strings.Repeat("aa", 32),
		CertFingerprint: strings.Repeat("bb", 32),
		FirstSeen:       time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Source:          "tofu",
	}
	if err := store.Put(ctx, ip6Pin); err != nil {
		t.Fatalf("Put IPv6: %v", err)
	}

	got, err := store.Get(ctx, "::1", 8443)
	if err != nil {
		t.Fatalf("Get IPv6: %v", err)
	}
	if got.Host != "::1" {
		t.Errorf("Host = %q, want ::1", got.Host)
	}
}

// =============================================================================
// JSON round-trip fidelity (all fields including FirstSeen)
// =============================================================================

func TestStoragePinStore_RoundTrip_AllFields(t *testing.T) {
	store, _ := NewStoragePinStore(newTestMemoryBackend(t))
	ctx := context.Background()

	want := &truststrap.Pin{
		Host:            "rfc.example.com",
		Port:            9999,
		SPKISHA256:      strings.Repeat("12", 32),
		CertFingerprint: strings.Repeat("34", 32),
		FirstSeen:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Source:          "tofu",
	}
	if err := store.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, want.Host, want.Port)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Host != want.Host {
		t.Errorf("Host: got %q want %q", got.Host, want.Host)
	}
	if got.Port != want.Port {
		t.Errorf("Port: got %d want %d", got.Port, want.Port)
	}
	if got.SPKISHA256 != want.SPKISHA256 {
		t.Errorf("SPKISHA256: got %q want %q", got.SPKISHA256, want.SPKISHA256)
	}
	if got.CertFingerprint != want.CertFingerprint {
		t.Errorf("CertFingerprint: got %q want %q", got.CertFingerprint, want.CertFingerprint)
	}
	if !got.FirstSeen.Equal(want.FirstSeen) {
		t.Errorf("FirstSeen: got %v want %v", got.FirstSeen, want.FirstSeen)
	}
	if got.Source != want.Source {
		t.Errorf("Source: got %q want %q", got.Source, want.Source)
	}
}

// =============================================================================
// pinStoreKey helper
// =============================================================================

func TestPinStoreKey_IPv4(t *testing.T) {
	key := pinStoreKey("10.0.0.1", 8443)
	if !strings.HasPrefix(key, pinKeyPrefix) {
		t.Errorf("key %q must start with %q", key, pinKeyPrefix)
	}
	if !strings.Contains(key, "10.0.0.1") {
		t.Errorf("key %q must contain host", key)
	}
}

func TestPinStoreKey_IPv6Bracketed(t *testing.T) {
	key := pinStoreKey("::1", 8443)
	// net.JoinHostPort brackets IPv6 addresses.
	if !strings.Contains(key, "[::1]") {
		t.Errorf("key %q must contain bracketed IPv6 [::1]", key)
	}
}

func TestPinStoreKey_PortZero(t *testing.T) {
	key := pinStoreKey("example.com", 0)
	if !strings.HasSuffix(key, ":0") {
		t.Errorf("key %q must end with :0 for port 0", key)
	}
}
