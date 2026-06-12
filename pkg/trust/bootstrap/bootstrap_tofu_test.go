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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// =============================================================================
// ModeTOFU dispatch — validation errors
// =============================================================================

func TestFetch_TOFUWithoutSubConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeTOFU,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for TOFU without TOFUConfig; got %v", err)
	}
}

func TestFetch_TOFUWithoutServerURLErrors(t *testing.T) {
	ps := truststrap.NewMemoryPinStore()
	_, err := Fetch(context.Background(), Config{
		Mode: ModeTOFU,
		TOFU: &TOFUConfig{PinStore: ps},
	})
	if !errors.Is(err, ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired for TOFU without ServerURL; got %v", err)
	}
}

func TestFetch_TOFUWithoutPinStoreErrors(t *testing.T) {
	// TOFUConfig present but PinStore nil → truststrap.NewTOFUBootstrapper returns
	// ErrTOFUPinStoreRequired, which we wrap as FetchError{Mode:tofu}.
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeTOFU,
		ServerURL: "https://kms.example.com:8443",
		TOFU:      &TOFUConfig{PinStore: nil},
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch for nil PinStore; got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Mode != ModeTOFU {
		t.Fatalf("expected FetchError{Mode:tofu}, got %T %v", err, err)
	}
}

// =============================================================================
// ModeTOFU dispatch — end-to-end with a local TLS test server
// =============================================================================

// newTOFUPinStore creates a StoragePinStore backed by storage.NewMemory().
// The engine-level backend correctly returns ErrNotFound for missing keys.
func newTOFUPinStore(t *testing.T) *StoragePinStore {
	t.Helper()
	store, err := NewStoragePinStore(storage.NewMemory())
	if err != nil {
		t.Fatalf("NewStoragePinStore: %v", err)
	}
	return store
}

// srvHostPort parses the host and port from an httptest.Server's listener address.
func srvHostPort(srv *httptest.Server) (string, int) {
	addr := srv.Listener.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("srvHostPort: %v", err))
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TestFetch_TOFUSuccess tests the full TOFU flow using a local TLS test server.
// First connection: pin is captured (trust-on-first-use).
// Second call: pin is already stored; fetch succeeds using the stored pin.
func TestFetch_TOFUSuccess(t *testing.T) {
	bundle := newTestPEMBundle(t)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	pinStore := newTOFUPinStore(t)

	cfg := Config{
		Mode:             ModeTOFU,
		ServerURL:        srv.URL,
		BundlePath:       "/",
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
		TOFU:             &TOFUConfig{PinStore: pinStore},
	}

	// First call: TOFU captures and persists the pin.
	got, err := Fetch(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Fetch TOFU first call: %v", err)
	}
	if got == nil || len(got.Certificates) == 0 {
		t.Fatalf("expected non-empty CABundle on first call, got %+v", got)
	}

	// Verify pin was persisted.
	host, port := srvHostPort(srv)
	pin, err := pinStore.Get(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Get pin after first call: %v", err)
	}
	if pin.SPKISHA256 == "" {
		t.Fatal("stored pin has empty SPKISHA256")
	}

	// Second call: pin already stored — strict SPKI verification applies.
	got2, err := Fetch(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Fetch TOFU second call (pin stored): %v", err)
	}
	if got2 == nil || len(got2.Certificates) == 0 {
		t.Fatalf("expected non-empty CABundle on second call, got %+v", got2)
	}
}

// TestFetch_TOFUConfirmFuncRejection verifies that returning an error from
// ConfirmFunc causes the bootstrap to fail with ErrFetch wrapping
// ErrTOFURejected, and that no pin is persisted.
func TestFetch_TOFUConfirmFuncRejection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PEM"))
	}))
	defer srv.Close()

	pinStore := newTOFUPinStore(t)
	rejectErr := errors.New("operator rejected pin")

	_, err := Fetch(context.Background(), Config{
		Mode:             ModeTOFU,
		ServerURL:        srv.URL,
		BundlePath:       "/",
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
		TOFU: &TOFUConfig{
			PinStore: pinStore,
			ConfirmFunc: func(_ context.Context, _ *truststrap.Pin) error {
				return rejectErr
			},
		},
	})
	if err == nil {
		t.Fatal("expected error when ConfirmFunc rejects; got nil")
	}
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch; got %v", err)
	}

	// Verify no pin was stored.
	pins, listErr := pinStore.List(context.Background())
	if listErr != nil {
		t.Fatalf("List: %v", listErr)
	}
	if len(pins) != 0 {
		t.Fatalf("expected 0 pins after rejection, got %d", len(pins))
	}
}

// TestFetch_TOFUPinMismatchFails verifies that a pre-stored wrong SPKI pin
// causes the fetch to fail — the SPKI-verified connection rejects the
// server certificate.
func TestFetch_TOFUPinMismatchFails(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	pinStore := newTOFUPinStore(t)
	host, port := srvHostPort(srv)

	// Pre-seed a wrong SPKI pin so the store already has a pin for this server.
	wrongPin := &truststrap.Pin{
		Host:            host,
		Port:            port,
		SPKISHA256:      "0000000000000000000000000000000000000000000000000000000000000000",
		CertFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		FirstSeen:       time.Now(),
		Source:          "tofu",
	}
	if err := pinStore.Put(context.Background(), wrongPin); err != nil {
		t.Fatalf("pre-seed wrong pin: %v", err)
	}

	_, err := Fetch(context.Background(), Config{
		Mode:             ModeTOFU,
		ServerURL:        srv.URL,
		BundlePath:       "/",
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
		TOFU:             &TOFUConfig{PinStore: pinStore},
	})
	if err == nil {
		t.Fatal("expected error for SPKI pin mismatch; got nil")
	}
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch for pin mismatch; got %v", err)
	}
}

// =============================================================================
// ModeAuto — TOFU excluded without explicit MethodOrder
// =============================================================================

func TestFetch_AutoExcludesTOFUByDefault(t *testing.T) {
	// Auto with only TOFU configured and no TOFUMethodOrder → TOFU is not
	// included in autoCfg (guard requires len(TOFUMethodOrder) > 0), so the
	// effective method set is empty → ErrModeNotConfigured.
	ps := truststrap.NewMemoryPinStore()
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeAuto,
		ServerURL: "https://kms.example.com:8443",
		TOFU:      &TOFUConfig{PinStore: ps},
		// TOFUMethodOrder not set → TOFU is excluded from ModeAuto
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured when TOFU is the only sub-config "+
			"but TOFUMethodOrder is nil; got %v", err)
	}
}
