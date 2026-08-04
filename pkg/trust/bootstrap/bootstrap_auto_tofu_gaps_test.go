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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// TestFetch_AutoIncludesTOFUWhenMethodOrderSet drives the fetchAuto branch
// that populates autoCfg.TOFU + autoCfg.MethodOrder: this only happens when
// cfg.TOFU.PinStore, cfg.ServerURL, and a non-empty cfg.TOFUMethodOrder are
// all present simultaneously. With every other sub-config left nil and
// TOFUMethodOrder restricted to MethodTOFU, truststrap.AutoFetch has exactly
// one method available, so a successful fetch proves the TOFU branch was
// actually wired into autoCfg (not silently skipped).
func TestFetch_AutoIncludesTOFUWhenMethodOrderSet(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	pinStore := newTOFUPinStore(t)

	got, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        srv.URL,
		BundlePath:       "/",
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
		TOFU:             &TOFUConfig{PinStore: pinStore},
		TOFUMethodOrder:  []truststrap.Method{truststrap.MethodTOFU},
	})
	if err != nil {
		t.Fatalf("Fetch auto+TOFU: %v", err)
	}
	if got == nil || len(got.Certificates) == 0 {
		t.Fatalf("expected non-empty CABundle, got %+v", got)
	}

	// Confirm the TOFU path actually ran (not some other method) by checking
	// a pin was captured for the server.
	host, port := srvHostPort(srv)
	if _, err := pinStore.Get(context.Background(), host, port); err != nil {
		t.Fatalf("expected TOFU to persist a pin, Get: %v", err)
	}
}
