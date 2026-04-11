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

//go:build integration

// Package truststrap provides end-to-end integration tests for
// TrustService.ImportFromTrustStrap against a real go-xkms bootstrap
// server (xkms-server + CoreDNS stack from test/integration/bootstrap).
//
// These tests exercise the upper-most facade (TrustService) per the
// xkey integration test convention, verifying the full fetch → parse →
// AddPEM → notifyMutate flow against a live bootstrap endpoint.
//
// Required environment variables (set by the bootstrap docker-compose
// stack; tests skip when unset so the file can also be run locally):
//
//   BOOTSTRAP_SERVER_URL        — https://xkms-server:8443
//   BOOTSTRAP_NOISE_ADDR        — xkms-server:8445
//   BOOTSTRAP_NOISE_STATIC_KEY  — hex-encoded 32-byte Curve25519 pubkey
//   BOOTSTRAP_SPKI_PIN          — hex-encoded SHA-256 SPKI pin
//
// DANE is intentionally not exercised here: the CoreDNS fixture does
// not serve DNSSEC AD-validated responses, and TrustService does not
// expose a hook for overriding the TLSA resolver. DANE coverage is
// already provided by test/integration/bootstrap/bootstrap_test.go,
// which has direct access to the truststrap package and can inject a
// non-DNSSEC resolver.
package truststrap

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Environment variable names exposed by the bootstrap docker-compose stack.
const (
	envServerURL = "BOOTSTRAP_SERVER_URL"
	envNoiseAddr = "BOOTSTRAP_NOISE_ADDR"
	envNoiseKey  = "BOOTSTRAP_NOISE_STATIC_KEY"
	envSPKIPin   = "BOOTSTRAP_SPKI_PIN"
)

// requiredEnv returns the value of the named environment variable or
// skips the test if it is unset, so the file can be compiled and
// selectively run outside the bootstrap stack.
func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	val := os.Getenv(key)
	if val == "" {
		t.Skipf("integration: %s not set (run via bootstrap docker-compose stack)", key)
	}
	return val
}

// newTrustService builds a TrustService backed by a fresh FileStore in a
// temporary directory. Caller does not need to clean up; t.TempDir()
// handles removal at the end of the test.
func newTrustService(t *testing.T) (*services.TrustService, truststore.TrustStore) {
	t.Helper()
	dir := t.TempDir()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dir, "truststore"),
	})
	require.NoError(t, err, "new file store")
	return services.NewTrustService(store), store
}

// ----------------------------------------------------------------------
// Direct (plain HTTPS with system trust store)
// ----------------------------------------------------------------------

func TestImportFromTrustStrap_Direct_LiveServer(t *testing.T) {
	serverURL := requiredEnv(t, envServerURL)

	svc, store := newTrustService(t)
	var mutateCalled atomic.Int32
	svc.SetOnMutate(func() { mutateCalled.Add(1) })

	added, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method: "direct",
		Server: serverURL,
	})
	require.NoError(t, err, "ImportFromTrustStrap via Direct must succeed against live server")
	assert.Greater(t, added, 0, "at least one certificate must be imported")
	assert.Equal(t, int32(1), mutateCalled.Load(), "notifyMutate must fire on success")

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, added, count, "store count must match imported count")
}

func TestImportFromTrustStrap_Direct_Unreachable(t *testing.T) {
	// Skip only if we're not running in the bootstrap stack at all — the
	// presence of any env var implies integration mode.
	_ = requiredEnv(t, envServerURL)

	svc, _ := newTrustService(t)

	_, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method: "direct",
		// RFC 5737 TEST-NET, unreachable.
		Server: "https://192.0.2.1:9999",
	})
	require.Error(t, err, "unreachable server must fail")
	require.ErrorIs(t, err, services.ErrTrustStrapFetch)
}

// ----------------------------------------------------------------------
// SPKI (TLS with pinned Subject Public Key Info)
// ----------------------------------------------------------------------

func TestImportFromTrustStrap_SPKI_LiveServer(t *testing.T) {
	serverURL := requiredEnv(t, envServerURL)
	pin := requiredEnv(t, envSPKIPin)

	svc, store := newTrustService(t)

	added, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method:        "spki",
		Server:        serverURL,
		SPKIPinSHA256: pin,
	})
	require.NoError(t, err, "ImportFromTrustStrap via SPKI must succeed with valid pin")
	assert.Greater(t, added, 0, "at least one certificate must be imported")

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, added, count)
}

func TestImportFromTrustStrap_SPKI_WrongPin(t *testing.T) {
	serverURL := requiredEnv(t, envServerURL)

	svc, _ := newTrustService(t)

	_, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method: "spki",
		Server: serverURL,
		// Syntactically valid but does not match the server's SPKI.
		SPKIPinSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	require.Error(t, err, "wrong SPKI pin must fail TLS verification")
	require.ErrorIs(t, err, services.ErrTrustStrapFetch)
}

// ----------------------------------------------------------------------
// Noise (Noise_NK over TCP)
// ----------------------------------------------------------------------

func TestImportFromTrustStrap_Noise_LiveServer(t *testing.T) {
	addr := requiredEnv(t, envNoiseAddr)
	key := requiredEnv(t, envNoiseKey)

	svc, store := newTrustService(t)

	added, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method:          "noise",
		Server:          addr,
		ServerStaticKey: key,
	})
	require.NoError(t, err, "ImportFromTrustStrap via Noise must succeed with valid key")
	assert.Greater(t, added, 0, "at least one certificate must be imported")

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, added, count)
}

func TestImportFromTrustStrap_Noise_WrongKey(t *testing.T) {
	addr := requiredEnv(t, envNoiseAddr)

	svc, _ := newTrustService(t)

	_, err := svc.ImportFromTrustStrap(services.TrustStrapImportRequest{
		Method:          "noise",
		Server:          addr,
		ServerStaticKey: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	require.Error(t, err, "wrong Noise static key must fail the handshake")
	require.ErrorIs(t, err, services.ErrTrustStrapFetch)
}

// ----------------------------------------------------------------------
// Cross-method consistency
// ----------------------------------------------------------------------

// TestImportFromTrustStrap_AllMethodsReturnSameBundle verifies that every
// bootstrap mechanism fetches the same underlying CA bundle from the
// same live server. This guards against a regression where the wire
// format or filter logic diverges between transports.
func TestImportFromTrustStrap_AllMethodsReturnSameBundle(t *testing.T) {
	serverURL := requiredEnv(t, envServerURL)
	noiseAddr := requiredEnv(t, envNoiseAddr)
	noiseKey := requiredEnv(t, envNoiseKey)
	spkiPin := requiredEnv(t, envSPKIPin)

	methods := []struct {
		name string
		req  services.TrustStrapImportRequest
	}{
		{
			name: "direct",
			req: services.TrustStrapImportRequest{
				Method: "direct",
				Server: serverURL,
			},
		},
		{
			name: "spki",
			req: services.TrustStrapImportRequest{
				Method:        "spki",
				Server:        serverURL,
				SPKIPinSHA256: spkiPin,
			},
		},
		{
			name: "noise",
			req: services.TrustStrapImportRequest{
				Method:          "noise",
				Server:          noiseAddr,
				ServerStaticKey: noiseKey,
			},
		},
	}

	var baseline int
	for i, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			svc, store := newTrustService(t)
			added, err := svc.ImportFromTrustStrap(m.req)
			require.NoError(t, err)
			require.Greater(t, added, 0)

			count, err := store.Count()
			require.NoError(t, err)
			assert.Equal(t, added, count)

			if i == 0 {
				baseline = added
				return
			}
			assert.Equal(t, baseline, added,
				"method %q returned %d certs, expected %d (all transports must fetch the same bundle)",
				m.name, added, baseline)
		})
	}
}
