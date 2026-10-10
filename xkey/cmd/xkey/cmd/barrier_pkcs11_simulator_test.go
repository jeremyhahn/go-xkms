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

//go:build tpm_simulator

package cmd

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// keepOpen is the closer the barrier code receives for the shared simulator:
// the test owns the simulator and closes it in cleanup.
type keepOpen struct{}

func (keepOpen) Close() error { return nil }

// useBarrierTPMSimulator points the barrier commands at one in-process TPM
// simulator, provisioned with the Platform SRK `xkey setup` enrolls and held
// open for the whole test: the simulator is reset on every open, so a PIN
// sealed by one open could never be released by the next.
func useBarrierTPMSimulator(t *testing.T) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opened, err := openTPMWithKeyStore(logger, t.TempDir(), "", true)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, opened.Close()) })
	require.NoError(t, opened.TPM().Provision(nil))
	cfg := xkms.DefaultTPMConfig
	require.NoError(t, xkmstest.EnrollPlatformSRK(opened.TPM(), &cfg))

	savedSimulator := barrierTPMSimulator
	savedOpen := openBarrierPresealTPM
	barrierTPMSimulator = true
	openBarrierPresealTPM = func(*slog.Logger, string, string, bool) (xkms.TrustedPlatformModule, io.Closer, error) {
		return opened.TPM(), keepOpen{}, nil
	}
	t.Cleanup(func() {
		barrierTPMSimulator = savedSimulator
		openBarrierPresealTPM = savedOpen
	})
}

// TestInitBarrierPKCS11_SealsThePINAndSavesTheToken proves init seals the
// PIN where every later unseal releases it, and saves the token it names.
func TestInitBarrierPKCS11_SealsThePINAndSavesTheToken(t *testing.T) {
	useBarrierTPMSimulator(t)
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "xkey-barrier")
	pipeBarrier(t, "1234")
	dataDir := t.TempDir()

	require.NoError(t, initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", dataDir))

	store, closeStore, err := openBarrierPreseal(dataDir, "", true)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, closeStore()) })
	pin, err := store.Get(context.Background(), xkms.PresealPKCS11PIN)
	require.NoError(t, err)
	require.Equal(t, []byte("1234"), pin)

	loaded, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, config.BarrierPKCS11Config{Library: "/usr/lib/softhsm/libsofthsm2.so", Token: "xkey-barrier"}, *loaded.Barrier.PKCS11)
}

// TestBuildPKCS11BarrierStrategy_WithoutASealedPINFailsClosed proves a
// configured token whose PIN was never sealed is refused with the store's
// typed error, not a login attempt with no PIN.
func TestBuildPKCS11BarrierStrategy_WithoutASealedPINFailsClosed(t *testing.T) {
	useBarrierTPMSimulator(t)
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "xkey-barrier")
	loadedConfig.Barrier.PKCS11 = &config.BarrierPKCS11Config{Library: barrierPKCS11Library, Token: barrierPKCS11Token}

	strategy, closer, err := buildPKCS11BarrierStrategy(context.Background(), t.TempDir(), "", true)
	require.Nil(t, strategy)
	require.Nil(t, closer)
	var notFound *xkms.PresealNotFoundError
	require.ErrorAs(t, err, &notFound)
}
