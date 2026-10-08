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

package cmd

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// usePKCS11Barrier loads a default xkey config saved under a temporary
// directory and sets the --pkcs11-* flags to library and token.
func usePKCS11Barrier(t *testing.T, library, token string) {
	t.Helper()
	config.SetConfigDir(t.TempDir())
	savedCfg := loadedConfig
	loadedConfig = config.DefaultConfig()
	barrierPKCS11Library = library
	barrierPKCS11Token = token
	t.Cleanup(func() {
		config.ResetConfigDir()
		loadedConfig = savedCfg
		barrierPKCS11Library = ""
		barrierPKCS11Token = ""
	})
}

// TestInitBarrierPKCS11_OtherStrategiesAreNoOps proves every other strategy
// leaves the config and stdin untouched, so runBarrierInit can call it
// unconditionally.
func TestInitBarrierPKCS11_OtherStrategiesAreNoOps(t *testing.T) {
	saved := loadedConfig
	loadedConfig = nil
	t.Cleanup(func() { loadedConfig = saved })

	for _, s := range []string{"", "software", "tpm2", "aws_kms"} {
		require.NoError(t, initBarrierPKCS11(context.Background(), io.Discard, s, t.TempDir()), "strategy %q", s)
	}
}

func TestInitBarrierPKCS11_NoConfigLoaded(t *testing.T) {
	saved := loadedConfig
	loadedConfig = nil
	t.Cleanup(func() { loadedConfig = saved })

	err := initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", t.TempDir())
	require.ErrorIs(t, err, ErrBarrierConfigNotLoaded)
}

// TestInitBarrierPKCS11_RequiresTheToken proves a missing --pkcs11-library
// or --pkcs11-token is refused before a PIN is read.
func TestInitBarrierPKCS11_RequiresTheToken(t *testing.T) {
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "")
	pipeBarrier(t, "1234")

	err := initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", t.TempDir())
	require.ErrorIs(t, err, config.ErrBarrierPKCS11ConfigInvalid)
}

func TestInitBarrierPKCS11_RefusesAnEmptyPIN(t *testing.T) {
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "xkey-barrier")
	pipeBarrier(t, "")

	err := initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", t.TempDir())
	require.ErrorIs(t, err, ErrBarrierPKCS11PINEmpty)
}

// TestInitBarrierPKCS11Cmd_FlagsRegistered proves the token flags exist on
// `barrier init` and that there is no flag carrying the PIN.
func TestInitBarrierPKCS11Cmd_FlagsRegistered(t *testing.T) {
	require.NotNil(t, barrierInitCmd.Flags().Lookup("pkcs11-library"))
	require.NotNil(t, barrierInitCmd.Flags().Lookup("pkcs11-token"))
	require.Nil(t, barrierInitCmd.Flags().Lookup("pkcs11-pin"))
}
