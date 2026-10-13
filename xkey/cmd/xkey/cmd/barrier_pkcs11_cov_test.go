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
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withoutBarrierTPM points the barrier at a TPM device that does not exist,
// the state of a host with no TPM.
func withoutBarrierTPM(t *testing.T) {
	t.Helper()
	setBarrierFlagForTest(t, &barrierTPMDevice, filepath.Join(t.TempDir(), "tpmrm0"))
	setBarrierFlagForTest(t, &barrierTPMSimulator, false)
}

func TestInitBarrierPKCS11_PINReadFailureSavesNothing(t *testing.T) {
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "xkey-barrier")
	pipeBarrier(t)
	restore := setBarrierStdin(errReader{err: errors.New("pipe broke")})
	t.Cleanup(restore)

	err := initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", t.TempDir())

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "read_password", barrierErr.Operation)
	assert.Equal(t, config.DefaultConfig().Barrier.PKCS11, loadedConfig.Barrier.PKCS11,
		"the token must not be saved without a sealed PIN")
}

func TestInitBarrierPKCS11_WithoutTPMSavesNothing(t *testing.T) {
	usePKCS11Barrier(t, "/usr/lib/softhsm/libsofthsm2.so", "xkey-barrier")
	withoutBarrierTPM(t)
	pipeBarrier(t, "1234")

	err := initBarrierPKCS11(context.Background(), io.Discard, "pkcs11", t.TempDir())

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "open_tpm", barrierErr.Operation)
	assert.Equal(t, config.DefaultConfig().Barrier.PKCS11, loadedConfig.Barrier.PKCS11,
		"the token must not be saved without a sealed PIN")
}

func TestBuildPKCS11BarrierStrategy_NoConfigLoaded(t *testing.T) {
	setBarrierFlagForTest(t, &loadedConfig, nil)

	strategy, closer, err := buildPKCS11BarrierStrategy(context.Background(), t.TempDir(), "", false)
	require.ErrorIs(t, err, ErrBarrierConfigNotLoaded)
	assert.Nil(t, strategy)
	assert.Nil(t, closer)
}

func TestBuildPKCS11BarrierStrategy_RequiresASavedToken(t *testing.T) {
	setBarrierFlagForTest(t, &loadedConfig, config.DefaultConfig())

	strategy, closer, err := buildPKCS11BarrierStrategy(context.Background(), t.TempDir(), "", false)
	require.ErrorIs(t, err, config.ErrBarrierPKCS11ConfigInvalid)
	assert.Nil(t, strategy)
	assert.Nil(t, closer)
}

func TestBuildPKCS11BarrierStrategy_WithoutTPMIsError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Barrier.PKCS11 = &config.BarrierPKCS11Config{Library: "/usr/lib/softhsm/libsofthsm2.so", Token: "xkey-barrier"}
	setBarrierFlagForTest(t, &loadedConfig, cfg)
	missing := filepath.Join(t.TempDir(), "tpmrm0")

	strategy, closer, err := buildPKCS11BarrierStrategy(context.Background(), t.TempDir(), missing, false)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "open_tpm", barrierErr.Operation)
	assert.Nil(t, strategy)
	assert.Nil(t, closer)
}
