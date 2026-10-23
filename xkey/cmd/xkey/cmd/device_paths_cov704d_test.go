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

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// c704dUnresolvableHome makes the xKey home unresolvable: XKEY_HOME names a
// directory beneath a regular file, which can never be created.
func c704dUnresolvableHome(t *testing.T) {
	t.Helper()
	xhome.ResetRoot()
	t.Cleanup(xhome.ResetRoot)
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv(xhome.EnvHome, filepath.Join(blocker, "home"))
	t.Setenv("SUDO_USER", "")
}

// c704dBlockedDataDir isolates the xKey home and puts a regular file where
// its data directory belongs, so the data directory cannot be created.
func c704dBlockedDataDir(t *testing.T) {
	t.Helper()
	root := isolateDeviceBarrierHome(t)
	dataDir := (&xhome.Home{Root: root}).DataDir()
	require.NoError(t, os.WriteFile(dataDir, nil, 0o600))
}

func TestGetSharePolicyPath_UnresolvableHomeFails(t *testing.T) {
	c704dUnresolvableHome(t)

	path, err := getSharePolicyPath()

	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	assert.Empty(t, path)
}

func TestRunSharePolicyRemove_UnresolvableHomeRefuses(t *testing.T) {
	c704dUnresolvableHome(t)

	err := runSharePolicyRemove(&cobra.Command{}, []string{"pkcs11", "key-1"})

	require.ErrorIs(t, err, ErrSharePolicyLoadFailed)
}

func TestOpenDeviceBarrier_HomeFailuresRefuse(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{name: "unresolvable home", setup: c704dUnresolvableHome},
		{name: "data directory blocked", setup: c704dBlockedDataDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			barrier, closeBarrier, err := openDeviceBarrier(deviceBarrierCommand(t))

			require.ErrorIs(t, err, ErrDeviceBarrierUnsealFailed)
			assert.Nil(t, barrier)
			assert.Nil(t, closeBarrier)
		})
	}
}

func TestOpenDeviceBarrier_CommandWithoutBarrierFlagsRefuses(t *testing.T) {
	isolateDeviceBarrierHome(t)

	barrier, closeBarrier, err := openDeviceBarrier(&cobra.Command{})

	require.ErrorIs(t, err, ErrPINInputFlagsMissing)
	assert.Nil(t, barrier)
	assert.Nil(t, closeBarrier)
}

func TestListenHandler_UndecodableRequestIsAParseError(t *testing.T) {
	handler := newListenHandler(t, nil)

	raw, err := handler.HandleRequest(context.Background(), []byte("{not json"))

	require.NoError(t, err)
	resp := decodeListenResponse(t, raw)
	require.NotNil(t, resp.Error)
	assert.Equal(t, pairingproto.ErrorCodeParseError, resp.Error.Code)
	assert.Zero(t, resp.ID)
}

func TestOpenSyncService_OpensOnAFreshHome(t *testing.T) {
	isolateDeviceBarrierHome(t)

	svc, sources, err := openSyncService(&cobra.Command{})

	require.NoError(t, err)
	require.NotNil(t, svc)
	require.NotNil(t, sources)
	sources.Close()
}

func TestOpenSyncService_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr error
	}{
		{name: "unresolvable home", setup: c704dUnresolvableHome, wantErr: ErrBackupStoreUnavailable},
		{
			name: "stores sealed under the barrier",
			setup: func(t *testing.T) {
				isolateDeviceBarrierHome(t)
				initDeviceBarrier(t, "c704d-barrier-password")
			},
			wantErr: ErrBackupBarrierEncrypted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			svc, sources, err := openSyncService(&cobra.Command{})

			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, svc)
			assert.Nil(t, sources)
		})
	}
}

func TestUnifiedConfigOrDefault(t *testing.T) {
	original := loadedConfig
	t.Cleanup(func() { loadedConfig = original })

	loadedConfig = nil
	assert.Equal(t, xkeyconfig.DefaultConfig(), unifiedConfigOrDefault(), "no loaded config falls back to the defaults")

	loaded := xkeyconfig.DefaultConfig()
	loadedConfig = loaded
	assert.Same(t, loaded, unifiedConfigOrDefault(), "a loaded config is used as is")
}

func TestLoadPairingAttestationTrust_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		wantErr error
	}{
		{
			name: "corrupt devices file",
			setup: func(t *testing.T) {
				isolateDeviceBarrierHome(t)
				path, err := getDevicesConfigPath()
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, []byte("devices: [unterminated"), 0o600))
			},
			wantErr: ErrDeviceConfigLoadFailed,
		},
		{name: "trust store unavailable", setup: c704dBlockedDataDir, wantErr: attestation.ErrDeviceAttestVerifyFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			trust, err := loadPairingAttestationTrust()

			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, trust)
		})
	}
}
