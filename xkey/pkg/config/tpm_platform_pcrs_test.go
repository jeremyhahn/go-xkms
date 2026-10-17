package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestLoadFromPath_TPMPlatformPCRs proves tpm.platform-pcrs is read from the
// file, overridden by the environment, and left unset (the SDK default) when
// the file does not name it.
func TestLoadFromPath_TPMPlatformPCRs(t *testing.T) {
	unset := filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(unset, []byte("tpm:\n  device: /dev/tpmrm0\n"), 0600))
	cfg, err := LoadFromPath(unset)
	require.NoError(t, err)
	assert.Nil(t, cfg.TPM.PlatformPCRs)

	board := filepath.Join(t.TempDir(), "xkey.yaml")
	require.NoError(t, os.WriteFile(board, []byte("tpm:\n  platform-pcrs: [0, 7, 14]\n"), 0600))
	cfg, err = LoadFromPath(board)
	require.NoError(t, err)
	assert.Equal(t, xkms.TPMPCRSet{0, 7, 14}, cfg.TPM.PlatformPCRs)

	t.Setenv("XKEY_TPM_PLATFORM_PCRS", "7,11")
	cfg, err = LoadFromPath(board)
	require.NoError(t, err)
	assert.Equal(t, xkms.TPMPCRSet{7, 11}, cfg.TPM.PlatformPCRs)
}

// TestLoadFromPath_TPMPlatformPCRs_Refused proves loading refuses every set
// tpm2.PCRSet.Validate refuses, with its typed error.
func TestLoadFromPath_TPMPlatformPCRs_Refused(t *testing.T) {
	tests := map[string]struct {
		pcrs    string
		wantErr error
	}{
		"resettable PCR 16": {pcrs: "[7, 16]", wantErr: xkms.ErrTPMPlatformPCRResettable},
		"resettable PCR 23": {pcrs: "[23]", wantErr: xkms.ErrTPMPlatformPCRResettable},
		"out of range":      {pcrs: "[7, 24]", wantErr: xkms.ErrTPMPlatformPCROutOfRange},
		"duplicate":         {pcrs: "[7, 7]", wantErr: xkms.ErrTPMPlatformPCRDuplicate},
		"explicit empty":    {pcrs: "[]", wantErr: xkms.ErrTPMPlatformPCRSetEmpty},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "xkey.yaml")
			require.NoError(t, os.WriteFile(path, []byte("tpm:\n  platform-pcrs: "+tc.pcrs+"\n"), 0600))

			cfg, err := LoadFromPath(path)

			assert.Nil(t, cfg)
			assert.ErrorIs(t, err, ErrConfigInvalid)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}
