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

package attestation_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

func TestRevocationSource_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"entries":{"2c8cdddfd5e03bfc":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`), 0o600))

	source, err := attestation.RevocationSource(config.PhoneConfig{AttestationStatusFile: path, AttestationStatusURL: "http://unused.test/status"})

	require.NoError(t, err)
	list, ok := source.(*xkms.AndroidStatusList)
	require.True(t, ok, "a configured file wins over the URL")
	entry, listed := list.Lookup(new(big.Int).SetUint64(0x2c8cdddfd5e03bfc))
	assert.True(t, listed)
	assert.Equal(t, "REVOKED", string(entry.Status))
}

func TestRevocationSource_FileErrors(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	require.NoError(t, os.WriteFile(malformed, []byte(`{"entries":{"ab":{"status":"VALID"}}}`), 0o600))

	cases := map[string]struct {
		path string
		want []error
	}{
		"missing": {filepath.Join(dir, "absent.json"), []error{xkms.ErrAndroidStatusListUnavailable}},
		// A file that does not parse is an outage of the list, like a
		// missing one, so verify-user spends no uvRetries on it.
		"malformed": {malformed, []error{xkms.ErrAndroidStatusListMalformed, xkms.ErrAndroidStatusListUnavailable}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			source, err := attestation.RevocationSource(config.PhoneConfig{AttestationStatusFile: tc.path})

			assert.Nil(t, source)
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
			for _, want := range tc.want {
				require.ErrorIs(t, err, want)
			}
		})
	}
}

func TestRevocationSource_DefaultsToGoogleAndKeepsOneSourcePerURL(t *testing.T) {
	first, err := attestation.RevocationSource(config.PhoneConfig{})
	require.NoError(t, err)
	again, err := attestation.RevocationSource(config.PhoneConfig{})
	require.NoError(t, err)

	httpList, ok := first.(*xkms.AndroidHTTPStatusList)
	require.True(t, ok)
	assert.Equal(t, xkms.AndroidGoogleStatusListURL, httpList.URL())
	assert.Same(t, first, again, "the cached list outlives one trust load")

	other, err := attestation.RevocationSource(config.PhoneConfig{AttestationStatusURL: "https://mirror.test/attestation/status"})
	require.NoError(t, err)
	assert.NotSame(t, first, other)
	assert.Equal(t, "https://mirror.test/attestation/status", other.(*xkms.AndroidHTTPStatusList).URL())
}

func TestRevocationSource_InvalidURL(t *testing.T) {
	source, err := attestation.RevocationSource(config.PhoneConfig{AttestationStatusURL: "ftp://mirror.test/status"})

	assert.Nil(t, source)
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
}
