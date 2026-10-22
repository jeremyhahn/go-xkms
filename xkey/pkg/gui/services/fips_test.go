// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"crypto/fips140"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nssdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noiseOutsideFIPS reports whether the calling test may run the phone's
// Noise_XX channel in this process. Noise_XX is pinned to X25519, which the
// FIPS 140-3 module refuses: under GODEBUG=fips140=only it asserts the typed
// refusal, re-runs the test with fips140=off and reports false, so the caller
// returns at once.
func noiseOutsideFIPS(t *testing.T) bool {
	t.Helper()
	key, err := bootstrap.GenerateNoiseStaticKey()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, bootstrap.ErrNoiseFIPSUnsupported) {
		return false
	}
	require.NoError(t, err)
	key.Destroy()
	return true
}

// nssdbOutsideFIPS reports whether the calling test may build a browser's NSS
// database in this process. The cert9.db/key4.db formats mandate SHA-1, so
// under GODEBUG=fips140=only nssdb refuses with nssdb.ErrFIPSUnsupported: the
// helper asserts that, re-runs the test with fips140=off and reports false.
func nssdbOutsideFIPS(t *testing.T) bool {
	t.Helper()
	err := nssdb.InitDir(filepath.Join(t.TempDir(), "nssdb"))
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nssdb.ErrFIPSUnsupported) {
		return false
	}
	require.NoError(t, err)
	return true
}

// nativeMessagingOutsideFIPS reports whether the calling test may run the
// browser extension's native-messaging session in this process. The session
// key agreement is X25519, which the FIPS 140-3 module refuses: under
// GODEBUG=fips140=only the helper asserts nativemsg.ErrHandshakeFailed,
// re-runs the test with fips140=off and reports false.
func nativeMessagingOutsideFIPS(t *testing.T) bool {
	t.Helper()
	_, _, err := nativemsg.NewSessionCrypto()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nativemsg.ErrHandshakeFailed) {
		return false
	}
	require.NoError(t, err)
	return true
}

// assertLegacyFingerprints checks a certificate's SHA-1 and MD5 fingerprints:
// present outside FIPS 140-only mode, and empty under it, because that mode's
// module refuses both digests.
func assertLegacyFingerprints(t *testing.T, sha1Fingerprint, md5Fingerprint string) {
	t.Helper()
	if fips140.Enforced() {
		assert.Empty(t, sha1Fingerprint)
		assert.Empty(t, md5Fingerprint)
		return
	}
	assert.NotEmpty(t, sha1Fingerprint)
	assert.NotEmpty(t, md5Fingerprint)
}

// serviceNoiseOutsideFIPS is noiseOutsideFIPS for a test that already holds
// the error of a PhoneService call reaching the Noise channel: under
// GODEBUG=fips140=only that error must carry the typed X25519 refusal.
func serviceNoiseOutsideFIPS(t *testing.T, err error) bool {
	t.Helper()
	return fipstest.OutsideFIPSAfterRefusal(t, err, bootstrap.ErrNoiseFIPSUnsupported)
}
