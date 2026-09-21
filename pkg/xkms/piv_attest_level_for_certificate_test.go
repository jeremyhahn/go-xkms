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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedCertForKey mints a fresh self-signed certificate over key, with
// serial distinguishing it from any other certificate minted for the same
// key. Two certificates from this helper over the same key share nothing
// but their SubjectPublicKeyInfo — exactly the shape a renewed login
// certificate has against the certificate a slot was originally enrolled
// with, and exactly what proves the match in
// PIVManager.AttestLevelForCertificate is SPKI-based rather than whole-
// certificate equality.
func selfSignedCertForKey(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// setupPIVManagerWithEnrolledSlot initializes the PIV manager singleton with
// one backend ("piv-backend") whose store holds enrolledCert in slot 9a, and
// whose resolved generator implements PIVAttestLevelReporter reporting
// level. Returns the store so a test can additionally break it (listErr).
func setupPIVManagerWithEnrolledSlot(t *testing.T, enrolledCert *x509.Certificate, level types.AttestLevel) *mockPIVCertStorage {
	t.Helper()
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	store := newMockPIVCertStorage()
	require.NoError(t, store.Store(pivcert.PIVSlot(pivcert.PIVSlotAuthentication), enrolledCert))

	require.NoError(t, InitializePIV(&PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{"piv-backend": store},
	}))
	require.NoError(t, SetPIVBackendResolver(func(string) (PIVKeyGenerator, error) {
		return attestLevelReportingGenerator{level: level}, nil
	}))

	return store
}

// TestAttestLevelForCertificate_MatchesHardwareEnrolledKey proves a login
// certificate sharing SubjectPublicKeyInfo with a hardware-enrolled slot
// resolves to the recorded level, even though the presented certificate is
// a different object entirely (a distinct serial, as a renewal would be).
func TestAttestLevelForCertificate_MatchesHardwareEnrolledKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrolledCert := selfSignedCertForKey(t, key, "piv-9a", 1)
	loginCert := selfSignedCertForKey(t, key, "alice login", 2)

	setupPIVManagerWithEnrolledSlot(t, enrolledCert, types.AttestLevelHardware)

	mgr, err := GetPIVManager()
	require.NoError(t, err)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), loginCert)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, types.AttestLevelHardware, level)
}

// TestAttestLevelForCertificate_MatchesSoftwareEnrolledKey is the software
// companion: the recorded level is exactly what the generator reports, not
// upgraded or downgraded because a slot happened to match.
func TestAttestLevelForCertificate_MatchesSoftwareEnrolledKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrolledCert := selfSignedCertForKey(t, key, "piv-9a", 1)
	loginCert := selfSignedCertForKey(t, key, "bob login", 2)

	setupPIVManagerWithEnrolledSlot(t, enrolledCert, types.AttestLevelSoftware)

	mgr, err := GetPIVManager()
	require.NoError(t, err)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), loginCert)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, types.AttestLevelSoftware, level)
}

// TestAttestLevelForCertificate_NoMatch proves a certificate whose key was
// never enrolled in any registered PIV slot reports found=false and no
// error — this is the ordinary case (a passkey, a generic mTLS client cert)
// and must defer to the chain-derived decision, not be treated as a lookup
// failure.
func TestAttestLevelForCertificate_NoMatch(t *testing.T) {
	enrolledKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrolledCert := selfSignedCertForKey(t, enrolledKey, "piv-9a", 1)

	setupPIVManagerWithEnrolledSlot(t, enrolledCert, types.AttestLevelHardware)

	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	unrelatedCert := selfSignedCertForKey(t, unrelatedKey, "unrelated login", 99)

	mgr, err := GetPIVManager()
	require.NoError(t, err)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), unrelatedCert)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, types.AttestLevelUnattested, level)
}

// TestAttestLevelForCertificate_NilCertificate covers the input-validation
// half of this function's contract: a nil certificate cannot match
// anything and must not panic computing a thumbprint over it.
func TestAttestLevelForCertificate_NilCertificate(t *testing.T) {
	enrolledKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enrolledCert := selfSignedCertForKey(t, enrolledKey, "piv-9a", 1)
	setupPIVManagerWithEnrolledSlot(t, enrolledCert, types.AttestLevelHardware)

	mgr, err := GetPIVManager()
	require.NoError(t, err)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, types.AttestLevelUnattested, level)
}

// TestAttestLevelForCertificate_BackendError proves a registered backend
// whose PIV store cannot be listed surfaces as ErrPIVAttestLevelLookupFailed
// rather than being silently read as "no match" — a caller deciding whether
// to trust a login needs to know the lookup itself failed.
func TestAttestLevelForCertificate_BackendError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	loginCert := selfSignedCertForKey(t, key, "carol login", 1)

	store := setupPIVManagerWithEnrolledSlot(t, selfSignedCertForKey(t, key, "piv-9a", 2), types.AttestLevelHardware)
	store.listErr = errors.New("token communication failure")

	mgr, err := GetPIVManager()
	require.NoError(t, err)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), loginCert)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVAttestLevelLookupFailed)
	assert.False(t, found)
	assert.Equal(t, types.AttestLevelUnattested, level)
}

// TestAttestLevelForCertificate_NotInitialized proves calling the method on
// a manager that was never obtained (nil receiver) resolves to
// found=false, nil error, rather than a nil-pointer panic — the method is
// meant to be safe for an optional-capability wiring pattern where the
// caller checks GetPIVManager's own error, but a defensive nil receiver
// must not crash the login path either.
func TestAttestLevelForCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	t.Cleanup(func() { ResetPIV() })

	var mgr *PIVManager
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedCertForKey(t, key, "dave login", 1)

	level, found, err := mgr.AttestLevelForCertificate(context.Background(), cert)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, types.AttestLevelUnattested, level)
}
