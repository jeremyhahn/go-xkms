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
// +build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// TestEndorsementKeyReadbacks_PropagateReadFailures proves EKPublic, EKRSA,
// EKECC and SSRKPublic each surface a TPM-level read failure as their own
// typed error instead of a bare go-tpm error, on a simulator whose EK/SSRK
// handles were never provisioned.
func TestEndorsementKeyReadbacks_PropagateReadFailures(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)

	_, _, err := h.TPM.EKPublic()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEKPublicRead)

	_, err = h.TPM.EKRSA()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEKRSAParse)

	_, err = h.TPM.EKECC()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEKECCParse)

	_, _, err = h.TPM.SSRKPublic()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSRKPublicRead)
}

// TestEKECCAndEKRSA_AgreeWithTheLiveKeyType proves EKECC and EKRSA actually
// check the live key's type rather than trusting the configured algorithm
// string: on an EK provisioned as ECC, EKECC must succeed and EKRSA -- which
// this same TPM would also serve if asked -- must reject the mismatched
// parameters union instead of returning a bogus RSA key.
func TestEKECCAndEKRSA_AgreeWithTheLiveKeyType(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.EK.RSAConfig = nil
		c.EK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.EK.KeyAlgorithm = "ECDSA"
	})

	eccPub, err := h.TPM.EKECC()
	require.NoError(t, err)
	require.NotNil(t, eccPub)
	require.Equal(t, elliptic.P256(), eccPub.Curve)

	_, err = h.TPM.EKRSA()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEKRSAParse)
}

// TestEKAttributes_DerivesFromLiveKeyOrConfig table-tests the branches
// EKAttributes takes once the persistent EK has been read back: an invalid
// configured algorithm string must fail closed rather than silently default,
// an RSA EK with no configured RSAConfig must derive its key size from the
// live public key instead of reporting a zero size, and an ECC EK is
// resolved either from an explicit configured curve or, absent one, from the
// live key -- with an unresolvable configured curve name rejected.
func TestEKAttributes_DerivesFromLiveKeyOrConfig(t *testing.T) {
	t.Run("invalid configured algorithm", func(t *testing.T) {
		h := newSimHarness(t, nil)
		h.TPM.ekAttrs = nil
		h.TPM.config.EK.KeyAlgorithm = "not-a-real-algorithm"

		_, err := h.TPM.EKAttributes()
		require.Error(t, err)
	})

	t.Run("RSA EK with no configured RSAConfig derives key size from the live key", func(t *testing.T) {
		h := newSimHarness(t, nil)
		h.TPM.ekAttrs = nil
		h.TPM.config.EK.RSAConfig = nil

		attrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)
		require.NotNil(t, attrs.RSAAttributes)
		require.Equal(t, 2048, attrs.RSAAttributes.KeySize,
			"the live EK was provisioned at 2048 bits by newSimConfig's RSAConfig")
	})

	t.Run("ECC-configured algorithm with an explicit curve", func(t *testing.T) {
		h := newSimHarness(t, nil)
		h.TPM.ekAttrs = nil
		h.TPM.config.EK.KeyAlgorithm = "ECDSA"
		h.TPM.config.EK.ECCConfig = &store.ECCConfig{Curve: "P-384"}

		attrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)
		require.NotNil(t, attrs.ECCAttributes)
		require.Equal(t, elliptic.P384(), attrs.ECCAttributes.Curve)
	})

	t.Run("ECC-configured algorithm with an unresolvable curve name", func(t *testing.T) {
		h := newSimHarness(t, nil)
		h.TPM.ekAttrs = nil
		h.TPM.config.EK.KeyAlgorithm = "ECDSA"
		h.TPM.config.EK.ECCConfig = &store.ECCConfig{Curve: "not-a-curve"}

		_, err := h.TPM.EKAttributes()
		require.Error(t, err)
	})

	t.Run("ECC-configured algorithm with no ECCConfig derives from the live key", func(t *testing.T) {
		h := newSimHarness(t, nil)
		h.TPM.ekAttrs = nil
		h.TPM.config.EK.KeyAlgorithm = "ECDSA"
		h.TPM.config.EK.ECCConfig = nil

		// The live EK this simulator actually provisioned is RSA (newSimConfig
		// sets RSAConfig, not ECCConfig), so the type assertion onto
		// *ecdsa.PublicKey fails and the curve is left nil rather than
		// erroring: EKAttributes reports what it can determine instead of
		// refusing the whole call over a config/live-key mismatch it did not
		// cause.
		attrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)
		require.NotNil(t, attrs.ECCAttributes)
		require.Nil(t, attrs.ECCAttributes.Curve)
	})
}

// TestIDevIDAttributes_RejectsAnUnparsableConfiguredSignatureAlgorithm
// proves the IDevID rebuild path -- exercised whenever an existing IDevID is
// looked up after process restart -- refuses a configuration whose signature
// algorithm this package cannot parse, rather than caching a KeyAttributes
// with a zero-value SignatureAlgorithm that every downstream CSR/certify
// path would silently mis-sign under.
func TestIDevIDAttributes_RejectsAnUnparsableConfiguredSignatureAlgorithm(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK, false)

	h.TPM.idevidAttrs = nil
	h.TPM.config.IDevID.SignatureAlgorithm = "not-a-real-signature-algorithm"

	_, err := h.TPM.IDevIDAttributes()
	require.Error(t, err)
}

// TestIDevID_RejectsAnUnparsablePublicKey proves IDevID -- the public-key-only
// accessor -- surfaces a DER parse failure as ErrIDevIDPublicParse instead of
// a bare x509 error, the same contract EK() already holds for the
// Endorsement Key.
func TestIDevID_RejectsAnUnparsablePublicKey(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK, false)

	h.TPM.idevidAttrs.TPMAttributes.PublicKeyBytes = []byte("not a DER-encoded public key")

	_, err := h.TPM.IDevID()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIDevIDPublicParse)
}
