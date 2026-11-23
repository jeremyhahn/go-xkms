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

package deviceattest01

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// mintAliasWithApplication mints an alias certificate for key, signed by it,
// whose UCCS measurements claim (273) is the ruled shape carrying evidence
// as the application's 32 bytes.
func mintAliasWithApplication(t *testing.T, key *ecdsa.PrivateKey, evidence []byte) *x509.Certificate {
	t.Helper()
	mode, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	coswid, err := mode.Marshal(map[int64]any{
		0:  bytes.Repeat([]byte{0x5a}, 16),
		1:  "app-fw",
		2:  map[int64]any{31: "vendor", 33: 1},
		3:  map[int64]any{17: map[int64]any{24: "app", 7: []any{1, evidence}}},
		12: 0,
	})
	require.NoError(t, err)
	measurements, err := mode.Marshal([]any{[]any{258, coswid}})
	require.NoError(t, err)
	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{
		Nonce: DICENonce(diceKeyAuth),
		Other: map[int64][]byte{dice.ClaimMeasurements: measurements},
	})
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(11),
		Subject:            pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    []pkix.Extension{uccs, ueidExtension(t)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

// referencedFor is provisionedFor with reference registered as the device's
// application reference.
func referencedFor(t *testing.T, key *ecdsa.PrivateKey, reference []byte) *TrustAnchorVerifier {
	t.Helper()
	return registryVerifier(t, TrustAnchors{Devices: testRegistry{
		hex.EncodeToString(diceUeid): {DeviceIDKey: spkiOf(t, key), ApplicationReference: reference},
	}})
}

func TestVerifyRegisteredDeviceHoldsTheApplicationReference(t *testing.T) {
	ctx := context.Background()
	deviceKey := newP256Key(t)
	registered := bytes.Repeat([]byte{0xa5}, 32)
	other := bytes.Repeat([]byte{0x5a}, 32)

	t.Run("the registered application is accepted", func(t *testing.T) {
		leaf := mintAliasWithApplication(t, deviceKey, registered)
		attested, err := referencedFor(t, deviceKey, registered).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		require.NoError(t, err)
		assert.Same(t, leaf, attested.Leaf)
	})

	t.Run("another application is refused", func(t *testing.T) {
		leaf := mintAliasWithApplication(t, deviceKey, other)
		_, err := referencedFor(t, deviceKey, registered).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
		assert.ErrorIs(t, err, dice.ErrApplicationEvidenceMismatch)
	})

	t.Run("an alias without a measurements claim is refused", func(t *testing.T) {
		leaf := mintAlias(t, &deviceKey.PublicKey, deviceKey, x509.ECDSAWithSHA256, make([]byte, 32))
		_, err := referencedFor(t, deviceKey, registered).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, dice.ErrApplicationEvidenceMismatch)
	})

	t.Run("an endorsed device is held to its reference", func(t *testing.T) {
		fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, false, false)
		registry := fixture.registry()
		registry[hex.EncodeToString(diceUeid)].ApplicationReference = registered
		v := registryVerifier(t, TrustAnchors{DICERoots: []*x509.Certificate{fixture.root}, Devices: registry})
		leaf, err := x509.ParseCertificate(fixture.leafDER)
		require.NoError(t, err)
		_, err = v.VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, dice.ErrApplicationEvidenceMismatch)
	})

	t.Run("a reference that is not 32 bytes is an invalid record", func(t *testing.T) {
		leaf := mintAliasWithApplication(t, deviceKey, registered)
		_, err := referencedFor(t, deviceKey, registered[:31]).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrProvisioningRecordInvalid)
		assert.ErrorIs(t, err, dice.ErrInvalidApplicationReference)
	})

	t.Run("no registered reference leaves the application unchecked", func(t *testing.T) {
		leaf := mintAliasWithApplication(t, deviceKey, other)
		_, err := provisionedFor(t, deviceKey).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
		require.NoError(t, err)
	})
}

func TestConfirmRegistrationHoldsTheApplicationReference(t *testing.T) {
	ctx := context.Background()
	deviceKey := newP256Key(t)
	registered := bytes.Repeat([]byte{0xa5}, 32)
	leaf := mintAliasWithApplication(t, deviceKey, registered)

	validated, err := referencedFor(t, deviceKey, registered).VerifyRegisteredDevice(ctx, leaf, diceKeyAuth)
	require.NoError(t, err)
	verified := &VerifiedAttestation{Format: FormatDICE, LeafDER: leaf.Raw, AttestedSPKI: validated.AttestedSPKI}

	t.Run("an unchanged reference confirms", func(t *testing.T) {
		require.NoError(t, verified.ConfirmRegistration(ctx, referencedFor(t, deviceKey, registered), nil))
	})

	t.Run("a reference changed after validation is refused", func(t *testing.T) {
		err := verified.ConfirmRegistration(ctx, referencedFor(t, deviceKey, bytes.Repeat([]byte{0x5a}, 32)), nil)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, dice.ErrApplicationEvidenceMismatch)
	})
}
