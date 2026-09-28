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

package keybackend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errProvider is the failure injected by the stub key provider.
var errProvider = errors.New("provider unavailable")

// newSoftwareBackendAdapter builds an adapter over the in-memory software
// key provider. Everything stays in process: no files, no hardware.
func newSoftwareBackendAdapter(t *testing.T) *BackendAdapter {
	t.Helper()

	backend, err := xkms.NewSoftwareBackend(&xkms.SoftwareBackendConfig{
		KeyStorage: xkms.NewStorageMemory(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	adapter := NewBackendAdapter(backend, xkms.BackendTypeSoftware)
	adapter.SetLogger(slog.New(slog.DiscardHandler))
	return adapter
}

// TestBackendAdapter_CredentialLifecycle drives generate -> sign -> verify ->
// load -> delete against the real software provider, checking the COSE public
// key actually verifies the signature the adapter produced.
func TestBackendAdapter_CredentialLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
		hash      crypto.Hash
		curve     elliptic.Curve
	}{
		{"ES256", COSEAlgES256, crypto.SHA256, elliptic.P256()},
		{"ES384", COSEAlgES384, crypto.SHA384, elliptic.P384()},
		{"ES512", COSEAlgES512, crypto.SHA512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adapter := newSoftwareBackendAdapter(t)
			credentialID := []byte("credential-" + tt.name)

			handle, coseKey, err := adapter.GenerateCredentialKey(tt.algorithm, credentialID)
			require.NoError(t, err)
			require.NotNil(t, handle)
			assert.Equal(t, credentialID, handle.CredentialID())
			assert.Equal(t, tt.algorithm, handle.Algorithm())
			assert.Equal(t, xkms.BackendTypeSoftware, handle.BackendID())

			pub := decodeCOSEEC2(t, coseKey, tt.curve)
			assert.Equal(t, tt.algorithm, coseAlgorithm(t, coseKey))

			data := []byte("authenticator data || client data hash")
			sig, err := adapter.Sign(handle, tt.algorithm, data)
			require.NoError(t, err)

			h := tt.hash.New()
			h.Write(data)
			assert.True(t, ecdsa.VerifyASN1(pub, h.Sum(nil), sig),
				"the COSE public key must verify the adapter's signature")
			assertLowS(t, sig, tt.curve)

			// LoadKey must find the credential that was just generated.
			loaded, err := adapter.LoadKey(credentialID, tt.algorithm)
			require.NoError(t, err)
			assert.Equal(t, credentialID, loaded.CredentialID())

			// Software keys are extractable.
			pkcs8, err := adapter.ExportPrivateKey(loaded)
			require.NoError(t, err)
			parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
			require.NoError(t, err)
			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			require.True(t, ok)
			// Compared as encoded keys rather than via the deprecated raw X
			// coordinate, which also makes this a stronger assertion: X alone
			// leaves Y and the curve unchecked.
			wantPub, err := pub.Bytes()
			require.NoError(t, err)
			gotPub, err := ecKey.PublicKey.Bytes()
			require.NoError(t, err)
			assert.Equal(t, wantPub, gotPub, "the exported key must match the published public key")

			require.NoError(t, adapter.DeleteKey(handle))

			_, err = adapter.LoadKey(credentialID, tt.algorithm)
			assert.ErrorIs(t, err, ErrKeyNotFound, "a deleted credential must no longer load")
		})
	}
}

func TestBackendAdapter_EdDSALifecycle(t *testing.T) {
	t.Parallel()

	adapter := newSoftwareBackendAdapter(t)
	credentialID := []byte("credential-eddsa")

	handle, coseKey, err := adapter.GenerateCredentialKey(COSEAlgEdDSA, credentialID)
	require.NoError(t, err)

	var key map[int]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(coseKey, &key))

	var kty, alg, crv int
	var x []byte
	require.NoError(t, cbor.Unmarshal(key[1], &kty))
	require.NoError(t, cbor.Unmarshal(key[3], &alg))
	require.NoError(t, cbor.Unmarshal(key[-1], &crv))
	require.NoError(t, cbor.Unmarshal(key[-2], &x))

	assert.Equal(t, COSEKeyTypeOKP, kty)
	assert.Equal(t, COSEAlgEdDSA, alg)
	assert.Equal(t, COSECurveEd25519, crv)
	require.Len(t, x, ed25519.PublicKeySize)

	data := []byte("assertion payload")
	sig, err := adapter.Sign(handle, COSEAlgEdDSA, data)
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(ed25519.PublicKey(x), data, sig),
		"the published Ed25519 key must verify the signature")
}

func TestBackendAdapter_TypeAndCapabilities(t *testing.T) {
	t.Parallel()

	adapter := newSoftwareBackendAdapter(t)

	assert.Equal(t, xkms.BackendTypeSoftware, adapter.Type())

	caps := adapter.Capabilities()
	assert.Equal(t, []int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA}, caps.SupportedAlgorithms)
	// Attestation is a device identity provisioned by a Security Officer, not a
	// property of the key provider, so the adapter itself never claims it.
	// AttestingBackend is what carries the claim; see
	// TestAttestingBackend/claims_attestation_support.
	assert.False(t, caps.SupportsAttestation, "the adapter never claims attestation support")
	assert.False(t, caps.HardwareBacked, "the software provider is not hardware backed")
	assert.False(t, caps.HandlesUserVerification, "no key provider verifies the user")
	assert.False(t, adapter.HandlesUserVerificationFor(xkms.BackendTypeSoftware),
		"a software credential never carries a backend UV claim (#1162)")
	assert.False(t, adapter.HandlesUserVerificationFor("phone"))
	assert.False(t, caps.HandlesUserPresence, "no key provider collects presence")
	assert.False(t, adapter.HandlesUserPresenceFor(xkms.BackendTypeSoftware),
		"a software credential always gets the local presence check (#1162)")
}

func TestBackendAdapter_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	adapter := newSoftwareBackendAdapter(t)

	t.Run("generate with empty credential ID", func(t *testing.T) {
		_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, nil)
		assert.ErrorIs(t, err, ErrInvalidCredentialID)
	})

	t.Run("generate with unsupported algorithm", func(t *testing.T) {
		_, _, err := adapter.GenerateCredentialKey(-999, []byte("credential"))
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("load with empty credential ID", func(t *testing.T) {
		_, err := adapter.LoadKey(nil, COSEAlgES256)
		assert.ErrorIs(t, err, ErrInvalidCredentialID)
	})

	t.Run("load with unsupported algorithm", func(t *testing.T) {
		_, err := adapter.LoadKey([]byte("credential"), -999)
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("load unknown credential", func(t *testing.T) {
		_, err := adapter.LoadKey([]byte("never-generated"), COSEAlgES256)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("sign with nil handle", func(t *testing.T) {
		_, err := adapter.Sign(nil, COSEAlgES256, []byte("data"))
		assert.ErrorIs(t, err, ErrInvalidKeyHandle)
	})

	t.Run("sign with unsupported algorithm", func(t *testing.T) {
		handle := &adapterKeyHandle{credentialID: []byte("c"), algorithm: -999}
		_, err := adapter.Sign(handle, -999, []byte("data"))
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("delete with nil handle", func(t *testing.T) {
		assert.ErrorIs(t, adapter.DeleteKey(nil), ErrInvalidKeyHandle)
	})

	t.Run("export with nil handle", func(t *testing.T) {
		_, err := adapter.ExportPrivateKey(nil)
		assert.ErrorIs(t, err, ErrInvalidKeyHandle)
	})

	t.Run("export unknown credential", func(t *testing.T) {
		handle := &adapterKeyHandle{credentialID: []byte("never-generated"), algorithm: COSEAlgES256}
		_, err := adapter.ExportPrivateKey(handle)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("import is never supported", func(t *testing.T) {
		_, err := adapter.ImportPrivateKey([]byte("credential"), COSEAlgES256, []byte("pkcs8"))
		assert.ErrorIs(t, err, ErrImportNotSupported)
	})
}

func TestBackendAdapter_ClosedRejectsEverything(t *testing.T) {
	t.Parallel()

	adapter := newSoftwareBackendAdapter(t)
	handle, _, err := adapter.GenerateCredentialKey(COSEAlgES256, []byte("credential"))
	require.NoError(t, err)

	require.NoError(t, adapter.Close())
	require.NoError(t, adapter.Close(), "Close must be idempotent")

	_, _, err = adapter.GenerateCredentialKey(COSEAlgES256, []byte("credential"))
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = adapter.Sign(handle, COSEAlgES256, []byte("data"))
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = adapter.LoadKey([]byte("credential"), COSEAlgES256)
	assert.ErrorIs(t, err, ErrBackendClosed)

	assert.ErrorIs(t, adapter.DeleteKey(handle), ErrBackendClosed)

	_, err = adapter.ExportPrivateKey(handle)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// TestBackendAdapter_ProviderFailures verifies provider errors are wrapped in
// the package's sentinels so callers can distinguish generation from signing
// failures.
func TestBackendAdapter_ProviderFailures(t *testing.T) {
	t.Parallel()

	adapter := NewBackendAdapter(&stubProvider{err: errProvider}, xkms.BackendTypeSoftware)
	adapter.SetLogger(slog.New(slog.DiscardHandler))

	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, []byte("credential"))
	assert.ErrorIs(t, err, ErrKeyGenerationFailed)
	assert.ErrorIs(t, err, errProvider, "the provider cause must stay reachable")

	handle := &adapterKeyHandle{credentialID: []byte("credential"), algorithm: COSEAlgES256}
	_, err = adapter.Sign(handle, COSEAlgES256, []byte("data"))
	assert.ErrorIs(t, err, ErrSigningFailed)
	assert.ErrorIs(t, err, errProvider)

	assert.ErrorIs(t, adapter.DeleteKey(handle), errProvider)
}

// TestBackendAdapter_UnsupportedProviderKeyType covers the guard against a
// provider that returns a key the adapter cannot publish as a COSE key.
func TestBackendAdapter_UnsupportedProviderKeyType(t *testing.T) {
	t.Parallel()

	adapter := NewBackendAdapter(&stubProvider{generated: "not-a-key"}, xkms.BackendTypeSoftware)
	adapter.SetLogger(slog.New(slog.DiscardHandler))

	_, _, err := adapter.GenerateCredentialKey(COSEAlgES256, []byte("credential"))
	assert.ErrorIs(t, err, ErrKeyGenerationFailed)
	assert.Contains(t, err.Error(), "unsupported key type")
}

// TestBackendAdapter_COSEEncodingMismatch covers the guard against a provider
// returning a key whose type does not match the requested COSE algorithm.
func TestBackendAdapter_COSEEncodingMismatch(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// The provider hands back an Ed25519 key while ES256 was requested.
	adapter := NewBackendAdapter(&stubProvider{generated: priv}, xkms.BackendTypeSoftware)
	adapter.SetLogger(slog.New(slog.DiscardHandler))

	_, _, err = adapter.GenerateCredentialKey(COSEAlgES256, []byte("credential"))
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestAlgorithmsForBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backend xkms.BackendType
		want    []int
	}{
		{"tpm2 is limited to ES256", xkms.BackendTypeTPM2, []int{COSEAlgES256}},
		{"tpm2 module ids are limited to ES256", xkms.BackendType("tpm2-device-0"), []int{COSEAlgES256}},
		{"software supports the full set", xkms.BackendTypeSoftware,
			[]int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA}},
		{"pkcs11 supports the full set", xkms.BackendTypePKCS11,
			[]int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, algorithmsForBackend(tt.backend))
		})
	}
}

func TestStoreTypeForBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		backend xkms.BackendType
		want    xkms.StoreType
	}{
		{xkms.BackendTypeSoftware, xkms.StoreSoftware},
		{xkms.BackendTypeTPM2, xkms.StoreTPM2},
		{xkms.BackendTypePKCS11, xkms.StorePKCS11},
		{xkms.BackendTypeAWSKMS, xkms.StoreAWSKMS},
		{xkms.BackendTypeGCPKMS, xkms.StoreGCPKMS},
		{xkms.BackendTypeAzureKV, xkms.StoreAzureKV},
		{xkms.BackendTypeVault, xkms.StoreVault},
		{xkms.BackendTypePhone, xkms.StorePhone},
		// Module-ID-style backend types (e.g. a second PKCS#11 token
		// registered under its own instance name) fall through to the
		// prefix-matching loop rather than the exact-match cases above.
		{xkms.BackendType("pkcs11-libykcs11-slot-0"), xkms.StorePKCS11},
		{xkms.BackendType("tpm2-simulator"), xkms.StoreTPM2},
		{xkms.BackendType("awskms-us-east-1"), xkms.StoreAWSKMS},
		{xkms.BackendType("gcpkms-project-a"), xkms.StoreGCPKMS},
		{xkms.BackendType("azurekv-vault-1"), xkms.StoreAzureKV},
		{xkms.BackendType("vault-transit"), xkms.StoreVault},
		// A backend type matching no known prefix passes through unchanged.
		{xkms.BackendType("mystery-backend"), xkms.StoreType("mystery-backend")},
	}

	for _, tt := range tests {
		t.Run(string(tt.backend), func(t *testing.T) {
			assert.Equal(t, tt.want, storeTypeForBackend(tt.backend))
		})
	}
}

func TestCurveForAlgorithm(t *testing.T) {
	t.Parallel()

	assert.Equal(t, elliptic.P256(), curveForAlgorithm(COSEAlgES256))
	assert.Equal(t, elliptic.P384(), curveForAlgorithm(COSEAlgES384))
	assert.Equal(t, elliptic.P521(), curveForAlgorithm(COSEAlgES512))
	assert.Nil(t, curveForAlgorithm(COSEAlgEdDSA), "EdDSA has no elliptic.Curve")
	assert.Nil(t, curveForAlgorithm(-999))
}

// ---------------------------------------------------------------------------
// COSE encoding
// ---------------------------------------------------------------------------

func TestEncodeCOSEPublicKey_TypeMismatches(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       crypto.PublicKey
		algorithm int
	}{
		{"ed25519 key with an ECDSA algorithm", edPub, COSEAlgES256},
		{"ecdsa key with EdDSA", &ecKey.PublicKey, COSEAlgEdDSA},
		{"unknown algorithm", &ecKey.PublicKey, -999},
		{"nil key", nil, COSEAlgES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeCOSEPublicKey(tt.key, tt.algorithm)
			assert.Nil(t, encoded)
			assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
		})
	}
}

// TestEncodeCOSEPublicKey_RSA covers the RSA dispatch branch (used only for
// a TPM Initial Attestation Key's public key): EncodeCOSEPublicKey must
// route an *rsa.PublicKey with an RSA COSE algorithm to encodeCOSERSAKey
// rather than falling through to ErrUnsupportedAlgorithm.
func TestEncodeCOSEPublicKey_RSA(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	encoded, err := EncodeCOSEPublicKey(&rsaKey.PublicKey, COSEAlgRS256)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	kty, ok := decoded[1].(uint64)
	require.True(t, ok)
	assert.Equal(t, uint64(COSEKeyTypeRSA), kty)
}

// TestEncodeCOSEEC2Key_PadsCoordinates verifies short coordinates are
// left-padded to the curve size. CTAP2 clients read fixed-width fields, so an
// unpadded coordinate silently corrupts the published key.
func TestEncodeCOSEEC2Key_PadsCoordinates(t *testing.T) {
	t.Parallel()

	// X and Y are deliberately tiny so the raw big.Int bytes are shorter than
	// the 32-byte P-256 field width.
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1), //nolint:staticcheck // the fixture DELIBERATELY builds coordinates shorter than the field width, which is the property under test; a validating constructor cannot express it.
		Y:     big.NewInt(2), //nolint:staticcheck // the fixture DELIBERATELY builds coordinates shorter than the field width, which is the property under test; a validating constructor cannot express it.
	}

	encoded, err := encodeCOSEEC2Key(key, COSEAlgES256)
	require.NoError(t, err)

	var coseKey map[int]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(encoded, &coseKey))

	var x, y []byte
	require.NoError(t, cbor.Unmarshal(coseKey[-2], &x))
	require.NoError(t, cbor.Unmarshal(coseKey[-3], &y))

	require.Len(t, x, 32)
	require.Len(t, y, 32)
	assert.Equal(t, byte(1), x[31])
	assert.Equal(t, byte(2), y[31])
	assert.Equal(t, byte(0), x[0], "coordinates must be left-padded with zeros")
}

func TestEncodeCOSEEC2Key_CurveIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		curve     elliptic.Curve
		algorithm int
		wantCrv   int
	}{
		{"P-256", elliptic.P256(), COSEAlgES256, COSECurveP256},
		{"P-384", elliptic.P384(), COSEAlgES384, COSECurveP384},
		{"P-521", elliptic.P521(), COSEAlgES512, COSECurveP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			encoded, err := EncodeCOSEPublicKey(&key.PublicKey, tt.algorithm)
			require.NoError(t, err)

			var coseKey map[int]cbor.RawMessage
			require.NoError(t, cbor.Unmarshal(encoded, &coseKey))

			var kty, alg, crv int
			require.NoError(t, cbor.Unmarshal(coseKey[1], &kty))
			require.NoError(t, cbor.Unmarshal(coseKey[3], &alg))
			require.NoError(t, cbor.Unmarshal(coseKey[-1], &crv))

			assert.Equal(t, COSEKeyTypeEC2, kty)
			assert.Equal(t, tt.algorithm, alg)
			assert.Equal(t, tt.wantCrv, crv)
		})
	}
}

func TestNormalizeLowS(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	t.Run("high S is flipped", func(t *testing.T) {
		highS := new(big.Int).Add(halfN, big.NewInt(1))
		der := marshalECDSASig(t, big.NewInt(42), highS)

		normalized, err := NormalizeLowS(der, curve)
		require.NoError(t, err)

		r, s := unmarshalECDSASig(t, normalized)
		assert.Equal(t, big.NewInt(42), r, "R must not change")
		assert.Equal(t, new(big.Int).Sub(n, highS), s)
		assert.LessOrEqual(t, s.Cmp(halfN), 0, "the result must be in low-S form")
	})

	t.Run("low S is unchanged", func(t *testing.T) {
		lowS := big.NewInt(12345)
		der := marshalECDSASig(t, big.NewInt(42), lowS)

		normalized, err := NormalizeLowS(der, curve)
		require.NoError(t, err)

		r, s := unmarshalECDSASig(t, normalized)
		assert.Equal(t, big.NewInt(42), r)
		assert.Equal(t, lowS, s)
	})

	t.Run("exactly half N is unchanged", func(t *testing.T) {
		der := marshalECDSASig(t, big.NewInt(42), halfN)

		normalized, err := NormalizeLowS(der, curve)
		require.NoError(t, err)

		_, s := unmarshalECDSASig(t, normalized)
		assert.Equal(t, halfN, s, "S == n/2 is already low-S")
	})

	t.Run("malformed DER is rejected", func(t *testing.T) {
		for _, in := range [][]byte{nil, {}, []byte("not der"), {0x30, 0x00}} {
			out, err := NormalizeLowS(in, curve)
			assert.Nil(t, out)
			assert.ErrorIs(t, err, ErrSigningFailed)
		}
	})

	t.Run("trailing garbage is rejected", func(t *testing.T) {
		der := marshalECDSASig(t, big.NewInt(1), big.NewInt(2))
		out, err := NormalizeLowS(append(der, 0x00), curve)
		assert.Nil(t, out)
		assert.ErrorIs(t, err, ErrSigningFailed, "trailing bytes must not be silently ignored")
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// decodeCOSEEC2 decodes a COSE EC2 key into an ecdsa.PublicKey.
func decodeCOSEEC2(t *testing.T, coseKey []byte, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()

	var key map[int]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(coseKey, &key))

	var x, y []byte
	require.NoError(t, cbor.Unmarshal(key[-2], &x))
	require.NoError(t, cbor.Unmarshal(key[-3], &y))

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x), //nolint:staticcheck // test helper decoding a COSE key; the raw form is what the wire carries and what the assertion is about.
		Y:     new(big.Int).SetBytes(y), //nolint:staticcheck // test helper decoding a COSE key; the raw form is what the wire carries and what the assertion is about.
	}
}

// coseAlgorithm extracts the alg label from a COSE key.
func coseAlgorithm(t *testing.T, coseKey []byte) int {
	t.Helper()

	var key map[int]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(coseKey, &key))

	var alg int
	require.NoError(t, cbor.Unmarshal(key[3], &alg))
	return alg
}

// assertLowS fails if the signature carries a high S value.
func assertLowS(t *testing.T, der []byte, curve elliptic.Curve) {
	t.Helper()

	_, s := unmarshalECDSASig(t, der)
	halfN := new(big.Int).Rsh(curve.Params().N, 1)
	assert.LessOrEqual(t, s.Cmp(halfN), 0, "WebAuthn requires low-S signatures")
}

func marshalECDSASig(t *testing.T, r, s *big.Int) []byte {
	t.Helper()

	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	require.NoError(t, err)
	return der
}

func unmarshalECDSASig(t *testing.T, der []byte) (*big.Int, *big.Int) {
	t.Helper()

	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(der, &sig)
	require.NoError(t, err)
	require.Empty(t, rest)
	return sig.R, sig.S
}

// stubProvider is a KeyProvider whose behaviour is fully scripted.
type stubProvider struct {
	xkms.KeyProvider

	err       error
	generated crypto.PrivateKey
}

func (p *stubProvider) GenerateKey(_ context.Context, _ *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.generated, nil
}

func (p *stubProvider) Signer(_ context.Context, _ *xkms.KeyAttributes) (crypto.Signer, error) {
	if p.err != nil {
		return nil, p.err
	}
	signer, ok := p.generated.(crypto.Signer)
	if !ok {
		return nil, errProvider
	}
	return signer, nil
}

func (p *stubProvider) DeleteKey(_ context.Context, _ *xkms.KeyAttributes) error {
	return p.err
}

func (p *stubProvider) GetKey(_ context.Context, _ *xkms.KeyAttributes) (crypto.PrivateKey, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.generated, nil
}

func (p *stubProvider) Capabilities() xkms.Capabilities {
	return xkms.Capabilities{}
}

// failingSigner is a crypto.Signer whose Sign call always fails, used to
// reach BackendAdapter.Sign's post-Signer() error path -- distinct from a
// failure to obtain a Signer at all, which TestBackendAdapter_ProviderFailures
// already covers.
type failingSigner struct{ public crypto.PublicKey }

func (s *failingSigner) Public() crypto.PublicKey { return s.public }

func (s *failingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer refused")
}

// TestBackendAdapter_SignFailure covers the branch where the provider hands
// back a Signer that itself refuses to sign, distinct from failing to produce
// a Signer at all.
func TestBackendAdapter_SignFailure(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	adapter := NewBackendAdapter(&stubProvider{generated: &failingSigner{public: &priv.PublicKey}}, xkms.BackendTypeSoftware)
	adapter.SetLogger(slog.New(slog.DiscardHandler))

	handle := &adapterKeyHandle{credentialID: []byte("credential"), algorithm: COSEAlgES256}
	_, err = adapter.Sign(handle, COSEAlgES256, []byte("data"))
	assert.ErrorIs(t, err, ErrSigningFailed)
}

// TestBackendAdapter_DeleteKeyUnsupportedAlgorithm covers DeleteKey's
// propagation of lookupCredentialAttrs' failure, the one DeleteKey branch none
// of the other adapter tests reach.
func TestBackendAdapter_DeleteKeyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	adapter := newSoftwareBackendAdapter(t)
	handle := &adapterKeyHandle{credentialID: []byte("credential"), algorithm: -999}

	err := adapter.DeleteKey(handle)

	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// TestBackendAdapter_ExportPrivateKey_ProviderFailures covers ExportPrivateKey
// against the provider itself, rather than against lookupCredentialAttrs: a
// provider that cannot produce the key material at all, and one that produces
// key material x509 cannot marshal as PKCS#8 -- the hardware-bound case
// ExportNotSupported exists for.
func TestBackendAdapter_ExportPrivateKey_ProviderFailures(t *testing.T) {
	t.Parallel()

	handle := &adapterKeyHandle{credentialID: []byte("credential"), algorithm: COSEAlgES256}

	t.Run("provider cannot produce the key", func(t *testing.T) {
		adapter := NewBackendAdapter(&stubProvider{err: errProvider}, xkms.BackendTypeSoftware)
		adapter.SetLogger(slog.New(slog.DiscardHandler))

		_, err := adapter.ExportPrivateKey(handle)
		assert.ErrorIs(t, err, ErrKeyNotFound)
	})

	t.Run("key material is not PKCS#8-marshalable", func(t *testing.T) {
		// A hardware-bound signer never hands back raw key material x509 can
		// marshal, which is exactly what makes it non-exportable.
		adapter := NewBackendAdapter(&stubProvider{generated: "opaque-hardware-handle"}, xkms.BackendTypeSoftware)
		adapter.SetLogger(slog.New(slog.DiscardHandler))

		_, err := adapter.ExportPrivateKey(handle)
		assert.ErrorIs(t, err, ErrExportNotSupported)
	})
}
