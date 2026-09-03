// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package software

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createX25519Attrs builds the attributes an X25519 agreement key is declared
// with. X25519 has no x509.PublicKeyAlgorithm constant, so the presence of
// X25519Attributes -- not KeyAlgorithm -- is what names the algorithm; see
// types.KeyAttributes.ID.
func createX25519Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:               cn,
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
}

// TestValidateKeyType_Ed25519DeclaredAsECDSAIsRefused is go-xkms#53's reported
// defect, in the shape a consumer measured it: an Ed25519 private key declared
// as ECDSA-P256 imported successfully, because ECDSA and Ed25519 both fell
// through a default arm commented "basic validation is sufficient".
//
// Those two are the algorithms the signing policy uses -- ed25519 by default,
// ECDSA-P256 under FIPS -- so the unvalidated pair was the pair that mattered.
func TestValidateKeyType_Ed25519DeclaredAsECDSAIsRefused(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	err = validateKeyType(key, createECDSAAttrs("ed25519-as-ecdsa", "P-256"))

	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
	assert.Contains(t, err.Error(), "expected Ed25519 key")
}

// TestValidateKeyType_ECDSADeclaredAsEd25519IsRefused is the mirror of the
// reported defect. A validator that only closed the direction the consumer
// happened to measure would leave the other one open.
func TestValidateKeyType_ECDSADeclaredAsEd25519IsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	err = validateKeyType(key, createEd25519Attrs("ecdsa-as-ed25519"))

	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
	assert.Contains(t, err.Error(), "expected ECDSA key")
}

// TestValidateKeyType_X25519MismatchesAreRefusedBothWays covers the agreement
// key in both directions: an X25519 key declared as ECDSA, and an ECDSA key
// declared as X25519. Neither was checked before, and the ECDH arm is what
// keeps the refusing default from breaking a key type the backend supports.
func TestValidateKeyType_X25519MismatchesAreRefusedBothWays(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("X25519 key declared as ECDSA", func(t *testing.T) {
		err := validateKeyType(x25519Key, createECDSAAttrs("x25519-as-ecdsa", "P-256"))
		require.Error(t, err)
		assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
		assert.Contains(t, err.Error(), "X25519Attributes")
	})

	t.Run("ECDSA key declared as X25519", func(t *testing.T) {
		err := validateKeyType(ecdsaKey, createX25519Attrs("ecdsa-as-x25519"))
		require.Error(t, err)
		assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
		assert.Contains(t, err.Error(), "expected ECDSA key")
	})

	t.Run("X25519 key declared as X25519", func(t *testing.T) {
		assert.NoError(t, validateKeyType(x25519Key, createX25519Attrs("x25519-matching")))
	})
}

// TestValidateKeyType_UnknownKeyTypeIsRefused pins the fail-closed default.
// The arm it replaces was commented "basic validation is sufficient", which
// validated nothing: a description no arm recognises cannot be checked against
// the key, so it is refused rather than blessed.
func TestValidateKeyType_UnknownKeyTypeIsRefused(t *testing.T) {
	type unknownPrivateKey struct{}

	err := validateKeyType(unknownPrivateKey{}, createRSAAttrs("unknown-type", 2048))

	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
	assert.Contains(t, err.Error(), "unsupported private key type")
}

// TestValidateKeyType_PublicKeysAreRefused covers every algorithm's public
// key. Only the RSA one was refused before; the others reached the no-op
// default, so a public key could be stored where a private key belongs.
func TestValidateKeyType_PublicKeysAreRefused(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name  string
		key   any
		attrs *types.KeyAttributes
	}{
		{"RSA", &rsaKey.PublicKey, createRSAAttrs("pub-rsa", 2048)},
		{"ECDSA", &ecdsaKey.PublicKey, createECDSAAttrs("pub-ecdsa", "P-256")},
		{"Ed25519", edPub, createEd25519Attrs("pub-ed25519")},
		{"X25519", xKey.PublicKey(), createX25519Attrs("pub-x25519")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyType(tc.key, tc.attrs)
			require.Error(t, err)
			assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
			assert.Contains(t, err.Error(), "expected private key but got public key")
		})
	}
}

// TestValidateKeyType_MatchingDeclarationsAreAdmitted proves the tightened
// validator is not a denial of service: every supported key type still imports
// when the declaration describes it.
func TestValidateKeyType_MatchingDeclarationsAreAdmitted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// An RSA key whose attributes carry no RSAAttributes block at all. Four
	// backends reconstruct KeyAlgorithm with the block left nil, and their
	// attributes reach this validator through CopyKey and the migrator, so the
	// existing nil guard is load-bearing rather than defensive.
	rsaNoBlock := createRSAAttrs("rsa-no-block", 2048)
	rsaNoBlock.RSAAttributes = nil

	ecdsaNoBlock := createECDSAAttrs("ecdsa-no-block", "P-256")
	ecdsaNoBlock.ECCAttributes = nil

	cases := []struct {
		name  string
		key   any
		attrs *types.KeyAttributes
	}{
		{"RSA 2048", rsaKey, createRSAAttrs("rsa-2048", 2048)},
		{"RSA with no RSAAttributes", rsaKey, rsaNoBlock},
		{"ECDSA P-256", p256, createECDSAAttrs("ec-p256", "P-256")},
		{"ECDSA P-384", p384, createECDSAAttrs("ec-p384", "P-384")},
		{"ECDSA with no ECCAttributes", p256, ecdsaNoBlock},
		{"Ed25519", edKey, createEd25519Attrs("ed25519")},
		{"X25519", xKey, createX25519Attrs("x25519")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NoError(t, validateKeyType(tc.key, tc.attrs))
		})
	}
}

// TestValidateKeyType_CurveIsNotComparedAgainstTheDeclaredOne pins a
// deliberate omission, so that restoring the comparison is a decision rather
// than an accident.
//
// go-xkms#53 asks for the curve to be checked against the declared variant. It
// is NOT checked, because no legitimate producer can satisfy the comparison
// today: PKCS8Backend.ListKeys reconstructs attributes from the storage key
// identifier, which carries no curve, and hardcodes P-256 for every ECDSA key.
// Both CopyKey paths and the migrator reach this validator through that
// reconstruction, so comparing curves refuses every copy and migrate of a
// non-P-256 EC key -- the export succeeds and the import refuses.
//
// The same reconstruction sends the PKCS#11 C_UnwrapKey path here declaring
// P-256 whenever the unwrap template names no curve, which is how a curve
// comparison broke C_UnwrapKey for every non-P-256 EC key.
//
// What that leaves open, stated rather than implied: a P-384 key can be
// imported while declaring P-256. It is inert today -- the curve is not part
// of types.KeyAttributes.ID() and Signer recovers it from the DER -- and stops
// being inert the moment anything trusts attrs.ECCAttributes for a decision.
// go-xkms#156 carries the caveat and the ListKeys fix the comparison needs.
func TestValidateKeyType_CurveIsNotComparedAgainstTheDeclaredOne(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	err = validateKeyType(p384, createECDSAAttrs("p384-declared-p256", "P-256"))

	assert.NoError(t, err, "a curve comparison here refuses every copy, migrate and C_UnwrapKey of a non-P-256 EC key")
}

// TestImportKey_RefusesEd25519MaterialDeclaredAsECDSA runs the reported defect
// through the whole import ceremony rather than through validateKeyType alone,
// which is the path the consumer's failing scenario takes.
func TestImportKey_RefusesEd25519MaterialDeclaredAsECDSA(t *testing.T) {
	be, _ := createTestBackend(t)
	sb := be.(*SoftwareBackend)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	attrs := createECDSAAttrs("import-ed25519-as-ecdsa", "P-256")
	params, err := sb.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := sb.WrapKey(ctx, der, params)
	require.NoError(t, err)

	err = sb.ImportKey(ctx, attrs, wrapped)

	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
	assert.Contains(t, err.Error(), "expected Ed25519 key")
}

// TestImportKey_AdmitsNonP256ECMaterialDeclaredAsP256 is the C_UnwrapKey
// regression, measured at the layer that caused it. The PKCS#11 module unwraps
// a P-384 key through attributes the service resolved to P-256 whenever the
// unwrap template names no curve; a curve-equality check here refused it, and
// that import previously succeeded with a fully usable stored key.
func TestImportKey_AdmitsNonP256ECMaterialDeclaredAsP256(t *testing.T) {
	be, _ := createTestBackend(t)
	sb := be.(*SoftwareBackend)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)

	attrs := createECDSAAttrs("import-p384-as-p256", "P-256")
	params, err := sb.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := sb.WrapKey(ctx, der, params)
	require.NoError(t, err)

	require.NoError(t, sb.ImportKey(ctx, attrs, wrapped))

	// The stored key is the P-384 one, not a P-256 substitute: the material is
	// what was imported and the DER carries its real curve.
	signer, err := sb.Signer(ctx, attrs)
	require.NoError(t, err)
	stored, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P384(), stored.Curve)
}
