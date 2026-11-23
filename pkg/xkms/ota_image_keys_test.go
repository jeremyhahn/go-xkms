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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func otaKey(backend, boardID string) *transport.OTAImageKeyRequest {
	return &transport.OTAImageKeyRequest{Backend: backend, BoardID: boardID, Algorithm: OTAImageAlgorithmES256}
}

func TestOTAImageKeyID(t *testing.T) {
	id, err := OTAImageKeyID("cm4-rev2")
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4-rev2", id)

	for _, bad := range []string{
		"",
		"CM4",
		"cm4_rev2",
		"cm4/rev2",
		"../cm4",
		"-cm4",
		"cm4-",
		"cm4--v2",
		"cm4 rev2",
		strings.Repeat("a", 64),
	} {
		_, err := OTAImageKeyID(bad)
		assert.ErrorIs(t, err, ErrInvalidBoardID, "board id %q", bad)
	}
	_, err = OTAImageKeyID(strings.Repeat("a", 63))
	assert.NoError(t, err, "a 63-character board id is valid")
}

func TestCreateOTAImageKey_ES256(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	resp, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", resp.KeyID)

	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "an OTA image key is an ECDSA key")
	assert.Equal(t, elliptic.P256(), ecPub.Curve)

	_, err = svc.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "rpi5"})
	assert.NoError(t, err, "an empty algorithm selects ES256")
}

func TestCreateOTAImageKey_OneKeyPerBoard(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	_, err = svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.ErrorIs(t, err, ErrKeyAlreadyExists, "a board has exactly one OTA image key")

	_, err = svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	_, err = svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.Error(t, err, "a rotated board key cannot be created again")
}

func TestCreateOTAImageKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.CreateOTAImageKey(ctx, nil)
	assert.ErrorIs(t, err, ErrNilConfig)

	_, err = svc.CreateOTAImageKey(ctx, otaKey("software", ""))
	assert.ErrorIs(t, err, ErrInvalidBoardID)

	_, err = svc.CreateOTAImageKey(ctx, otaKey("software", "Bad_Board"))
	assert.ErrorIs(t, err, ErrInvalidBoardID)

	for _, alg := range []string{"ES384", "ES512", "RS256", "PS256", "EdDSA", "es256", "ecdsa"} {
		_, err = svc.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", Algorithm: alg})
		assert.ErrorIs(t, err, ErrOTAImageAlgorithm, "algorithm %q", alg)
	}

	_, err = svc.CreateOTAImageKey(ctx, otaKey("no-such-backend", "cm4"))
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestRotateOTAImageKey_OldVersionStillVerifies(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	image := []byte("firmware image")

	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	v1, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), v1.KeyVersion)

	rotated, err := svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)
	assert.Equal(t, "ota-image-cm4", rotated.KeyID)

	v2, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), v2.KeyVersion, "signing moves to the new version")

	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)
	for _, sig := range []*transport.SignResponse{v1, v2} {
		// The generic Verify takes DER; the OTA signature is r || s.
		resp, err := svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: keyID, Data: image, Signature: otaSignatureToDER(t, sig.Signature),
		})
		require.NoError(t, err)
		assert.True(t, resp.Valid, "version %d still verifies", sig.KeyVersion)
		assert.Equal(t, sig.KeyVersion, resp.KeyVersion)
	}
}

func TestRotateOTAImageKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.RotateOTAImageKey(ctx, nil)
	assert.ErrorIs(t, err, ErrNilConfig)

	_, err = svc.RotateOTAImageKey(ctx, otaKey("software", "cm4/../x"))
	assert.ErrorIs(t, err, ErrInvalidBoardID)

	_, err = svc.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", Algorithm: "RS256"})
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm)

	_, err = svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.ErrorIs(t, err, ErrKeyNotFound, "a board with no key cannot be rotated")
}

func TestRotateOTAImageKey_RefusesANonES256Key(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)
	genKey(t, svc, "", keyID, "rsa", 2048)

	_, err = svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm, "a board key that is not ES256 is never rotated")

	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("x")})
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm, "a board key that is not ES256 never signs an image")
}

// nonExtractableProvider is the software provider under the cloud KMS
// contract for a non-extractable key: GetKey returns (nil, nil) and the key
// is reached only through Signer.
type nonExtractableProvider struct {
	types.KeyProvider
}

func (nonExtractableProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}

// setupNonExtractableService is setupDeriveService with its software
// provider behind nonExtractableProvider.
func setupNonExtractableService(t *testing.T) *XKMSService {
	t.Helper()
	return setupWrappedProviderService(t, func(p types.KeyProvider) types.KeyProvider {
		return nonExtractableProvider{p}
	})
}

// setupWrappedProviderService wires a single "software" backend whose
// in-memory key provider is wrapped by wrap.
func setupWrappedProviderService(t *testing.T, wrap func(types.KeyProvider) types.KeyProvider) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: wrap(provider), CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": b},
		DefaultBackend: "software",
	}))

	svc, err := Get()
	require.NoError(t, err)
	wireKeyVersionStore(t)
	return svc
}

func TestOTAImageKey_NonExtractableBackend(t *testing.T) {
	svc := setupNonExtractableService(t)
	ctx := context.Background()
	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	rotated, err := svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err, "a non-extractable P-256 board key is rotated")

	digest := sha256.Sum256([]byte("firmware image"))
	resp, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend: "software", BoardID: "cm4", Data: digest[:], DataIsDigest: true,
	})
	require.NoError(t, err, "a non-extractable P-256 board key signs an image")

	block, _ := pem.Decode([]byte(rotated.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, verifyOTASignature(t, pub.(*ecdsa.PublicKey), digest[:], resp.Signature),
		"the image is signed by the rotated version")
}

func TestOTAImageKey_NonExtractableBackendRefusesANonES256Key(t *testing.T) {
	svc := setupNonExtractableService(t)
	ctx := context.Background()
	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)
	genKey(t, svc, "", keyID, "rsa", 2048)

	_, err = svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm)

	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("x")})
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm)
}

func TestBackendPublicKey(t *testing.T) {
	svc := setupNonExtractableService(t)
	ctx := context.Background()
	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)
	k, err := svc.resolveKeyIn(ctx, "software", "", keyID)
	require.NoError(t, err)
	cur, err := k.current()
	require.NoError(t, err)

	pub, err := backendPublicKey(ctx, k.backend, cur.attrs)
	require.NoError(t, err, "the public key is read through the signer")
	assert.IsType(t, &ecdsa.PublicKey{}, pub)

	absent := *cur.attrs
	absent.CN = "absent"
	_, err = backendPublicKey(ctx, k.backend, &absent)
	assert.Error(t, err, "a key neither the signer nor the decrypter reaches has no public key")
}

func TestSignOTAImage_Digest(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	created, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("firmware image"))
	resp, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend: "software", BoardID: "cm4", Data: digest[:], DataIsDigest: true,
	})
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(created.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, verifyOTASignature(t, pub.(*ecdsa.PublicKey), digest[:], resp.Signature),
		"the signature is ECDSA P-256 over the SHA-256 digest")
}

func TestSignOTAImage_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.SignOTAImage(ctx, nil)
	assert.ErrorIs(t, err, ErrNilConfig)

	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "", Data: []byte("x")})
	assert.ErrorIs(t, err, ErrInvalidBoardID)

	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("x")})
	assert.ErrorIs(t, err, ErrKeyNotFound, "a board with no key cannot sign")

	_, err = svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend: "software", BoardID: "cm4", Data: []byte("short"), DataIsDigest: true,
	})
	assert.Error(t, err, "a digest that is not 32 bytes is refused")
}

// verifyOTASignature checks an ES256 OTA_AUTH signature in the RFC 9053
// §2.1 encoding: 32-byte big-endian r, then 32-byte big-endian s.
func verifyOTASignature(t *testing.T, pub *ecdsa.PublicKey, digest, sig []byte) bool {
	t.Helper()
	require.Len(t, sig, 64, "an ES256 OTA signature is r || s, 64 bytes")
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest, r, s)
}

// otaSignatureToDER re-encodes an ES256 r || s OTA signature as the ASN.1
// DER ECDSA-Sig-Value the generic Verify takes.
func otaSignatureToDER(t *testing.T, sig []byte) []byte {
	t.Helper()
	require.Len(t, sig, 64)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(sig[:32]),
		S: new(big.Int).SetBytes(sig[32:]),
	})
	require.NoError(t, err)
	return der
}

func TestSignOTAImage_FixedWidthRSAndGenericSignStaysDER(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	created, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(created.PublicKeyPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub := parsed.(*ecdsa.PublicKey)

	digest := sha256.Sum256([]byte("firmware image"))
	ota, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend: "software", BoardID: "cm4", Data: digest[:], DataIsDigest: true,
	})
	require.NoError(t, err)
	assert.True(t, verifyOTASignature(t, pub, digest[:], ota.Signature),
		"the OTA signature is r || s and verifies after splitting")
	assert.False(t, ecdsa.VerifyASN1(pub, digest[:], ota.Signature), "the OTA signature is not DER")

	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)
	generic, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software", KeyID: keyID, Data: digest[:], Hash: crypto.SHA256.String(), DataIsDigest: true,
	})
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], generic.Signature),
		"the generic Sign on the same key still returns DER")
}

func TestSignOTAImage_RefusesAMalformedSignerSignature(t *testing.T) {
	svc := setupWrappedProviderService(t, func(p types.KeyProvider) types.KeyProvider {
		return malformedSignatureProvider{p}
	})
	ctx := context.Background()
	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("firmware image"))
	_, err = svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{
		Backend: "software", BoardID: "cm4", Data: digest[:], DataIsDigest: true,
	})
	var encErr *ErrOTASignatureEncoding
	require.ErrorAs(t, err, &encErr)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// malformedSignatureProvider hands out signers that return bytes which are
// not an ASN.1 DER ECDSA signature.
type malformedSignatureProvider struct {
	types.KeyProvider
}

func (p malformedSignatureProvider) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	signer, err := p.KeyProvider.Signer(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return malformedSigner{signer}, nil
}

type malformedSigner struct {
	crypto.Signer
}

func (malformedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte("not a DER signature"), nil
}

func TestFixedWidthECDSASignature(t *testing.T) {
	curve := elliptic.P256()
	order := curve.Params().N
	der := func(r, s *big.Int) []byte {
		out, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
		require.NoError(t, err)
		return out
	}

	t.Run("short r is left-padded to 32 bytes", func(t *testing.T) {
		sMax := new(big.Int).Sub(order, big.NewInt(1))
		got, err := fixedWidthECDSASignature(der(big.NewInt(1), sMax), curve)
		require.NoError(t, err)
		require.Len(t, got, 64)
		want := make([]byte, 64)
		want[31] = 1
		sMax.FillBytes(want[32:])
		assert.Equal(t, want, got)
	})

	t.Run("short s is left-padded to 32 bytes", func(t *testing.T) {
		got, err := fixedWidthECDSASignature(der(big.NewInt(0x0102), big.NewInt(0x7f)), curve)
		require.NoError(t, err)
		want := make([]byte, 64)
		want[30], want[31] = 0x01, 0x02
		want[63] = 0x7f
		assert.Equal(t, want, got)
	})

	valid := der(big.NewInt(1), big.NewInt(1))
	for name, input := range map[string][]byte{
		"not DER":        []byte("not a DER signature"),
		"empty":          {},
		"trailing data":  append(append([]byte{}, valid...), 0x00),
		"zero r":         der(big.NewInt(0), big.NewInt(1)),
		"negative s":     der(big.NewInt(1), big.NewInt(-1)),
		"r equals order": der(order, big.NewInt(1)),
		"s wider than the curve": der(big.NewInt(1),
			new(big.Int).Lsh(big.NewInt(1), 300)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixedWidthECDSASignature(input, curve)
			var encErr *ErrOTASignatureEncoding
			require.ErrorAs(t, err, &encErr)
			assert.True(t, errors.Is(err, ErrInvalidSignature))
			assert.NotEmpty(t, encErr.Error())
		})
	}
}

// otaPublicKeyFromPEM parses the PKIX PEM public key a key response carries.
func otaPublicKeyFromPEM(t *testing.T, pemKey string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemKey))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ec, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	return ec
}

// assertOTAPublicExport checks an export against the expected public key:
// raw X || Y (each left-padded to 32 bytes) and an EC2 P-256 COSE_Key
// (RFC 9052 §7, RFC 9053 §7.1.1) with the key id and no private part.
func assertOTAPublicExport(t *testing.T, resp *transport.OTAImagePublicKeyResponse, want *ecdsa.PublicKey, keyID string) {
	t.Helper()
	point, err := want.Bytes() // 0x04 || X || Y, 32 bytes each
	require.NoError(t, err)
	require.Len(t, point, 65)
	x, y := point[1:33], point[33:]

	require.Len(t, resp.Raw, 64, "the raw export is X || Y")
	assert.Equal(t, x, resp.Raw[:32])
	assert.Equal(t, y, resp.Raw[32:])

	var coseKey map[int]any
	require.NoError(t, cbor.Unmarshal(resp.COSEKey, &coseKey))
	assert.Equal(t, uint64(2), coseKey[1], "kty is EC2")
	assert.Equal(t, []byte(keyID), coseKey[2], "kid is the board key id")
	assert.Equal(t, int64(-7), coseKey[3], "alg is ES256")
	assert.Equal(t, uint64(1), coseKey[-1], "crv is P-256")
	assert.Equal(t, x, coseKey[-2])
	assert.Equal(t, y, coseKey[-3])
	_, hasD := coseKey[-4]
	assert.False(t, hasD, "the COSE_Key carries no private key")
}

func TestOTAImageKeys_ExportPublicKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	keyID, err := OTAImageKeyID("cm4")
	require.NoError(t, err)

	created, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	resp, err := svc.ExportOTAImagePublicKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	assert.Equal(t, keyID, resp.KeyID)
	assert.Equal(t, "cm4", resp.BoardID)
	assert.Equal(t, uint32(1), resp.Version)
	assertOTAPublicExport(t, resp, otaPublicKeyFromPEM(t, created.PublicKeyPEM), keyID)

	_, err = svc.ExportOTAImagePublicKey(ctx, otaKey("software", "pi5"))
	assert.ErrorIs(t, err, ErrKeyNotFound, "a board with no key has nothing to export")

	_, err = svc.ExportOTAImagePublicKey(ctx, nil)
	assert.ErrorIs(t, err, ErrNilConfig)

	rotated, err := svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	resp, err = svc.ExportOTAImagePublicKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), resp.Version, "the export follows the rotation")
	assertOTAPublicExport(t, resp, otaPublicKeyFromPEM(t, rotated.PublicKeyPEM), keyID)

	// #1778: a go-cose consumer decodes the exported COSE_Key and verifies
	// a SignOTAImage signature (r || s) made after the rotation.
	var key cose.Key
	require.NoError(t, key.UnmarshalCBOR(resp.COSEKey))
	assert.Equal(t, cose.KeyTypeEC2, key.Type)
	assert.Equal(t, cose.AlgorithmES256, key.Algorithm)
	assert.Equal(t, []byte(keyID), key.ID)
	crv, x, y, d := key.EC2()
	assert.Equal(t, cose.CurveP256, crv)
	assert.Equal(t, resp.Raw, append(append([]byte{}, x...), y...), "Raw is X || Y of the COSE_Key")
	assert.Empty(t, d, "the COSE_Key carries no d")

	image := []byte("firmware image after rotation")
	sig, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), sig.KeyVersion)
	pub, err := key.PublicKey()
	require.NoError(t, err)
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, pub)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(image, sig.Signature), "the exported key verifies the new version's signature")
}
