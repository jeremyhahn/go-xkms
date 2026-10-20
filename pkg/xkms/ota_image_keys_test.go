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
	"encoding/pem"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		resp, err := svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: keyID, Data: image, Signature: sig.Signature,
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
	Reset()
	t.Cleanup(Reset)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: nonExtractableProvider{provider}, CertStorage: storage.New()})
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
	assert.True(t, ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], resp.Signature),
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
	assert.True(t, ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], resp.Signature),
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
