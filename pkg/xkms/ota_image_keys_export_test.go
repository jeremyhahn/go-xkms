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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// rawPoint returns the X || Y of a PEM-encoded P-256 public key.
func rawPoint(t *testing.T, publicKeyPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(publicKeyPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok)
	ecdhPub, err := pub.ECDH()
	require.NoError(t, err)
	return ecdhPub.Bytes()[1:]
}

// TestExportOTAImageKey_PublicKeyAndCOSEKey proves the export carries the
// board key's X || Y and a COSE_Key with exactly the RFC 9053 §7.1.1 EC2
// fields, in deterministic CBOR, that verifies the board's OTA signature.
func TestExportOTAImageKey_PublicKeyAndCOSEKey(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	created, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	export, err := svc.ExportOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	assert.Equal(t, "cm4", export.BoardID)
	assert.Equal(t, "ota-image-cm4", export.KeyID)
	assert.Equal(t, uint32(1), export.KeyVersion)
	assert.Equal(t, OTAImageAlgorithmES256, export.Algorithm)
	require.Len(t, export.PublicKey, 64)
	assert.Equal(t, rawPoint(t, created.PublicKeyPEM), export.PublicKey)

	var fields map[int]any
	require.NoError(t, cbor.Unmarshal(export.COSEKey, &fields))
	assert.Equal(t, map[int]any{
		1:  uint64(2),
		2:  []byte("ota-image-cm4"),
		3:  int64(-7),
		-1: uint64(1),
		-2: export.PublicKey[:32],
		-3: export.PublicKey[32:],
	}, fields, "kty EC2, kid, alg ES256, crv P-256, x, y and nothing else")

	detMode, err := cbor.CoreDetEncOptions().EncMode()
	require.NoError(t, err)
	canonical, err := detMode.Marshal(fields)
	require.NoError(t, err)
	assert.Equal(t, canonical, export.COSEKey, "RFC 8949 §4.2.1 core deterministic encoding")

	var key cose.Key
	require.NoError(t, key.UnmarshalCBOR(export.COSEKey))
	verifier, err := key.Verifier()
	require.NoError(t, err)
	image := []byte("firmware image")
	sig, err := svc.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(image, sig.Signature), "the exported key verifies the board's OTA signature")
}

// TestExportOTAImageKey_FollowsRotation proves the export is the current
// version, the one SignOTAImage signs with.
func TestExportOTAImageKey_FollowsRotation(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	_, err := svc.CreateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	v1, err := svc.ExportOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	rotated, err := svc.RotateOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)
	v2, err := svc.ExportOTAImageKey(ctx, otaKey("software", "cm4"))
	require.NoError(t, err)

	assert.Equal(t, rotated.KeyVersion, v2.KeyVersion)
	assert.Equal(t, rawPoint(t, rotated.PublicKeyPEM), v2.PublicKey)
	assert.NotEqual(t, v1.PublicKey, v2.PublicKey)
	assert.Equal(t, v1.KeyID, v2.KeyID, "the key ID is the board's, across versions")
}

// TestExportOTAImageKey_TenantScoped proves a tenant's board key is exported
// only in that tenant.
func TestExportOTAImageKey_TenantScoped(t *testing.T) {
	svc := setupDeriveService(t)
	req := &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", TenantID: "acme"}
	_, err := svc.CreateOTAImageKey(identityCtx("acme"), req)
	require.NoError(t, err)

	export, err := svc.ExportOTAImageKey(identityCtx("acme"), req)
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", export.KeyID)

	_, err = svc.ExportOTAImageKey(identityCtx("globex"), &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", TenantID: "globex"})
	assert.ErrorIs(t, err, ErrKeyNotFound, "another tenant's board key is not found")
}

func TestExportOTAImageKey_Errors(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	_, err := svc.ExportOTAImageKey(ctx, nil)
	assert.ErrorIs(t, err, ErrNilConfig)

	_, err = svc.ExportOTAImageKey(ctx, otaKey("software", "Bad_Board"))
	assert.ErrorIs(t, err, ErrInvalidBoardID)

	_, err = svc.ExportOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", Algorithm: "ES384"})
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm)

	_, err = svc.ExportOTAImageKey(ctx, otaKey("software", "cm4"))
	assert.ErrorIs(t, err, ErrKeyNotFound, "a board with no key has nothing to export")

	keyID, err := OTAImageKeyID("pi5")
	require.NoError(t, err)
	genKey(t, svc, "", keyID, "rsa", 2048)
	_, err = svc.ExportOTAImageKey(ctx, otaKey("software", "pi5"))
	assert.ErrorIs(t, err, ErrOTAImageAlgorithm, "a board key that is not ES256 is never exported as one")
}

// TestOTAImagePublicKeyEncodings_LeftPadsCoordinates proves a coordinate
// with a leading zero octet keeps it in both encodings (RFC 9053 §7.1.1).
func TestOTAImagePublicKeyEncodings_LeftPadsCoordinates(t *testing.T) {
	var pub *ecdsa.PublicKey
	for i := 0; i < 1<<14 && pub == nil; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecdhPub, err := priv.PublicKey.ECDH()
		require.NoError(t, err)
		if ecdhPub.Bytes()[1] == 0 {
			pub = &priv.PublicKey
		}
	}
	require.NotNil(t, pub, "a P-256 key with a short X")

	point, coseKey, err := otaImagePublicKeyEncodings("ota-image-cm4", pub)
	require.NoError(t, err)
	require.Len(t, point, 64)
	assert.Zero(t, point[0])

	var key cose.Key
	require.NoError(t, key.UnmarshalCBOR(coseKey))
	_, x, y, d := key.EC2()
	assert.Equal(t, point[:32], x)
	assert.Equal(t, point[32:], y)
	assert.Nil(t, d, "no private key")
}

func TestOTAImagePublicKeyEncodings_RefusesAnInvalidKey(t *testing.T) {
	_, _, err := otaImagePublicKeyEncodings("ota-image-cm4", &ecdsa.PublicKey{Curve: elliptic.P224()})
	assert.Error(t, err, "a key that is not a P-256 point is refused")
}
