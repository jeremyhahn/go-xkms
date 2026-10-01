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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestSign_RawECDSA_ThroughService drives the service the way the PKCS#11
// module's CKM_ECDSA does: hash "NONE", DataIsDigest, a caller-built digest of
// 32, 48 or 64 bytes. Each signature must verify through the service and,
// independently, through crypto/ecdsa over exactly the bytes supplied; a
// changed digest must not verify.
func TestSign_RawECDSA_ThroughService(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	key, err := software.GenerateECDSA(ctx, &types.KeyAttributes{
		CN:            "raw-ecdsa",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)
	pub := &key.(*ecdsa.PrivateKey).PublicKey

	for _, size := range []int{32, 48, 64} {
		digest := make([]byte, size)
		_, err := rand.Read(digest)
		require.NoError(t, err)

		signResp, err := svc.Sign(ctx, &transport.SignRequest{
			Backend: "software", KeyID: "raw-ecdsa", Data: digest, Hash: "NONE", DataIsDigest: true,
		})
		require.NoError(t, err, "raw ECDSA over a %d-byte digest", size)
		require.True(t, ecdsa.VerifyASN1(pub, digest, signResp.Signature), "%d-byte digest: signature does not verify over the supplied bytes", size)

		verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: "raw-ecdsa", Data: digest, Signature: signResp.Signature, Hash: "NONE", DataIsDigest: true,
		})
		require.NoError(t, err)
		require.True(t, verifyResp.Valid, "%d-byte digest: the service rejected its own signature", size)

		digest[0] ^= 0xff
		verifyResp, err = svc.Verify(ctx, &transport.VerifyRequest{
			Backend: "software", KeyID: "raw-ecdsa", Data: digest, Signature: signResp.Signature, Hash: "NONE", DataIsDigest: true,
		})
		require.NoError(t, err)
		require.False(t, verifyResp.Valid, "%d-byte digest: a changed digest verified", size)
	}
}
