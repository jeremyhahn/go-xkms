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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listedAttrsByCN finds the entry for cn in a ListKeys result, failing the
// test if it is absent.
func listedAttrsByCN(t *testing.T, listed []*types.KeyAttributes, cn string) *types.KeyAttributes {
	t.Helper()
	for _, ka := range listed {
		if ka.CN == cn {
			return ka
		}
	}
	t.Fatalf("ListKeys did not report %q", cn)
	return nil
}

// TestListKeys_ReportsImportedKeyExportablePolicy is the success case for
// go-xkms#932: ListKeys must read CKA_EXTRACTABLE and CKA_SENSITIVE off the
// token itself, the same source buildImportKeyTemplate wrote them to
// (pkcs11_importexport.go), rather than reporting the KeyAttributes zero
// value for every enumerated key.
//
// Before this fix ListKeys never populated Exportable or Sensitive at all, so
// every key -- imported exportable or not -- read back as Exportable=false,
// Sensitive=false. findKeyAttrs and loadStoredKeyAttrs (pkg/xkms) consume
// exactly this return value, so the defect meant ExportKey, RotateKey and
// CopyKey by CN or kid always refused an imported key that was in fact
// exportable, and never flagged one that was Sensitive.
//
// The keys here are ECDSA P-256: a P-256 PKCS8 private key is small enough to
// wrap directly under this backend's 4096-bit RSA-OAEP wrapping key (the same
// direct-OAEP path ExportKey uses), unlike an RSA private key, whose PKCS8
// encoding is too large for a single OAEP operation and needs the hybrid
// envelope this backend's ExportKey does not implement for private keys.
func TestListKeys_ReportsImportedKeyExportablePolicy(t *testing.T) {
	b := newProvisionedBackend(t, "list-keys-exportable")
	ctx := context.Background()

	cases := []struct {
		cn         string
		exportable bool
	}{
		{cn: "list-exportable-ec", exportable: true},
		{cn: "list-sealed-ec", exportable: false},
	}

	for _, tc := range cases {
		attrs := &types.KeyAttributes{
			CN:            tc.cn,
			KeyType:       backend.KEY_TYPE_TLS,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			StoreType:     backend.STORE_PKCS11,
			Exportable:    tc.exportable,
		}

		original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "generating source material for %s", tc.cn)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(original)
		require.NoError(t, err)

		params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
		require.NoError(t, err)
		wrapped := wrapAsKeyOwner(t, b, pkcs8, params)
		require.NoError(t, b.ImportKey(ctx, attrs, wrapped))
	}

	listed, err := b.ListKeys(ctx)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.cn, func(t *testing.T) {
			ka := listedAttrsByCN(t, listed, tc.cn)
			assert.Equal(t, tc.exportable, ka.Exportable,
				"ListKeys must report the CKA_EXTRACTABLE value buildImportKeyTemplate wrote")
			assert.True(t, ka.Sensitive,
				"an imported private key is unconditionally CKA_SENSITIVE")

			// This backend's ExportKey wraps a private key directly under
			// CKM_RSA_PKCS_OAEP with no hybrid fallback (unlike ImportKey), and
			// SoftHSM2 answers CKR_KEY_NOT_WRAPPABLE for any private-key
			// C_WrapKey regardless of size -- a pre-existing limitation of
			// what ExportKey implements, not something go-xkms#932 changes.
			// The property this test verifies is where a failure comes from:
			// an Exportable=true key must never be refused by the Exportable
			// policy check itself, only (if at all) by the token's own
			// wrapping mechanism.
			_, err := b.ExportKey(ctx, ka, tokenOAEPAlgorithm)
			if tc.exportable {
				assert.NotErrorIs(t, err, backend.ErrKeyNotExportable,
					"a key ListKeys reports as Exportable must clear the policy check")
			} else {
				assert.ErrorIs(t, err, backend.ErrKeyNotExportable,
					"a key ListKeys reports as sealed must be refused by policy")
			}
		})
	}
}

// TestListKeys_GeneratedKeyReportsSealedRegardlessOfRequestedExportable is the
// error-path counterpart: a key pair generated on the token is always written
// CKA_EXTRACTABLE=CK_FALSE (generatedKeyExtractable, signer_rsa.go), because
// the generate entry points take no exportability policy from the caller.
// ListKeys must report that truthfully as Exportable=false even though the
// caller's attrs asked for Exportable=true -- it must never echo the
// caller's request back as though the token had honoured it.
func TestListKeys_GeneratedKeyReportsSealedRegardlessOfRequestedExportable(t *testing.T) {
	b := newProvisionedBackend(t, "list-keys-generated-sealed")
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "list-generated-rsa",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		StoreType:     backend.STORE_PKCS11,
		Exportable:    true,
	}

	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	listed, err := b.ListKeys(ctx)
	require.NoError(t, err)

	ka := listedAttrsByCN(t, listed, attrs.CN)
	assert.False(t, ka.Exportable,
		"a generated key is sealed in the token; ListKeys must not echo the caller's request")
	assert.True(t, ka.Sensitive)

	_, err = b.ExportKey(ctx, ka, tokenOAEPAlgorithm)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable,
		"the round-tripped attributes must refuse export exactly as the token does")
}
