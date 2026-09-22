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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestGenerateKeyHonoursExportableForSymmetricKeys pins a field that was being
// dropped.
//
// buildKeyAttributes assigned Exportable at the end of the function, after the
// asymmetric parsing — and the symmetric branch returns before reaching it. Every
// symmetric key generated through this API was therefore stored non-exportable
// whatever the request said, and ExportKeyMaterial refused it.
//
// The request is the authority. PKCS#11 v3.2 Table 30 makes a secret key
// CKA_EXTRACTABLE by default, so the PKCS#11 module sends Exportable=true unless
// the application's template says CK_FALSE; dropping it made
// C_GetAttributeValue(CKA_VALUE) fail on a key whose own attributes said its
// value could be read.
func TestGenerateKeyHonoursExportableForSymmetricKeys(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	t.Run("exportable is honoured", func(t *testing.T) {
		const keyID = "exportable-secret"
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "Symmetric", Algorithm: "Symmetric",
			KeySize:    256,
			Exportable: true,
		})
		require.NoError(t, err)

		resp, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
			Backend: "software",
			KeyID:   keyID,
		})
		require.NoError(t, err, "the request asked for an exportable key, so its value must be readable")
		assert.Len(t, resp.KeyMaterial, 32)
	})

	t.Run("a key that did not ask to be exportable stays protected", func(t *testing.T) {
		const keyID = "protected-secret"
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "Symmetric", Algorithm: "Symmetric",
			KeySize:    256,
			Exportable: false,
		})
		require.NoError(t, err)

		_, err = svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
			Backend: "software",
			KeyID:   keyID,
		})
		require.Error(t, err,
			"honouring Exportable=true must not have made every key exportable")
	})

	t.Run("a protected key can still be derived from", func(t *testing.T) {
		// The two are different powers. §5.18.5 constrains the derived key's
		// sensitivity from the base key's and places no extractability
		// requirement on the base key itself.
		const keyID = "protected-derivable"
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "Symmetric", Algorithm: "Symmetric",
			KeySize: 256,
		})
		require.NoError(t, err)

		derived := deriveFromStored(t, svc, keyID, []byte("salt"), []byte("info"))
		assert.Len(t, derived, 32)
	})
}
