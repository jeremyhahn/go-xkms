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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestExportKeyMaterialRefusesSensitiveKeys covers the rule that makes
// CKA_SENSITIVE mean anything to a caller the service does not trust.
//
// A PKCS#11 module keeps CKA_SENSITIVE on its own object so it can answer
// C_GetAttributeValue without a round trip, and it decides from that copy
// whether to ask the daemon for the key's bytes. That copy is client-side
// state -- for the module in this repository it is a record in a local file --
// so a caller who can write to it can clear the flag and make the request.
// Before this rule existed the daemon had no opinion: types.KeyAttributes
// modelled Exportable and nothing else, so a key generated with the ordinary
// combination of CKA_SENSITIVE=CK_TRUE and CKA_EXTRACTABLE=CK_TRUE would have
// its plaintext handed over on request.
//
// The two cases below are the same key material distinguished only by
// Sensitive, so a regression that ignores the field fails the first subtest
// while the second keeps it honest -- refusing everything would pass the first
// on its own.
func TestExportKeyMaterialRefusesSensitiveKeys(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	t.Run("a sensitive key never yields its plaintext", func(t *testing.T) {
		const keyID = "sensitive-secret"
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "Symmetric", Algorithm: "Symmetric",
			KeySize:    256,
			Exportable: true,
			Sensitive:  true,
		})
		require.NoError(t, err)

		_, err = svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
			Backend: "software",
			KeyID:   keyID,
		})
		require.Error(t, err,
			"a key recorded sensitive must not release its plaintext even when it is also exportable")
		assert.True(t, errors.Is(err, ErrKeySensitive),
			"the refusal must name sensitivity, not be a generic export failure: %v", err)
	})

	t.Run("a non-sensitive exportable key still exports", func(t *testing.T) {
		const keyID = "plain-secret"
		_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
			KeyID:   keyID,
			Backend: "software",
			KeyType: "Symmetric", Algorithm: "Symmetric",
			KeySize:    256,
			Exportable: true,
			Sensitive:  false,
		})
		require.NoError(t, err)

		resp, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
			Backend: "software",
			KeyID:   keyID,
		})
		require.NoError(t, err,
			"refusing sensitive keys must not have made every key unexportable")
		assert.Len(t, resp.KeyMaterial, 32)
	})
}

// TestSensitiveSurvivesTheKeyRecord checks that Sensitive is actually persisted
// rather than merely honoured within the call that set it.
//
// The symmetric key ID string has no room for attributes, so exportability is
// carried in a separate versioned metadata record and everything else about the
// key is reconstructed by parsing the ID. A new attribute that is not added to
// that record round-trips as false: the generate call would look correct and
// the refusal above would still fire, because attrs is built from the request
// on that path -- but every later reader, ExportKeyMaterial included, resolves
// the key through ListKeys and would see a key that had lost its sensitivity.
func TestSensitiveSurvivesTheKeyRecord(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	const keyID = "persisted-sensitive-secret"
	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "Symmetric", Algorithm: "Symmetric",
		KeySize:    256,
		Exportable: true,
		Sensitive:  true,
	})
	require.NoError(t, err)

	b, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)

	attrs, err := findKeyAttrs(ctx, b, keyID)
	require.NoError(t, err)

	assert.True(t, attrs.Sensitive,
		"the key's own record must report it sensitive, or the refusal only works for the caller that created it")
	assert.True(t, attrs.Exportable,
		"sensitivity and exportability are independent; recording one must not clear the other")
}
