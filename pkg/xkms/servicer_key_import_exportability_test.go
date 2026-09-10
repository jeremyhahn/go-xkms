// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func boolPtr(v bool) *bool { return &v }

// TestApplyImportExportability pins the write-once defaults and that an
// explicit choice wins over them for either kind of material.
func TestApplyImportExportability(t *testing.T) {
	symmetric := func() *types.KeyAttributes {
		return &types.KeyAttributes{CN: "k", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM}
	}
	asymmetric := func() *types.KeyAttributes {
		return &types.KeyAttributes{CN: "k", KeyType: types.KeyTypeSigning}
	}
	for name, tc := range map[string]struct {
		attrs          *types.KeyAttributes
		exportable     *bool
		sensitive      bool
		wantExportable bool
	}{
		"symmetric unset defaults to exportable":      {attrs: symmetric(), wantExportable: true},
		"asymmetric unset defaults to not exportable": {attrs: asymmetric(), wantExportable: false},
		"symmetric explicit false is honoured":        {attrs: symmetric(), exportable: boolPtr(false), wantExportable: false},
		"asymmetric explicit true is honoured":        {attrs: asymmetric(), exportable: boolPtr(true), wantExportable: true},
		"sensitive is carried independently":          {attrs: symmetric(), sensitive: true, wantExportable: true},
	} {
		t.Run(name, func(t *testing.T) {
			ApplyImportExportability(tc.attrs, tc.exportable, tc.sensitive)
			assert.Equal(t, tc.wantExportable, tc.attrs.Exportable)
			assert.Equal(t, tc.sensitive, tc.attrs.Sensitive)
		})
	}
}

// TestBuildImportKeyAttributes_Exportability proves the request's choice
// reaches the attributes the backend stores, through the same builder every
// import over the service takes.
func TestBuildImportKeyAttributes_Exportability(t *testing.T) {
	unset, err := buildImportKeyAttributes(&transport.ImportKeyRequest{KeyID: "k", KeyType: "symmetric", KeySize: 256}, "software")
	require.NoError(t, err)
	assert.True(t, unset.Exportable, "a symmetric import that says nothing keeps the exportable default")

	refused, err := buildImportKeyAttributes(&transport.ImportKeyRequest{KeyID: "k", KeyType: "symmetric", KeySize: 256, Exportable: boolPtr(false), Sensitive: true}, "software")
	require.NoError(t, err)
	assert.False(t, refused.Exportable)
	assert.True(t, refused.Sensitive)

	rsa, err := buildImportKeyAttributes(&transport.ImportKeyRequest{KeyID: "k", KeyType: "rsa", KeySize: 2048, Exportable: boolPtr(true)}, "software")
	require.NoError(t, err)
	assert.True(t, rsa.Exportable, "an explicit true is honoured for asymmetric material too")
}

// importSymmetricThroughCeremony runs the BYOK ceremony against the software
// backend and imports 32 bytes of material under keyID with the given
// exportability choice.
func importSymmetricThroughCeremony(t *testing.T, svc *XKMSService, keyID string, exportable *bool, sensitive bool) []byte {
	t.Helper()
	ctx := context.Background()
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}

	params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     keyID,
		Algorithm: string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256),
		KeyType:   "symmetric",
		KeySize:   256,
	})
	require.NoError(t, err)

	wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           "software",
		KeyMaterial:       material,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: params.WrappingPublicKey,
		ImportToken:       params.ImportToken,
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "software",
		KeyID:              keyID,
		KeyType:            "symmetric",
		KeySize:            256,
		WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
		Algorithm:          wrapped.Algorithm,
		ImportToken:        params.ImportToken,
		Exportable:         exportable,
		Sensitive:          sensitive,
	})
	require.NoError(t, err)
	return material
}

// TestImportKey_NonExportableSymmetricRefusesMaterialExport is the control
// this request could not express: secret material imported with
// exportable=false stays in the backend, and the raw-material export that
// used to recover every imported symmetric key is refused.
func TestImportKey_NonExportableSymmetricRefusesMaterialExport(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	importSymmetricThroughCeremony(t, svc, "non-exportable", boolPtr(false), false)
	_, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "non-exportable"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrKeyNotExportable), "got %v", err)

	// The write-once default still stands for a request that says nothing,
	// so existing callers keep an exportable key.
	material := importSymmetricThroughCeremony(t, svc, "default-exportable", nil, false)
	export, err := svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "default-exportable"})
	require.NoError(t, err)
	assert.Equal(t, material, export.KeyMaterial)
}

// TestImportKey_SensitiveSymmetricRefusesMaterialExport proves the sensitive
// flag reaches the record: the key may exist and be exportable, and its
// plaintext is still never released.
func TestImportKey_SensitiveSymmetricRefusesMaterialExport(t *testing.T) {
	svc := setupDeriveService(t)
	importSymmetricThroughCeremony(t, svc, "sensitive", nil, true)
	_, err := svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{Backend: "software", KeyID: "sensitive"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeySensitive), "got %v", err)
}
