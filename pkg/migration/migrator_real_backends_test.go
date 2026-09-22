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

package migration

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRealSoftwareBackend returns a real, independently-storaged
// software.Backend -- not a mock -- so a test built on two of them proves
// the migration ceremony against production wrap/unwrap code, not a
// hand-written stand-in for it.
func newRealSoftwareBackend(t *testing.T) types.KeyProvider {
	t.Helper()
	b, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	return b
}

// TestMigrateKeyAcrossDistinctSoftwareBackends proves a migration between
// two independent software.Backend instances -- through the public
// NewMigrator/MigrateKey path, exactly as a caller of this package uses it
// -- succeeds end to end and leaves a key that is genuinely usable on the
// destination.
//
// The two backends share no state: each has its own in-memory map of
// minted wrapping keys, so this can only pass if exportKeyTo genuinely
// wrapped the material under the DESTINATION's own import parameters
// rather than a wrapping key the source mints and tracks for itself the
// way plain ExportKey does (go-xkms#154, mirroring the identical defect
// fixed in xkms.CopyKey by go-xkms#567).
//
// MigrateKey's default (SkipVerification=false) already asks the
// destination for a Signer and exercises it against the migrated key as
// part of ValidateMigration -- that is the "usable on the destination"
// proof for a signing key, so this test relies on MigrateKey itself
// failing if that signature does not verify.
func TestMigrateKeyAcrossDistinctSoftwareBackends(t *testing.T) {
	source := newRealSoftwareBackend(t)
	dest := newRealSoftwareBackend(t)

	migrator, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = migrator.Close() }()

	attrs := &types.KeyAttributes{
		CN:            "cross-instance-migration-key",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	}

	sourcePriv, err := source.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	sourceKey := sourcePriv.(*rsa.PrivateKey)

	err = migrator.MigrateKey(context.Background(), attrs, &MigrateOptions{
		WrappingAlgorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	})
	require.NoError(t, err, "migration between two distinct software backends must succeed")

	// Belt and suspenders on top of MigrateKey's own sign-validation: the
	// destination's copy must hold the exact key material the source did.
	destPriv, err := dest.GetKey(context.Background(), attrs)
	require.NoError(t, err)
	destKey := destPriv.(*rsa.PrivateKey)
	assert.Equal(t, sourceKey.N, destKey.N,
		"the destination's copy must hold the source's key material")

	// And the destination's key must be independently usable for signing,
	// not merely present.
	signer, err := dest.Signer(context.Background(), attrs)
	require.NoError(t, err)
	digest := []byte("xkms-migration-usability-check")
	sig, err := signer.Sign(nil, digest, crypto.Hash(0))
	require.NoError(t, err, "the migrated key must be usable for signing on the destination")
	assert.NoError(t, rsa.VerifyPKCS1v15(&sourceKey.PublicKey, crypto.Hash(0), digest, sig))
}

// exportToUnsupportedSource wraps a real software.Backend so every other
// operation (GenerateKey, GetImportParameters, GetKey, ...) is genuine, but
// ExportKeyTo always refuses with backend.ErrExportToUnsupported -- the
// posture PKCS#11, TPM2 and every cloud KMS backend actually have.
type exportToUnsupportedSource struct {
	backend.ImportExportBackend
}

func (s *exportToUnsupportedSource) ExportKeyTo(_ context.Context, _ *types.KeyAttributes, _ *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return nil, backend.ErrExportToUnsupported
}

// TestMigrateKeyExportToUnsupportedLeavesDestinationUntouched proves that
// when the source backend cannot re-wrap for the destination's own import
// parameters, MigrateKey surfaces the typed refusal and the destination
// never receives the key.
func TestMigrateKeyExportToUnsupportedLeavesDestinationUntouched(t *testing.T) {
	realSource := newRealSoftwareBackend(t)
	dest := newRealSoftwareBackend(t)

	attrs := &types.KeyAttributes{
		CN:            "export-to-unsupported-key",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	}
	_, err := realSource.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	source := &exportToUnsupportedSource{ImportExportBackend: realSource.(backend.ImportExportBackend)}

	migrator, err := NewMigrator(source, dest)
	require.NoError(t, err)
	defer func() { _ = migrator.Close() }()

	err = migrator.MigrateKey(context.Background(), attrs, &MigrateOptions{
		WrappingAlgorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrExportToUnsupported), "unexpected error: %v", err)

	_, err = dest.GetKey(context.Background(), attrs)
	assert.Error(t, err, "the destination must never receive a key when the source cannot re-wrap for it")

	keys, err := dest.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys, "the destination must hold no keys at all")
}
