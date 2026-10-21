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

package preseal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errNoPlatformSRK stands in for a TPM whose Platform SRK is not enrolled.
var errNoPlatformSRK = errors.New("platform SRK not enrolled")

// secretTPM is a TPM whose sealing is a software secret sealer, so the
// Store's own logic runs without the simulator. The simulator tests cover
// the real TPM path.
type secretTPM struct {
	*seal.SecretSealer
	psrkErr error
}

func (s *secretTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) {
	if s.psrkErr != nil {
		return nil, s.psrkErr
	}
	return &types.KeyAttributes{CN: "psrk"}, nil
}

// The test TPMs' sealing secrets are 32 bytes: HKDF refuses a key under 112
// bits under GODEBUG=fips140=only (SP 800-131A).
const (
	tpmSecret      = "preseal test platform srk secret"
	otherTPMSecret = "preseal test another srk secret!"
)

func newSecretTPM(t *testing.T, secret string) *secretTPM {
	t.Helper()
	sealer, err := seal.NewSecretSealer([]byte(secret))
	require.NoError(t, err)
	return &secretTPM{SecretSealer: sealer}
}

func TestNew_RejectsMissingDependencies(t *testing.T) {
	_, err := New(nil, storage.NewMemory(), nil)
	require.ErrorIs(t, err, ErrTPMRequired)

	_, err = New(newSecretTPM(t, tpmSecret), nil, nil)
	require.ErrorIs(t, err, ErrRecordsRequired)

	tpm := newSecretTPM(t, tpmSecret)
	tpm.psrkErr = errNoPlatformSRK
	_, err = New(tpm, storage.NewMemory(), nil)
	var srkErr *PlatformSRKError
	require.ErrorAs(t, err, &srkErr)
	require.ErrorIs(t, err, errNoPlatformSRK)
}

func TestOpen_RequiresDirectory(t *testing.T) {
	_, err := Open(newSecretTPM(t, tpmSecret), "", nil)
	require.ErrorIs(t, err, ErrDirRequired)
}

func TestOpen_ClosesRecordsWhenTheTPMIsUnusable(t *testing.T) {
	tpm := newSecretTPM(t, tpmSecret)
	tpm.psrkErr = errNoPlatformSRK
	_, err := Open(tpm, t.TempDir(), nil)
	var srkErr *PlatformSRKError
	require.ErrorAs(t, err, &srkErr)
}

func TestStore_PutGetRoundTripsAndPersists(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tpm := newSecretTPM(t, tpmSecret)

	store, err := Open(tpm, dir, nil)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, PKCS11PIN, []byte("1234")))
	require.NoError(t, store.Put(ctx, PKCS11PIN, []byte("5678")), "a second Put replaces the secret")
	require.NoError(t, store.Close())

	reopened, err := Open(tpm, dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	got, err := reopened.Get(ctx, PKCS11PIN)
	require.NoError(t, err)
	require.Equal(t, []byte("5678"), got)
}

func TestStore_GetReportsTypedFailures(t *testing.T) {
	ctx := context.Background()
	records := storage.NewMemory()
	store, err := New(newSecretTPM(t, tpmSecret), records, nil)
	require.NoError(t, err)

	var notFound *NotFoundError
	_, err = store.Get(ctx, PKCS11PIN)
	require.ErrorAs(t, err, &notFound)
	require.Equal(t, PKCS11PIN, notFound.Name)

	require.NoError(t, store.Put(ctx, PKCS11PIN, []byte("1234")))
	other, err := New(newSecretTPM(t, otherTPMSecret), records, nil)
	require.NoError(t, err)
	var refused *RefusedError
	_, err = other.Get(ctx, PKCS11PIN)
	require.ErrorAs(t, err, &refused, "a record sealed by another TPM must be refused")

	require.NoError(t, records.Put(ctx, "platform-store/garbled", []byte("not a sealed record")))
	var unsealErr *UnsealError
	_, err = store.Get(ctx, "garbled")
	require.ErrorAs(t, err, &unsealErr)
}

func TestStore_PutReportsTypedFailures(t *testing.T) {
	ctx := context.Background()
	store, err := New(newSecretTPM(t, tpmSecret), storage.NewMemory(), nil)
	require.NoError(t, err)

	var empty *EmptySecretError
	require.ErrorAs(t, store.Put(ctx, PKCS11PIN, nil), &empty)

	var sealErr *SealError
	require.ErrorAs(t, store.Put(ctx, " ", []byte("1234")), &sealErr)
	require.ErrorIs(t, sealErr, seal.ErrInvalidSecretName)
}
