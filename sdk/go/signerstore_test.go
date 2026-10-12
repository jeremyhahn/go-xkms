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

package xkms_test

import (
	"log/slog"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkOnlyBackend is the shape of a consumer's TrustedCA key store written
// against the SDK alone: it delegates key operations to a backend it was
// given and owns its signer store. Its SignerStore method is declared with
// the SDK's SignerStorer, which is what the ServiceBackend contract requires.
type sdkOnlyBackend struct {
	xkms.ServiceBackend
	signers xkms.SignerStorer
}

func (b *sdkOnlyBackend) SignerStore() xkms.SignerStorer { return b.signers }

// Compile-time proof that an SDK-only type satisfies the full backend
// contract and can be returned from TrustedCA's per-CA key-store factory.
var (
	_ xkms.ServiceBackend               = (*sdkOnlyBackend)(nil)
	_ xkms.TrustedCAKeyStoreFactoryFunc = func(string) (xkms.ServiceBackend, error) {
		return &sdkOnlyBackend{}, nil
	}
)

func openSDKSignerStore(t *testing.T) xkms.SignerStorer {
	t.Helper()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })
	daos, err := xkms.NewBackendDAOFactory(backend)
	require.NoError(t, err)
	signers, err := xkms.NewSignerStore(slog.New(slog.DiscardHandler), daos)
	require.NoError(t, err)
	return signers
}

// A signature persisted through the SDK-built store reads back through the
// backend contract's SignerStore, and serves as the integrity-check checksum.
func TestNewSignerStore_PersistsSignaturesBehindTheBackendContract(t *testing.T) {
	var backend xkms.ServiceBackend = &sdkOnlyBackend{signers: openSDKSignerStore(t)}

	attrs := &xkms.KeyAttributes{CN: "issuing-ca"}
	opts := &xkms.SignerStoreOpts{KeyAttributes: attrs, BlobCN: "firmware.bin"}
	digest := []byte("digest-bytes")
	signature := []byte("signature-bytes")
	require.NoError(t, backend.SignerStore().SaveSignature(opts, signature, digest))

	gotDigest, gotSignature, err := backend.SignerStore().GetSignature(opts)
	require.NoError(t, err)
	assert.Equal(t, digest, gotDigest)
	assert.Equal(t, signature, gotSignature)

	checksum, err := backend.SignerStore().Checksum(&xkms.VerifyOpts{KeyAttributes: attrs, BlobCN: "firmware.bin"})
	require.NoError(t, err)
	assert.Equal(t, digest, checksum)
}

// Without a DAO factory the store is refused with the SDK's sentinel.
func TestNewSignerStore_NilDAOFactory(t *testing.T) {
	signers, err := xkms.NewSignerStore(slog.New(slog.DiscardHandler), nil)
	require.ErrorIs(t, err, xkms.ErrSignerStoreNilDAOFactory)
	assert.Nil(t, signers)
}

// A record that was never saved is reported as the SDK's not-found type, so
// a consumer can tell "no signature" from a storage failure.
func TestSignerStore_GetSignatureNotFound(t *testing.T) {
	signers := openSDKSignerStore(t)

	_, _, err := signers.GetSignature(&xkms.SignerStoreOpts{
		KeyAttributes: &xkms.KeyAttributes{CN: "issuing-ca"},
		BlobCN:        "missing.bin",
	})
	var notFound *xkms.ErrSignatureNotFound
	require.ErrorAs(t, err, &notFound)
}
