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

package seal

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// fakeBackendGet is a StorageBackend whose Get returns canned values; all other
// methods are nil (unused by these tests, satisfied via interface embedding).
type fakeBackendGet struct {
	qrdbsdk.StorageBackend
	val []byte
	err error
}

func (f fakeBackendGet) Get(context.Context, string) ([]byte, error) { return f.val, f.err }

func TestTenantMetadataStore_TranslatesNotFound(t *testing.T) {
	store := tenantMetadataStore{fakeBackendGet{err: storage.ErrNotFound}}

	_, err := store.Get(context.Background(), "missing")
	assert.ErrorIs(t, err, qrdbsdk.ErrSecretNotFound,
		"xkms storage.ErrNotFound must surface as go-qrdb ErrSecretNotFound")
}

func TestTenantMetadataStore_PassesThroughValueAndOtherErrors(t *testing.T) {
	// A present value is returned unchanged.
	ok := tenantMetadataStore{fakeBackendGet{val: []byte("record")}}
	v, err := ok.Get(context.Background(), "present")
	require.NoError(t, err)
	assert.Equal(t, []byte("record"), v)

	// An unrelated error is not rewritten to ErrSecretNotFound.
	sentinel := errors.New("disk exploded")
	bad := tenantMetadataStore{fakeBackendGet{err: sentinel}}
	_, err = bad.Get(context.Background(), "boom")
	assert.ErrorIs(t, err, sentinel)
	assert.NotErrorIs(t, err, qrdbsdk.ErrSecretNotFound)
}
