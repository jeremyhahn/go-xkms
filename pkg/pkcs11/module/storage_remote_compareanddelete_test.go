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

package module

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The remote state backend claims storage.CompareAndDeleter, and the claim is
// backed by the PKCS11StateCAD RPC: the guard is evaluated by the server where
// the writes of every host sharing the token serialise, never by a lock here.
// The shared conformance suite holds it to the same contract as every other
// backend that claims the capability.
func TestRemoteBackend_CompareAndDelete_Contract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b, _ := newRemoteBackendForTest(t)
			return b
		},
		AllowsEmptyValue: true,
	})
}

// The guarded swap stays available alongside the guarded release: the two
// capabilities are independent, and losing the swap would break the
// multi-client lockout counter.
func TestRemoteBackend_ClaimsBothGuardedCapabilities(t *testing.T) {
	var b storage.Backend = &remoteBackend{}
	assert.Implements(t, (*storage.CompareAndDeleter)(nil), b)
	assert.Implements(t, (*storage.CompareAndSwapper)(nil), b)
}

// The RPC carries the backend's namespace and the guard verbatim: a value the
// client did not observe must not release the record, and the record must be
// addressed under the (tenant, token) the backend was built for.
func TestRemoteBackend_CompareAndDelete_ForwardsNamespaceAndGuard(t *testing.T) {
	b, client := newRemoteBackendForTest(t)
	ctx := context.Background()
	cad, ok := b.(storage.CompareAndDeleter)
	require.True(t, ok)

	require.NoError(t, b.Put(ctx, "pkcs11/markers/claim", []byte("holder-A")))

	deleted, err := cad.CompareAndDelete(ctx, "pkcs11/markers/claim", []byte("holder-B"))
	require.NoError(t, err)
	assert.False(t, deleted, "a guard the caller did not observe must refuse")
	_, present := client.data[client.k("tenant-x", "tok0", "pkcs11/markers/claim")]
	assert.True(t, present, "a refusal leaves the record in place")

	deleted, err = cad.CompareAndDelete(ctx, "pkcs11/markers/claim", []byte("holder-A"))
	require.NoError(t, err)
	assert.True(t, deleted)
	_, present = client.data[client.k("tenant-x", "tok0", "pkcs11/markers/claim")]
	assert.False(t, present, "the record is released under the backend's own namespace")
}

// erroringCADClient fails the guarded delete so the error path is observable:
// the backend must surface the transport failure rather than report a refusal,
// because an error means the outcome is unknown and a refusal means it is not.
type erroringCADClient struct {
	*fakePKCS11StateClient
	err error
}

func (c *erroringCADClient) PKCS11StateCAD(_ context.Context, _ *transport.PKCS11StateCADRequest) (*transport.PKCS11StateCADResponse, error) {
	return nil, c.err
}

func TestRemoteBackend_CompareAndDelete_TransportErrorIsNotARefusal(t *testing.T) {
	errDown := errors.New("connection reset")
	client := &erroringCADClient{fakePKCS11StateClient: newFakePKCS11StateClient(), err: errDown}
	b, err := newRemoteBackend(client, "tenant-x", "tok0")
	require.NoError(t, err)
	cad, ok := b.(storage.CompareAndDeleter)
	require.True(t, ok)

	deleted, err := cad.CompareAndDelete(context.Background(), "pkcs11/markers/claim", []byte("holder-A"))
	require.ErrorIs(t, err, errDown)
	assert.False(t, deleted)
}
