//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// privateWritePausingBackend calls beforePrivateWrite once, right before the
// first blob write that replaces a private blob (an overwriting Save or a
// conditional write), and only then forwards the write.
type privateWritePausingBackend struct {
	store.KeyBackend
	once               sync.Once
	beforePrivateWrite func()
}

func (p *privateWritePausingBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	if ext == store.FSEXT_PRIVATE_BLOB && overwrite {
		p.once.Do(p.beforePrivateWrite)
	}
	return p.KeyBackend.Save(attrs, data, ext, overwrite)
}

// conditionalBlobWriter is the shape of the blob store's conditional write.
type conditionalBlobWriter interface {
	CompareAndSwap(attrs *types.KeyAttributes, ext types.FSExtension, expected, next []byte) (bool, error)
}

func (p *privateWritePausingBackend) CompareAndSwap(attrs *types.KeyAttributes, ext types.FSExtension, expected, next []byte) (bool, error) {
	cas, ok := p.KeyBackend.(conditionalBlobWriter)
	if !ok {
		return false, errors.New("test backend: wrapped store has no conditional write")
	}
	if ext == store.FSEXT_PRIVATE_BLOB {
		p.once.Do(p.beforePrivateWrite)
	}
	return cas.CompareAndSwap(attrs, ext, expected, next)
}

// createdKeyPair creates a real key for attrs in a scratch store and returns
// its two blobs.
func createdKeyPair(t *testing.T, h *simHarness, attrs *types.KeyAttributes) ([]byte, []byte) {
	t.Helper()
	scratch := newSharedBlobStore(t)
	_, err := h.TPM.CreateRSA(attrs, scratch, false)
	require.NoError(t, err)
	priv, err := scratch.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	pub, err := scratch.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	return priv, pub
}

func newSharedBlobStore(t *testing.T) store.KeyBackend {
	t.Helper()
	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = factory.Close() })
	return factory.KeyBackend()
}

// recoverInOtherProcess is process B's whole recovery of the incomplete key,
// as the shared blob store sees it: B takes A's fence over, writes its private
// blob and publishes its public blob. B runs in another process, so no lock A
// holds in its own process orders B's writes against A's.
func recoverInOtherProcess(t *testing.T, shared store.KeyBackend, attrs *types.KeyAttributes, priv, pub []byte) {
	t.Helper()
	fenceA, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.True(t, isKeyPairRecoveryFence(fenceA), "process A must hold the fence while it pauses")
	fenceB := append(append([]byte{}, keyPairRecoveryFence...), []byte("process-B")...)
	if cas, ok := shared.(conditionalBlobWriter); ok {
		swapped, err := cas.CompareAndSwap(attrs, store.FSEXT_PUBLIC_BLOB, fenceA, fenceB)
		require.NoError(t, err)
		require.True(t, swapped)
		current, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		swapped, err = cas.CompareAndSwap(attrs, store.FSEXT_PRIVATE_BLOB, current, priv)
		require.NoError(t, err)
		require.True(t, swapped)
		swapped, err = cas.CompareAndSwap(attrs, store.FSEXT_PUBLIC_BLOB, fenceB, pub)
		require.NoError(t, err)
		require.True(t, swapped)
		return
	}
	require.NoError(t, shared.Save(attrs, fenceB, store.FSEXT_PUBLIC_BLOB, true))
	require.NoError(t, shared.Save(attrs, priv, store.FSEXT_PRIVATE_BLOB, true))
	require.NoError(t, shared.Save(attrs, pub, store.FSEXT_PUBLIC_BLOB, true))
}

// Two recoverers of one incomplete key share only the blob store (separate
// processes): A installs its fence and pauses right before its private write,
// B takes the fence over and stores its whole pair, then A resumes. The stored
// pair must be B's, and it must load.
func TestSaveKeyPair_RecoverersSharingOnlyTheBlobStoreLeaveOneMatchingPair(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := signingKeyAttrs(t, h, "shared-store-recovery", x509.RSA, nil)
	privA, pubA := createdKeyPair(t, h, attrs)
	privB, pubB := createdKeyPair(t, h, attrs)

	shared := newSharedBlobStore(t)
	// An earlier save stopped between its two writes: a private blob only.
	require.NoError(t, shared.Save(attrs, []byte("private-stale"), store.FSEXT_PRIVATE_BLOB, false))

	recoverA := &privateWritePausingBackend{KeyBackend: shared, beforePrivateWrite: func() {
		recoverInOtherProcess(t, shared, attrs, privB, pubB)
	}}
	aErr := h.TPM.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: privA},
		tpm2.BytesAs2B[tpm2.TPMTPublic](pubA), recoverA, false)

	gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.Equal(t, pubB, gotPub, "process B's publication must stand (A err=%v)", aErr)
	require.Equal(t, privB, gotPriv,
		"the private blob must be the one matching the published public blob (A err=%v)", aErr)
	require.Error(t, aErr, "the recoverer that lost the fence must fail")

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, shared)
	require.NoError(t, err, "the stored pair must load")
	h.TPM.Flush(loaded.ObjectHandle)
}
