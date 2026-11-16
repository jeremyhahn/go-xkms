package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func newSinkBackend(t *testing.T) xkms.StorageBackend {
	t.Helper()
	be, err := xkms.NewMemoryBackend()
	require.NoError(t, err)
	t.Cleanup(func() { _ = be.Close() })
	return be
}

func emitN(t *testing.T, s *BarrierSink, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, s.Emit(context.Background(), xkms.QRDBNodeAuditEvent{
			Actor: "xkey", Resource: "xkey", Action: "op", Outcome: "success",
		}))
	}
}

func TestBarrierSink_ReopenLoadsAndContinuesTheChain(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	s, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	emitN(t, s, 3)
	require.NoError(t, s.VerifyChain(ctx))
	require.NoError(t, s.Close())

	s2, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()
	emitN(t, s2, 2)
	require.NoError(t, s2.VerifyChain(ctx))
	page, err := s2.Query(ctx, xkms.QRDBNodeAuditFilter{})
	require.NoError(t, err)
	assert.Len(t, page.Events, 5)
}

func TestBarrierSink_TamperedRecordBreaksTheChain(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	s, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	emitN(t, s, 3)

	raw, err := be.Get(ctx, recordKey(2))
	require.NoError(t, err)
	raw[len(raw)-2] ^= 0x01
	require.NoError(t, be.Put(ctx, recordKey(2), raw))

	var broken *ChainBrokenError
	assert.True(t, errors.As(s.VerifyChain(ctx), &broken))
	_, err = OpenBarrierSink(ctx, be, 100)
	assert.True(t, errors.As(err, &broken), "a broken chain refuses to load")
}

func TestBarrierSink_DeletedRecordBreaksTheChain(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	s, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	emitN(t, s, 3)

	require.NoError(t, be.Delete(ctx, recordKey(3)))
	var broken *ChainBrokenError
	assert.True(t, errors.As(s.VerifyChain(ctx), &broken), "a truncated tail is detected")
	require.NoError(t, be.Delete(ctx, recordKey(1)))
	assert.True(t, errors.As(s.VerifyChain(ctx), &broken), "a gap is detected")
}

func TestBarrierSink_NilBackend(t *testing.T) {
	_, err := OpenBarrierSink(context.Background(), nil, 1)
	assert.ErrorIs(t, err, ErrNilBarrierBackend)
}
