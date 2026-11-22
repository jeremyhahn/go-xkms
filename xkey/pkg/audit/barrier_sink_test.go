package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// TestBarrierSink_MigratesLegacyBackendStoreRecords: an installation the
// removed BackendStore wrote to (Entry JSON at <unix_nano>-<seq>.json under
// the audit prefix) opens, keeps those records in the chain oldest first,
// and holds no legacy key afterwards.
func TestBarrierSink_MigratesLegacyBackendStoreRecords(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	dir := filepath.Join("testdata", "legacy-backendstore")
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 2)
	// Written in reverse so the migration's ordering is what is tested.
	for i := len(files) - 1; i >= 0; i-- {
		raw, err := os.ReadFile(filepath.Join(dir, files[i].Name()))
		require.NoError(t, err)
		require.NoError(t, be.Put(ctx, files[i].Name(), raw))
	}

	s, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err, "an upgraded installation opens")
	emitN(t, s, 1)
	require.NoError(t, s.VerifyChain(ctx))
	page, err := s.Query(ctx, xkms.QRDBNodeAuditFilter{})
	require.NoError(t, err)
	require.Len(t, page.Events, 3)
	actions := map[string]bool{}
	for _, ev := range page.Events {
		actions[ev.Action] = true
	}
	assert.True(t, actions[string(OpKeyCreated)])
	assert.True(t, actions[string(OpKeyDeleted)])
	require.NoError(t, s.Close())

	keys, err := be.List(ctx, "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{recordKey(1), recordKey(2), recordKey(3)}, keys, "legacy keys are gone")

	first, err := be.Get(ctx, recordKey(1))
	require.NoError(t, err)
	assert.Contains(t, string(first), string(OpKeyCreated), "the oldest legacy record is first")

	s2, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err, "reopening after migration")
	defer func() { _ = s2.Close() }()
	page, err = s2.Query(ctx, xkms.QRDBNodeAuditFilter{})
	require.NoError(t, err)
	assert.Len(t, page.Events, 3, "migration runs once")
}

func TestBarrierSink_UndecodableLegacyRecordFailsOpen(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	require.NoError(t, be.Put(ctx, "1731000000000000000-1.json", []byte("{not json")))
	_, err := OpenBarrierSink(ctx, be, 100)
	require.Error(t, err, "a legacy record is never dropped silently")
}
