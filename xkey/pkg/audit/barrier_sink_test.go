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

// TestBarrierSink_TailDeletedWhileStoppedFailsReopen proves the sealed
// checkpoint keeps the chain head across a restart: records deleted from the
// tail while the sink is closed are refused on reopen, and so is a deleted
// checkpoint.
func TestBarrierSink_TailDeletedWhileStoppedFailsReopen(t *testing.T) {
	ctx := context.Background()

	t.Run("tail deleted", func(t *testing.T) {
		be := newSinkBackend(t)
		s, err := OpenBarrierSink(ctx, be, 100)
		require.NoError(t, err)
		emitN(t, s, 4)
		require.NoError(t, s.Close())

		require.NoError(t, be.Delete(ctx, recordKey(4)))
		require.NoError(t, be.Delete(ctx, recordKey(3)))
		_, err = OpenBarrierSink(ctx, be, 100)
		var broken *ChainBrokenError
		require.ErrorAs(t, err, &broken)
		assert.Contains(t, broken.Reason, "truncated")
	})

	t.Run("checkpoint deleted", func(t *testing.T) {
		be := newSinkBackend(t)
		s, err := OpenBarrierSink(ctx, be, 100)
		require.NoError(t, err)
		emitN(t, s, 2)
		require.NoError(t, s.Close())

		require.NoError(t, be.Delete(ctx, checkpointKey))
		_, err = OpenBarrierSink(ctx, be, 100)
		var broken *ChainBrokenError
		require.ErrorAs(t, err, &broken)
		assert.Contains(t, broken.Reason, "missing")
	})

	t.Run("all records deleted", func(t *testing.T) {
		be := newSinkBackend(t)
		s, err := OpenBarrierSink(ctx, be, 100)
		require.NoError(t, err)
		emitN(t, s, 2)
		require.NoError(t, s.Close())

		require.NoError(t, be.Delete(ctx, recordKey(1)))
		require.NoError(t, be.Delete(ctx, recordKey(2)))
		_, err = OpenBarrierSink(ctx, be, 100)
		var broken *ChainBrokenError
		require.ErrorAs(t, err, &broken)
	})

	t.Run("intact chain reopens and verifies", func(t *testing.T) {
		be := newSinkBackend(t)
		s, err := OpenBarrierSink(ctx, be, 100)
		require.NoError(t, err)
		emitN(t, s, 3)
		require.NoError(t, s.Close())

		s, err = OpenBarrierSink(ctx, be, 100)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()
		require.NoError(t, s.VerifyChain(ctx))
	})
}

// TestBarrierSink_CrashBeforeCheckpointReopens proves the one repair the
// reopen makes: a record persisted whose checkpoint write was lost (a crash
// between the two writes) is accepted and the checkpoint rewritten.
func TestBarrierSink_CrashBeforeCheckpointReopens(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	s, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	emitN(t, s, 2)
	stale, err := be.Get(ctx, checkpointKey)
	require.NoError(t, err)
	emitN(t, s, 1)
	require.NoError(t, s.Close())
	require.NoError(t, be.Put(ctx, checkpointKey, stale)) // checkpoint of record 2

	s, err = OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.VerifyChain(ctx))

	// A checkpoint two records behind is not a crash: it is refused.
	require.NoError(t, s.Close())
	emitless, err := OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err)
	emitN(t, emitless, 1)
	require.NoError(t, emitless.Close())
	require.NoError(t, be.Put(ctx, checkpointKey, stale))
	_, err = OpenBarrierSink(ctx, be, 100)
	var broken *ChainBrokenError
	require.ErrorAs(t, err, &broken)
}

// checkpointFaultBackend fails every checkpoint Put once armed.
type checkpointFaultBackend struct {
	xkms.StorageBackend
	armed bool
}

func (f *checkpointFaultBackend) Put(ctx context.Context, key string, value []byte) error {
	if f.armed && key == checkpointKey {
		return errInjected
	}
	return f.StorageBackend.Put(ctx, key, value)
}

// A fresh sink seals a sequence-zero checkpoint before its first append, so
// an interruption between record 1 and its checkpoint reopens (repaired)
// instead of failing as a broken chain.
func TestBarrierSink_FirstRecordWithoutCheckpointReopens(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	fb := &checkpointFaultBackend{StorageBackend: be}
	s, err := OpenBarrierSink(ctx, fb, 100)
	require.NoError(t, err)
	exists, err := be.Exists(ctx, checkpointKey)
	require.NoError(t, err)
	require.True(t, exists, "the open seals a sequence-zero checkpoint")

	fb.armed = true
	err = s.Emit(ctx, xkms.QRDBNodeAuditEvent{
		Actor: "xkey", Resource: "xkey", Action: "first", Outcome: "success",
	})
	require.ErrorIs(t, err, errInjected, "the checkpoint Put fails after record 1")
	require.NoError(t, s.Close())
	_, err = be.Get(ctx, recordKey(1))
	require.NoError(t, err, "record 1 was written")

	s, err = OpenBarrierSink(ctx, be, 100)
	require.NoError(t, err, "the reopen repairs the one-behind checkpoint")
	defer func() { _ = s.Close() }()
	require.NoError(t, s.VerifyChain(ctx))
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
	assert.ElementsMatch(t, []string{recordKey(1), recordKey(2), recordKey(3), checkpointKey}, keys, "legacy keys are gone")

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

func TestBarrierSink_SecondWriterOnTheChainIsRefused(t *testing.T) {
	ctx := context.Background()
	be := newSinkBackend(t)
	lock := filepath.Join(t.TempDir(), "audit.lock")

	first, err := OpenBarrierSink(ctx, be, 100, WithWriterLock(lock))
	require.NoError(t, err)
	_, err = OpenBarrierSink(ctx, be, 100, WithWriterLock(lock))
	require.ErrorIs(t, err, ErrAuditWriterLocked, "two sinks must never append to one chain")

	emitN(t, first, 2)
	require.NoError(t, first.Close())

	second, err := OpenBarrierSink(ctx, be, 100, WithWriterLock(lock))
	require.NoError(t, err, "the lock is free once the first writer closes")
	defer func() { _ = second.Close() }()
	emitN(t, second, 1)
	require.NoError(t, second.VerifyChain(ctx))
	page, err := second.Query(ctx, xkms.QRDBNodeAuditFilter{})
	require.NoError(t, err)
	assert.Len(t, page.Events, 3, "no record was overwritten")
}

// faultBackend fails the record Put or the Delete numbered failPut /
// failDelete (1-based, 0 never); checkpoint Puts are not counted.
type faultBackend struct {
	xkms.StorageBackend
	puts, deletes       int
	failPut, failDelete int
}

var errInjected = errors.New("injected I/O failure")

func (f *faultBackend) Put(ctx context.Context, key string, value []byte) error {
	if key == checkpointKey {
		return f.StorageBackend.Put(ctx, key, value)
	}
	f.puts++
	if f.puts == f.failPut {
		return errInjected
	}
	return f.StorageBackend.Put(ctx, key, value)
}

func (f *faultBackend) Delete(ctx context.Context, key string) error {
	f.deletes++
	if f.deletes == f.failDelete {
		return errInjected
	}
	return f.StorageBackend.Delete(ctx, key)
}

func TestBarrierSink_InterruptedLegacyMigrationResumesWithoutDuplicates(t *testing.T) {
	for _, tc := range []struct {
		name                string
		failPut, failDelete int
	}{
		{name: "second append fails", failPut: 2},
		{name: "first delete fails", failDelete: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			be := newSinkBackend(t)
			dir := filepath.Join("testdata", "legacy-backendstore")
			files, err := os.ReadDir(dir)
			require.NoError(t, err)
			for _, f := range files {
				raw, err := os.ReadFile(filepath.Join(dir, f.Name()))
				require.NoError(t, err)
				require.NoError(t, be.Put(ctx, f.Name(), raw))
			}

			fb := &faultBackend{StorageBackend: be, failPut: tc.failPut, failDelete: tc.failDelete}
			_, err = OpenBarrierSink(ctx, fb, 100)
			require.ErrorIs(t, err, errInjected, "the interrupted migration fails the open")

			s, err := OpenBarrierSink(ctx, be, 100)
			require.NoError(t, err, "the retry opens")
			defer func() { _ = s.Close() }()
			require.NoError(t, s.VerifyChain(ctx))
			page, err := s.Query(ctx, xkms.QRDBNodeAuditFilter{})
			require.NoError(t, err)
			require.Len(t, page.Events, len(files), "each legacy record is in the chain exactly once")
			sources := map[string]bool{}
			for _, ev := range page.Events {
				src, _ := ev.Attributes[legacySourceAttr].(string)
				assert.False(t, sources[src], "legacy record %s migrated twice", src)
				sources[src] = true
			}
			keys, err := be.List(ctx, "")
			require.NoError(t, err)
			for _, k := range keys {
				_, _, legacy := parseLegacyKey(k)
				assert.False(t, legacy, "legacy key %s left behind", k)
			}
		})
	}
}
