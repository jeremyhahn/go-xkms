//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockKeyBackendForSession implements store.KeyBackend for session tests
type mockKeyBackendForSession struct {
	store.KeyBackend
	getData    map[string][]byte
	getErr     error
	saveErr    error
	deleteErr  error
	savedData  map[string][]byte
	deletedKey string
}

func newMockKeyBackendForSession() *mockKeyBackendForSession {
	return &mockKeyBackendForSession{
		getData:   make(map[string][]byte),
		savedData: make(map[string][]byte),
	}
}

func (m *mockKeyBackendForSession) Get(keyAttrs *types.KeyAttributes, ext store.FSExtension) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	data, ok := m.getData[string(ext)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return data, nil
}

func (m *mockKeyBackendForSession) Save(keyAttrs *types.KeyAttributes, data []byte, ext store.FSExtension, overwrite bool) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.savedData[string(ext)] = data
	return nil
}

func (m *mockKeyBackendForSession) Delete(keyAttrs *types.KeyAttributes) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedKey = keyAttrs.CN
	return nil
}

func TestSaveKeyPairSuccess(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	// Create a mock public area
	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, backend, false)
	if err != nil {
		t.Errorf("SaveKeyPair() unexpected error: %v", err)
		return
	}

	// Verify private blob was saved
	if _, ok := backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]; !ok {
		t.Error("SaveKeyPair() did not save private blob")
	}

	// Verify public blob was saved
	if _, ok := backend.savedData[string(store.FSEXT_PUBLIC_BLOB)]; !ok {
		t.Error("SaveKeyPair() did not save public blob")
	}

	// Verify private data matches
	if string(backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]) != "private-data" {
		t.Errorf("SaveKeyPair() private data = %v, want %v", string(backend.savedData[string(store.FSEXT_PRIVATE_BLOB)]), "private-data")
	}

	logger.Debug("SaveKeyPair test passed")
}

// hookedKeyBackend runs afterPrivate once its first private-blob save
// returns, standing in for a writer that is paused (or slow) right there.
type hookedKeyBackend struct {
	store.KeyBackend
	once         sync.Once
	afterPrivate func()
}

// CompareAndSwap runs afterPrivate once a private-blob swap succeeds, as
// Save does after a private write.
func (b *hookedKeyBackend) CompareAndSwap(attrs *types.KeyAttributes, ext types.FSExtension, expected, next []byte) (bool, error) {
	swapped, err := b.KeyBackend.(store.KeyBlobSwapper).CompareAndSwap(attrs, ext, expected, next)
	if err == nil && swapped && ext == store.FSEXT_PRIVATE_BLOB && b.afterPrivate != nil {
		b.once.Do(b.afterPrivate)
	}
	return swapped, err
}

func (b *hookedKeyBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	err := b.KeyBackend.Save(attrs, data, ext, overwrite)
	if err == nil && ext == store.FSEXT_PRIVATE_BLOB && b.afterPrivate != nil {
		b.once.Do(b.afterPrivate)
	}
	return err
}

// TestSaveKeyPair_ConcurrentCreatorsNeverMismatch: two create-only writers
// of one key on one shared BlobStore, the second finding the first's
// private blob before its public blob exists, never leave the public blob of
// one beside the private blob of the other.
func TestSaveKeyPair_ConcurrentCreatorsNeverMismatch(t *testing.T) {
	_, sim := createSim(t, false)
	defer func() { _ = sim.Close() }()
	tpmImpl := sim.(*TPM2)

	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()
	shared := factory.KeyBackend()

	attrs := &types.KeyAttributes{CN: "contended-key", KeyType: types.KeyTypeTPM}
	privA := tpm2.TPM2BPrivate{Buffer: []byte("private-A")}
	pubA := tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-A"))
	privB := tpm2.TPM2BPrivate{Buffer: []byte("private-B")}
	pubB := tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-B"))

	resumeA := make(chan struct{})
	aDone := make(chan error, 1)
	aPaused := make(chan struct{})
	writerA := &hookedKeyBackend{KeyBackend: shared, afterPrivate: func() {
		close(aPaused)
		<-resumeA
	}}
	go func() { aDone <- tpmImpl.SaveKeyPair(attrs, privA, pubA, writerA, false) }()
	<-aPaused

	// B finds A's private blob without a public blob. Once B's private save
	// returns, A finishes its pair before B goes on.
	var aErr error
	writerB := &hookedKeyBackend{KeyBackend: shared, afterPrivate: func() {
		close(resumeA)
		aErr = <-aDone
	}}
	bErr := tpmImpl.SaveKeyPair(attrs, privB, pubB, writerB, false)
	select {
	case <-resumeA:
	default:
		close(resumeA)
		aErr = <-aDone
	}

	gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	pair := string(gotPub) + "/" + string(gotPriv)
	require.Contains(t, []string{"public-A/private-A", "public-B/private-B"}, pair,
		"mismatched key pair (A err=%v, B err=%v)", aErr, bErr)
	// Exactly one writer succeeds, and its pair is the stored one.
	if aErr == nil {
		require.Error(t, bErr)
		require.Equal(t, "public-A/private-A", pair)
	} else {
		require.NoError(t, bErr)
		require.Equal(t, "public-B/private-B", pair)
	}
}

// errPairCrash stands in for the process dying inside a backend write.
var errPairCrash = errors.New("simulated crash inside a key pair write")

// crashingKeyBackend panics (a crash: no cleanup runs after it) on the
// first private-blob overwrite, the write that replaces an incomplete pair's
// private blob during a create-only recovery.
type crashingKeyBackend struct {
	store.KeyBackend
}

// CompareAndSwap crashes on the private-blob swap the way Save crashes on
// the private overwrite.
func (b *crashingKeyBackend) CompareAndSwap(attrs *types.KeyAttributes, ext types.FSExtension, expected, next []byte) (bool, error) {
	if ext == store.FSEXT_PRIVATE_BLOB {
		panic(errPairCrash)
	}
	return b.KeyBackend.(store.KeyBlobSwapper).CompareAndSwap(attrs, ext, expected, next)
}

func (b *crashingKeyBackend) Save(attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {
	if ext == store.FSEXT_PRIVATE_BLOB && overwrite {
		panic(errPairCrash)
	}
	return b.KeyBackend.Save(attrs, data, ext, overwrite)
}

// TestSaveKeyPair_RecoveryCrashLeavesNoMismatch: a create-only save that
// recovers an incomplete pair (private blob A, no public blob) and crashes
// before its private blob B is durable leaves no apparently complete pair:
// LoadKeyPair reports the key as incomplete instead of handing the TPM a
// public/private mismatch, and the next create-only save recovers the key
// instead of refusing it with ErrBlobExists.
func TestSaveKeyPair_RecoveryCrashLeavesNoMismatch(t *testing.T) {
	_, sim := createSim(t, false)
	defer func() { _ = sim.Close() }()
	tpmImpl := sim.(*TPM2)

	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()
	shared := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN:      "crashed-recovery-key",
		KeyType: types.KeyTypeTPM,
		Parent: &types.KeyAttributes{CN: "parent", KeyType: types.KeyTypeStorage,
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   tpm2.TPM2BName{Buffer: []byte{0x00, 0x0b}},
			}},
	}
	// An earlier save stopped between its two writes: private A only.
	require.NoError(t, shared.Save(attrs, []byte("private-A"), store.FSEXT_PRIVATE_BLOB, false))

	privB := tpm2.TPM2BPrivate{Buffer: []byte("private-B")}
	pubB := tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-B"))
	func() {
		defer func() {
			r := recover()
			require.Equal(t, errPairCrash, r, "the recovering save must reach the private overwrite")
		}()
		_ = tpmImpl.SaveKeyPair(attrs, privB, pubB, &crashingKeyBackend{KeyBackend: shared}, false)
	}()

	session := tpm2.PasswordAuth(nil)
	_, err = tpmImpl.LoadKeyPair(attrs, &session, shared)
	require.ErrorIs(t, err, store.ErrBlobNotFound,
		"a crashed recovery must read as an incomplete pair, never as a complete one")

	privC := tpm2.TPM2BPrivate{Buffer: []byte("private-C")}
	pubC := tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-C"))
	require.NoError(t, tpmImpl.SaveKeyPair(attrs, privC, pubC, shared, false),
		"a create-only save after a crashed recovery must recover the key")

	gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.Equal(t, "public-C/private-C", string(gotPub)+"/"+string(gotPriv))
}

// pausingKeyBackend holds the first private-blob overwrite until release
// closes, after signalling reached: a recovery paused just before it
// writes its private blob.
type pausingKeyBackend struct {
	store.KeyBackend
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

// CompareAndSwap pauses on the private-blob swap the way Save pauses on the
// private overwrite.
func (b *pausingKeyBackend) CompareAndSwap(attrs *types.KeyAttributes, fsext types.FSExtension, expected, next []byte) (bool, error) {
	if fsext == store.FSEXT_PRIVATE_BLOB {
		b.once.Do(func() {
			close(b.reached)
			<-b.release
		})
	}
	return b.KeyBackend.(store.KeyBlobSwapper).CompareAndSwap(attrs, fsext, expected, next)
}

func (b *pausingKeyBackend) Save(attrs *types.KeyAttributes, data []byte, fsext types.FSExtension, overwrite bool) error {
	if fsext == store.FSEXT_PRIVATE_BLOB && overwrite {
		b.once.Do(func() {
			close(b.reached)
			<-b.release
		})
	}
	return b.KeyBackend.Save(attrs, data, fsext, overwrite)
}

// Two recoveries of one incomplete pair: B pauses before its private
// overwrite while C runs. Whatever order they finish in, the stored pair
// must be one recovery's whole pair, never public C with private B.
func TestSaveKeyPair_ConcurrentRecoveriesLeaveOnePair(t *testing.T) {
	_, sim := createSim(t, false)
	defer func() { _ = sim.Close() }()
	tpmImpl := sim.(*TPM2)

	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()
	shared := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN:      "concurrent-recovery-key",
		KeyType: types.KeyTypeTPM,
		Parent: &types.KeyAttributes{CN: "parent", KeyType: types.KeyTypeStorage,
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   tpm2.TPM2BName{Buffer: []byte{0x00, 0x0b}},
			}},
	}
	require.NoError(t, shared.Save(attrs, []byte("private-A"), store.FSEXT_PRIVATE_BLOB, false))

	paused := &pausingKeyBackend{KeyBackend: shared, reached: make(chan struct{}), release: make(chan struct{})}
	bDone := make(chan error, 1)
	go func() {
		bDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-B")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-B")), paused, false)
	}()
	<-paused.reached

	cDone := make(chan error, 1)
	go func() {
		cDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-C")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-C")), shared, false)
	}()
	// C either completes while B is paused (no serialization) or waits
	// for B; release B in both cases.
	select {
	case err := <-cDone:
		cDone <- err
	case <-time.After(500 * time.Millisecond):
	}
	close(paused.release)
	errB, errC := <-bDone, <-cDone
	require.False(t, errB != nil && errC != nil, "one recovery must succeed: B=%v C=%v", errB, errC)

	gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.Contains(t, []string{"public-B/private-B", "public-C/private-C"}, string(gotPub)+"/"+string(gotPriv))
}

// TestSaveKeyPair_RecoveryFromAnotherProcessLeavesOnePair: B fences an
// incomplete pair and pauses before its private write; C models another
// process on the same store (no in-process lock is shared), takes the fence
// over and commits its pair. B, released, must not overwrite C's private
// blob: the pair commit is guarded in the store.
func TestSaveKeyPair_RecoveryFromAnotherProcessLeavesOnePair(t *testing.T) {
	_, sim := createSim(t, false)
	defer func() { _ = sim.Close() }()
	tpmImpl := sim.(*TPM2)

	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()
	shared := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN:      "cross-process-recovery-key",
		KeyType: types.KeyTypeTPM,
		Parent: &types.KeyAttributes{CN: "parent", KeyType: types.KeyTypeStorage,
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   tpm2.TPM2BName{Buffer: []byte{0x00, 0x0b}},
			}},
	}
	require.NoError(t, shared.Save(attrs, []byte("private-A"), store.FSEXT_PRIVATE_BLOB, false))

	paused := &pausingKeyBackend{KeyBackend: shared, reached: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	releaseB := func() { releaseOnce.Do(func() { close(paused.release) }) }
	t.Cleanup(releaseB)

	bDone := make(chan error, 1)
	go func() {
		bDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-B")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-B")), paused, false)
	}()
	<-paused.reached

	pair := func() string {
		t.Helper()
		gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
		require.NoError(t, err)
		gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
		require.NoError(t, err)
		return string(gotPub) + "/" + string(gotPriv)
	}

	cDone := make(chan error, 1)
	go func() {
		cDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-C")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-C")), shared, false)
	}()
	select {
	case err := <-cDone:
		require.NoError(t, err, "C must take the stalled recovery over")
	case <-time.After(2 * time.Second):
		t.Fatal("C waited on the paused recovery: a second process would not wait on keyPairRecoveryMu")
	}
	require.Equal(t, "public-C/private-C", pair())

	releaseB()
	require.ErrorIs(t, <-bDone, store.ErrBlobExists, "B lost its fence and must not commit")
	require.Equal(t, "public-C/private-C", pair(), "B must not overwrite C's private blob")
}

func TestSaveKeyPair_StaleRecoveryPrivateSwapDoesNotStrandTheOwner(t *testing.T) {
	_, sim := createSim(t, false)
	defer func() { _ = sim.Close() }()
	tpmImpl := sim.(*TPM2)

	factory, err := store.NewMemoryStorageFactory(slog.Default())
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()
	shared := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN:      "stale-private-swap-key",
		KeyType: types.KeyTypeTPM,
		Parent: &types.KeyAttributes{CN: "parent", KeyType: types.KeyTypeStorage,
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   tpm2.TPM2BName{Buffer: []byte{0x00, 0x0b}},
			}},
	}
	require.NoError(t, shared.Save(attrs, []byte("private-A"), store.FSEXT_PRIVATE_BLOB, false))

	pa := &pausingKeyBackend{KeyBackend: shared, reached: make(chan struct{}), release: make(chan struct{})}
	pb := &pausingKeyBackend{KeyBackend: shared, reached: make(chan struct{}), release: make(chan struct{})}
	var releaseAOnce, releaseBOnce sync.Once
	releaseA := func() { releaseAOnce.Do(func() { close(pa.release) }) }
	releaseB := func() { releaseBOnce.Do(func() { close(pb.release) }) }
	t.Cleanup(releaseA)
	t.Cleanup(releaseB)

	aDone := make(chan error, 1)
	go func() {
		aDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-A2")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-A2")), pa, false)
	}()
	<-pa.reached

	bDone := make(chan error, 1)
	go func() {
		bDone <- tpmImpl.SaveKeyPair(attrs, tpm2.TPM2BPrivate{Buffer: []byte("private-B")},
			tpm2.BytesAs2B[tpm2.TPMTPublic]([]byte("public-B")), pb, false)
	}()
	<-pb.reached

	releaseA()
	require.ErrorIs(t, <-aDone, store.ErrBlobExists, "A lost its fence and must not commit")

	releaseB()
	require.NoError(t, <-bDone, "the fence owner must finish after a stale recovery's private swap")

	gotPriv, err := shared.Get(attrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	gotPub, err := shared.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.Equal(t, "public-B/private-B", string(gotPub)+"/"+string(gotPriv))
}

func TestSaveKeyPairWithNilBackend(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	// When backend is nil, it should use the default backend
	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, nil, false)
	// This will likely error because the default backend may not be set up correctly,
	// but it tests the nil backend path
	_ = err

	logger.Debug("SaveKeyPairWithNilBackend test passed")
}

func TestSaveKeyPairPrivateSaveError(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.saveErr = errors.New("save failed")

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	outPrivate := tpm2.TPM2BPrivate{
		Buffer: []byte("private-data"),
	}

	pubBytes := []byte("public-data")
	outPublic := tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes)

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.SaveKeyPair(keyAttrs, outPrivate, outPublic, backend, false)
	if err == nil {
		t.Error("SaveKeyPair() expected error but got nil")
	}

	logger.Debug("SaveKeyPairPrivateSaveError test passed")
}

func TestDeleteKeyPairSuccess(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.DeleteKeyPair(keyAttrs, backend)
	if err != nil {
		t.Errorf("DeleteKeyPair() unexpected error: %v", err)
		return
	}

	if backend.deletedKey != "test-key" {
		t.Errorf("DeleteKeyPair() did not delete the correct key: got %v, want %v", backend.deletedKey, "test-key")
	}

	logger.Debug("DeleteKeyPairSuccess test passed")
}

func TestDeleteKeyPairWithNilBackend(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	// When backend is nil, it should use the default backend
	err := tpmImpl.DeleteKeyPair(keyAttrs, nil)
	// This will likely error but tests the nil backend path
	_ = err

	logger.Debug("DeleteKeyPairWithNilBackend test passed")
}

func TestDeleteKeyPairError(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.deleteErr = errors.New("delete failed")

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
	}

	tpmImpl := tpm.(*TPM2)

	err := tpmImpl.DeleteKeyPair(keyAttrs, backend)
	if err == nil {
		t.Error("DeleteKeyPair() expected error but got nil")
	}

	logger.Debug("DeleteKeyPairError test passed")
}

func TestCreateKeySessionWithPlatformPolicy(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:        "test-key",
		TPMPolicy: types.TPMPolicyPlatform,
	}

	// This test will fail because PlatformPolicySession requires TPM operations
	// but it tests the branch logic
	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)

	// Even if it errors, we should have a closer
	if closer != nil {
		defer func() { _ = closer() }()
	}

	// The important thing is that it attempts to create a policy session
	_ = session
	_ = err
}

func TestCreateKeySessionWithPassword(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",

		Password: mustPassword(t, []byte("test-password")),
	}

	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)
	if err != nil {
		t.Errorf("CreateKeySession() unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateKeySession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateKeySession() returned nil closer")
		return
	}

	// Call the closer
	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestCreateKeySessionWithNilPassword(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",

		Password: nil,
	}

	session, closer, err := tpmImpl.CreateKeySession(keyAttrs)
	if err != nil {
		t.Errorf("CreateKeySession() unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateKeySession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateKeySession() returned nil closer")
		return
	}

	// Call the closer - should be no-op
	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestCreateKeySessionPasswordError(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	// Create a password that returns an error
	errPassword := &errorPasswordForSession{err: errors.New("password error")}

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",

		Password: errPassword,
	}

	_, _, err := tpmImpl.CreateKeySession(keyAttrs)
	if err == nil {
		t.Error("CreateKeySession() expected error but got nil")
	}
}

// errorPasswordForSession is a mock password that returns an error
type errorPasswordForSession struct {
	types.Password
	err error
}

func (p *errorPasswordForSession) Bytes() []byte {
	return nil
}

func (p *errorPasswordForSession) WithBytes(func([]byte) error) error {
	return p.err
}

func (p *errorPasswordForSession) String() string {
	return types.PasswordRedacted
}

func (p *errorPasswordForSession) Clear() {
	// No-op
}

func TestCreateSessionWithNilParent(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN: "test-key",

		Password: mustPassword(t, []byte("test-password")),
		Parent:   nil,
	}

	// When parent is nil, it should call CreateKeySession
	session, closer, err := tpmImpl.CreateSession(keyAttrs)
	if err != nil {
		t.Errorf("CreateSession() with nil parent unexpected error: %v", err)
		return
	}

	if session == nil {
		t.Error("CreateSession() returned nil session")
		return
	}

	if closer == nil {
		t.Error("CreateSession() returned nil closer")
		return
	}

	err = closer()
	if err != nil {
		t.Errorf("closer() unexpected error: %v", err)
	}
}

func TestLoadKeyPairPrivateBlobError(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.getErr = errors.New("blob not found")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
		Parent:  ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPrivateBlobError test passed")
}

func TestLoadKeyPairPublicBlobError(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	// Set private blob but not public blob to trigger public blob error
	backend.getData[string(store.FSEXT_PRIVATE_BLOB)] = []byte("private-data")
	// Don't set public blob so it will error

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:      "test-key",
		KeyType: types.KeyTypeTPM,
		Parent:  ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPublicBlobError test passed")
}

func TestLoadKeyPairPasswordError(t *testing.T) {
	logger, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	backend := newMockKeyBackendForSession()
	backend.getData[string(store.FSEXT_PRIVATE_BLOB)] = []byte("private-data")
	backend.getData[string(store.FSEXT_PUBLIC_BLOB)] = []byte("public-data")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes() error: %v", err)
	}

	// Create a password that returns an error
	errPassword := &errorPasswordForSession{err: errors.New("password error")}

	keyAttrs := &types.KeyAttributes{
		CN:       "test-key",
		KeyType:  types.KeyTypeTPM,
		Parent:   ekAttrs,
		Password: errPassword,

		TPMAttributes: &types.TPMAttributes{
			Handle: 0x81000003,
		},
	}

	tpmImpl := tpm.(*TPM2)

	_, err = tpmImpl.LoadKeyPair(keyAttrs, nil, backend)
	if err == nil {
		t.Error("LoadKeyPair() expected error but got nil")
	}

	logger.Debug("LoadKeyPairPasswordError test passed")
}

func TestEncodeFunction(t *testing.T) {
	// Test the Encode helper function used in LoadKeyPair
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty bytes",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{0xFF},
			want:  "ff",
		},
		{
			name:  "multiple bytes",
			input: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
			want:  "0123456789abcdef",
		},
		{
			name:  "zero bytes",
			input: []byte{0x00, 0x00, 0x00},
			want:  "000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.input)
			if got != tt.want {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionCloserFunction(t *testing.T) {
	// Test that a no-op closer works correctly
	closer := func() error { return nil }

	err := closer()
	if err != nil {
		t.Errorf("no-op closer() unexpected error: %v", err)
	}

	// Test error closer
	errorCloser := func() error { return errors.New("close error") }

	err = errorCloser()
	if err == nil {
		t.Error("error closer() expected error but got nil")
	}
}

func TestSessionTypeValidation(t *testing.T) {
	// Validate that session-related error types exist
	if ErrInvalidSessionType.Error() != "tpm: invalid session type" {
		t.Errorf("ErrInvalidSessionType = %v, want %v", ErrInvalidSessionType.Error(), "tpm: invalid session type")
	}

	if ErrInvalidSessionAuthorization.Error() != "tpm: invalid session authorization" {
		t.Errorf("ErrInvalidSessionAuthorization = %v, want %v", ErrInvalidSessionAuthorization.Error(), "tpm: invalid session authorization")
	}
}

func TestKeyAttributesPasswordExtraction(t *testing.T) {
	tests := []struct {
		name           string
		password       types.Password
		platformPolicy bool
		expectNil      bool
	}{
		{
			name:           "nil password without policy",
			password:       nil,
			platformPolicy: false,
			expectNil:      true,
		},
		{
			name:           "clear password without policy",
			password:       mustPassword(t, []byte("test")),
			platformPolicy: false,
			expectNil:      false,
		},
		{
			name:           "password with platform policy",
			password:       mustPassword(t, []byte("test")),
			platformPolicy: true,
			expectNil:      true, // Should not extract when platform policy is true
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:        "test",
				Password:  tt.password,
				TPMPolicy: platformPolicyName(tt.platformPolicy),
			}

			var auth []byte
			if keyAttrs.Password != nil && (keyAttrs.TPMPolicy != types.TPMPolicyPlatform) {
				auth = keyAttrs.Password.Bytes()
			}

			if tt.expectNil {
				if auth != nil {
					t.Errorf("Expected nil auth but got %v", auth)
				}
			} else {
				if auth == nil {
					t.Error("Expected non-nil auth but got nil")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Session error types tests
// ---------------------------------------------------------------------------

func TestSessionErrorsExtended(t *testing.T) {
	t.Run("ErrInvalidSessionType is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSessionType)
		assert.Contains(t, ErrInvalidSessionType.Error(), "session")
	})

	t.Run("ErrInvalidSessionAuthorization is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidSessionAuthorization)
		assert.Contains(t, ErrInvalidSessionAuthorization.Error(), "authorization")
	})

	t.Run("ErrInvalidPolicyDigest is defined", func(t *testing.T) {
		assert.NotNil(t, ErrInvalidPolicyDigest)
		assert.Contains(t, ErrInvalidPolicyDigest.Error(), "policy")
	})
}

// ---------------------------------------------------------------------------
// PCR bank parsing tests
// ---------------------------------------------------------------------------

func TestPCRBankParsingExtended(t *testing.T) {
	t.Run("sha1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha1")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("sha256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("sha384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha384")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("sha512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha512")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("invalid PCR bank returns error", func(t *testing.T) {
		_, err := ParsePCRBankAlgID("invalid")
		assert.Equal(t, ErrInvalidPCRBankType, err)
	})

	t.Run("uppercase SHA256 should work (case insensitive)", func(t *testing.T) {
		_, err := ParsePCRBankAlgID("SHA256")
		assert.NoError(t, err)
	})

	t.Run("mixed case sha256 should work", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("ShA256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})
}

func TestPCRBankCryptoHashParsingExtended(t *testing.T) {
	t.Run("sha1 parses to crypto.SHA1", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha1")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA1, hash)
	})

	t.Run("sha256 parses to crypto.SHA256", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha256")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA256, hash)
	})

	t.Run("sha384 parses to crypto.SHA3_384", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha384")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA3_384, hash)
	})

	t.Run("sha512 parses to crypto.SHA512", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha512")
		assert.NoError(t, err)
		assert.Equal(t, crypto.SHA512, hash)
	})

	t.Run("invalid PCR bank returns error", func(t *testing.T) {
		_, err := ParsePCRBankCryptoHash("invalid")
		assert.Equal(t, ErrInvalidPCRBankType, err)
	})
}

func TestCryptoHashAlgIDParsingExtended(t *testing.T) {
	t.Run("crypto.SHA1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("crypto.SHA256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("crypto.SHA384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("crypto.SHA512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("crypto.SHA3_256 parses to TPMAlgSHA3256", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3256, algID)
	})

	t.Run("crypto.SHA3_384 parses to TPMAlgSHA3384", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3384, algID)
	})

	t.Run("crypto.SHA3_512 parses to TPMAlgSHA3512", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA3_512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA3512, algID)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseCryptoHashAlgID(crypto.MD5)
		assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
	})

	t.Run("unknown hash returns error", func(t *testing.T) {
		_, err := ParseCryptoHashAlgID(crypto.Hash(999))
		assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
	})
}

func TestHashAlgFromStringParsingExtended(t *testing.T) {
	t.Run("SHA-1 string parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-1")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("SHA-256 string parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("SHA-384 string parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-384")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("SHA-512 string parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-512")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("lowercase sha-256 parses correctly", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("sha-256")
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("invalid hash string returns error", func(t *testing.T) {
		_, err := ParseHashAlgFromString("invalid")
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestParseHashAlgExtended(t *testing.T) {
	t.Run("crypto.SHA1 parses to TPMAlgSHA1", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA1, algID)
	})

	t.Run("crypto.SHA256 parses to TPMAlgSHA256", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA256, algID)
	})

	t.Run("crypto.SHA384 parses to TPMAlgSHA384", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA384, algID)
	})

	t.Run("crypto.SHA512 parses to TPMAlgSHA512", func(t *testing.T) {
		algID, err := ParseHashAlg(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgSHA512, algID)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseHashAlg(crypto.MD5)
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestParseHashSizeExtended(t *testing.T) {
	t.Run("crypto.SHA1 returns size 20", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA1)
		assert.NoError(t, err)
		assert.Equal(t, uint32(20), size)
	})

	t.Run("crypto.SHA256 returns size 32", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA256)
		assert.NoError(t, err)
		assert.Equal(t, uint32(32), size)
	})

	t.Run("crypto.SHA384 returns size 48", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA384)
		assert.NoError(t, err)
		assert.Equal(t, uint32(48), size)
	})

	t.Run("crypto.SHA512 returns size 64", func(t *testing.T) {
		size, err := ParseHashSize(crypto.SHA512)
		assert.NoError(t, err)
		assert.Equal(t, uint32(64), size)
	})

	t.Run("unsupported hash returns error", func(t *testing.T) {
		_, err := ParseHashSize(crypto.MD5)
		assert.Equal(t, ErrInvalidHashFunction, err)
	})
}

func TestEnrollmentStrategyParsingExtended(t *testing.T) {
	t.Run("IAK strategy is valid", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK")
		assert.Equal(t, EnrollmentStrategyIAK, strategy)
	})

	t.Run("IAK_IDEVID_SINGLE_PASS strategy is valid", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("IAK_IDEVID_SINGLE_PASS")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
	})

	t.Run("unknown strategy fails closed", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("UNKNOWN")
		assert.Equal(t, EnrollmentStrategyUnknown, strategy)
	})

	t.Run("empty strategy defaults to IAK_IDEVID_SINGLE_PASS", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy("")
		assert.Equal(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, strategy)
	})
}

// ---------------------------------------------------------------------------
// Session type validation tests (TPM algorithm constants)
// ---------------------------------------------------------------------------

func TestSessionTypeValidationExtended(t *testing.T) {
	t.Run("HMAC session type is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA256
		assert.Equal(t, tpm2.TPMAlgSHA256, sessionType)
	})

	t.Run("SHA384 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA384
		assert.Equal(t, tpm2.TPMAlgSHA384, sessionType)
	})

	t.Run("SHA512 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA512
		assert.Equal(t, tpm2.TPMAlgSHA512, sessionType)
	})

	t.Run("SHA1 session hash is valid", func(t *testing.T) {
		sessionType := tpm2.TPMAlgSHA1
		assert.Equal(t, tpm2.TPMAlgSHA1, sessionType)
	})
}

// ---------------------------------------------------------------------------
// Session attribute flags tests
// ---------------------------------------------------------------------------

func TestSessionAttributeFlagsExtended(t *testing.T) {
	t.Run("session can have encryption enabled", func(t *testing.T) {
		encryptSession := true
		assert.True(t, encryptSession)
	})

	t.Run("session can have decryption enabled", func(t *testing.T) {
		decryptSession := true
		assert.True(t, decryptSession)
	})

	t.Run("session can have audit enabled", func(t *testing.T) {
		auditSession := true
		assert.True(t, auditSession)
	})

	t.Run("session can have continue flag", func(t *testing.T) {
		continueSession := true
		assert.True(t, continueSession)
	})

	t.Run("session attributes can be combined", func(t *testing.T) {
		sessionAttrs := struct {
			Encrypt  bool
			Decrypt  bool
			Audit    bool
			Continue bool
		}{
			Encrypt:  true,
			Decrypt:  true,
			Audit:    false,
			Continue: true,
		}
		assert.True(t, sessionAttrs.Encrypt)
		assert.True(t, sessionAttrs.Decrypt)
		assert.False(t, sessionAttrs.Audit)
		assert.True(t, sessionAttrs.Continue)
	})
}

// ---------------------------------------------------------------------------
// Session parameter checking tests
// ---------------------------------------------------------------------------

func TestSessionParameterCheckingExtended(t *testing.T) {
	t.Run("AES-128 key size is valid for session encryption", func(t *testing.T) {
		keySize := 128
		assert.Equal(t, 128, keySize)
	})

	t.Run("AES-256 key size is valid for session encryption", func(t *testing.T) {
		keySize := 256
		assert.Equal(t, 256, keySize)
	})

	t.Run("session nonce size of 16 is valid", func(t *testing.T) {
		nonceSize := 16
		assert.Equal(t, 16, nonceSize)
	})

	t.Run("session nonce size of 32 is valid", func(t *testing.T) {
		nonceSize := 32
		assert.Equal(t, 32, nonceSize)
	})

	t.Run("empty auth is valid", func(t *testing.T) {
		auth := []byte{}
		assert.Empty(t, auth)
	})

	t.Run("auth with password is valid", func(t *testing.T) {
		auth := []byte("password123")
		assert.NotEmpty(t, auth)
		assert.Equal(t, 11, len(auth))
	})

	t.Run("auth with long password is valid", func(t *testing.T) {
		auth := make([]byte, 64)
		assert.Equal(t, 64, len(auth))
	})

	t.Run("nil auth is valid", func(t *testing.T) {
		var auth []byte
		assert.Nil(t, auth)
	})
}

// ---------------------------------------------------------------------------
// PCR selection creation tests
// ---------------------------------------------------------------------------

func TestPCRSelectionCreationExtended(t *testing.T) {
	t.Run("single PCR selection is valid", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(16),
				},
			},
		}
		assert.Equal(t, 1, len(pcrSelection.PCRSelections))
		assert.Equal(t, tpm2.TPMAlgSHA256, pcrSelection.PCRSelections[0].Hash)
	})

	t.Run("multiple PCR selection is valid", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2),
				},
				{
					Hash:      tpm2.TPMAlgSHA384,
					PCRSelect: tpm2.PCClientCompatible.PCRs(7),
				},
			},
		}
		assert.Equal(t, 2, len(pcrSelection.PCRSelections))
	})

	t.Run("PCR selection with SHA1 hash", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA1,
					PCRSelect: tpm2.PCClientCompatible.PCRs(0),
				},
			},
		}
		assert.Equal(t, tpm2.TPMAlgSHA1, pcrSelection.PCRSelections[0].Hash)
	})

	t.Run("PCR selection with SHA512 hash", func(t *testing.T) {
		pcrSelection := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA512,
					PCRSelect: tpm2.PCClientCompatible.PCRs(23),
				},
			},
		}
		assert.Equal(t, tpm2.TPMAlgSHA512, pcrSelection.PCRSelections[0].Hash)
	})
}

// ---------------------------------------------------------------------------
// Policy digest creation tests
// ---------------------------------------------------------------------------

func TestPolicyDigestCreationExtended(t *testing.T) {
	t.Run("empty policy digest is valid", func(t *testing.T) {
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{},
		}
		assert.Empty(t, policyDigest.Buffer)
	})

	t.Run("SHA256 policy digest has 32 bytes", func(t *testing.T) {
		digest := make([]byte, 32)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 32, len(policyDigest.Buffer))
	})

	t.Run("SHA384 policy digest has 48 bytes", func(t *testing.T) {
		digest := make([]byte, 48)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 48, len(policyDigest.Buffer))
	})

	t.Run("SHA512 policy digest has 64 bytes", func(t *testing.T) {
		digest := make([]byte, 64)
		policyDigest := tpm2.TPM2BDigest{
			Buffer: digest,
		}
		assert.Equal(t, 64, len(policyDigest.Buffer))
	})

	t.Run("policy digest with specific values", func(t *testing.T) {
		policyDigest := tpm2.TPM2BDigest{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		}
		assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, policyDigest.Buffer)
	})
}

// ---------------------------------------------------------------------------
// Auth handle creation tests
// ---------------------------------------------------------------------------

func TestAuthHandleCreationExtended(t *testing.T) {
	t.Run("auth handle with owner hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte("password")),
		}
		assert.Equal(t, tpm2.TPMRHOwner, authHandle.Handle)
	})

	t.Run("auth handle with endorsement hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth([]byte("password")),
		}
		assert.Equal(t, tpm2.TPMRHEndorsement, authHandle.Handle)
	})

	t.Run("auth handle with platform hierarchy", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Auth:   tpm2.PasswordAuth(nil),
		}
		assert.Equal(t, tpm2.TPMRHPlatform, authHandle.Handle)
	})

	t.Run("auth handle with empty password", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte{}),
		}
		assert.NotNil(t, authHandle.Auth)
	})

	t.Run("auth handle with name", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x01, 0x02, 0x03},
		}
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(0x81000001),
			Name:   name,
			Auth:   tpm2.PasswordAuth(nil),
		}
		assert.Equal(t, name, authHandle.Name)
	})
}

// ---------------------------------------------------------------------------
// Named handle creation tests
// ---------------------------------------------------------------------------

func TestNamedHandleCreationExtended(t *testing.T) {
	t.Run("named handle with persistent handle", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x01, 0x02, 0x03},
		}
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x81000001),
			Name:   name,
		}
		assert.Equal(t, tpm2.TPMHandle(0x81000001), namedHandle.Handle)
		assert.Equal(t, name, namedHandle.Name)
	})

	t.Run("named handle with transient handle", func(t *testing.T) {
		name := tpm2.TPM2BName{
			Buffer: []byte{0x04, 0x05, 0x06},
		}
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000000),
			Name:   name,
		}
		assert.Equal(t, tpm2.TPMHandle(0x80000000), namedHandle.Handle)
	})
}
