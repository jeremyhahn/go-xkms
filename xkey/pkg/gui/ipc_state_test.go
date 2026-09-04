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

package gui

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// testLogger returns a logger that discards output.
func stateTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newStatePWStore builds a file-backed static password store in a temp
// directory.
func newStatePWStore(t *testing.T) staticpw.Store {
	t.Helper()

	backend, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	return staticpw.NewStore(backend)
}

// newStatePINService builds a software-backed PIN service in a temp
// directory, matching what the daemon runs with the software strategy.
func newStatePINService(t *testing.T) *services.PINService {
	t.Helper()

	fileStore, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)

	pinStore, err := xkms.NewPINStoreAdapter(fileStore)
	require.NoError(t, err)

	backend, err := qrdbsdk.NewSoftwareBackend(pinStore, qrdbsdk.AutoDetectHashConfig())
	require.NoError(t, err)

	svc := services.NewPINService()
	svc.SetPINService(qrdbsdk.NewPINService(backend, stateTestLogger()))
	return svc
}

// --- PIN ---

func TestHandleStatePIN_ReportsWhetherPINsAreSetNeverTheirValues(t *testing.T) {
	pinSvc := newStatePINService(t)
	handler := &guiIPCHandler{app: &App{pinService: pinSvc, log: stateTestLogger()}}

	before, err := handler.HandleStatePIN()
	require.NoError(t, err)
	assert.False(t, before.SOPINSet)
	assert.False(t, before.UserPINSet)

	require.NoError(t, pinSvc.SetSOPIN("", "so-pin-one"))
	require.NoError(t, pinSvc.SetUserPIN("so-pin-one", "user-pin-one"))

	after, err := handler.HandleStatePIN()
	require.NoError(t, err)
	assert.True(t, after.SOPINSet, "a device with an SO PIN must not report otherwise")
	assert.True(t, after.UserPINSet)
	assert.True(t, after.Initialized)
	assert.NotEmpty(t, after.Strategy)
}

func TestHandleStatePIN_WithoutAPINServiceReportsUnavailable(t *testing.T) {
	handler := &guiIPCHandler{app: &App{log: stateTestLogger()}}

	_, err := handler.HandleStatePIN()
	require.ErrorIs(t, err, ErrStatePINUnavailable)
}

func TestHandleStatePIN_UnbackedPINServiceSurfacesAStateError(t *testing.T) {
	// A PINService with no backend wired must report a failure rather than
	// answer "no PIN set", which is the false negative this work removes.
	handler := &guiIPCHandler{app: &App{pinService: services.NewPINService(), log: stateTestLogger()}}

	_, err := handler.HandleStatePIN()
	require.ErrorIs(t, err, ipc.ErrStateOperation)
}

// --- barrier ---

func TestHandleStateBarrier_ReportsTheServiceSealState(t *testing.T) {
	svc := services.NewBarrierService(t.TempDir(), stateTestLogger())
	handler := &guiIPCHandler{app: &App{barrierService: svc, log: stateTestLogger()}}

	result, err := handler.HandleStateBarrier()
	require.NoError(t, err)
	assert.False(t, result.Initialized)
	assert.True(t, result.Sealed)
}

func TestHandleStateBarrier_WithoutABarrierServiceReportsUnavailable(t *testing.T) {
	handler := &guiIPCHandler{app: &App{log: stateTestLogger()}}

	_, err := handler.HandleStateBarrier()
	require.ErrorIs(t, err, ErrStateBarrierUnavailable)
}

// --- password store ---

func TestHandleStatePasswordStore_CountsEntriesAndNamesTheBackend(t *testing.T) {
	store := newStatePWStore(t)
	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "DatabaseProd", Password: "s3cr3t-value"}))

	svc := services.NewStaticPasswordService(store)
	handler := &guiIPCHandler{app: &App{
		staticPWService:     svc,
		staticpwStore:       store,
		staticpwBackendKind: staticPWBackendFile,
		log:                 stateTestLogger(),
	}}

	result, err := handler.HandleStatePasswordStore()
	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.False(t, result.Locked)
	assert.Equal(t, staticPWBackendFile, result.Backend)
	assert.Equal(t, 1, result.Count)
}

func TestHandleStatePasswordStore_WithoutAStoreReportsUnavailableAndLocked(t *testing.T) {
	handler := &guiIPCHandler{app: &App{log: stateTestLogger()}}

	result, err := handler.HandleStatePasswordStore()
	require.NoError(t, err)
	assert.False(t, result.Available)
	assert.True(t, result.Locked)
}

func TestHandleStatePasswordList_NeverReturnsPasswordValues(t *testing.T) {
	// The IPC socket is authenticated by filesystem permission alone. The
	// listing carries metadata so an operator can see what is stored; the
	// values stay behind the barrier.
	store := newStatePWStore(t)
	require.NoError(t, store.Add(&xkms.StaticPassword{
		Name:     "DatabaseProd",
		Title:    "Production DB",
		Username: "admin",
		Password: "s3cr3t-value",
		URL:      "https://db.example.com",
		Notes:    "rotate quarterly",
	}))

	svc := services.NewStaticPasswordService(store)
	handler := &guiIPCHandler{app: &App{
		staticPWService: svc,
		staticpwStore:   store,
		log:             stateTestLogger(),
	}}

	result, err := handler.HandleStatePasswordList()
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)

	entry := result.Entries[0]
	assert.Equal(t, "DatabaseProd", entry.Name)
	assert.Equal(t, "Production DB", entry.Title)
	assert.Equal(t, "admin", entry.Username)
	assert.Equal(t, "https://db.example.com", entry.URL)
	assert.NotEmpty(t, entry.CreatedAt)

	// The wire type has no field that could carry a secret; assert on the
	// encoded form so a future field addition breaks this test.
	assert.NotContains(t, entryFields(entry), "s3cr3t-value")
	assert.NotContains(t, entryFields(entry), "rotate quarterly")
}

func TestHandleStatePasswordList_WithoutAStoreReturnsAnEmptyList(t *testing.T) {
	handler := &guiIPCHandler{app: &App{log: stateTestLogger()}}

	result, err := handler.HandleStatePasswordList()
	require.NoError(t, err)
	assert.Empty(t, result.Entries)
}

// entryFields renders every field of an entry so a test can assert that no
// secret material appears anywhere in it.
func entryFields(entry ipc.PasswordEntryInfo) string {
	return entry.Name + "|" + entry.Title + "|" + entry.Username + "|" +
		entry.URL + "|" + entry.FolderPath + "|" + entry.CreatedAt + "|" + entry.UpdatedAt
}

// sealedPWStore is a store whose reads fail the way a sealed barrier makes
// them fail. Only List is exercised, so the embedded interface stays nil.
type sealedPWStore struct {
	staticpw.Store
}

// errBarrierSealed is the failure a sealed barrier surfaces on a read.
var errBarrierSealed = errors.New("seal: barrier is sealed")

func (sealedPWStore) List() ([]*xkms.StaticPassword, error) {
	return nil, errBarrierSealed
}

func TestHandleStatePasswordStore_SealedBarrierReportsLockedNotAnError(t *testing.T) {
	// The operator still needs to learn where the store is and why it is
	// unreadable; failing the whole query would tell them neither.
	store := sealedPWStore{}
	handler := &guiIPCHandler{app: &App{
		staticPWService:     services.NewStaticPasswordService(store),
		staticpwStore:       store,
		staticpwBackendKind: staticPWBackendBarrier,
		log:                 stateTestLogger(),
	}}

	result, err := handler.HandleStatePasswordStore()
	require.NoError(t, err)
	assert.True(t, result.Available)
	assert.True(t, result.Locked)
	assert.Equal(t, staticPWBackendBarrier, result.Backend)
	assert.Zero(t, result.Count)
}

func TestHandleStatePasswordList_SealedBarrierSurfacesAStateError(t *testing.T) {
	// Unlike the store summary, a listing has no honest degraded form: an
	// empty list would read as "no passwords stored", which is the false
	// negative this work removes.
	store := sealedPWStore{}
	handler := &guiIPCHandler{app: &App{
		staticPWService: services.NewStaticPasswordService(store),
		staticpwStore:   store,
		log:             stateTestLogger(),
	}}

	_, err := handler.HandleStatePasswordList()
	require.ErrorIs(t, err, ipc.ErrStateOperation)
}
