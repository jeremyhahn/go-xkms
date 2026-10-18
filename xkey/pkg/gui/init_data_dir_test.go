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

// Regression tests for the bug fixed in initializeDataDir() (Finding #10).
//
// Bug: When xkey restarted with an initialized-but-sealed barrier, the startup
// path pre-resolved and set a.dataDir (so the PIN service could locate
// data/pin/), but did NOT call initializeDataDir(). The old guard was:
//
//	if a.dataDir != "" { return ErrDataDirAlreadyInit }
//
// When the user later unsealed, PostBarrierUnseal() called initializeDataDir(),
// which immediately returned ErrDataDirAlreadyInit — so no barrier-backed
// stores were ever opened.
//
// Fix: the guard was changed to:
//
//	if a.dataDirInit { return ErrDataDirAlreadyInit }
//
// with a.dataDirInit set to true only at the successful end of the function.
// a.dataDir is now pre-set (when available) and reused rather than treated as
// an already-initialized sentinel.

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMinimalApp builds the smallest App struct that can exercise
// initializeDataDir() without touching the host or requiring hardware.
//
// It mirrors the service fields that NewApp() produces, but uses only
// in-memory and file-backed stores rooted inside a temp directory. The
// barrier service is freshly constructed (no barrier initialized), so
// GetBackend() returns nil and initializeDataDir takes the plain-file path.
func newMinimalApp(t *testing.T) *App {
	t.Helper()

	xkeyHome := t.TempDir()
	t.Setenv("XKEY_HOME", xkeyHome)

	log := slog.Default()

	// configDirPath: use a subdir inside xkeyHome so nothing escapes.
	cfgDir := filepath.Join(xkeyHome, "config")

	auditStore, err := audit.NewBackendStore(xkmssdk.NewStorageMemory(), 100, log)
	require.NoError(t, err, "audit.NewBackendStore")

	barrierSvc := services.NewBarrierService(cfgDir, log)
	pinSvc := services.NewPINService()
	pinSvc.SetBarrierService(barrierSvc)
	appLockSvc := services.NewAppLockService(pinSvc, barrierSvc)

	staticPWSvc := services.NewStaticPasswordService(nil)
	oathSvc := services.NewOATHService(nil)
	fido2Svc := services.NewFIDO2Service(nil)
	fido2DeviceSvc := services.NewFIDO2DeviceService(log)
	tpmSvc := services.NewTPMService()
	phoneSvc := services.NewPhoneService()
	trustSvc := services.NewTrustService(nil)
	oidcSvc := services.NewOIDCService(log)
	sealSvc := services.NewSealService("")
	pivSvc := services.NewPIVService(nil, "software")
	teamSvc := services.NewTeamService()
	pairingSvc := services.NewPairingService(log)
	registry := backendregistry.NewMemoryRegistry()
	keySvc := services.NewKeyService()
	autofillSvc := services.NewAutoFillService(staticPWSvc, oathSvc, appLockSvc, auditStore, log)

	// tpmAccessor with a nil-returning getter: Acquire returns ErrTPMNotAvailable,
	// so initLocalKeyStore skips the TPM wiring branch harmlessly.
	tpmAccessor := services.NewTPMAccessor(func() xkmssdk.TrustedPlatformModule {
		return nil
	})

	return &App{
		pinService:         pinSvc,
		log:                log,
		configDirPath:      cfgDir,
		config:             DefaultGUIConfig(),
		barrierService:     barrierSvc,
		oathService:        oathSvc,
		fido2Service:       fido2Svc,
		fido2DeviceService: fido2DeviceSvc,
		staticPWService:    staticPWSvc,
		teamService:        teamSvc,
		trustService:       trustSvc,
		tpmService:         tpmSvc,
		phoneService:       phoneSvc,
		oidcService:        oidcSvc,
		pivService:         pivSvc,
		sealService:        sealSvc,
		auditStore:         auditStore,
		backendRegistry:    registry,
		pairingService:     pairingSvc,
		keyService:         keySvc,
		tpmAccessor:        tpmAccessor,
		autofillService:    autofillSvc,
		sshService:         services.NewSSHService(nil),
		sshProfileService:  services.NewSSHProfileService(nil),
		sshConnectService:  services.NewSSHConnectService(),
		sshConsoleService:  services.NewSSHConsoleService(),
		sshLocalService:    services.NewSSHLocalService(),
		storageService:     services.NewStorageService(),
		agentService:       services.NewAgentService(),
		shutdownDone:       make(chan struct{}),
	}
}

// TestApp_CloseStaticPWStore_ReleasesFileBackend covers the no-barrier path of
// initializeDataDir on the Pebble engine, which refuses a second open of a
// store its own process still holds: the passwords store reopens only if
// closeStaticPWStore released the file backend the DAO store does not own.
func TestApp_CloseStaticPWStore_ReleasesFileBackend(t *testing.T) {
	app := newMinimalApp(t)
	app.storageEngineOnce.Do(func() { app.storageEngine = "pebble" })

	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.Equal(t, staticPWBackendFile, app.staticpwBackendKind,
		"precondition: with no barrier the password store must open on a file backend")

	require.NoError(t, app.closeStaticPWStore())

	reopened, err := xkmssdk.StorageOpenEngine(xkmssdk.StorageEngineConfig{
		Kind: "pebble",
		Path: filepath.Join(app.dataDir, "passwords"),
	})
	require.NoError(t, err, "the password store's backend must be released on close")
	require.NoError(t, reopened.Close())
}

// failingCloseBackend is a storage backend whose Close always fails.
type failingCloseBackend struct {
	xkmssdk.StorageBackend
}

var errBackendCloseFailed = errors.New("backend close failed")

func (failingCloseBackend) Close() error { return errBackendCloseFailed }

// TestApp_CloseStaticPWStore_ReportsBackendCloseError verifies a failure to
// release the backend reaches the shutdown step rather than being dropped,
// and that an App with no password store wired closes cleanly.
func TestApp_CloseStaticPWStore_ReportsBackendCloseError(t *testing.T) {
	app := newMinimalApp(t)
	require.NoError(t, app.closeStaticPWStore(), "nothing wired must close cleanly")

	app.staticpwBackend = failingCloseBackend{StorageBackend: xkmssdk.NewStorageMemory()}
	assert.ErrorIs(t, app.closeStaticPWStore(), errBackendCloseFailed)
}

// TestInitializeDataDir_PreSetDataDirSucceeds is the primary regression test.
//
// It simulates the sealed-barrier startup path: a.dataDir is pre-resolved and
// set (so the PIN service can find data/pin/), but a.dataDirInit remains false.
// Under the old code the subsequent call from PostBarrierUnseal() would return
// ErrDataDirAlreadyInit; under the fix it must return nil.
func TestInitializeDataDir_PreSetDataDirSucceeds(t *testing.T) {
	app := newMinimalApp(t)

	// Simulate the pre-unseal startup: dataDir is resolved and set, but
	// dataDirInit is false (stores have NOT been opened yet).
	xkeyHome := t.TempDir()
	t.Setenv("XKEY_HOME", xkeyHome)
	app.dataDir = filepath.Join(xkeyHome, "data")
	app.dataDirInit = false // explicit — this is the invariant under test

	err := app.initializeDataDir()
	assert.NoError(t, err,
		"initializeDataDir must succeed when dataDir is pre-set but dataDirInit=false")
	assert.True(t, app.dataDirInit,
		"dataDirInit must be true after successful initialization")
}

// TestInitializeDataDir_UnopenableStoresDegrade verifies that, with no
// barrier, a store whose path cannot be opened is left unset and logged
// rather than failing the data directory: the remaining stores still open
// and the directory is marked initialized.
func TestInitializeDataDir_UnopenableStoresDegrade(t *testing.T) {
	app := newMinimalApp(t)
	logs := captureLog(app)
	dir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "oath.json"), 0o700))
	for _, name := range []string{"fido2", "passwords", "teams", "trust", "oidc", "extension"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
	}
	app.dataDir = dir

	require.NoError(t, app.initializeDataDir())

	assert.True(t, app.dataDirInit)
	assert.Nil(t, app.oathStore, "an OATH file that cannot be read leaves no OATH store")
	assert.Nil(t, app.fido2Storage, "a FIDO2 path that is a file leaves no credential storage")
	assert.Nil(t, app.staticpwStore, "a password path that is a file leaves no password store")
	assert.Nil(t, app.trustStore, "a trust path that is a file leaves no trust store")
	for _, msg := range []string{
		"failed to open OATH store",
		"failed to create FIDO2 storage backend",
		"failed to create FIDO2 RP policy backend",
		"failed to create password file store",
		"failed to create team file store",
		"failed to open trust store",
		"failed to create OIDC data directory",
		"failed to create extension pairing directory",
	} {
		assert.True(t, logs.Contains(msg), "missing warning %q", msg)
	}
}

// TestInitializeDataDir_IdempotentGuard verifies the guard still works:
// calling initializeDataDir() a second time returns ErrDataDirAlreadyInit.
func TestInitializeDataDir_IdempotentGuard(t *testing.T) {
	app := newMinimalApp(t)

	// First call must succeed.
	err := app.initializeDataDir()
	require.NoError(t, err, "first call to initializeDataDir must succeed")
	require.True(t, app.dataDirInit)

	// Second call must return the sentinel error.
	err = app.initializeDataDir()
	assert.True(t, errors.Is(err, ErrDataDirAlreadyInit),
		"second call must return ErrDataDirAlreadyInit, got: %v", err)
}

// TestInitializeDataDir_FreshAppNoDataDir verifies the common case: a fresh
// App with no dataDir pre-set resolves the directory from XKEY_HOME and
// succeeds.
func TestInitializeDataDir_FreshAppNoDataDir(t *testing.T) {
	app := newMinimalApp(t) // XKEY_HOME already set to a temp dir inside newMinimalApp

	assert.Empty(t, app.dataDir, "precondition: dataDir must be empty before first call")
	assert.False(t, app.dataDirInit, "precondition: dataDirInit must be false")

	err := app.initializeDataDir()
	assert.NoError(t, err, "initializeDataDir must succeed with empty dataDir")
	assert.NotEmpty(t, app.dataDir, "dataDir must be set after initialization")
	assert.True(t, app.dataDirInit, "dataDirInit must be true after success")
}

// TestInitializeDataDir_DataDirSetDoesNotImplyInit documents the invariant
// that drove the bug: dataDir != "" alone must NOT be treated as "already
// initialized". Only dataDirInit==true signals completion.
func TestInitializeDataDir_DataDirSetDoesNotImplyInit(t *testing.T) {
	app := newMinimalApp(t)

	xkeyHome := t.TempDir()
	t.Setenv("XKEY_HOME", xkeyHome)

	// Pre-set dataDir exactly as the sealed-barrier startup path does.
	app.dataDir = filepath.Join(xkeyHome, "data")
	// dataDirInit remains false — stores are NOT yet open.

	// Must NOT return ErrDataDirAlreadyInit.
	err := app.initializeDataDir()
	assert.False(t, errors.Is(err, ErrDataDirAlreadyInit),
		"a pre-set dataDir with dataDirInit=false must not be rejected as already initialized")
}

// TestInitializeDataDir_LUKSLocked_FailsClosed_NoPlaintextWritten is the
// go-xkms#722 regression test: when a LUKS volume is configured for this
// xkey home but not mounted, initializeDataDir must refuse to open any
// store — returning the canonical xkmssdk.ErrLUKSVolumeLocked sentinel —
// rather than silently creating the data directory on the plain,
// unencrypted filesystem beneath the unmounted mount point.
func TestInitializeDataDir_LUKSLocked_FailsClosed_NoPlaintextWritten(t *testing.T) {
	app := newMinimalApp(t)

	vol, err := luks.NewVolume()
	require.NoError(t, err, "luks.NewVolume")
	require.NoError(t, os.WriteFile(vol.LUKSPath, []byte("fake luks container"), 0600))

	err = app.initializeDataDir()
	require.Error(t, err, "initializeDataDir must fail while the LUKS volume is locked")
	assert.ErrorIs(t, err, xkmssdk.ErrLUKSVolumeLocked)
	assert.False(t, app.dataDirInit, "dataDirInit must remain false while locked")

	// Nothing must have been written beneath the mount point: the data
	// subdirectory that initializeDataDir populates must not exist on the
	// plain filesystem underneath the unmounted mount point. (The mount
	// point directory itself already exists — it is XKEY_HOME, created by
	// t.TempDir() before the volume was even configured.)
	dataSubdir := filepath.Join(vol.MountPoint, "data")
	_, statErr := os.Stat(dataSubdir)
	assert.True(t, os.IsNotExist(statErr),
		"no plaintext data must be written beneath the unmounted LUKS mount point, got stat err: %v", statErr)
}

// TestInitializeDataDir_StorageServiceWired_NoLUKS_Unchanged verifies that
// wiring a.storageService does not change behavior for a home with no LUKS
// volume configured: RequireUnlocked is a no-op and initialization succeeds
// exactly as it did before go-xkms#722.
func TestInitializeDataDir_StorageServiceWired_NoLUKS_Unchanged(t *testing.T) {
	app := newMinimalApp(t)

	err := app.initializeDataDir()
	assert.NoError(t, err, "initializeDataDir must succeed unchanged when no LUKS volume is configured")
	assert.True(t, app.dataDirInit)
}
