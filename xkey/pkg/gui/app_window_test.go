// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v2/pkg/options"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

var errWails = errors.New("wails: no display")

// recordingWindow is a windowRuntime that records the events and window
// calls the App makes, in order.
type recordingWindow struct {
	mu     sync.Mutex
	events []string
	calls  []string
}

var _ windowRuntime = (*recordingWindow)(nil)

func (w *recordingWindow) record(dst *[]string, entry string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	*dst = append(*dst, entry)
}

func (w *recordingWindow) EventsEmit(_ context.Context, eventName string, _ ...any) {
	w.record(&w.events, eventName)
}

func (w *recordingWindow) WindowShow(context.Context) { w.record(&w.calls, "show") }

func (w *recordingWindow) WindowHide(context.Context) { w.record(&w.calls, "hide") }

func (w *recordingWindow) WindowUnminimise(context.Context) { w.record(&w.calls, "unminimise") }

func (w *recordingWindow) WindowCenter(context.Context) { w.record(&w.calls, "center") }

func (w *recordingWindow) WindowSetAlwaysOnTop(_ context.Context, onTop bool) {
	if onTop {
		w.record(&w.calls, "on-top")
		return
	}
	w.record(&w.calls, "not-on-top")
}

func (w *recordingWindow) Events() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.events)
}

func (w *recordingWindow) Calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.calls)
}

// exitRecorder replaces process exit: it records each exit code without
// blocking, so Quit's five-second watchdog cannot stall a test.
func exitRecorder() (func(int), <-chan int) {
	codes := make(chan int, 2)
	return func(code int) {
		select {
		case codes <- code:
		default:
		}
	}, codes
}

// windowedApp is a fully wired App started on a recording window.
func windowedApp(t *testing.T) (*App, *recordingWindow, <-chan int) {
	t.Helper()
	app := newWiredApp(t)
	window := &recordingWindow{}
	exit, codes := exitRecorder()
	app.ui = window
	app.exit = exit
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	app.ctx = ctx
	return app, window, codes
}

func TestApp_ShowWindow_RaisesThenReleasesAlwaysOnTop(t *testing.T) {
	window := &recordingWindow{}
	app := &App{ctx: context.Background(), ui: window, log: lifecycleTestLogger()}

	app.ShowWindow()

	assert.Equal(t, []string{"unminimise", "show", "center", "on-top"}, window.Calls()[:4])
	require.Eventually(t, func() bool {
		return slices.Contains(window.Calls(), "not-on-top")
	}, 2*time.Second, 10*time.Millisecond, "always-on-top must be cleared after the window is raised")
}

func TestApp_HideWindow_HidesWindow(t *testing.T) {
	window := &recordingWindow{}
	app := &App{ctx: context.Background(), ui: window, log: lifecycleTestLogger()}

	app.HideWindow()

	assert.Equal(t, []string{"hide"}, window.Calls())
}

// The frontend's minimise-to-tray verb reaches the App's window and hides it.
func TestApp_MinimizeToTray_HidesTheWindow(t *testing.T) {
	app, window, _ := windowedApp(t)

	app.appService.MinimizeToTray()

	assert.Equal(t, []string{"hide"}, window.Calls())
}

// A browser extension's pairing request reaches the frontend as an
// extension-pairing-request event once the data directory is initialised.
func TestApp_RequestPairing_EmitsPairingRequestEvent(t *testing.T) {
	app, window, _ := windowedApp(t)
	require.NoError(t, app.initializeDataDir())

	identityKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	code, err := app.pairingService.RequestPairing(identityKey, "chrome-extension://pairing-test")
	require.NoError(t, err)
	require.NotEmpty(t, code)

	assert.Contains(t, window.Events(), string(events.EventExtensionPairingRequest))
}

// A static password past its expiry is deleted by the expiry checker that
// postDataDirStartup starts, and the deletion reaches the frontend as a
// password:expired event.
func TestApp_PostDataDirStartup_ExpiredPasswordEmitsPasswordExpired(t *testing.T) {
	app, window, _ := windowedApp(t)
	require.NoError(t, app.initializeDataDir())
	require.NotNil(t, app.staticpwStore, "precondition: initializeDataDir must wire a static password store")
	require.NoError(t, app.staticpwStore.Add(&staticpw.StaticPassword{
		Name:      "expired-entry",
		Password:  "pw",
		ExpiresAt: time.Now().Add(-time.Hour),
	}))

	app.postDataDirStartup()
	t.Cleanup(func() {
		if app.expiryChecker != nil {
			app.expiryChecker.Stop()
		}
	})
	require.NotNil(t, app.expiryChecker, "postDataDirStartup must start the expiry checker")

	expired, err := app.expiryChecker.CheckExpired()
	require.NoError(t, err)
	require.Len(t, expired, 1)
	assert.Equal(t, "expired-entry", expired[0].Name)
	assert.Contains(t, window.Events(), "password:expired")
	_, err = app.staticpwStore.Get("expired-entry")
	assert.Error(t, err, "the expired entry must be deleted from the store")
}

// Deleting a tenant on the connected server reaches the frontend as a
// tenant-deleted event.
func TestApp_DeleteTenant_EmitsTenantDeletedEvent(t *testing.T) {
	app, window, _ := windowedApp(t)
	connectWiredApp(t, app, newBackendsServer(t, http.StatusOK, `{"backends":[]}`))
	app.tenantService.SetContext(context.Background())

	require.NoError(t, app.tenantService.DeleteTenant("tenant-a"))

	assert.Contains(t, window.Events(), string(events.EventTenantDeleted))
}

func TestApp_EmitEvent_ForwardsEventType(t *testing.T) {
	window := &recordingWindow{}
	app := &App{ctx: context.Background(), ui: window, log: lifecycleTestLogger()}

	app.EmitEvent(events.NewEvent(events.EventBarrierLocked, nil))

	assert.Equal(t, []string{string(events.EventBarrierLocked)}, window.Events())
}

func TestApp_BeforeClose_AutoTrayHidesInsteadOfQuitting(t *testing.T) {
	window := &recordingWindow{}
	cfg := DefaultGUIConfig()
	cfg.AutoTray = true
	app := &App{config: cfg, ui: window, log: lifecycleTestLogger()}

	prevent := app.beforeClose(context.Background())

	assert.True(t, prevent, "closing the window with the tray enabled must not quit")
	assert.Equal(t, []string{"hide"}, window.Calls())
}

func TestApp_Quit_ShutsDownAndExitsZero(t *testing.T) {
	app, window, codes := windowedApp(t)

	app.Quit()

	assert.Equal(t, 0, <-codes, "a completed shutdown must exit with status 0")
	assert.True(t, app.trayQuit.Load(), "quit must tell beforeClose not to intercept the close")
	assert.Contains(t, window.Events(), "app:shutting_down")
	assert.Contains(t, window.Calls(), "show", "quit shows the window for the shutdown overlay")
	select {
	case <-app.shutdownDone:
	default:
		t.Fatal("quit must run the shutdown sequence before exiting")
	}
}

func TestApp_Run_HandsLifecycleHooksToWails(t *testing.T) {
	app := newWiredApp(t)
	var got *options.App
	app.runWails = func(opts *options.App) error {
		got = opts
		return nil
	}

	require.NoError(t, app.Run())

	require.NotNil(t, got)
	assert.Equal(t, "xKey", got.Title)
	assert.Equal(t, app.config.WindowWidth, got.Width)
	assert.Equal(t, app.config.WindowHeight, got.Height)
	assert.Equal(t, app.config.StartMinimized, got.StartHidden)
	assert.NotNil(t, got.OnStartup)
	assert.NotNil(t, got.OnShutdown)
	assert.NotNil(t, got.OnBeforeClose)
	assert.Contains(t, got.Bind, any(app), "the App itself must be bound to the frontend")
	assert.Contains(t, got.Bind, any(app.barrierService))
	require.NotNil(t, got.Linux)
	assert.Equal(t, "xkey", got.Linux.ProgramName)
}

func TestApp_Run_SecondCallFailsAndWailsErrorPropagates(t *testing.T) {
	app := newWiredApp(t)
	app.runWails = func(*options.App) error { return errWails }

	require.ErrorIs(t, app.Run(), errWails)
	assert.ErrorIs(t, app.Run(), ErrAlreadyRunning, "a running app must refuse a second event loop")
}

func TestApp_StartupReturningUser_AutoUnsealFailureEmitsFailedEvent(t *testing.T) {
	app, window, _ := windowedApp(t)
	app.config.AutoUnsealEnabled = true
	app.config.AutoUnsealBlobID = "missing-blob"
	app.tray = NewTrayManager(app)

	app.startupReturningUser(app.ctx)

	assert.Contains(t, window.Events(), "storage:auto_unseal_failed",
		"an auto-unseal blob that cannot be unsealed must be reported to the frontend")
	assert.NotContains(t, window.Events(), "storage:auto_unseal_success")
}
