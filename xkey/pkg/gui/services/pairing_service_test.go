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

package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// pairingEventCollector captures emitted events for test assertions.
type pairingEventCollector struct {
	mu     sync.Mutex
	events []events.Event
}

func (c *pairingEventCollector) emit(evt events.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evt)
}

func (c *pairingEventCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *pairingEventCollector) hasEventType(et events.EventType) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == et {
			return true
		}
	}
	return false
}

func (c *pairingEventCollector) lastEvent() events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return events.Event{}
	}
	return c.events[len(c.events)-1]
}

// generateTestIdentityKey creates a random Ed25519 key pair and returns
// the public key as base64.
func generateTestIdentityKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, base64.StdEncoding.EncodeToString(pub)
}

// newTestVerifier creates a PairingVerifier backed by a temp file.
func newTestVerifier(t *testing.T) *nativemsg.PairingVerifier {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "pairing.json")
	v, err := nativemsg.NewPairingVerifier(statePath)
	require.NoError(t, err)
	return v
}

// setupPairingService creates a PairingService with context and event collector.
func setupPairingService(t *testing.T) (*PairingService, *pairingEventCollector) {
	t.Helper()
	svc := NewPairingService(slog.Default())
	svc.SetContext(context.Background())
	collector := &pairingEventCollector{}
	svc.SetEventEmitter(collector.emit)
	return svc, collector
}

func TestNewPairingService(t *testing.T) {
	t.Run("returns non-nil with logger", func(t *testing.T) {
		svc := NewPairingService(slog.Default())
		require.NotNil(t, svc)
		assert.NotNil(t, svc.log)
	})

	t.Run("returns non-nil with nil logger", func(t *testing.T) {
		svc := NewPairingService(nil)
		require.NotNil(t, svc)
		assert.NotNil(t, svc.log)
	})
}

func TestPairingService_SetContext(t *testing.T) {
	svc := NewPairingService(slog.Default())
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestPairingService_SetVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	v := newTestVerifier(t)
	svc.SetVerifier(v)
	assert.Equal(t, v, svc.verifier)
}

func TestPairingService_GetPairingStatus_NoVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	status := svc.GetPairingStatus()
	require.NotNil(t, status)
	assert.False(t, status.Paired)
	assert.Empty(t, status.Origin)
	assert.Empty(t, status.PairedAt)
}

func TestPairingService_GetPairingStatus_UnpairedVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	status := svc.GetPairingStatus()
	require.NotNil(t, status)
	assert.False(t, status.Paired)
}

func TestPairingService_GetPairingStatus_Paired(t *testing.T) {
	svc, _ := setupPairingService(t)
	v := newTestVerifier(t)
	svc.SetVerifier(v)

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://test-extension-id"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	err = svc.VerifyPairingCode(keyB64, origin, code)
	require.NoError(t, err)

	status := svc.GetPairingStatus()
	require.NotNil(t, status)
	assert.True(t, status.Paired)
	assert.Equal(t, origin, status.Origin)
	assert.NotEmpty(t, status.PairedAt)
}

func TestPairingService_IsPaired_NoVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	assert.False(t, svc.IsPaired())
}

func TestPairingService_IsPaired_Unpaired(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	assert.False(t, svc.IsPaired())
}

func TestPairingService_IsPaired_AfterPairing(t *testing.T) {
	svc, _ := setupPairingService(t)
	v := newTestVerifier(t)
	svc.SetVerifier(v)

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://test-id"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)

	err = svc.VerifyPairingCode(keyB64, origin, code)
	require.NoError(t, err)

	assert.True(t, svc.IsPaired())
}

func TestPairingService_RequestPairing_NoVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	_, keyB64 := generateTestIdentityKey(t)
	_, err := svc.RequestPairing(keyB64, "chrome-extension://test")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

func TestPairingService_RequestPairing_EmptyIdentityKey(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	_, err := svc.RequestPairing("", "chrome-extension://test")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestPairingService_RequestPairing_InvalidBase64(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	_, err := svc.RequestPairing("not-valid-base64!!!", "chrome-extension://test")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestPairingService_RequestPairing_EmptyOrigin(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	_, keyB64 := generateTestIdentityKey(t)
	_, err := svc.RequestPairing(keyB64, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidOrigin)
}

func TestPairingService_RequestPairing_Success(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://abc123"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)
	assert.Len(t, code, 6)

	assert.Equal(t, 1, collector.count())
	assert.True(t, collector.hasEventType(events.EventExtensionPairingRequest))

	evt := collector.lastEvent()
	payload, ok := evt.Payload.(events.ExtensionPairingRequestPayload)
	require.True(t, ok)
	assert.Equal(t, code, payload.Code)
	assert.Equal(t, origin, payload.Origin)
}

func TestPairingService_RequestPairing_NoEmitter(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetContext(context.Background())
	svc.SetVerifier(newTestVerifier(t))

	_, keyB64 := generateTestIdentityKey(t)
	code, err := svc.RequestPairing(keyB64, "chrome-extension://test")
	require.NoError(t, err)
	assert.Len(t, code, 6)
}

func TestPairingService_VerifyPairingCode_NoVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	_, keyB64 := generateTestIdentityKey(t)
	err := svc.VerifyPairingCode(keyB64, "chrome-extension://test", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

func TestPairingService_VerifyPairingCode_EmptyIdentityKey(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	err := svc.VerifyPairingCode("", "chrome-extension://test", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestPairingService_VerifyPairingCode_EmptyOrigin(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	_, keyB64 := generateTestIdentityKey(t)
	err := svc.VerifyPairingCode(keyB64, "", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidOrigin)
}

func TestPairingService_VerifyPairingCode_EmptyCode(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	_, keyB64 := generateTestIdentityKey(t)
	err := svc.VerifyPairingCode(keyB64, "chrome-extension://test", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidCode)
}

func TestPairingService_VerifyPairingCode_InvalidBase64(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetVerifier(newTestVerifier(t))
	err := svc.VerifyPairingCode("not-base64!!!", "chrome-extension://test", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestPairingService_VerifyPairingCode_WrongCode(t *testing.T) {
	svc, _ := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://test"

	_, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)

	err = svc.VerifyPairingCode(keyB64, origin, "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingFailed)
}

func TestPairingService_VerifyPairingCode_Success(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://test-ext"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)

	err = svc.VerifyPairingCode(keyB64, origin, code)
	require.NoError(t, err)

	assert.True(t, collector.hasEventType(events.EventExtensionPaired))

	evt := collector.lastEvent()
	payload, ok := evt.Payload.(events.ExtensionPairedPayload)
	require.True(t, ok)
	assert.Equal(t, origin, payload.Origin)
}

func TestPairingService_Unpair_NoVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.Unpair("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

func TestPairingService_Unpair_NotPaired(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	err := svc.Unpair("")
	require.NoError(t, err)

	assert.True(t, collector.hasEventType(events.EventExtensionUnpaired))
	assert.False(t, svc.IsPaired())
}

func TestPairingService_Unpair_AfterPairing(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://unpair-test"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)

	err = svc.VerifyPairingCode(keyB64, origin, code)
	require.NoError(t, err)
	assert.True(t, svc.IsPaired())

	err = svc.Unpair("")
	require.NoError(t, err)
	assert.False(t, svc.IsPaired())

	assert.True(t, collector.hasEventType(events.EventExtensionUnpaired))
}

func TestPairingService_FullLifecycle(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	// Initially unpaired.
	assert.False(t, svc.IsPaired())
	status := svc.GetPairingStatus()
	assert.False(t, status.Paired)

	// Start pairing.
	_, keyB64 := generateTestIdentityKey(t)
	origin := "chrome-extension://lifecycle-test"

	code, err := svc.RequestPairing(keyB64, origin)
	require.NoError(t, err)
	assert.Len(t, code, 6)

	// Complete pairing.
	err = svc.VerifyPairingCode(keyB64, origin, code)
	require.NoError(t, err)
	assert.True(t, svc.IsPaired())

	status = svc.GetPairingStatus()
	assert.True(t, status.Paired)
	assert.Equal(t, origin, status.Origin)
	assert.NotEmpty(t, status.PairedAt)

	// Unpair.
	err = svc.Unpair("")
	require.NoError(t, err)
	assert.False(t, svc.IsPaired())

	status = svc.GetPairingStatus()
	assert.False(t, status.Paired)

	// Verify all events were emitted in order.
	assert.Equal(t, 3, collector.count())
	assert.True(t, collector.hasEventType(events.EventExtensionPairingRequest))
	assert.True(t, collector.hasEventType(events.EventExtensionPaired))
	assert.True(t, collector.hasEventType(events.EventExtensionUnpaired))
}

func TestPairingService_SetEventEmitter(t *testing.T) {
	svc := NewPairingService(slog.Default())
	assert.Nil(t, svc.emitter)

	called := false
	svc.SetEventEmitter(func(evt events.Event) {
		called = true
	})
	assert.NotNil(t, svc.emitter)

	svc.emit(events.EventExtensionUnpaired, nil)
	assert.True(t, called)
}

func TestPairingService_Emit_NilEmitter(t *testing.T) {
	svc := NewPairingService(slog.Default())
	// Should not panic when no emitter is set.
	svc.emit(events.EventExtensionUnpaired, nil)
}

// mockIPCProvider implements IPCStatusProvider for testing.
type mockIPCProvider struct {
	running    bool
	socketPath string
}

func (m *mockIPCProvider) IsRunning() bool    { return m.running }
func (m *mockIPCProvider) SocketPath() string { return m.socketPath }

func TestPairingService_SetIPCProvider(t *testing.T) {
	svc := NewPairingService(slog.Default())
	assert.Nil(t, svc.ipcProvider)

	provider := &mockIPCProvider{running: true, socketPath: "/tmp/test.sock"}
	svc.SetIPCProvider(provider)
	assert.NotNil(t, svc.ipcProvider)
}

func TestPairingService_GetExtensionFullStatus_NoProviders(t *testing.T) {
	svc := NewPairingService(slog.Default())

	status := svc.GetExtensionFullStatus()
	require.NotNil(t, status)
	assert.False(t, status.IPCRunning)
	assert.Empty(t, status.IPCSocketPath)
	assert.Empty(t, status.PairedExtensions)
	assert.Equal(t, 0, len(status.PairedExtensions))
	assert.NotNil(t, status.Manifests)
}

func TestPairingService_GetExtensionFullStatus_WithIPCProvider(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.SetIPCProvider(&mockIPCProvider{
		running:    true,
		socketPath: "/run/user/1000/xkey/xkey.sock",
	})

	status := svc.GetExtensionFullStatus()
	require.NotNil(t, status)
	assert.True(t, status.IPCRunning)
	assert.Equal(t, "/run/user/1000/xkey/xkey.sock", status.IPCSocketPath)
}

func TestPairingService_InstallManifest(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	err := svc.InstallManifest("chrome")
	require.NoError(t, err)

	// Verify the manifest file was created.
	path, err := nativemsg.ManifestPath(nativemsg.BrowserChrome)
	require.NoError(t, err)
	_, err = os.Stat(path)
	assert.NoError(t, err, "chrome manifest file should exist after install")
}

func TestPairingService_InstallManifest_CaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	err := svc.InstallManifest("Chrome")
	require.NoError(t, err)

	path, err := nativemsg.ManifestPath(nativemsg.BrowserChrome)
	require.NoError(t, err)
	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestPairingService_UninstallManifest(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	// Install first, then uninstall.
	err := svc.InstallManifest("firefox")
	require.NoError(t, err)

	path, err := nativemsg.ManifestPath(nativemsg.BrowserFirefox)
	require.NoError(t, err)
	_, err = os.Stat(path)
	require.NoError(t, err, "manifest should exist before uninstall")

	err = svc.UninstallManifest("firefox")
	require.NoError(t, err)

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "manifest should be removed after uninstall")
}

func TestPairingService_InstallManifest_InvalidBrowser(t *testing.T) {
	svc := NewPairingService(slog.Default())

	err := svc.InstallManifest("safari")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestInvalidBrowser)
}

func TestPairingService_UninstallManifest_InvalidBrowser(t *testing.T) {
	svc := NewPairingService(slog.Default())

	err := svc.UninstallManifest("opera")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestInvalidBrowser)
}

func TestPairingService_InstallManifest_All(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	err := svc.InstallManifest("all")
	require.NoError(t, err)

	// Both manifests should exist.
	chromePath, err := nativemsg.ManifestPath(nativemsg.BrowserChrome)
	require.NoError(t, err)
	_, err = os.Stat(chromePath)
	assert.NoError(t, err, "chrome manifest should exist")

	firefoxPath, err := nativemsg.ManifestPath(nativemsg.BrowserFirefox)
	require.NoError(t, err)
	_, err = os.Stat(firefoxPath)
	assert.NoError(t, err, "firefox manifest should exist")
}

func TestPairingService_UninstallManifest_All(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	// Install both first.
	require.NoError(t, svc.InstallManifest("all"))

	// Uninstall both.
	err := svc.UninstallManifest("all")
	require.NoError(t, err)

	chromePath, err := nativemsg.ManifestPath(nativemsg.BrowserChrome)
	require.NoError(t, err)
	_, err = os.Stat(chromePath)
	assert.True(t, os.IsNotExist(err), "chrome manifest should be removed")

	firefoxPath, err := nativemsg.ManifestPath(nativemsg.BrowserFirefox)
	require.NoError(t, err)
	_, err = os.Stat(firefoxPath)
	assert.True(t, os.IsNotExist(err), "firefox manifest should be removed")
}

func TestPairingService_UninstallManifest_All_NoneInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	svc := NewPairingService(slog.Default())

	// Uninstalling when none are installed should not return an error
	// (ErrManifestNotFound is silently skipped for "all").
	err := svc.UninstallManifest("all")
	assert.NoError(t, err)
}

func TestPairingService_InstallManifest_EmptyString(t *testing.T) {
	svc := NewPairingService(slog.Default())

	err := svc.InstallManifest("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestInvalidBrowser)
}

func TestPairingService_GetExtensionFullStatus_WithPairing(t *testing.T) {
	svc := NewPairingService(slog.Default())

	dir := t.TempDir()
	statePath := filepath.Join(dir, "pairing.json")
	verifier, err := nativemsg.NewPairingVerifier(statePath)
	require.NoError(t, err)
	svc.SetVerifier(verifier)

	// Pair an extension.
	pub, _, keyErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, keyErr)
	identityKeyB64 := base64.StdEncoding.EncodeToString(pub)

	code, reqErr := svc.RequestPairing(identityKeyB64, "chrome-extension://test-full-status")
	require.NoError(t, reqErr)

	verifyErr := svc.VerifyPairingCode(identityKeyB64, "chrome-extension://test-full-status", code)
	require.NoError(t, verifyErr)

	status := svc.GetExtensionFullStatus()
	require.NotNil(t, status)
	require.Len(t, status.PairedExtensions, 1)
	assert.True(t, status.PairedExtensions[0].Paired)
	assert.Equal(t, "chrome-extension://test-full-status", status.PairedExtensions[0].Origin)
	assert.NotEmpty(t, status.PairedExtensions[0].PairedAt)
}

func TestPairingService_GetPairedExtensions_Empty(t *testing.T) {
	svc := NewPairingService(slog.Default())

	// No verifier set — should return nil.
	extensions := svc.GetPairedExtensions()
	assert.Nil(t, extensions)

	// Set verifier but don't pair anything — should return empty slice.
	svc.SetVerifier(newTestVerifier(t))
	extensions = svc.GetPairedExtensions()
	assert.Empty(t, extensions)
}

func TestPairingService_GetPairedExtensions_MultiBrowser(t *testing.T) {
	svc, _ := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	// Pair Chrome extension.
	_, chromeKeyB64 := generateTestIdentityKey(t)
	chromeOrigin := "chrome-extension://chrome-test-id"
	chromeCode, err := svc.RequestPairing(chromeKeyB64, chromeOrigin)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(chromeKeyB64, chromeOrigin, chromeCode)
	require.NoError(t, err)

	// Pair Firefox extension.
	_, firefoxKeyB64 := generateTestIdentityKey(t)
	firefoxOrigin := "moz-extension://firefox-test-id"
	firefoxCode, err := svc.RequestPairing(firefoxKeyB64, firefoxOrigin)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(firefoxKeyB64, firefoxOrigin, firefoxCode)
	require.NoError(t, err)

	// GetPairedExtensions should return both.
	extensions := svc.GetPairedExtensions()
	require.Len(t, extensions, 2)

	origins := make(map[string]bool)
	for _, ext := range extensions {
		assert.True(t, ext.Paired)
		assert.NotEmpty(t, ext.PairedAt)
		origins[ext.Origin] = true
	}
	assert.True(t, origins[chromeOrigin], "chrome origin should be present")
	assert.True(t, origins[firefoxOrigin], "firefox origin should be present")
}

func TestPairingService_Unpair_SpecificOrigin(t *testing.T) {
	svc, collector := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	// Pair Chrome extension.
	_, chromeKeyB64 := generateTestIdentityKey(t)
	chromeOrigin := "chrome-extension://chrome-specific-unpair"
	chromeCode, err := svc.RequestPairing(chromeKeyB64, chromeOrigin)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(chromeKeyB64, chromeOrigin, chromeCode)
	require.NoError(t, err)

	// Pair Firefox extension.
	_, firefoxKeyB64 := generateTestIdentityKey(t)
	firefoxOrigin := "moz-extension://firefox-specific-unpair"
	firefoxCode, err := svc.RequestPairing(firefoxKeyB64, firefoxOrigin)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(firefoxKeyB64, firefoxOrigin, firefoxCode)
	require.NoError(t, err)

	// Both should be paired.
	extensions := svc.GetPairedExtensions()
	require.Len(t, extensions, 2)

	// Unpair only Chrome.
	err = svc.Unpair(chromeOrigin)
	require.NoError(t, err)

	// Only Firefox should remain.
	extensions = svc.GetPairedExtensions()
	require.Len(t, extensions, 1)
	assert.Equal(t, firefoxOrigin, extensions[0].Origin)
	assert.True(t, extensions[0].Paired)

	// Verify unpair event was emitted.
	assert.True(t, collector.hasEventType(events.EventExtensionUnpaired))
}

func TestPairingService_MultiBrowserStatus(t *testing.T) {
	svc, _ := setupPairingService(t)
	svc.SetVerifier(newTestVerifier(t))

	// Pair two extensions.
	_, keyA := generateTestIdentityKey(t)
	originA := "chrome-extension://multi-status-chrome"
	codeA, err := svc.RequestPairing(keyA, originA)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(keyA, originA, codeA)
	require.NoError(t, err)

	_, keyB := generateTestIdentityKey(t)
	originB := "moz-extension://multi-status-firefox"
	codeB, err := svc.RequestPairing(keyB, originB)
	require.NoError(t, err)
	err = svc.VerifyPairingCode(keyB, originB, codeB)
	require.NoError(t, err)

	// GetExtensionFullStatus should include both paired extensions.
	status := svc.GetExtensionFullStatus()
	require.NotNil(t, status)
	require.Len(t, status.PairedExtensions, 2)

	origins := make(map[string]bool)
	for _, ext := range status.PairedExtensions {
		assert.True(t, ext.Paired)
		assert.NotEmpty(t, ext.PairedAt)
		origins[ext.Origin] = true
	}
	assert.True(t, origins[originA], "chrome origin should be in full status")
	assert.True(t, origins[originB], "firefox origin should be in full status")
}
