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

package secretservice

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// errStoreUnavailable is injected to exercise store failure handling.
var errStoreUnavailable = errors.New("password store unavailable")

// newLoopbackBus returns a *dbus.Conn wired to an in-process peer that drains
// everything the daemon writes. This lets the D-Bus object export and signal
// emission paths run without a session bus. The returned close function tears
// the pipe down.
// testSender is the D-Bus unique connection name a test acts under. The
// Secret Service API records it as the session's ClientPath, so it has to be a
// realistic bus name rather than an empty string -- an empty sender would let a
// regression that drops the sender through go unnoticed.
const testSender = dbus.Sender(":1.42")

func newLoopbackBus(t *testing.T) (*dbus.Conn, func()) {
	t.Helper()

	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.Discard, server)
	}()

	conn, err := dbus.NewConn(client)
	require.NoError(t, err)

	var once sync.Once
	closePeer := func() {
		once.Do(func() {
			_ = server.Close()
			_ = client.Close()
			wg.Wait()
		})
	}
	t.Cleanup(func() {
		closePeer()
		_ = conn.Close()
	})

	return conn, closePeer
}

// busDaemon pairs a daemon with the teardown hook for its loopback bus.
type busDaemon struct {
	*Daemon
	closePeer func()
}

// newBusDaemon builds a daemon with an in-process bus connection attached.
func newBusDaemon(t *testing.T, store xkms.StaticPasswordStore) *busDaemon {
	t.Helper()

	d, err := NewDaemon(store, DefaultConfig(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	conn, closePeer := newLoopbackBus(t)
	d.conn = conn

	return &busDaemon{Daemon: d, closePeer: closePeer}
}

// TestDaemon_ExportObjects verifies the Secret Service object and its
// introspection data are exported on the connection. A failure here means no
// client (gnome-keyring consumers, libsecret) could bind to the service.
func TestDaemon_ExportObjects(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	require.NoError(t, d.exportObjects())

	// Exporting again must remain idempotent: the daemon re-registers the same
	// paths on reconnect.
	require.NoError(t, d.exportObjects())
}

// TestDaemon_OpenSession_Plain covers the unencrypted session algorithm.
func TestDaemon_OpenSession_Plain(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)

	output, path, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	assert.NotEqual(t, dbus.ObjectPath("/"), path)
	assert.Equal(t, "", output.Value())

	sess, ok := d.getSession(path)
	require.True(t, ok, "the session must be registered under the returned path")
	assert.Equal(t, AlgorithmPlain, sess.Algorithm)
	assert.Empty(t, sess.AESKey, "a plain session must not derive an AES key")

	entries := auditLog.recorded()
	require.Len(t, entries, 1)
	assert.Equal(t, audit.OpSecretServiceSessionOpened, entries[0].Operation)
	assert.True(t, entries[0].Success)

	// Each OpenSession must get a distinct path.
	_, second, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	assert.NotEqual(t, path, second)
}

// TestDaemon_OpenSession_DH performs the real Diffie-Hellman handshake a
// libsecret client would perform and verifies both sides derive the same AES
// key by round-tripping a secret through GetSecrets.
func TestDaemon_OpenSession_DH(t *testing.T) {
	store := newMemoryStore()
	require.NoError(t, store.Add(&xkms.StaticPassword{
		Name:     "github",
		Username: "alice",
		Password: "s3cret-value",
	}))

	d := newBusDaemon(t, store)

	clientKeys, err := GenerateDHKeyPair()
	require.NoError(t, err)

	output, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmDH,
		dbus.MakeVariant(PublicKeyToBytes(clientKeys.Public)))
	require.Nil(t, dbusErr)

	serverPubBytes, ok := output.Value().([]byte)
	require.True(t, ok, "the DH response must carry the server's public key")

	sess, ok := d.getSession(sessionPath)
	require.True(t, ok)
	assert.Equal(t, AlgorithmDH, sess.Algorithm)
	require.NotEmpty(t, sess.AESKey, "a DH session must derive an AES key")

	// Derive the same key on the client side.
	shared := ComputeSharedSecret(clientKeys.Private, PublicKeyFromBytes(serverPubBytes))
	clientKey := DeriveAESKey(shared)
	assert.Equal(t, sess.AESKey, clientKey, "both peers must derive the same session key")

	// Fetch the secret and decrypt it with the client-derived key.
	pw, err := store.Get("github")
	require.NoError(t, err)
	itemPath := d.mapper.ItemPathFromPassword(d.mapper.CollectionPathFromFolder(""), pw.ID)

	secrets, dbusErr := d.GetSecrets([]dbus.ObjectPath{itemPath}, sessionPath)
	require.Nil(t, dbusErr)
	require.Len(t, secrets, 1)

	secret := secrets[itemPath]
	assert.NotEqual(t, []byte("s3cret-value"), secret.Value, "the secret must be encrypted in a DH session")

	plaintext, err := NewSessionCryptoFromKey(clientKey).Decrypt(secret.Parameters, secret.Value)
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", string(plaintext))
}

func TestDaemon_OpenSession_UnsupportedAlgorithm(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)

	output, path, dbusErr := d.OpenSession(testSender, "rot13", dbus.MakeVariant(""))
	require.NotNil(t, dbusErr)
	assert.Equal(t, dbus.ObjectPath("/"), path)
	assert.Nil(t, output.Value())
	assert.Contains(t, dbusErr.Error(), ErrInvalidAlgorithm.Error())

	assert.Empty(t, d.sessions, "a rejected algorithm must not create a session")

	entries := auditLog.recorded()
	require.Len(t, entries, 1)
	assert.False(t, entries[0].Success)
}

func TestDaemon_OpenSession_DHWithNonBinaryInput(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	// A client that sends a string instead of a byte array must be rejected
	// rather than crashing the daemon.
	_, path, dbusErr := d.OpenSession(testSender, AlgorithmDH, dbus.MakeVariant("not-bytes"))
	require.NotNil(t, dbusErr)
	assert.Equal(t, dbus.ObjectPath("/"), path)
	assert.Empty(t, d.sessions)
}

func TestDaemon_CreateCollection_EmitsSignal(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	tests := []struct {
		name       string
		properties map[string]dbus.Variant
		alias      string
		wantFolder string
	}{
		{
			name:       "alias maps to the default folder",
			alias:      DefaultCollection,
			wantFolder: DefaultConfig().DefaultCollectionFolder,
		},
		{
			name:       "label is used when no alias is given",
			properties: map[string]dbus.Variant{"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Work")},
			wantFolder: "Work",
		},
		{
			name:       "non-string label is ignored",
			properties: map[string]dbus.Variant{"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant(42)},
			wantFolder: "",
		},
		{
			name:       "no alias and no label falls back to the root folder",
			wantFolder: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collectionPath, promptPath, dbusErr := d.CreateCollection(tt.properties, tt.alias)
			require.Nil(t, dbusErr)
			assert.Equal(t, dbus.ObjectPath("/"), promptPath, "creation must not require a prompt")
			assert.Equal(t, d.mapper.CollectionPathFromFolder(tt.wantFolder), collectionPath)
		})
	}
}

func TestDaemon_SearchItems_StoreFailure(t *testing.T) {
	d := newBusDaemon(t, &failingStore{})

	auditLog := &recordingAudit{}
	d.SetAuditLogger(auditLog)

	unlocked, locked, dbusErr := d.SearchItems(map[string]string{"service": "example.com"})
	require.NotNil(t, dbusErr)
	assert.Nil(t, unlocked)
	assert.Nil(t, locked)

	entries := auditLog.recorded()
	require.Len(t, entries, 1)
	assert.False(t, entries[0].Success)
	assert.Contains(t, entries[0].Error, errStoreUnavailable.Error())
}

func TestDaemon_Collections_StoreFailure(t *testing.T) {
	d := newBusDaemon(t, &failingStore{})

	collections, dbusErr := d.Collections()
	require.NotNil(t, dbusErr)
	assert.Nil(t, collections)
}

func TestDaemon_GetSecrets_SkipsUnusableItems(t *testing.T) {
	store := newMemoryStore()
	require.NoError(t, store.Add(&xkms.StaticPassword{Name: "github", Password: "s3cret"}))

	d := newBusDaemon(t, store)

	_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)

	pw, err := store.Get("github")
	require.NoError(t, err)
	collectionPath := d.mapper.CollectionPathFromFolder("")
	goodPath := d.mapper.ItemPathFromPassword(collectionPath, pw.ID)

	items := []dbus.ObjectPath{
		goodPath,
		"/malformed",                 // no hex-decodable item segment
		collectionPath + "/deadbeef", // decodes but is not a known password
	}

	secrets, dbusErr := d.GetSecrets(items, sessionPath)
	require.Nil(t, dbusErr)
	require.Len(t, secrets, 1, "unusable items must be skipped, not fail the whole call")

	secret := secrets[goodPath]
	assert.Equal(t, []byte("s3cret"), secret.Value, "a plain session returns the password verbatim")
	assert.Empty(t, secret.Parameters)
	assert.Equal(t, sessionPath, secret.Session)
}

func TestDaemon_GetSecrets_UnknownSession(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	secrets, dbusErr := d.GetSecrets([]dbus.ObjectPath{"/org/freedesktop/secrets/collection/login/00"}, "/no/such/session")
	require.NotNil(t, dbusErr)
	assert.Nil(t, secrets)
	assert.Contains(t, dbusErr.Error(), ErrSessionNotFound.Error())
}

// TestDaemon_Start_DBusUnavailable verifies Start fails cleanly (and does not
// mark itself running) when no bus is reachable.
func TestDaemon_Start_DBusUnavailable(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/xkey-test-bus")
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/xkey-test-bus")

	for _, bus := range []string{"session", "system"} {
		t.Run(bus, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Bus = bus

			d, err := NewDaemon(newMemoryStore(), cfg, slog.New(slog.DiscardHandler))
			require.NoError(t, err)

			assert.ErrorIs(t, d.Start(), ErrDBusUnavailable)
			assert.False(t, d.IsRunning())
		})
	}
}

// TestDaemon_Stop_ReleasesConnection verifies Stop tears down sessions and the
// bus connection even when releasing the well-known name fails (which is what
// happens when the bus has already gone away).
func TestDaemon_Stop_ReleasesConnection(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	_, sessionPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	_, ok := d.getSession(sessionPath)
	require.True(t, ok)

	d.running.Store(true)

	// Drop the peer so the ReleaseName round trip fails immediately, the way
	// it does when the bus has already gone away.
	d.closePeer()

	require.NoError(t, d.Stop())

	assert.False(t, d.IsRunning())
	assert.Nil(t, d.conn, "the bus connection must be released")
	_, ok = d.getSession(sessionPath)
	assert.False(t, ok, "sessions must be dropped on shutdown")

	// Stop is idempotent.
	require.NoError(t, d.Stop())
}

// failingStore is a StaticPasswordStore whose list operations always fail.
type failingStore struct {
	xkms.StaticPasswordStore
}

func (s *failingStore) List() ([]*xkms.StaticPassword, error) { return nil, errStoreUnavailable }
func (s *failingStore) ListFolders() ([]string, error)        { return nil, errStoreUnavailable }

// recordingAudit captures audit entries emitted by the daemon.
type recordingAudit struct {
	audit.Logger

	mu      sync.Mutex
	entries []audit.Entry
}

func (l *recordingAudit) Log(e audit.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}

func (l *recordingAudit) recorded() []audit.Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Entry(nil), l.entries...)
}

// TestOpenSession_RecordsCallerAsClientPath is the regression test for the
// session's ClientPath, which used to be hardcoded empty with a "TODO: get
// sender" note.
//
// The Secret Service API identifies a session's owner by the caller's D-Bus
// unique connection name. Leaving it empty meant every session looked
// anonymous and indistinguishable from every other, so nothing downstream
// could attribute a secret request to the client that made it. godbus supplies
// the sender to any method whose first parameter is a dbus.Sender, so the fix
// was to declare it and record it.
func TestOpenSession_RecordsCallerAsClientPath(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	_, path, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)

	d.sessionsMu.RLock()
	session, ok := d.sessions[path]
	d.sessionsMu.RUnlock()
	require.True(t, ok, "the opened session must be retrievable at its path")
	assert.Equal(t, string(testSender), session.ClientPath,
		"the session must record the caller's bus name, not an empty string")
}

// TestOpenSession_DistinctCallersRecordDistinctClientPaths proves the recorded
// value tracks the actual caller rather than being a constant: two different
// senders must yield two different ClientPaths.
func TestOpenSession_DistinctCallersRecordDistinctClientPaths(t *testing.T) {
	d := newBusDaemon(t, newMemoryStore())

	const other = dbus.Sender(":1.99")

	_, firstPath, dbusErr := d.OpenSession(testSender, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)
	_, secondPath, dbusErr := d.OpenSession(other, AlgorithmPlain, dbus.MakeVariant(""))
	require.Nil(t, dbusErr)

	d.sessionsMu.RLock()
	first, firstOK := d.sessions[firstPath]
	second, secondOK := d.sessions[secondPath]
	d.sessionsMu.RUnlock()
	require.True(t, firstOK)
	require.True(t, secondOK)

	assert.Equal(t, string(testSender), first.ClientPath)
	assert.Equal(t, string(other), second.ClientPath)
	assert.NotEqual(t, first.ClientPath, second.ClientPath)
}
