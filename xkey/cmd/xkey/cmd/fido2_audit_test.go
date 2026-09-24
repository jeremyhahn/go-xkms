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

package cmd

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/stretchr/testify/require"
)

// failingAuditLogger implements audit.Logger, failing every write with a
// fixed error. It is shared by the fido2.go and extension_serve.go audit
// wiring tests (go-xkms#804) to prove that an audit-write failure refuses
// the operation at each production entry point, the same way the
// xkey/pkg/authenticator package tests prove it at the package boundary.
type failingAuditLogger struct {
	err error
}

func (l *failingAuditLogger) Log(audit.Entry) error { return l.err }

func (l *failingAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) error {
	return l.err
}

func (l *failingAuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) error {
	return l.err
}

func (l *failingAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) error {
	return l.err
}

func (l *failingAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) error {
	return l.err
}

func (l *failingAuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, err error, details map[string]any) error {
	return l.err
}

func (l *failingAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	return l.err
}

func (l *failingAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) error {
	return l.err
}

func (l *failingAuditLogger) LogUserPresenceEvent(op audit.OperationType, source string, success bool, details map[string]any) error {
	return l.err
}

var _ audit.Logger = (*failingAuditLogger)(nil)

// bufferLogger returns an slog.Logger writing JSON to buf, so a test can
// assert on the audit records the daemon's slog-backed audit.Logger emits.
func bufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestNewFIDO2Device_SetPINEmitsAuditRecord verifies that `xkey fido2
// --set-pin` -- the daemon's PIN-seeding entry point -- is wired to an audit
// logger (go-xkms#804): establishing the initial PIN produces an OpPINSeeded
// record in the daemon's log stream.
func TestNewFIDO2Device_SetPINEmitsAuditRecord(t *testing.T) {
	var buf bytes.Buffer
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "123456")

	device, err := newFIDO2Device(cfg, bufferLogger(&buf))
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	require.True(t, device.auth.IsPINSet())

	out := buf.String()
	require.Contains(t, out, `"component":"audit"`)
	require.Contains(t, out, `"operation":"`+string(audit.OpPINSeeded)+`"`)
	require.Contains(t, out, `"success":true`)
}

// TestNewFIDO2Device_AuditWriteFailureRefusesPINSeed verifies that a failed
// audit write refuses PIN establishment for the `xkey fido2` daemon, the same
// write-failure policy the authenticator package enforces internally
// (go-xkms#688/#766/#804).
func TestNewFIDO2Device_AuditWriteFailureRefusesPINSeed(t *testing.T) {
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "")

	device, err := newFIDO2Device(cfg, discardLogger())
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	auditErr := errors.New("audit backend unavailable")
	device.auth.SetAuditLogger(&failingAuditLogger{err: auditErr})

	err = device.auth.SetInitialPIN([]byte("123456"))
	require.ErrorIs(t, err, auditErr)

	// establishPINLocked accepts the PIN into in-memory state before the
	// audit gate (so IsPINSet, which reads that in-memory state, is not the
	// right check here -- see the authenticator package's own
	// TestSetInitialPIN_AuditWriteFailure_FailsAndDoesNotPersistPIN). What
	// must not happen is persistence: a failed audit write must leave
	// nothing durable behind.
	stateful, ok := device.auth.Storage().(authenticator.StatefulCredentialStorage)
	require.True(t, ok, "test fixture must use a StatefulCredentialStorage")
	if persisted, loadErr := stateful.LoadState(); loadErr == nil {
		require.False(t, persisted.PINSet, "no PIN state must be persisted when its audit record could not be written")
	} else {
		require.ErrorIs(t, loadErr, authenticator.ErrStateNotFound)
	}
}

// TestNewFIDO2Device_MakeCredentialEmitsAuditRecord verifies that the `xkey
// fido2` daemon's shared authenticator is wired to an audit logger for
// credential creation (go-xkms#804): MakeCredential produces an
// OpFIDO2CredentialCreated record in the daemon's log stream.
func TestNewFIDO2Device_MakeCredentialEmitsAuditRecord(t *testing.T) {
	var buf bytes.Buffer
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "")

	device, err := newFIDO2Device(cfg, bufferLogger(&buf))
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	// The daemon's default presence handler is socket-based and waits for an
	// IPC touch approval that nothing in this test sends. Substituting an
	// auto-grant handler isolates the audit-wiring assertion from that
	// separate, already-tested ceremony.
	device.auth.SetUserPresenceHandler(authenticator.NewAutoGrantHandler())

	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := authenticator.RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := authenticator.User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "Test User"}
	params := []authenticator.PublicKeyCredentialParam{{Type: "public-key", Alg: authenticator.COSEAlgES256}}

	resp, err := device.auth.MakeCredential(clientDataHash[:], rp, user, params, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	out := buf.String()
	require.Contains(t, out, `"component":"audit"`)
	require.Contains(t, out, `"operation":"`+string(audit.OpFIDO2CredentialCreated)+`"`)
	require.Contains(t, out, `"success":true`)
}

// TestNewFIDO2Device_AuditWriteFailureRefusesCredentialCreation verifies that
// a failed audit write refuses credential creation for the `xkey fido2`
// daemon (go-xkms#688/#766/#804).
func TestNewFIDO2Device_AuditWriteFailureRefusesCredentialCreation(t *testing.T) {
	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "")

	device, err := newFIDO2Device(cfg, discardLogger())
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	device.auth.SetUserPresenceHandler(authenticator.NewAutoGrantHandler())

	auditErr := errors.New("audit backend unavailable")
	device.auth.SetAuditLogger(&failingAuditLogger{err: auditErr})

	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := authenticator.RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := authenticator.User{ID: []byte("user-2"), Name: "user2@example.com", DisplayName: "Test User Two"}
	params := []authenticator.PublicKeyCredentialParam{{Type: "public-key", Alg: authenticator.COSEAlgES256}}

	_, err = device.auth.MakeCredential(clientDataHash[:], rp, user, params, nil)
	require.ErrorIs(t, err, auditErr)
}
