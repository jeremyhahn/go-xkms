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
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/stretchr/testify/require"
)

// These tests exercise the same audit wiring runExtensionServe installs on
// the authenticator initHeadlessAuthenticator returns (go-xkms#804):
//
//	auth.SetAuditLogger(auditLogger)
//
// runExtensionServe itself is not driven end to end here -- it opens a real
// IPC socket and (in barrier mode) a real barrier, which the existing
// TestExtensionServeCmd_* tests already cover host-safely with a temp
// directory and no-barrier/no-auth flags. What is specific to this issue is
// that the authenticator initHeadlessAuthenticator builds actually reaches an
// audit logger and that a write failure from that logger refuses the
// operation, so these tests build the authenticator the same way
// runExtensionServe does and apply the identical wiring line.

// TestExtensionServeAuthenticator_SetPINEmitsAuditRecord verifies that the
// headless `xkey extension serve` daemon's authenticator, wired with
// auth.SetAuditLogger the way runExtensionServe wires it, records
// OpPINSeeded when a PIN is established in-process.
func TestExtensionServeAuthenticator_SetPINEmitsAuditRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := bufferLogger(&buf)

	backend, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(backend, pinSvc, logger)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	auditLogger := audit.NewSlogLogger(logger)
	auth.SetAuditLogger(auditLogger)

	require.NoError(t, auth.SetInitialPIN([]byte("123456")))

	out := buf.String()
	require.Contains(t, out, `"component":"audit"`)
	require.Contains(t, out, `"operation":"`+string(audit.OpPINSeeded)+`"`)
	require.Contains(t, out, `"success":true`)
}

// TestExtensionServeAuthenticator_AuditWriteFailureRefusesPINSeed verifies
// that a failed audit write refuses PIN establishment for the headless
// extension-serve daemon's authenticator (go-xkms#688/#766/#804).
func TestExtensionServeAuthenticator_AuditWriteFailureRefusesPINSeed(t *testing.T) {
	backend, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(backend, pinSvc, discardLogger())
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	auditErr := errors.New("audit backend unavailable")
	auth.SetAuditLogger(&failingAuditLogger{err: auditErr})

	err = auth.SetInitialPIN([]byte("123456"))
	require.ErrorIs(t, err, auditErr)

	stateful, ok := auth.Storage().(authenticator.StatefulCredentialStorage)
	require.True(t, ok, "test fixture must use a StatefulCredentialStorage")
	if persisted, loadErr := stateful.LoadState(); loadErr == nil {
		require.False(t, persisted.PINSet, "no PIN state must be persisted when its audit record could not be written")
	} else {
		require.ErrorIs(t, loadErr, authenticator.ErrStateNotFound)
	}
}

// TestExtensionServeAuthenticator_MakeCredentialEmitsAuditRecord verifies
// that the headless extension-serve daemon's authenticator, wired the way
// runExtensionServe wires it, records OpFIDO2CredentialCreated when a
// credential is created.
func TestExtensionServeAuthenticator_MakeCredentialEmitsAuditRecord(t *testing.T) {
	var buf bytes.Buffer
	logger := bufferLogger(&buf)

	backend, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(backend, pinSvc, logger)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	auditLogger := audit.NewSlogLogger(logger)
	auth.SetAuditLogger(auditLogger)

	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := authenticator.RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := authenticator.User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "Test User"}
	params := []authenticator.PublicKeyCredentialParam{{Type: "public-key", Alg: authenticator.COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash[:], rp, user, params, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	out := buf.String()
	require.Contains(t, out, `"component":"audit"`)
	require.Contains(t, out, `"operation":"`+string(audit.OpFIDO2CredentialCreated)+`"`)
	require.Contains(t, out, `"success":true`)
}

// TestExtensionServeAuthenticator_AuditWriteFailureRefusesCredentialCreation
// verifies that a failed audit write refuses credential creation for the
// headless extension-serve daemon's authenticator (go-xkms#688/#766/#804).
func TestExtensionServeAuthenticator_AuditWriteFailureRefusesCredentialCreation(t *testing.T) {
	backend, err := xkms.NewFileStorageBackend(t.TempDir())
	require.NoError(t, err)
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(backend, pinSvc, discardLogger())
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	auditErr := errors.New("audit backend unavailable")
	auth.SetAuditLogger(&failingAuditLogger{err: auditErr})

	clientDataHash := sha256.Sum256([]byte("test client data"))
	rp := authenticator.RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := authenticator.User{ID: []byte("user-2"), Name: "user2@example.com", DisplayName: "Test User Two"}
	params := []authenticator.PublicKeyCredentialParam{{Type: "public-key", Alg: authenticator.COSEAlgES256}}

	_, err = auth.MakeCredential(clientDataHash[:], rp, user, params, nil)
	require.ErrorIs(t, err, auditErr)
}
