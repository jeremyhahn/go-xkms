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

package nssdb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitDir_MkdirFailure verifies InitDir reports a typed error when the
// target path cannot be created, instead of leaving the caller believing the
// browser trust store was initialized.
func TestInitDir_MkdirFailure(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	err := InitDir(filepath.Join(blocker, "nssdb"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInitDir)
}

// TestAddTrustedCA_CertDatabaseFailure verifies a failing cert9.db write is
// reported as ErrInsertCertificate. A silent failure here would leave the
// browser trusting nothing while the CLI reports success.
func TestAddTrustedCA_CertDatabaseFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	// Break the certificate database underneath the writer.
	require.NoError(t, w.certDB.Close())

	err = w.AddTrustedCA(testCA(t), "xkey Test CA")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsertCertificate)
}

// TestAddTrustedCA_KeyDatabaseFailure verifies a failing key4.db signature
// write is reported as ErrSignatureInsert. Without the PBMAC1 signatures NSS
// silently ignores the trust flags.
func TestAddTrustedCA_KeyDatabaseFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	// Break only the key database: the certificate insert still succeeds.
	require.NoError(t, w.keyDB.Close())

	err = w.AddTrustedCA(testCA(t), "xkey Test CA")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureInsert)
}

// TestRemoveByPrefix_DatabaseFailure verifies removal failures are surfaced,
// so a stale CA is never reported as revoked when it is still trusted.
func TestRemoveByPrefix_DatabaseFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))
	require.NoError(t, w.certDB.Close())

	assert.Error(t, w.RemoveByPrefix("xkey"))
}

// TestNewWriter_PasswordInitFailure verifies the constructor fails when the
// key4.db schema cannot hold the password entry, rather than returning a
// writer whose trust signatures would be unverifiable.
func TestNewWriter_PasswordInitFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A key4.db that is a directory cannot be opened as a SQLite database.
	require.NoError(t, os.Mkdir(filepath.Join(dir, key4DBFile), 0700))

	w, err := NewWriter(dir)
	require.Error(t, err)
	assert.Nil(t, w)
}

func TestNSSDBTypedErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("disk full")

	detail := &DetailError{Err: ErrInsertCertificate, Detail: ": constraint failed"}
	assert.Equal(t, ErrInsertCertificate.Error()+": constraint failed", detail.Error())
	assert.ErrorIs(t, detail, ErrInsertCertificate)
	assert.NotErrorIs(t, detail, ErrInsertTrust)

	msg := &MessageError{Msg: "nssdb: unexpected attribute encoding"}
	assert.Equal(t, "nssdb: unexpected attribute encoding", msg.Error())
	assert.NotErrorIs(t, msg, cause)

	wrapped := &WrappedError{Msg: "write pkcs11.txt", Err: cause}
	assert.Equal(t, "write pkcs11.txt: disk full", wrapped.Error())
	assert.ErrorIs(t, wrapped, cause)
}

// TestInitDir_PKCS11TxtFailure verifies InitDir reports a typed error when
// pkcs11.txt cannot be written. Without it NSS never loads the database.
func TestInitDir_PKCS11TxtFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Occupy pkcs11.txt with a directory so the file write fails for any user.
	require.NoError(t, os.Mkdir(filepath.Join(dir, pkcs11TxtFile), 0700))

	err := InitDir(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWritePKCS11Txt)
}

// TestNewWriter_CertDatabaseUnusable verifies an unusable cert9.db is reported
// at construction time rather than on the first write.
func TestNewWriter_CertDatabaseUnusable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, cert9DBFile), 0700))

	w, err := NewWriter(dir)
	require.Error(t, err)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, ErrCreateSchema)
}
