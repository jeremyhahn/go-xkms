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
	"database/sql"
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

// TestAddTrustedCA_TrustInsertFailure verifies that a failure inserting the
// trust object specifically (the certificate object having already been
// inserted successfully) is reported as ErrInsertTrust, distinct from
// ErrInsertCertificate. A certificate object with no matching trust object
// is exactly the "shows up but is not trusted" defect this package exists
// to prevent, so the two failure modes must stay distinguishable.
//
// generateObjectID hands out (baseID, baseID+1) pairs from a package-level
// counter; reserving one id and pre-occupying baseID+1 of the *next* pair
// predicts the trust object's id and collides only that insert, leaving the
// certificate insert (baseID) untouched.
//
// Deliberately not t.Parallel(): the prediction only holds if nothing else
// calls the package-level generateObjectID counter between the reservation
// and AddTrustedCA's own call, which a concurrently running parallel test
// calling AddTrustedCA could do.
func TestAddTrustedCA_TrustInsertFailure(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	reserved := generateObjectID()
	predictedTrustID := reserved + 3 // next pair is (reserved+2, reserved+3)

	_, err = w.certDB.Exec("INSERT INTO nssPublic (id) VALUES (?)", predictedTrustID)
	require.NoError(t, err)

	err = w.AddTrustedCA(testCA(t), "xkey Test CA")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsertTrust)
	assert.False(t, errors.Is(err, ErrInsertCertificate), "the certificate insert must have succeeded before the trust insert collided")
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

// TestWriteTrustSignatures_SkipsUnparsableAttributeName verifies a
// malformed attribute name in the map is skipped rather than aborting the
// whole signature write — writeTrustSignatures is only ever called with
// buildTrustAttrs' own output in production, so this exercises the guard
// directly rather than relying on being able to smuggle a bad key through
// AddTrustedCA.
func TestWriteTrustSignatures_SkipsUnparsableAttributeName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	err = w.writeTrustSignatures(1, map[string][]byte{"not-a-valid-attr-name": []byte("x")})
	assert.NoError(t, err, "an unparsable attribute name must be skipped, not fatal")
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

// TestNewWriter_CertSchemaCreationLocked verifies that a cert9.db whose file
// already exists in WAL mode but is held write-locked by another connection
// (rather than being wholly unopenable) fails schema creation with a typed
// error, rather than returning a Writer over a database with no schema.
func TestNewWriter_CertSchemaCreationLocked(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, cert9DBFile)

	blocker, err := sql.Open("sqlite", certPath)
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()

	// Put the file into WAL mode ahead of NewWriter so its own WAL pragma is
	// a same-mode no-op, then hold the write lock open so the CREATE TABLE
	// that follows collides with it instead.
	_, err = blocker.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, err)
	_, err = blocker.Exec("BEGIN IMMEDIATE")
	require.NoError(t, err)

	w, err := NewWriter(dir)
	require.Error(t, err)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, ErrCreateSchema)
}

// TestNewWriter_KeySchemaCreationLocked mirrors
// TestNewWriter_CertSchemaCreationLocked for key4.db: a write lock held by
// another connection during schema creation is reported as a typed error.
func TestNewWriter_KeySchemaCreationLocked(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, key4DBFile)

	blocker, err := sql.Open("sqlite", keyPath)
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()

	_, err = blocker.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, err)
	_, err = blocker.Exec("BEGIN IMMEDIATE")
	require.NoError(t, err)

	w, err := NewWriter(dir)
	require.Error(t, err)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, ErrCreateSchema)
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
