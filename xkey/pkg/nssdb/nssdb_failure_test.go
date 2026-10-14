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

// TestCleanupSuffix verifies cleanupSuffix reports every non-nil cleanup
// error it is given rather than silently dropping any of them, and stays
// empty when cleanup fully succeeded.
func TestCleanupSuffix(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", cleanupSuffix(), "no cleanup calls means no suffix")
	assert.Equal(t, "", cleanupSuffix(nil, nil), "successful cleanup calls must not appear in the suffix")
	assert.Equal(t, " (cleanup: disk full)", cleanupSuffix(errors.New("disk full")))
	assert.Equal(t, " (cleanup: disk full; also busy)",
		cleanupSuffix(nil, errors.New("disk full"), errors.New("also busy")),
		"every non-nil cleanup error must be reported, not just the first")
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

// seedDB runs stmts against the SQLite file at path before a Writer opens it,
// standing in for a database left behind by another NSS tool or an older
// xkey.
func seedDB(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	for _, stmt := range stmts {
		_, err := db.Exec(stmt)
		require.NoError(t, err, stmt)
	}
}

// countRows returns the number of rows in table that match where.
func countRows(t *testing.T, db *sql.DB, table, where string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM "+table+" WHERE "+where).Scan(&n))
	return n
}

// TestNewWriter_ForeignMetaDataTable verifies that a key4.db whose metaData
// table cannot hold the password entry fails NewWriter with ErrPasswordInit
// instead of returning a Writer that cannot sign trust objects.
func TestNewWriter_ForeignMetaDataTable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	seedDB(t, filepath.Join(dir, key4DBFile), "CREATE TABLE metaData (id PRIMARY KEY, item1)")

	w, err := NewWriter(dir)
	require.Error(t, err)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, ErrPasswordInit)
}

// TestInitDir_UnusableDatabase verifies that InitDir reports the Writer's
// error when the directory already holds a cert9.db it cannot open.
func TestInitDir_UnusableDatabase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, cert9DBFile), 0700))

	err := InitDir(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCreateSchema)
	assert.FileExists(t, filepath.Join(dir, pkcs11TxtFile))
}

// TestAddTrustedCA_NilSerial verifies that a certificate without a serial
// number is rejected with ErrSerialEncode before anything is written.
func TestAddTrustedCA_NilSerial(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	cert := testCA(t)
	cert.SerialNumber = nil

	err = w.AddTrustedCA(cert, "xkey No Serial")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSerialEncode)
	assert.Zero(t, countRows(t, w.certDB, "nssPublic", "1"))
}

// TestRemoveByPrefix_TrustQueryFailure verifies that a cert9.db whose
// nssPublic table lacks the object-class column fails the trust lookup with
// ErrRemoveTrust and leaves the matching certificate in place.
func TestRemoveByPrefix_TrustQueryFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	seedDB(t, filepath.Join(dir, cert9DBFile),
		"CREATE TABLE nssPublic (id PRIMARY KEY, a3, a81, a82, a101, a102)",
		"INSERT INTO nssPublic (id, a3, a81, a82) VALUES (1, CAST('xkey CA' AS BLOB), x'01', x'02')",
	)

	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRemoveTrust)
	assert.Equal(t, 1, countRows(t, w.certDB, "nssPublic", "id = 1"))
}

// TestRemoveByPrefix_UnscannableCertificateID verifies that a matching
// certificate row whose id is not an integer fails with ErrRemoveCertificate.
func TestRemoveByPrefix_UnscannableCertificateID(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	_, err = w.certDB.Exec("INSERT INTO nssPublic (id, a3) VALUES ('not-a-number', CAST('xkey CA' AS BLOB))")
	require.NoError(t, err)

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRemoveCertificate)
}

// TestRemoveByPrefix_UnscannableTrustID verifies that a trust object linked
// to a removed certificate whose id is not an integer fails with
// ErrRemoveTrust and deletes nothing.
func TestRemoveByPrefix_UnscannableTrustID(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))
	_, err = w.certDB.Exec("INSERT INTO nssPublic (id, a0, a81, a82) " +
		"SELECT 'bogus', a0, a81, a82 FROM nssPublic WHERE hex(a0) = 'CE534353'")
	require.NoError(t, err)

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRemoveTrust)
	assert.Equal(t, 3, countRows(t, w.certDB, "nssPublic", "1"))
}

// TestRemoveByPrefix_DeleteRejected verifies that a cert9.db refusing the
// DELETE surfaces ErrRemoveCertificate and keeps both objects.
func TestRemoveByPrefix_DeleteRejected(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))
	_, err = w.certDB.Exec("CREATE TRIGGER keep BEFORE DELETE ON nssPublic BEGIN SELECT RAISE(ABORT, 'read-only'); END")
	require.NoError(t, err)

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRemoveCertificate)
	assert.Equal(t, 2, countRows(t, w.certDB, "nssPublic", "1"))
}

// TestRemoveByPrefix_SignatureDeleteRejected verifies that a key4.db refusing
// to drop the trust signatures surfaces ErrRemoveTrust after the objects
// themselves are gone.
func TestRemoveByPrefix_SignatureDeleteRejected(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()

	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))
	_, err = w.keyDB.Exec("CREATE TRIGGER keep BEFORE DELETE ON metaData BEGIN SELECT RAISE(ABORT, 'read-only'); END")
	require.NoError(t, err)

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRemoveTrust)
	assert.Zero(t, countRows(t, w.certDB, "nssPublic", "1"))
	assert.NotZero(t, countRows(t, w.keyDB, "metaData", "id LIKE 'sig_cert_%'"))
}
