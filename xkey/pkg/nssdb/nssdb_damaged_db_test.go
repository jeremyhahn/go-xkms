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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeKey4WithoutItem2 leaves a key4.db in dir whose metaData table predates
// the item2 column, so the password entry can be read but never stored.
func writeKey4WithoutItem2(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, key4DBFile))
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE metaData (id PRIMARY KEY, item1)")
	require.NoError(t, err)
	require.NoError(t, db.Close())
}

func TestNewWriter_PasswordEntryCannotBeStored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey4WithoutItem2(t, dir)

	w, err := NewWriter(dir)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, ErrPasswordInit)
}

func TestInitDir_SurfacesWriterFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeKey4WithoutItem2(t, dir)

	assert.ErrorIs(t, InitDir(dir), ErrPasswordInit)
}

func TestRemoveByPrefix_DeleteRefusedKeepsTheCertificate(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))

	_, err = w.certDB.Exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON nssPublic
		BEGIN SELECT RAISE(ABORT, 'delete refused'); END`)
	require.NoError(t, err)

	assert.ErrorIs(t, w.RemoveByPrefix("xkey"), ErrRemoveCertificate)

	var remaining int
	require.NoError(t, w.certDB.QueryRow(
		"SELECT COUNT(*) FROM nssPublic WHERE CAST(a3 AS TEXT) LIKE 'xkey%'").Scan(&remaining))
	assert.Positive(t, remaining)
}

func TestRemoveByPrefix_SignatureCleanupFailure(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	require.NoError(t, w.AddTrustedCA(testCA(t), "xkey Test CA"))

	// A key4.db that lost its metaData table cannot drop the HMAC signatures.
	_, err = w.keyDB.Exec("DROP TABLE metaData")
	require.NoError(t, err)

	assert.ErrorIs(t, w.RemoveByPrefix("xkey"), ErrRemoveTrust)
}
