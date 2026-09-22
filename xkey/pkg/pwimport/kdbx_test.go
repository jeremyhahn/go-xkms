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

package pwimport

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

// kdbxValue builds a plain (unprotected) KeePass value.
func kdbxValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

// kdbxProtectedValue builds a protected KeePass value (the encoder encrypts it
// in the inner stream, exactly as KeePass stores passwords).
func kdbxProtectedValue(key, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(true)},
	}
}

// writeTestKDBX builds a real KDBX database with nested groups and writes it to
// a temp file, returning the path. Using the upstream encoder means the parser
// under test reads a genuine KeePass container (AES/ChaCha inner stream,
// protected passwords, compressed XML) rather than a hand-rolled approximation.
func writeTestKDBX(t *testing.T, password string) string {
	t.Helper()

	created := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	modified := time.Date(2024, 4, 2, 11, 30, 0, 0, time.UTC)
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	times := func(withExpiry bool) gokeepasslib.TimeData {
		td := gokeepasslib.TimeData{
			CreationTime:         &wrappers.TimeWrapper{Time: created},
			LastModificationTime: &wrappers.TimeWrapper{Time: modified},
			Expires:              wrappers.NewBoolWrapper(withExpiry),
		}
		if withExpiry {
			td.ExpiryTime = &wrappers.TimeWrapper{Time: expires}
		}
		return td
	}

	rootEntry := gokeepasslib.NewEntry()
	rootEntry.Values = []gokeepasslib.ValueData{
		kdbxValue("Title", "GitHub"),
		kdbxValue("UserName", "alice"),
		kdbxProtectedValue("Password", "gh-s3cret"),
		kdbxValue("URL", "https://github.com"),
		kdbxValue("Notes", "work account"),
		kdbxValue("otp", "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP"),
	}
	rootEntry.Tags = "work, vcs "
	rootEntry.Times = times(true)

	// An entry with no password must be skipped by the parser.
	emptyEntry := gokeepasslib.NewEntry()
	emptyEntry.Values = []gokeepasslib.ValueData{kdbxValue("Title", "No Password")}

	nestedEntry := gokeepasslib.NewEntry()
	nestedEntry.Values = []gokeepasslib.ValueData{
		kdbxValue("Title", "Bank"),
		kdbxProtectedValue("Password", "bank-s3cret"),
		kdbxValue("TOTP", "not-an-otpauth-url"),
	}
	nestedEntry.Times = times(false)

	nested := gokeepasslib.NewGroup()
	nested.Name = "Finance"
	nested.Entries = []gokeepasslib.Entry{nestedEntry}

	inner := gokeepasslib.NewGroup()
	inner.Name = "Personal"
	inner.Entries = []gokeepasslib.Entry{rootEntry, emptyEntry}
	inner.Groups = []gokeepasslib.Group{nested}

	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Groups = []gokeepasslib.Group{inner}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}

	require.NoError(t, db.LockProtectedEntries())

	path := filepath.Join(t.TempDir(), "vault.kdbx")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	require.NoError(t, gokeepasslib.NewEncoder(f).Encode(db))
	return path
}

func TestKDBXParser_Format(t *testing.T) {
	t.Parallel()

	assert.Equal(t, FormatKDBX, NewKDBXParser().Format())
}

// TestKDBXParser_Parse_RealDatabase parses a genuine KDBX container and checks
// every field the importer depends on, including nested group paths, protected
// passwords, TOTP detection, tags, and timestamps.
func TestKDBXParser_Parse_RealDatabase(t *testing.T) {
	t.Parallel()

	path := writeTestKDBX(t, "correct horse battery staple")

	entries, err := NewKDBXParser().Parse(path, &ImportOptions{Password: "correct horse battery staple"})
	require.NoError(t, err)
	require.Len(t, entries, 2, "the entry without a password must be skipped")

	byTitle := make(map[string]*ParsedEntry, len(entries))
	for _, e := range entries {
		byTitle[e.Title] = e
	}

	github := byTitle["GitHub"]
	require.NotNil(t, github)
	assert.Equal(t, "alice", github.Username)
	assert.Equal(t, "gh-s3cret", openSecretString(t, github.Password), "protected values must be unlocked")
	assert.Equal(t, "https://github.com", github.URL)
	assert.Equal(t, "work account", github.Notes)
	assert.Equal(t, "Personal", github.FolderPath, "the Root group must not appear in the path")
	assert.Equal(t, []string{"work", "vcs"}, github.Tags, "tags must be split and trimmed")
	assert.True(t, github.HasTOTP)
	assert.Equal(t, "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP", github.TOTPURL)
	assert.Equal(t, 2024, github.CreatedAt.UTC().Year())
	assert.Equal(t, time.April, github.UpdatedAt.UTC().Month())
	assert.Equal(t, 2030, github.ExpiresAt.UTC().Year())

	bank := byTitle["Bank"]
	require.NotNil(t, bank)
	assert.Equal(t, "Personal/Finance", bank.FolderPath, "nested groups must build a path")
	assert.Equal(t, "not-an-otpauth-url", bank.TOTPURL)
	assert.False(t, bank.HasTOTP, "a non-otpauth value must not be flagged as TOTP")
	assert.True(t, bank.ExpiresAt.IsZero(), "expiry must be ignored when the entry does not expire")
}

func TestKDBXParser_Parse_TargetFolderPrefix(t *testing.T) {
	t.Parallel()

	path := writeTestKDBX(t, "pw")

	entries, err := NewKDBXParser().Parse(path, &ImportOptions{
		Password:     "pw",
		TargetFolder: "Imported",
	})
	require.NoError(t, err)

	folders := make([]string, 0, len(entries))
	for _, e := range entries {
		folders = append(folders, e.FolderPath)
	}
	assert.ElementsMatch(t, []string{"Imported/Personal", "Imported/Personal/Finance"}, folders)
}

// TestKDBXParser_Parse_TargetFolderForRootEntries covers the branch where an
// entry lives directly in the root group and only the target folder applies.
func TestKDBXParser_Parse_TargetFolderForRootEntries(t *testing.T) {
	t.Parallel()

	entry := gokeepasslib.NewEntry()
	entry.Values = []gokeepasslib.ValueData{
		kdbxValue("Title", "Loose"),
		kdbxProtectedValue("Password", "loose-s3cret"),
	}

	root := gokeepasslib.NewGroup()
	root.Name = "Root"
	root.Entries = []gokeepasslib.Entry{entry}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	require.NoError(t, db.LockProtectedEntries())

	path := filepath.Join(t.TempDir(), "flat.kdbx")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, gokeepasslib.NewEncoder(f).Encode(db))
	require.NoError(t, f.Close())

	entries, err := NewKDBXParser().Parse(path, &ImportOptions{Password: "pw", TargetFolder: "Imported"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Imported", entries[0].FolderPath)

	// Without a target folder, a root-level entry has no folder at all.
	entries, err = NewKDBXParser().Parse(path, &ImportOptions{Password: "pw"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Empty(t, entries[0].FolderPath)
}

func TestKDBXParser_Parse_Rejections(t *testing.T) {
	t.Parallel()

	path := writeTestKDBX(t, "right-password")

	tests := []struct {
		name    string
		path    string
		opts    *ImportOptions
		wantErr error
	}{
		{"nil options", path, nil, ErrPasswordRequired},
		{"empty password", path, &ImportOptions{}, ErrPasswordRequired},
		{"missing file", filepath.Join(t.TempDir(), "absent.kdbx"), &ImportOptions{Password: "pw"}, ErrInvalidFile},
		{"wrong password", path, &ImportOptions{Password: "wrong-password"}, ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := NewKDBXParser().Parse(tt.path, tt.opts)
			assert.Nil(t, entries)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestKDBXParser_Parse_NotAKDBXFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "notes.txt")
	require.NoError(t, os.WriteFile(path, []byte("this is not a keepass database"), 0600))

	entries, err := NewKDBXParser().Parse(path, &ImportOptions{Password: "pw"})
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// TestKDBXParser_Parse_EmptyDatabase verifies a database with no usable entries
// is reported as such instead of returning an empty success.
func TestKDBXParser_Parse_EmptyDatabase(t *testing.T) {
	t.Parallel()

	root := gokeepasslib.NewGroup()
	root.Name = "Root"

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials("pw")
	db.Content.Root = &gokeepasslib.RootData{Groups: []gokeepasslib.Group{root}}
	require.NoError(t, db.LockProtectedEntries())

	path := filepath.Join(t.TempDir(), "empty.kdbx")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, gokeepasslib.NewEncoder(f).Encode(db))
	require.NoError(t, f.Close())

	entries, err := NewKDBXParser().Parse(path, &ImportOptions{Password: "pw"})
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrNoEntriesFound)
}

func TestKDBXParser_ParseTime_Nil(t *testing.T) {
	t.Parallel()

	assert.True(t, NewKDBXParser().parseTime(nil).IsZero())

	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, now, NewKDBXParser().parseTime(&wrappers.TimeWrapper{Time: now}))
}

// TestImporter_Import_KDBX drives the KDBX format through the public importer,
// proving format detection and the store write path work for real databases.
func TestImporter_Import_KDBX(t *testing.T) {
	t.Parallel()

	path := writeTestKDBX(t, "pw")

	importer := newTestImporter(t)

	result, err := importer.Import(&ImportOptions{
		FilePath:   path,
		Password:   "pw",
		ImportTOTP: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Imported)
	assert.Equal(t, 0, result.Failed)
	assert.Equal(t, 1, result.TOTPImported)
	assert.Positive(t, result.Duration)

	preview, err := importer.Preview(&ImportOptions{FilePath: path, Password: "pw"})
	require.NoError(t, err)
	assert.Len(t, preview, 2)
}
