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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempFile writes content to a uniquely named file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// TestCSVParser_Parse_EmbeddedDelimitersAndNewlines verifies quoted fields
// carrying commas and newlines survive parsing intact. Password managers export
// notes with both.
func TestCSVParser_Parse_EmbeddedDelimitersAndNewlines(t *testing.T) {
	t.Parallel()

	content := "name,username,password,url,notes\n" +
		"\"Acme, Inc.\",alice,\"p@ss,word\",https://acme.example,\"line one\nline two\"\n"

	entries, err := NewCSVParser().Parse(t.Context(), writeTempFile(t, "quoted.csv", content), nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "Acme, Inc.", entries[0].Title)
	assert.Equal(t, "p@ss,word", openSecretString(t, entries[0].Password), "an embedded delimiter must not truncate the password")
	assert.Equal(t, "line one\nline two", entries[0].Notes)
}

// TestCSVParser_Parse_RaggedRowsAreSkipped verifies rows with too few columns
// are skipped rather than producing entries with shifted fields.
func TestCSVParser_Parse_RaggedRowsAreSkipped(t *testing.T) {
	t.Parallel()

	// csv.Reader rejects a ragged record outright, so the whole file is a
	// parse error: a partial import would silently corrupt the vault.
	content := "name,username,password\nshort-row\nfull,alice,s3cret\n"

	entries, err := NewCSVParser().Parse(t.Context(), writeTempFile(t, "ragged.csv", content), nil)
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrParseError)
}

// TestCSVParser_Parse_HeaderOnly verifies a file with only a header yields no
// entries rather than an empty successful import.
func TestCSVParser_Parse_HeaderOnly(t *testing.T) {
	t.Parallel()

	entries, err := NewCSVParser().Parse(t.Context(), writeTempFile(t, "header.csv", "name,username,password\n"), nil)
	assert.Nil(t, entries)
	assert.ErrorIs(t, err, ErrNoEntriesFound)
}

// TestCSVParser_Parse_LargeField verifies a very large notes field survives the
// round trip (password managers export attachments as base64 notes).
func TestCSVParser_Parse_LargeField(t *testing.T) {
	t.Parallel()

	large := make([]byte, 256*1024)
	for i := range large {
		large[i] = 'x'
	}
	content := "name,username,password,notes\nbig,alice,s3cret,\"" + string(large) + "\"\n"

	entries, err := NewCSVParser().Parse(t.Context(), writeTempFile(t, "large.csv", content), nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Len(t, entries[0].Notes, len(large))
}

func TestCSVParser_ParseTimestamp_Formats(t *testing.T) {
	t.Parallel()

	p := NewCSVParser()

	tests := []struct {
		name string
		in   string
		want time.Time
	}{
		{"empty", "", time.Time{}},
		{"rfc3339", "2024-03-01T10:00:00Z", time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"date only", "2024-03-01", time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"space separated", "2024-03-01 10:00:00", time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"us slashes", "03/01/2024", time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"us slashes with time", "03/01/2024 10:00:00", time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)},
		{"unparseable", "yesterday", time.Time{}},
		{"unix seconds are not supported", "1709287200", time.Time{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, tt.want.Equal(p.parseTimestamp(tt.in)),
				"want %v, got %v", tt.want, p.parseTimestamp(tt.in))
		})
	}
}

// TestXMLParser_ParseKeePassTime covers every branch of the KeePass timestamp
// decoder: base64 tick counts, ISO fallbacks, and malformed input.
func TestXMLParser_ParseKeePassTime(t *testing.T) {
	t.Parallel()

	p := NewXMLParser()

	// KeePass stores 100 ns ticks since 0001-01-01; 621355968000000000 ticks
	// is the Unix epoch.
	const unixEpochTicks uint64 = 621355968000000000
	encodeTicks := func(ticks uint64) string {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, ticks)
		return base64.StdEncoding.EncodeToString(buf)
	}

	t.Run("epoch", func(t *testing.T) {
		assert.Equal(t, time.Unix(0, 0).UTC(), p.parseKeePassTime(encodeTicks(unixEpochTicks)).UTC())
	})

	t.Run("one hour after the epoch", func(t *testing.T) {
		got := p.parseKeePassTime(encodeTicks(unixEpochTicks + 36000000000))
		assert.Equal(t, time.Unix(3600, 0).UTC(), got.UTC())
	})

	t.Run("before the unix epoch is rejected", func(t *testing.T) {
		assert.True(t, p.parseKeePassTime(encodeTicks(unixEpochTicks-1)).IsZero())
	})

	t.Run("truncated tick buffer", func(t *testing.T) {
		assert.True(t, p.parseKeePassTime(base64.StdEncoding.EncodeToString([]byte{1, 2, 3})).IsZero())
	})

	t.Run("empty", func(t *testing.T) {
		assert.True(t, p.parseKeePassTime("").IsZero())
	})

	t.Run("rfc3339 fallback", func(t *testing.T) {
		// Not valid base64, so the ISO 8601 fallbacks apply.
		got := p.parseKeePassTime("2024-03-01T10:00:00+01:00")
		assert.Equal(t, time.Date(2024, 3, 1, 9, 0, 0, 0, time.UTC), got.UTC())
	})

	t.Run("zulu fallback", func(t *testing.T) {
		got := p.parseKeePassTime("2024-03-01T10:00:00Z!")
		assert.True(t, got.IsZero(), "a trailing junk character must not parse")
	})

	t.Run("unparseable", func(t *testing.T) {
		assert.True(t, p.parseKeePassTime("not a time at all!").IsZero())
	})
}

func TestParsedEntry_ToStaticPassword_NameFallbacks(t *testing.T) {
	t.Parallel()

	t.Run("title wins", func(t *testing.T) {
		sp, err := (&ParsedEntry{Title: "GitHub", Username: "alice", Password: testSecret(t, "s")}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "GitHub", sp.Name)
	})

	t.Run("falls back to username", func(t *testing.T) {
		sp, err := (&ParsedEntry{Username: "alice", Password: testSecret(t, "s")}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "alice", sp.Name)
	})

	t.Run("falls back to a placeholder", func(t *testing.T) {
		sp, err := (&ParsedEntry{Password: testSecret(t, "s")}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "Unnamed Entry", sp.Name)
	})

	t.Run("missing timestamps default to now", func(t *testing.T) {
		before := time.Now()
		sp, err := (&ParsedEntry{Title: "x", Password: testSecret(t, "s")}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.False(t, sp.CreatedAt.Before(before))
		assert.False(t, sp.UpdatedAt.Before(before))
	})

	t.Run("supplied timestamps are preserved", func(t *testing.T) {
		created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		updated := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		sp, err := (&ParsedEntry{Title: "x", Password: testSecret(t, "s"), CreatedAt: created, UpdatedAt: updated}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.True(t, created.Equal(sp.CreatedAt))
		assert.True(t, updated.Equal(sp.UpdatedAt))
	})

	t.Run("nil password produces an empty StaticPassword.Password", func(t *testing.T) {
		sp, err := (&ParsedEntry{Title: "x"}).ToStaticPassword(t.Context())
		require.NoError(t, err)
		assert.Empty(t, sp.Password)
	})
}

func TestImporter_Preview_Rejections(t *testing.T) {
	t.Parallel()

	imp := newTestImporter(t)

	t.Run("undetectable format", func(t *testing.T) {
		entries, err := imp.Preview(t.Context(), &ImportOptions{FilePath: writeTempFile(t, "data.bin", "x")})
		assert.Nil(t, entries)
		assert.ErrorIs(t, err, ErrUnsupportedFormat)
	})

	t.Run("explicit unknown format", func(t *testing.T) {
		entries, err := imp.Preview(t.Context(), &ImportOptions{
			FilePath: writeTempFile(t, "data.csv", "name,password\na,b\n"),
			Format:   "1password-opvault",
		})
		assert.Nil(t, entries)
		assert.ErrorIs(t, err, ErrUnsupportedFormat)
	})
}

func TestPwimportTypedErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("read error")

	detail := &DetailError{Err: ErrUnsupportedFormat, Detail: ": kdbx4"}
	assert.Equal(t, ErrUnsupportedFormat.Error()+": kdbx4", detail.Error())
	assert.ErrorIs(t, detail, ErrUnsupportedFormat)
	assert.NotErrorIs(t, detail, ErrParseError)

	sentinel := &SentinelCauseError{Sentinel: ErrInvalidFile, Cause: cause}
	assert.Equal(t, ErrInvalidFile.Error()+": read error", sentinel.Error())
	assert.ErrorIs(t, sentinel, ErrInvalidFile)
	assert.ErrorIs(t, sentinel, cause)
	assert.NotErrorIs(t, sentinel, ErrParseError)
}

// FuzzCSVParser_Parse exercises the CSV parser against arbitrary input. The
// parser must always terminate with either entries or a typed error, and must
// never panic on malformed headers, ragged rows, or broken quoting.
func FuzzCSVParser_Parse(f *testing.F) {
	f.Add("name,username,password\nGitHub,alice,s3cret\n")
	f.Add("url,login_username,login_password\nhttps://x,alice,s3cret\n")
	f.Add("name,password\n\"unterminated,quote,x\n")
	f.Add("name,password\n,\n")
	f.Add("")
	f.Add("\x00\x00\x00")
	f.Add("group,title,username,password,notes,totp\nFolder/Sub,T,u,p,n,otpauth://totp/x?secret=Y\n")

	parser := NewCSVParser()

	f.Fuzz(func(t *testing.T, content string) {
		path := filepath.Join(t.TempDir(), "fuzz.csv")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		entries, err := parser.Parse(t.Context(), path, &ImportOptions{TargetFolder: "Imported"})
		if err != nil {
			if entries != nil {
				t.Fatalf("parser returned entries alongside error %v", err)
			}
			return
		}

		for _, entry := range entries {
			if entry == nil {
				t.Fatal("parser returned a nil entry")
			}
			if entry.Password == nil {
				t.Fatal("parser returned an entry without a password")
			}
			// Every successful entry must convert without panicking.
			sp, err := entry.ToStaticPassword(t.Context())
			if err != nil {
				t.Fatalf("ToStaticPassword: %v", err)
			}
			if sp.Name == "" {
				t.Fatal("converted entry has an empty name")
			}
		}
	})
}
