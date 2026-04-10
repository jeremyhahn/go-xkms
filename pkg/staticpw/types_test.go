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

package staticpw

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStaticPassword_Validate_Valid(t *testing.T) {
	pw := &StaticPassword{
		Name:     "test-entry",
		Password: "secret123",
	}
	assert.NoError(t, pw.Validate())
}

func TestStaticPassword_Validate_MissingName(t *testing.T) {
	pw := &StaticPassword{
		Name:     "",
		Password: "secret123",
	}
	assert.ErrorIs(t, pw.Validate(), ErrInvalidName)
}

func TestStaticPassword_Validate_WhitespaceName(t *testing.T) {
	pw := &StaticPassword{
		Name:     "   ",
		Password: "secret123",
	}
	assert.ErrorIs(t, pw.Validate(), ErrInvalidName)
}

func TestStaticPassword_Validate_EmptyPassword(t *testing.T) {
	pw := &StaticPassword{
		Name:     "test-entry",
		Password: "",
	}
	assert.ErrorIs(t, pw.Validate(), ErrEmptyPassword)
}

func TestStaticPassword_DisplayTitle_WithTitle(t *testing.T) {
	pw := &StaticPassword{
		Name:  "entry-name",
		Title: "My Title",
	}
	assert.Equal(t, "My Title", pw.DisplayTitle())
}

func TestStaticPassword_DisplayTitle_FallsBackToName(t *testing.T) {
	pw := &StaticPassword{
		Name:  "entry-name",
		Title: "",
	}
	assert.Equal(t, "entry-name", pw.DisplayTitle())
}

func TestStaticPassword_FieldsSerialization(t *testing.T) {
	now := time.Now().UTC()
	pw := &StaticPassword{
		ID:         "abc123",
		Name:       "gmail",
		Title:      "Gmail Account",
		Username:   "user@gmail.com",
		Password:   "secret",
		URL:        "https://gmail.com",
		Notes:      "personal account",
		FolderPath: "email",
		ExpiresAt:  now.Add(24 * time.Hour),
		CreatedAt:  now,
		UpdatedAt:  now,
		ReadOnly:   true,
	}
	assert.Equal(t, "abc123", pw.ID)
	assert.Equal(t, "gmail", pw.Name)
	assert.Equal(t, "Gmail Account", pw.Title)
	assert.Equal(t, "user@gmail.com", pw.Username)
	assert.Equal(t, "secret", pw.Password)
	assert.Equal(t, "https://gmail.com", pw.URL)
	assert.Equal(t, "personal account", pw.Notes)
	assert.Equal(t, "email", pw.FolderPath)
	assert.True(t, pw.ReadOnly)
}

func TestGenerateID_Deterministic(t *testing.T) {
	id1 := GenerateID("MyEntry", "")
	id2 := GenerateID("MyEntry", "")
	assert.Equal(t, id1, id2, "same inputs must produce the same ID")
	assert.Len(t, id1, 16, "ID must be a 16-char hex string")
}

func TestGenerateID_CaseInsensitive(t *testing.T) {
	id1 := GenerateID("MyEntry", "")
	id2 := GenerateID("myentry", "")
	assert.Equal(t, id1, id2, "IDs must be case-insensitive")
}

func TestGenerateID_WithFolder(t *testing.T) {
	id := GenerateID("Gmail", "email/personal")
	assert.Len(t, id, 16, "ID with folder must be a 16-char hex string")
	// Same folder+name must produce same ID regardless of case.
	id2 := GenerateID("gmail", "email/personal")
	assert.Equal(t, id, id2)
}

func TestGenerateID_DifferentInputsDifferentIDs(t *testing.T) {
	id1 := GenerateID("entry-a", "")
	id2 := GenerateID("entry-b", "")
	assert.NotEqual(t, id1, id2, "different names must produce different IDs")
}

func TestGenerateID_FolderChangesID(t *testing.T) {
	id1 := GenerateID("entry", "")
	id2 := GenerateID("entry", "work")
	assert.NotEqual(t, id1, id2, "different folders must produce different IDs")
}

func TestStaticPassword_Validate_AllFieldsPopulated(t *testing.T) {
	pw := &StaticPassword{
		Name:       "full-entry",
		Password:   "secret123",
		Title:      "Full Entry",
		Username:   "user",
		URL:        "https://example.com",
		Notes:      "some notes",
		FolderPath: "folder/sub",
	}
	assert.NoError(t, pw.Validate())
}
