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
)

func TestCSVParser_Format(t *testing.T) {
	p := NewCSVParser()
	if got := p.Format(); got != FormatCSV {
		t.Errorf("Format() = %v, want %v", got, FormatCSV)
	}
}

func TestCSVParser_Parse_ValidFile(t *testing.T) {
	// Create a test CSV file.
	content := `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","Test Entry","testuser","secretpass","https://example.com","Test notes","","0","2026-03-02T17:51:09Z","2026-03-02T17:50:28Z"
"Work/Email","Gmail","user@gmail.com","gmailpass","https://gmail.com","Gmail account","otpauth://totp/test?secret=ABC","0","2026-03-02T18:00:00Z","2026-03-02T17:00:00Z"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// Verify first entry (Root group is ignored).
	entry1 := entries[0]
	if entry1.Title != "Test Entry" {
		t.Errorf("Entry 1 Title = %q, want %q", entry1.Title, "Test Entry")
	}
	if entry1.Username != "testuser" {
		t.Errorf("Entry 1 Username = %q, want %q", entry1.Username, "testuser")
	}
	if entry1.Password != "secretpass" {
		t.Errorf("Entry 1 Password = %q, want %q", entry1.Password, "secretpass")
	}
	if entry1.URL != "https://example.com" {
		t.Errorf("Entry 1 URL = %q, want %q", entry1.URL, "https://example.com")
	}
	if entry1.FolderPath != "" {
		t.Errorf("Entry 1 FolderPath = %q, want empty (Root)", entry1.FolderPath)
	}

	// Verify second entry with folder and TOTP.
	entry2 := entries[1]
	if entry2.Title != "Gmail" {
		t.Errorf("Entry 2 Title = %q, want %q", entry2.Title, "Gmail")
	}
	if entry2.FolderPath != "Work/Email" {
		t.Errorf("Entry 2 FolderPath = %q, want %q", entry2.FolderPath, "Work/Email")
	}
	if !entry2.HasTOTP {
		t.Error("Entry 2 HasTOTP = false, want true")
	}
	if entry2.TOTPURL != "otpauth://totp/test?secret=ABC" {
		t.Errorf("Entry 2 TOTPURL = %q, want %q", entry2.TOTPURL, "otpauth://totp/test?secret=ABC")
	}
}

func TestCSVParser_Parse_WithTargetFolder(t *testing.T) {
	content := `"Group","Title","Username","Password","URL","Notes"
"Root","Entry1","user1","pass1","","notes1"
"SubFolder","Entry2","user2","pass2","","notes2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	opts := &ImportOptions{
		TargetFolder: "Imported/KeePass",
	}
	entries, err := p.Parse(filePath, opts)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// Root entries get just the target folder.
	if entries[0].FolderPath != "Imported/KeePass" {
		t.Errorf("Entry 1 FolderPath = %q, want %q", entries[0].FolderPath, "Imported/KeePass")
	}

	// SubFolder entries get target/original.
	if entries[1].FolderPath != "Imported/KeePass/SubFolder" {
		t.Errorf("Entry 2 FolderPath = %q, want %q", entries[1].FolderPath, "Imported/KeePass/SubFolder")
	}
}

func TestCSVParser_Parse_AlternativeColumnNames(t *testing.T) {
	// Test with alternative column names like "folder", "user", "pass".
	content := `"Folder","Name","User","Pass","Website"
"Work","MyBank","bankuser","bankpass","https://bank.com"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Title != "MyBank" {
		t.Errorf("Title = %q, want %q", entry.Title, "MyBank")
	}
	if entry.Username != "bankuser" {
		t.Errorf("Username = %q, want %q", entry.Username, "bankuser")
	}
	if entry.Password != "bankpass" {
		t.Errorf("Password = %q, want %q", entry.Password, "bankpass")
	}
	if entry.FolderPath != "Work" {
		t.Errorf("FolderPath = %q, want %q", entry.FolderPath, "Work")
	}
}

func TestCSVParser_Parse_MissingPasswordColumn(t *testing.T) {
	content := `"Group","Title","Username","URL"
"Root","Entry1","user1","https://example.com"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	_, err := p.Parse(filePath, nil)
	if err == nil {
		t.Fatal("Parse() expected error for missing password column")
	}
}

func TestCSVParser_Parse_MissingIdentifierColumn(t *testing.T) {
	content := `"Group","Password","URL"
"Root","pass1","https://example.com"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	_, err := p.Parse(filePath, nil)
	if err == nil {
		t.Fatal("Parse() expected error for missing title/username column")
	}
}

func TestCSVParser_Parse_EmptyFile(t *testing.T) {
	content := `"Group","Title","Password"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	_, err := p.Parse(filePath, nil)
	if err != ErrNoEntriesFound {
		t.Errorf("Parse() error = %v, want %v", err, ErrNoEntriesFound)
	}
}

func TestCSVParser_Parse_NonexistentFile(t *testing.T) {
	p := NewCSVParser()
	_, err := p.Parse("/nonexistent/file.csv", nil)
	if err == nil {
		t.Fatal("Parse() expected error for nonexistent file")
	}
}

func TestCSVParser_Parse_Timestamps(t *testing.T) {
	content := `"Title","Password","Created","Last Modified"
"Entry1","pass1","2026-03-02T10:00:00Z","2026-03-02T12:00:00Z"
"Entry2","pass2","2026-03-02","2026-03-02 15:00:00"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// First entry with RFC3339 timestamps.
	expectedCreated1 := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)
	if !entries[0].CreatedAt.Equal(expectedCreated1) {
		t.Errorf("Entry 1 CreatedAt = %v, want %v", entries[0].CreatedAt, expectedCreated1)
	}

	// Second entry with date-only format.
	if entries[1].CreatedAt.IsZero() {
		t.Error("Entry 2 CreatedAt should not be zero")
	}
}

func TestCSVParser_Parse_SkipsEmptyPasswords(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
"Entry2","user2",""
"Entry3","user3","pass3"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewCSVParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Entry with empty password should be skipped.
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2 (empty password skipped)", len(entries))
	}

	if entries[0].Title != "Entry1" {
		t.Errorf("Entry 1 Title = %q, want %q", entries[0].Title, "Entry1")
	}
	if entries[1].Title != "Entry3" {
		t.Errorf("Entry 2 Title = %q, want %q", entries[1].Title, "Entry3")
	}
}
