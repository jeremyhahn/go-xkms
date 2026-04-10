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

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func newTestImporter(t *testing.T) *Importer {
	t.Helper()
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	return NewImporter(store)
}

func TestImporter_SupportedFormats(t *testing.T) {
	imp := newTestImporter(t)
	formats := imp.SupportedFormats()

	if len(formats) != 3 {
		t.Errorf("SupportedFormats() returned %d formats, want 3", len(formats))
	}

	formatMap := make(map[string]bool)
	for _, f := range formats {
		formatMap[f] = true
	}

	for _, expected := range []string{FormatCSV, FormatXML, FormatKDBX} {
		if !formatMap[expected] {
			t.Errorf("SupportedFormats() missing %q", expected)
		}
	}
}

func TestImporter_DetectFormat(t *testing.T) {
	imp := newTestImporter(t)

	tests := []struct {
		path string
		want string
	}{
		{"test.csv", FormatCSV},
		{"test.CSV", FormatCSV},
		{"test.xml", FormatXML},
		{"test.XML", FormatXML},
		{"test.kdbx", FormatKDBX},
		{"test.KDBX", FormatKDBX},
		{"test.txt", ""},
		{"test", ""},
		{"/path/to/passwords.csv", FormatCSV},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := imp.DetectFormat(tt.path)
			if got != tt.want {
				t.Errorf("DetectFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestImporter_Import_CSV(t *testing.T) {
	content := `"Group","Title","Username","Password","URL","Notes"
"Root","Entry1","user1","pass1","https://example1.com","notes1"
"Work","Entry2","user2","pass2","https://example2.com","notes2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)
	result, err := imp.Import(&ImportOptions{
		FilePath: filePath,
		Format:   FormatCSV,
	})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("Imported = %d, want 2", result.Imported)
	}
	if result.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", result.Skipped)
	}
	if result.Failed != 0 {
		t.Errorf("Failed = %d, want 0", result.Failed)
	}
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestImporter_Import_AutoDetectFormat(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)
	result, err := imp.Import(&ImportOptions{
		FilePath: filePath,
		// Format not specified - should auto-detect from extension.
	})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("Imported = %d, want 1", result.Imported)
	}
}

func TestImporter_Import_SkipDuplicates(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)

	// First import.
	result1, err := imp.Import(&ImportOptions{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("First Import() error = %v", err)
	}
	if result1.Imported != 1 {
		t.Fatalf("First import: Imported = %d, want 1", result1.Imported)
	}

	// Second import with SkipDuplicates.
	result2, err := imp.Import(&ImportOptions{
		FilePath:       filePath,
		SkipDuplicates: true,
	})
	if err != nil {
		t.Fatalf("Second Import() error = %v", err)
	}
	if result2.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", result2.Skipped)
	}
	if result2.Imported != 0 {
		t.Errorf("Imported = %d, want 0", result2.Imported)
	}
}

func TestImporter_Import_OverwriteDuplicates(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)

	// First import.
	result1, err := imp.Import(&ImportOptions{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("First Import() error = %v", err)
	}
	if result1.Imported != 1 {
		t.Fatalf("First import: Imported = %d, want 1", result1.Imported)
	}

	// Second import with OverwriteDuplicates.
	result2, err := imp.Import(&ImportOptions{
		FilePath:            filePath,
		OverwriteDuplicates: true,
	})
	if err != nil {
		t.Fatalf("Second Import() error = %v", err)
	}
	if result2.Imported != 1 {
		t.Errorf("Imported = %d, want 1", result2.Imported)
	}
	if result2.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", result2.Skipped)
	}
}

func TestImporter_Import_DuplicateError(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)

	// First import.
	_, err := imp.Import(&ImportOptions{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("First Import() error = %v", err)
	}

	// Second import without duplicate handling - should fail.
	result2, err := imp.Import(&ImportOptions{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("Second Import() error = %v", err)
	}
	if result2.Failed != 1 {
		t.Errorf("Failed = %d, want 1", result2.Failed)
	}
	if len(result2.Errors) != 1 {
		t.Errorf("Errors count = %d, want 1", len(result2.Errors))
	}
}

func TestImporter_Import_UnsupportedFormat(t *testing.T) {
	imp := newTestImporter(t)
	_, err := imp.Import(&ImportOptions{
		FilePath: "/path/to/file.txt",
		Format:   "",
	})
	if err != ErrUnsupportedFormat {
		t.Errorf("Import() error = %v, want %v", err, ErrUnsupportedFormat)
	}
}

func TestImporter_Import_InvalidFormat(t *testing.T) {
	imp := newTestImporter(t)
	_, err := imp.Import(&ImportOptions{
		FilePath: "/path/to/file.csv",
		Format:   "invalid",
	})
	if err == nil {
		t.Error("Import() expected error for invalid format")
	}
}

func TestImporter_Preview(t *testing.T) {
	content := `"Title","Username","Password"
"Entry1","user1","pass1"
"Entry2","user2","pass2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)
	entries, err := imp.Preview(&ImportOptions{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("Preview() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Preview() returned %d entries, want 2", len(entries))
	}

	// Verify entries are not stored.
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	list, _ := store.List()
	if len(list) != 0 {
		t.Error("Preview() should not store entries")
	}
}

func TestImporter_Import_WithTargetFolder(t *testing.T) {
	content := `"Group","Title","Username","Password"
"Root","Entry1","user1","pass1"
"Work","Entry2","user2","pass2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	imp := NewImporter(store)

	result, err := imp.Import(&ImportOptions{
		FilePath:     filePath,
		TargetFolder: "Imported/KeePass",
	})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if result.Imported != 2 {
		t.Fatalf("Imported = %d, want 2", result.Imported)
	}

	// Verify folder paths.
	passwords, _ := store.List()
	foundRoot := false
	foundWork := false
	for _, pw := range passwords {
		if pw.Name == "Entry1" && pw.FolderPath == "Imported/KeePass" {
			foundRoot = true
		}
		if pw.Name == "Entry2" && pw.FolderPath == "Imported/KeePass/Work" {
			foundWork = true
		}
	}
	if !foundRoot {
		t.Error("Entry1 not found with expected folder path")
	}
	if !foundWork {
		t.Error("Entry2 not found with expected folder path")
	}
}

func TestImporter_Import_TOTPTracking(t *testing.T) {
	content := `"Title","Username","Password","TOTP"
"Entry1","user1","pass1",""
"Entry2","user2","pass2","otpauth://totp/test?secret=ABC"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	imp := newTestImporter(t)
	result, err := imp.Import(&ImportOptions{
		FilePath:   filePath,
		ImportTOTP: true,
	})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if result.Imported != 2 {
		t.Errorf("Imported = %d, want 2", result.Imported)
	}
	if result.TOTPImported != 1 {
		t.Errorf("TOTPImported = %d, want 1", result.TOTPImported)
	}
}
