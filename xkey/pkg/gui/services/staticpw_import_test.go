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

package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

func newTestStaticPWImportService(t *testing.T) *StaticPasswordService {
	t.Helper()
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	return NewStaticPasswordService(store)
}

func TestStaticPasswordService_GetSupportedImportFormats(t *testing.T) {
	svc := newTestStaticPWImportService(t)
	formats := svc.GetSupportedImportFormats()

	if len(formats) != 3 {
		t.Errorf("GetSupportedImportFormats() returned %d formats, want 3", len(formats))
	}

	expected := map[string]bool{"csv": false, "xml": false, "kdbx": false}
	for _, f := range formats {
		if _, ok := expected[f]; ok {
			expected[f] = true
		} else {
			t.Errorf("Unexpected format: %s", f)
		}
	}

	for f, found := range expected {
		if !found {
			t.Errorf("Missing expected format: %s", f)
		}
	}
}

func TestStaticPasswordService_ImportPasswords_CSV(t *testing.T) {
	content := `"Group","Title","Username","Password","URL","Notes"
"Root","Entry1","user1","pass1","https://example1.com","notes1"
"Work","Entry2","user2","pass2","https://example2.com","notes2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	svc := newTestStaticPWImportService(t)
	result, err := svc.ImportPasswords(ImportParams{
		FilePath: filePath,
		Format:   "csv",
	})
	if err != nil {
		t.Fatalf("ImportPasswords() error = %v", err)
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
	if result.DurationMs < 0 {
		t.Error("DurationMs should be non-negative")
	}

	// Verify passwords were stored.
	passwords, err := svc.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords() error = %v", err)
	}
	if len(passwords) != 2 {
		t.Errorf("ListPasswords() returned %d, want 2", len(passwords))
	}
}

func TestStaticPasswordService_ImportPasswords_XML(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group>
			<UUID>root123</UUID>
			<Name>Root</Name>
			<Entry>
				<UUID>entry1</UUID>
				<String><Key>Password</Key><Value>xmlpass</Value></String>
				<String><Key>Title</Key><Value>XMLEntry</Value></String>
				<String><Key>UserName</Key><Value>xmluser</Value></String>
			</Entry>
		</Group>
		<DeletedObjects/>
	</Root>
</KeePassFile>
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.xml")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	svc := newTestStaticPWImportService(t)
	result, err := svc.ImportPasswords(ImportParams{
		FilePath: filePath,
		Format:   "xml",
	})
	if err != nil {
		t.Fatalf("ImportPasswords() error = %v", err)
	}

	if result.Imported != 1 {
		t.Errorf("Imported = %d, want 1", result.Imported)
	}

	// Verify password was stored correctly.
	passwords, err := svc.ListPasswords()
	if err != nil {
		t.Fatalf("ListPasswords() error = %v", err)
	}
	if len(passwords) != 1 {
		t.Fatalf("ListPasswords() returned %d, want 1", len(passwords))
	}
	if passwords[0].Title != "XMLEntry" {
		t.Errorf("Title = %q, want %q", passwords[0].Title, "XMLEntry")
	}
}

func TestStaticPasswordService_PreviewImport(t *testing.T) {
	content := `"Title","Username","Password"
"Preview1","user1","pass1"
"Preview2","user2","pass2"
"Preview3","user3","pass3"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	svc := newTestStaticPWImportService(t)
	preview, err := svc.PreviewImport(ImportParams{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("PreviewImport() error = %v", err)
	}

	if preview.Total != 3 {
		t.Errorf("Total = %d, want 3", preview.Total)
	}
	if len(preview.Entries) != 3 {
		t.Errorf("Entries count = %d, want 3", len(preview.Entries))
	}
	if preview.Format != "csv" {
		t.Errorf("Format = %q, want %q", preview.Format, "csv")
	}

	// Verify preview entries.
	for i, e := range preview.Entries {
		expected := []string{"Preview1", "Preview2", "Preview3"}[i]
		if e.Title != expected {
			t.Errorf("Entry[%d] Title = %q, want %q", i, e.Title, expected)
		}
	}

	// Verify passwords were NOT stored (preview only).
	passwords, _ := svc.ListPasswords()
	if len(passwords) != 0 {
		t.Errorf("PreviewImport should not store passwords, but got %d", len(passwords))
	}
}

func TestStaticPasswordService_ImportPasswords_WithTargetFolder(t *testing.T) {
	content := `"Group","Title","Username","Password"
"Root","Entry1","user1","pass1"
"Work","Entry2","user2","pass2"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	svc := newTestStaticPWImportService(t)
	result, err := svc.ImportPasswords(ImportParams{
		FilePath:     filePath,
		TargetFolder: "Imported/KeePass",
	})
	if err != nil {
		t.Fatalf("ImportPasswords() error = %v", err)
	}

	if result.Imported != 2 {
		t.Fatalf("Imported = %d, want 2", result.Imported)
	}

	// Verify folder paths.
	passwords, _ := svc.ListPasswords()
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

func TestStaticPasswordService_ImportPasswords_SkipDuplicates(t *testing.T) {
	content := `"Title","Password"
"TestEntry","testpass"
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.csv")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	svc := newTestStaticPWImportService(t)

	// First import.
	result1, err := svc.ImportPasswords(ImportParams{
		FilePath: filePath,
	})
	if err != nil {
		t.Fatalf("First ImportPasswords() error = %v", err)
	}
	if result1.Imported != 1 {
		t.Fatalf("First import: Imported = %d, want 1", result1.Imported)
	}

	// Second import with skip duplicates.
	result2, err := svc.ImportPasswords(ImportParams{
		FilePath:       filePath,
		SkipDuplicates: true,
	})
	if err != nil {
		t.Fatalf("Second ImportPasswords() error = %v", err)
	}
	if result2.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", result2.Skipped)
	}
	if result2.Imported != 0 {
		t.Errorf("Imported = %d, want 0", result2.Imported)
	}
}

func TestStaticPasswordService_ImportPasswords_InvalidFile(t *testing.T) {
	svc := newTestStaticPWImportService(t)

	// Empty path.
	_, err := svc.ImportPasswords(ImportParams{})
	if err == nil {
		t.Error("ImportPasswords() expected error for empty path")
	}

	// Non-existent file.
	_, err = svc.ImportPasswords(ImportParams{
		FilePath: "/nonexistent/file.csv",
	})
	if err == nil {
		t.Error("ImportPasswords() expected error for non-existent file")
	}
}

func TestStaticPasswordService_ImportPasswords_NoStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)

	_, err := svc.ImportPasswords(ImportParams{
		FilePath: "/some/file.csv",
	})
	if err != ErrStaticPWStoreNotSet {
		t.Errorf("ImportPasswords() error = %v, want %v", err, ErrStaticPWStoreNotSet)
	}

	_, err = svc.PreviewImport(ImportParams{
		FilePath: "/some/file.csv",
	})
	if err != ErrStaticPWStoreNotSet {
		t.Errorf("PreviewImport() error = %v, want %v", err, ErrStaticPWStoreNotSet)
	}
}
