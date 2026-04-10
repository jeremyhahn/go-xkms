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
)

func TestXMLParser_Format(t *testing.T) {
	p := NewXMLParser()
	if got := p.Format(); got != FormatXML {
		t.Errorf("Format() = %v, want %v", got, FormatXML)
	}
}

func TestXMLParser_Parse_ValidFile(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta>
		<Generator>KeePassXC</Generator>
		<DatabaseName>test</DatabaseName>
	</Meta>
	<Root>
		<Group>
			<UUID>YHJwm2yOSrOD1vXLrOenTw==</UUID>
			<Name>Root</Name>
			<Entry>
				<UUID>FDK3qtgKRtO4b4+nBYRY1g==</UUID>
				<IconID>0</IconID>
				<Tags>tag1,tag2</Tags>
				<Times>
					<CreationTime>2026-03-02T10:00:00Z</CreationTime>
					<LastModificationTime>2026-03-02T12:00:00Z</LastModificationTime>
					<ExpiryTime>2026-12-31T23:59:59Z</ExpiryTime>
					<Expires>True</Expires>
				</Times>
				<String>
					<Key>Notes</Key>
					<Value>Test notes</Value>
				</String>
				<String>
					<Key>Password</Key>
					<Value ProtectInMemory="True">secretpass</Value>
				</String>
				<String>
					<Key>Title</Key>
					<Value>Test Entry</Value>
				</String>
				<String>
					<Key>URL</Key>
					<Value>https://example.com</Value>
				</String>
				<String>
					<Key>UserName</Key>
					<Value>testuser</Value>
				</String>
			</Entry>
			<Group>
				<UUID>subgroup123</UUID>
				<Name>Work</Name>
				<Entry>
					<UUID>workentry123</UUID>
					<IconID>1</IconID>
					<Tags></Tags>
					<Times>
						<CreationTime>2026-03-02T09:00:00Z</CreationTime>
						<LastModificationTime>2026-03-02T09:00:00Z</LastModificationTime>
						<Expires>False</Expires>
					</Times>
					<String>
						<Key>Password</Key>
						<Value>workpass</Value>
					</String>
					<String>
						<Key>Title</Key>
						<Value>Work Entry</Value>
					</String>
					<String>
						<Key>UserName</Key>
						<Value>workuser</Value>
					</String>
					<String>
						<Key>otp</Key>
						<Value ProtectInMemory="True">otpauth://totp/Work:workuser?secret=ABC123</Value>
					</String>
				</Entry>
			</Group>
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

	p := NewXMLParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	// Verify first entry (in root group).
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
	if entry1.Notes != "Test notes" {
		t.Errorf("Entry 1 Notes = %q, want %q", entry1.Notes, "Test notes")
	}
	if entry1.FolderPath != "" {
		t.Errorf("Entry 1 FolderPath = %q, want empty", entry1.FolderPath)
	}
	if len(entry1.Tags) != 2 || entry1.Tags[0] != "tag1" || entry1.Tags[1] != "tag2" {
		t.Errorf("Entry 1 Tags = %v, want [tag1, tag2]", entry1.Tags)
	}
	if entry1.ExpiresAt.IsZero() {
		t.Error("Entry 1 ExpiresAt should not be zero")
	}

	// Verify second entry (in Work subgroup with TOTP).
	entry2 := entries[1]
	if entry2.Title != "Work Entry" {
		t.Errorf("Entry 2 Title = %q, want %q", entry2.Title, "Work Entry")
	}
	if entry2.FolderPath != "Work" {
		t.Errorf("Entry 2 FolderPath = %q, want %q", entry2.FolderPath, "Work")
	}
	if !entry2.HasTOTP {
		t.Error("Entry 2 HasTOTP = false, want true")
	}
	if entry2.TOTPURL != "otpauth://totp/Work:workuser?secret=ABC123" {
		t.Errorf("Entry 2 TOTPURL = %q, want otpauth://...", entry2.TOTPURL)
	}
}

func TestXMLParser_Parse_WithTargetFolder(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group>
			<UUID>root123</UUID>
			<Name>Root</Name>
			<Entry>
				<UUID>entry1</UUID>
				<String><Key>Password</Key><Value>pass1</Value></String>
				<String><Key>Title</Key><Value>Entry1</Value></String>
			</Entry>
			<Group>
				<UUID>sub1</UUID>
				<Name>SubFolder</Name>
				<Entry>
					<UUID>entry2</UUID>
					<String><Key>Password</Key><Value>pass2</Value></String>
					<String><Key>Title</Key><Value>Entry2</Value></String>
				</Entry>
			</Group>
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

	p := NewXMLParser()
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

func TestXMLParser_Parse_InvalidXML(t *testing.T) {
	content := `not valid xml at all`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.xml")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewXMLParser()
	_, err := p.Parse(filePath, nil)
	if err == nil {
		t.Fatal("Parse() expected error for invalid XML")
	}
}

func TestXMLParser_Parse_MissingRootGroup(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group></Group>
		<DeletedObjects/>
	</Root>
</KeePassFile>
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.xml")
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	p := NewXMLParser()
	_, err := p.Parse(filePath, nil)
	if err == nil {
		t.Fatal("Parse() expected error for missing root group UUID")
	}
}

func TestXMLParser_Parse_EmptyDatabase(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group>
			<UUID>root123</UUID>
			<Name>Root</Name>
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

	p := NewXMLParser()
	_, err := p.Parse(filePath, nil)
	if err != ErrNoEntriesFound {
		t.Errorf("Parse() error = %v, want %v", err, ErrNoEntriesFound)
	}
}

func TestXMLParser_Parse_NonexistentFile(t *testing.T) {
	p := NewXMLParser()
	_, err := p.Parse("/nonexistent/file.xml", nil)
	if err == nil {
		t.Fatal("Parse() expected error for nonexistent file")
	}
}

func TestXMLParser_Parse_SkipsEmptyPasswords(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group>
			<UUID>root123</UUID>
			<Name>Root</Name>
			<Entry>
				<UUID>entry1</UUID>
				<String><Key>Password</Key><Value>pass1</Value></String>
				<String><Key>Title</Key><Value>Entry1</Value></String>
			</Entry>
			<Entry>
				<UUID>entry2</UUID>
				<String><Key>Password</Key><Value></Value></String>
				<String><Key>Title</Key><Value>Entry2</Value></String>
			</Entry>
			<Entry>
				<UUID>entry3</UUID>
				<String><Key>Password</Key><Value>pass3</Value></String>
				<String><Key>Title</Key><Value>Entry3</Value></String>
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

	p := NewXMLParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Entry with empty password should be skipped.
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2 (empty password skipped)", len(entries))
	}
}

func TestXMLParser_Parse_NestedGroups(t *testing.T) {
	content := `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
	<Meta><DatabaseName>test</DatabaseName></Meta>
	<Root>
		<Group>
			<UUID>root123</UUID>
			<Name>Root</Name>
			<Group>
				<UUID>level1</UUID>
				<Name>Level1</Name>
				<Group>
					<UUID>level2</UUID>
					<Name>Level2</Name>
					<Entry>
						<UUID>deepentry</UUID>
						<String><Key>Password</Key><Value>deeppass</Value></String>
						<String><Key>Title</Key><Value>DeepEntry</Value></String>
					</Entry>
				</Group>
			</Group>
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

	p := NewXMLParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	if entries[0].FolderPath != "Level1/Level2" {
		t.Errorf("FolderPath = %q, want %q", entries[0].FolderPath, "Level1/Level2")
	}
}
