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

//go:build integration

package pwimport

import (
	"os"
	"testing"
)

func TestRealCSVFile(t *testing.T) {
	filePath := "/home/jhahn/test.csv"
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Skip("Real test CSV file not found")
	}

	p := NewCSVParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	t.Logf("Parsed %d entries from real CSV", len(entries))
	for i, e := range entries {
		t.Logf("  [%d] Title=%q, User=%q, HasTOTP=%v, FolderPath=%q",
			i+1, e.Title, e.Username, e.HasTOTP, e.FolderPath)
	}

	// Verify we got the expected entries.
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
}

func TestRealXMLFile(t *testing.T) {
	filePath := "/home/jhahn/test.xml"
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Skip("Real test XML file not found")
	}

	p := NewXMLParser()
	entries, err := p.Parse(filePath, nil)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	t.Logf("Parsed %d entries from real XML", len(entries))
	for i, e := range entries {
		t.Logf("  [%d] Title=%q, User=%q, Tags=%v, HasTOTP=%v, FolderPath=%q",
			i+1, e.Title, e.Username, e.Tags, e.HasTOTP, e.FolderPath)
	}

	// Verify we got the expected entries.
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}
}

func TestRealKDBXFile(t *testing.T) {
	filePath := "/home/jhahn/test.kdbx"
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Skip("Real test KDBX file not found")
	}

	p := NewKDBXParser()

	// Test without password - should fail.
	_, err := p.Parse(filePath, nil)
	if err != ErrPasswordRequired {
		t.Errorf("Expected ErrPasswordRequired, got %v", err)
	}

	// Test with wrong password - should fail.
	_, err = p.Parse(filePath, &ImportOptions{Password: "wrongpassword"})
	if err == nil {
		t.Error("Expected error for wrong password")
	}

	// Note: We can't test with the correct password without knowing it.
	// The user would need to provide the password for a complete test.
	t.Log("KDBX parser requires correct password to test fully")
}
