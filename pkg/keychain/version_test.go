// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	// The Version() function reads from the VERSION file in the project root
	version := Version()

	// Should not be empty
	if version == "" {
		t.Error("Version() returned empty string")
	}

	// Should return something (either actual version or "unknown")
	if version != "unknown" {
		// If we got a version, verify it's a reasonable format
		if len(version) < 1 {
			t.Errorf("Version() returned invalid version: %s", version)
		}
	}

	t.Logf("Library version: %s", version)
}

func TestVersion_WithVersionFile(t *testing.T) {
	// Create a temporary VERSION file for testing
	tempDir := t.TempDir()
	versionFile := filepath.Join(tempDir, "VERSION")

	testVersion := "v1.2.3-test"
	err := os.WriteFile(versionFile, []byte(testVersion), 0644)
	if err != nil {
		t.Fatalf("Failed to create test VERSION file: %v", err)
	}

	// Note: We can't easily test this without modifying the function
	// to accept a path parameter, but we can verify the current behavior
	version := Version()

	// Version should be either the real version or "unknown"
	// depending on whether VERSION file exists in the project root
	if version == "" {
		t.Error("Version() should never return empty string")
	}
}

func TestVersion_Consistency(t *testing.T) {
	// Version should return the same value on multiple calls
	version1 := Version()
	version2 := Version()

	if version1 != version2 {
		t.Errorf("Version() not consistent: got %s and %s", version1, version2)
	}
}

func TestVersion_NotPanic(t *testing.T) {
	// Ensure Version() doesn't panic even in edge cases
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Version() panicked: %v", r)
		}
	}()

	// Call multiple times to ensure no panic
	for i := 0; i < 10; i++ {
		_ = Version()
	}
}

func TestVersion_NotEmpty(t *testing.T) {
	// Version should never return an empty string
	version := Version()
	if version == "" {
		t.Error("Version() returned empty string, expected 'unknown' at minimum")
	}
}

func TestVersion_CallerEdgeCase(t *testing.T) {
	// The Version function uses runtime.Caller internally
	// This test ensures it handles the path correctly
	version := Version()

	// Version should be either a valid version string or "unknown"
	if version == "" {
		t.Error("Version() returned empty string")
	}

	// It should always return something readable
	if len(version) > 1000 {
		t.Errorf("Version() returned suspiciously long string: %d chars", len(version))
	}
}

func TestVersion_ThreadSafe(t *testing.T) {
	// Test that Version() is thread-safe
	done := make(chan bool)
	results := make(chan string, 100)

	// Start 100 goroutines calling Version() concurrently
	for i := 0; i < 100; i++ {
		go func() {
			results <- Version()
			done <- true
		}()
	}

	// Wait for all goroutines to finish
	for i := 0; i < 100; i++ {
		<-done
	}
	close(results)

	// Verify all results are identical
	var firstVersion string
	count := 0
	for v := range results {
		if count == 0 {
			firstVersion = v
		}
		if v != firstVersion {
			t.Errorf("Version() not consistent across goroutines: got %s and %s", firstVersion, v)
		}
		count++
	}

	if count != 100 {
		t.Errorf("Expected 100 results, got %d", count)
	}
}

func TestVersion_ValidFormat(t *testing.T) {
	version := Version()

	// Version should either be "unknown" or follow a version format
	if version == "unknown" {
		t.Log("VERSION file not found or empty, got 'unknown' as expected")
		return
	}

	// If we got a version, it should be a reasonable string
	if len(version) == 0 {
		t.Error("Version string is empty")
	}

	// Version string shouldn't contain newlines
	if strings.Contains(version, "\n") {
		t.Errorf("Version() contains newlines: %q", version)
	}

	// Version string shouldn't contain carriage returns
	if strings.Contains(version, "\r") {
		t.Errorf("Version() contains carriage returns: %q", version)
	}
}
