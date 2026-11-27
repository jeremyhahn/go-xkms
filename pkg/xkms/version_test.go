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

package xkms

import (
	"runtime/debug"
	"strings"
	"testing"
)

// TestLibraryVersion_FromBuildInfo: when go-xkms is imported by another
// application, debug.BuildInfo.Main is that application, so the library
// version must come from the go-xkms entry in Deps (Codex round 1 at
// 043aaf2e3 on #2322).
func TestLibraryVersion_FromBuildInfo(t *testing.T) {
	const mod = "github.com/jeremyhahn/go-xkms"
	app := debug.Module{Path: "example.com/app", Version: "v9.9.9"}
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "imported dependency",
			info: &debug.BuildInfo{Main: app, Deps: []*debug.Module{
				{Path: "example.com/other", Version: "v1.0.0"},
				{Path: mod, Version: "v0.64.2-alpha"},
			}},
			want: "v0.64.2-alpha",
		},
		{
			name: "replaced dependency",
			info: &debug.BuildInfo{Main: app, Deps: []*debug.Module{
				{Path: mod, Version: "v0.64.2-alpha", Replace: &debug.Module{Path: "example.com/fork", Version: "v0.64.3-alpha"}},
			}},
			want: "v0.64.3-alpha",
		},
		{
			name: "local directory replace",
			info: &debug.BuildInfo{Main: app, Deps: []*debug.Module{
				{Path: mod, Version: "v0.64.2-alpha", Replace: &debug.Module{Path: "../go-xkms"}},
			}},
			want: "unknown",
		},
		{
			name: "no go-xkms dependency",
			info: &debug.BuildInfo{Main: app},
			want: "unknown",
		},
		{
			name: "go-xkms main module",
			info: &debug.BuildInfo{Main: debug.Module{Path: mod, Version: "v0.65.0"}},
			want: "v0.65.0",
		},
		{
			name: "go-xkms devel build",
			info: &debug.BuildInfo{Main: debug.Module{Path: mod, Version: "(devel)"}},
			want: "unknown",
		},
		{
			name: "nil info",
			info: nil,
			want: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := libraryVersion(tt.info); got != tt.want {
				t.Fatalf("libraryVersion() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	// Version() reports the linker-set buildVersion (unset under go test)
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

func TestVersion_Readable(t *testing.T) {
	// Version reports the linker-set value, the module version or "unknown"
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
		t.Log("no linker version set, got 'unknown' as expected")
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
