// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestResolveConnection_RemoteFromEnv(t *testing.T) {
	t.Setenv("XKMS_DESKTOP_MODE", "remote")
	t.Setenv("XKMS_SERVER_URL", "https://xkms.example:8443")

	conn, cleanup, err := resolveConnection(context.Background(), slog.Default())
	if err != nil {
		t.Fatalf("resolveConnection: %v", err)
	}
	defer cleanup()

	if conn.Mode != ModeRemote {
		t.Errorf("mode = %q, want remote", conn.Mode)
	}
	if conn.BaseURL != "https://xkms.example:8443" {
		t.Errorf("base_url = %q", conn.BaseURL)
	}
	if conn.Token != "" {
		t.Errorf("remote mode must not carry a token, got %q", conn.Token)
	}
}

func TestResolveConnection_RemoteRequiresURL(t *testing.T) {
	t.Setenv("XKMS_DESKTOP_MODE", "remote")
	t.Setenv("XKMS_SERVER_URL", "")
	// Point the bookmark store at an empty temp config dir so no saved
	// bookmark satisfies the requirement.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, _, err := resolveConnection(context.Background(), slog.Default())
	if err == nil {
		t.Fatal("expected error when remote mode has no URL or bookmark")
	}
}

func TestResolveConnection_UnknownMode(t *testing.T) {
	t.Setenv("XKMS_DESKTOP_MODE", "bogus")

	_, _, err := resolveConnection(context.Background(), slog.Default())
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestBookmarks_RoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// Empty store reads as an empty list, not an error.
	marks, err := loadBookmarks()
	if err != nil {
		t.Fatalf("loadBookmarks (empty): %v", err)
	}
	if len(marks) != 0 {
		t.Fatalf("expected empty list, got %d", len(marks))
	}

	want := []Bookmark{
		{Name: "prod", BaseURL: "https://prod:8443"},
		{Name: "staging", BaseURL: "https://staging:8443"},
	}
	if err := saveBookmarks(want); err != nil {
		t.Fatalf("saveBookmarks: %v", err)
	}

	got, err := loadBookmarks()
	if err != nil {
		t.Fatalf("loadBookmarks: %v", err)
	}
	if len(got) != 2 || got[0].Name != "prod" || got[1].BaseURL != "https://staging:8443" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRunGUI_DisabledBuildReturnsError(t *testing.T) {
	// Under the default (no "desktop" tag) build, runGUI is the stub and must
	// report that GUI support is absent rather than silently succeeding.
	err := runGUI(Connection{Mode: ModeRemote, BaseURL: "https://x:8443"}, slog.Default())
	if err == nil {
		t.Skip("built with desktop tag; GUI stub not active")
	}
	var gu *GUIUnavailableError
	if !errorsAs(err, &gu) {
		t.Fatalf("expected GUIUnavailableError, got %T", err)
	}
}

// errorsAs is a tiny local errors.As to avoid an import solely for one call.
func errorsAs(err error, target **GUIUnavailableError) bool {
	if e, ok := err.(*GUIUnavailableError); ok {
		*target = e
		return true
	}
	return false
}

// ensure os is referenced (kept for future env-driven cases).
var _ = os.Getenv
