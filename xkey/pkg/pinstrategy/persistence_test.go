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

package pinstrategy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	pinDir := t.TempDir()

	if err := Save(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("Load = %q, want %q", got, qrdbsdk.PINStrategyTPM2)
	}

	// The file lives beside the PIN state, not in some other consumer's
	// own config file.
	wantPath := filepath.Join(pinDir, "strategy")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected strategy file at %s: %v", wantPath, err)
	}
}

func TestSave_OverwritesPreviousStrategy(t *testing.T) {
	pinDir := t.TempDir()

	if err := Save(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save (software): %v", err)
	}
	if err := Save(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save (tpm2): %v", err)
	}

	got, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("Load = %q, want %q after overwrite", got, qrdbsdk.PINStrategyTPM2)
	}
}

func TestLoad_NotPersistedIsTypedSentinel(t *testing.T) {
	pinDir := t.TempDir()

	_, err := Load(pinDir)
	if !errors.Is(err, ErrStrategyNotPersisted) {
		t.Fatalf("Load on empty PIN dir: got %v, want ErrStrategyNotPersisted", err)
	}
}

func TestLoad_CorruptFileIsLoadError(t *testing.T) {
	pinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pinDir, "strategy"), []byte("{not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(pinDir)
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("Load on corrupt file: got %T %v, want *LoadError", err, err)
	}
}

func TestSave_EmptyStrategyIsError(t *testing.T) {
	pinDir := t.TempDir()

	err := Save(pinDir, "")
	var saveErr *SaveError
	if !errors.As(err, &saveErr) {
		t.Fatalf("Save(\"\"): got %T %v, want *SaveError", err, err)
	}
}

func TestSave_UnwritablePINDirIsSaveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}

	root := t.TempDir()
	pinDir := filepath.Join(root, "pin")
	if err := os.Chmod(root, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0700) })

	err := Save(pinDir, qrdbsdk.PINStrategySoftware)
	var saveErr *SaveError
	if !errors.As(err, &saveErr) {
		t.Fatalf("Save into unwritable dir: got %T %v, want *SaveError", err, err)
	}
}

func TestLoad_UnreadableFileIsLoadError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores file permission bits")
	}

	pinDir := t.TempDir()
	if err := Save(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(Path(pinDir), 0000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(Path(pinDir), 0600) })

	_, err := Load(pinDir)
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("Load on unreadable file: got %T %v, want *LoadError", err, err)
	}
}

func TestPath_BesidePINState(t *testing.T) {
	got := Path("/data/pin")
	want := filepath.Join("/data/pin", "strategy")
	if got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}
