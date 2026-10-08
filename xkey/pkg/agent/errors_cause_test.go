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

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// TestAgentError_CarriesSentinelAndCause pins both halves of the contract at
// once: the sentinel stays matchable (callers switch on it) and the cause stays
// reachable (operators need it to know what actually went wrong).
//
// These previously could not both hold. A wrapper was built from the sentinel
// alone and the real error was dropped, so "failed to create DAO" named neither
// the field nor the reason and diagnosing it meant reading the dependency's
// source.
func TestAgentError_CarriesSentinelAndCause(t *testing.T) {
	cause := errors.New("underlying storage exploded")
	err := &AgentError{Operation: "save_agent", Err: ErrStoreWrite, Cause: cause}

	if !errors.Is(err, ErrStoreWrite) {
		t.Error("the sentinel must stay matchable so callers can classify the failure")
	}
	if !errors.Is(err, cause) {
		t.Error("the cause must stay matchable so the real failure is not lost")
	}
	if msg := err.Error(); !strings.Contains(msg, cause.Error()) {
		t.Errorf("Error() must report the cause; got %q", msg)
	}
}

// TestAgentError_WithoutCauseIsUnchanged covers the sites that genuinely have
// no underlying error (a validation rejection, say). Those must not grow a
// trailing separator or start reporting a nil cause.
func TestAgentError_WithoutCauseIsUnchanged(t *testing.T) {
	err := &AgentError{Operation: "validate_config", Err: ErrInvalidAddress}

	if !errors.Is(err, ErrInvalidAddress) {
		t.Error("sentinel must match when there is no cause")
	}
	if got, want := err.Error(), "agent: validate_config: "+ErrInvalidAddress.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestFileStore_SaveAgent_ReportsWriteCause proves the wiring end to end rather
// than only the error type: a real failing write must surface the operating
// system's reason, not just "store write failed".
//
// The failure is forced by pre-creating the destination path as a directory,
// so os.WriteFile fails with EISDIR. That is deterministic for every user --
// a permissions-based trick would silently stop failing under root and quietly
// stop testing anything.
func TestFileStore_SaveAgent_ReportsWriteCause(t *testing.T) {
	dir := t.TempDir()

	store, err := NewFileStore(dir, testLogger())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const deviceID = "device-1"
	if err := os.Mkdir(filepath.Join(dir, "agents", deviceID+".json"), 0700); err != nil {
		t.Fatalf("staging the unwritable destination: %v", err)
	}

	saveErr := store.SaveAgent(&AgentInfo{ID: deviceID})
	if saveErr == nil {
		t.Fatal("expected SaveAgent to fail when its destination is a directory")
	}

	if !errors.Is(saveErr, ErrStoreWrite) {
		t.Errorf("want the ErrStoreWrite sentinel, got %v", saveErr)
	}
	if !errors.Is(saveErr, fsutil.ErrTargetNotRegular) {
		t.Errorf("the underlying fsutil cause must survive wrapping; got %v", saveErr)
	}
	if !strings.Contains(saveErr.Error(), deviceID) {
		t.Errorf("the message should name the path that failed; got %q", saveErr)
	}
}
