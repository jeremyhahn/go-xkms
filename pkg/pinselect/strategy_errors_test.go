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

package pinselect

import (
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestLoadError_MessageAndUnwrap(t *testing.T) {
	cause := errors.New("permission denied")
	e := &StrategyLoadError{Path: "/data/pin/strategy", Cause: cause}

	if !strings.Contains(e.Error(), "/data/pin/strategy") {
		t.Fatalf("Error() should name the path, got %q", e.Error())
	}
	if !strings.Contains(e.Error(), "permission denied") {
		t.Fatalf("Error() should include the cause, got %q", e.Error())
	}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is(e, cause) = false, want true via Unwrap")
	}
}

func TestSaveError_MessageAndUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	e := &StrategySaveError{Path: "/data/pin/strategy", Cause: cause}

	if !strings.Contains(e.Error(), "/data/pin/strategy") {
		t.Fatalf("Error() should name the path, got %q", e.Error())
	}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is(e, cause) = false, want true via Unwrap")
	}
}

func TestProviderUnavailableError_NamesStrategy(t *testing.T) {
	e := &ProviderUnavailableError{Strategy: qrdbsdk.PINStrategyTPM2}

	if !strings.Contains(e.Error(), "tpm2") {
		t.Fatalf("Error() should name the governing strategy, got %q", e.Error())
	}
}

func TestUnknownStrategyError_NamesStrategy(t *testing.T) {
	e := &UnknownStrategyError{Strategy: "quantum"}

	if !strings.Contains(e.Error(), "quantum") {
		t.Fatalf("Error() should name the unrecognized strategy, got %q", e.Error())
	}
}
