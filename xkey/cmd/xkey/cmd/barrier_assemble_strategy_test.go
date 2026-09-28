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

// These tests exercise assembleBarrierStrategy's (barrier.go) software
// branches: the passphrase strategy it can build without any hardware, and
// the typed errors it returns for a strategy the CLI barrier does not
// support (pkcs11) or does not recognize at all. The tpm2 and cloud-KMS
// branches are covered separately (tpm2 needs the in-process simulator;
// cloud KMS needs provider credentials), so they are intentionally left out
// here.
package cmd

import (
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestAssembleBarrierStrategy_Passphrase(t *testing.T) {
	strategy, closer, err := assembleBarrierStrategy(xkms.StrategyPassphrase, t.TempDir())
	if err != nil {
		t.Fatalf("assembleBarrierStrategy(StrategyPassphrase) error = %v, want nil", err)
	}
	if strategy == nil {
		t.Fatal("assembleBarrierStrategy(StrategyPassphrase) strategy = nil, want a software strategy")
	}
	if closer != nil {
		t.Errorf("assembleBarrierStrategy(StrategyPassphrase) closer = %v, want nil for a software strategy", closer)
	}
}

func TestAssembleBarrierStrategy_PKCS11Unsupported(t *testing.T) {
	strategy, closer, err := assembleBarrierStrategy(xkms.StrategyPKCS11, t.TempDir())
	if strategy != nil {
		t.Errorf("assembleBarrierStrategy(StrategyPKCS11) strategy = %v, want nil", strategy)
	}
	if closer != nil {
		t.Errorf("assembleBarrierStrategy(StrategyPKCS11) closer = %v, want nil", closer)
	}

	var barrierErr *BarrierError
	if !errors.As(err, &barrierErr) {
		t.Fatalf("assembleBarrierStrategy(StrategyPKCS11) error = %v, want a *BarrierError", err)
	}
	if barrierErr.Operation != "assemble_strategy" {
		t.Errorf("barrierErr.Operation = %q, want %q", barrierErr.Operation, "assemble_strategy")
	}
}

func TestAssembleBarrierStrategy_UnknownID(t *testing.T) {
	const bogus xkms.StrategyID = "bogus-strategy"

	strategy, closer, err := assembleBarrierStrategy(bogus, t.TempDir())
	if strategy != nil {
		t.Errorf("assembleBarrierStrategy(%q) strategy = %v, want nil", bogus, strategy)
	}
	if closer != nil {
		t.Errorf("assembleBarrierStrategy(%q) closer = %v, want nil", bogus, closer)
	}

	var barrierErr *BarrierError
	if !errors.As(err, &barrierErr) {
		t.Fatalf("assembleBarrierStrategy(%q) error = %v, want a *BarrierError", bogus, err)
	}
	if barrierErr.Message == "" {
		t.Error("barrierErr.Message is empty, want a message naming the unsupported strategy")
	}
}
