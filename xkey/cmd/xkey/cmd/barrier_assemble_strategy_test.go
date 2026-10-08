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

// These tests exercise assembleBarrierStrategy's (barrier.go) branches that
// need no hardware: the passphrase strategy, the typed error for a pkcs11
// strategy with no token configured, and the one for a strategy it does not
// recognize at all. The tpm2 and cloud-KMS branches are covered separately
// (tpm2 needs the in-process simulator; cloud KMS needs provider
// credentials), and the configured pkcs11 branch needs a SoftHSM token.
package cmd

import (
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
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

// TestAssembleBarrierStrategy_PKCS11Unconfigured proves a pkcs11 barrier
// with no token in the xkey config is refused before any TPM or HSM is
// touched.
func TestAssembleBarrierStrategy_PKCS11Unconfigured(t *testing.T) {
	saved := loadedConfig
	loadedConfig = config.DefaultConfig()
	t.Cleanup(func() { loadedConfig = saved })

	strategy, closer, err := assembleBarrierStrategy(xkms.StrategyPKCS11, t.TempDir())
	if strategy != nil || closer != nil {
		t.Errorf("assembleBarrierStrategy(StrategyPKCS11) = %v, %v, want nil, nil", strategy, closer)
	}
	if !errors.Is(err, config.ErrBarrierPKCS11ConfigInvalid) {
		t.Fatalf("assembleBarrierStrategy(StrategyPKCS11) error = %v, want ErrBarrierPKCS11ConfigInvalid", err)
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
