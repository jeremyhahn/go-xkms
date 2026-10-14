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

package luks

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
)

// protectPassphrase places the passphrase in an enclave go-luks2 can read.
func TestProtectPassphrase_HoldsPassphrase(t *testing.T) {
	pass, err := protectPassphrase("correct horse")
	if err != nil {
		t.Fatalf("protectPassphrase: %v", err)
	}
	defer func() {
		if err := pass.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	}()
	err = pass.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, []byte("correct horse")) {
			t.Errorf("enclave holds %d bytes that are not the passphrase", len(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

// Under a process budget too small for one page, the passphrase enclave must
// be refused with a typed error: the allocation is admitted against the
// budget, never made outside it.
func TestProtectPassphrase_RefusedByProcessBudget(t *testing.T) {
	if !enclavetest.RunWithBudget(t, 1) {
		return
	}

	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}

	pass, err := protectPassphrase("correct horse")
	var execErr *ExecutorError
	if !errors.As(err, &execErr) || execErr.Operation != "protect_passphrase" {
		t.Fatalf("err = %v, want an ExecutorError for protect_passphrase", err)
	}
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("err = %v, want the budget refusal as its cause", err)
	}
	if pass != nil {
		t.Error("a refused passphrase returned an enclave")
	}
	if got := alloc.InUse(); got != 0 {
		t.Errorf("locked bytes after refusal = %d, want 0", got)
	}
}
