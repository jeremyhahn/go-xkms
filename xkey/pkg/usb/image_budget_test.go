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

package usb

import (
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// admitPassphraseCopy hands go-luks2 a frozen copy of the passphrase and
// leaves the source buffer intact.
func TestAdmitPassphraseCopy_CopiesAndFreezes(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("my-secret-passphrase"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	pass, err := admitPassphraseCopy(buf)
	if err != nil {
		t.Fatalf("admitPassphraseCopy: %v", err)
	}
	defer func() {
		if err := pass.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	}()
	equal, err := pass.EqualTo([]byte("my-secret-passphrase"))
	if err != nil || !equal {
		t.Fatalf("EqualTo = %v, %v; want the passphrase", equal, err)
	}
	if buf.Size() != len("my-secret-passphrase") {
		t.Fatalf("source buffer size = %d after the copy", buf.Size())
	}
}

func TestFreezePassphrase_FreezesMemoryEnclave(t *testing.T) {
	pass, err := enclave.NewMemorySized(8)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	defer func() {
		if err := pass.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	}()

	if err := freezePassphrase(pass); err != nil {
		t.Fatalf("freezePassphrase: %v", err)
	}
	if err := pass.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := freezePassphrase(pass); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("freezePassphrase on a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
	}
}

// unfreezable is a ByteAccess that hides the Freezer capability of the
// enclave it wraps.
type unfreezable struct {
	enclave.ByteAccess
}

func TestFreezePassphrase_RefusesHandleWithoutFreezer(t *testing.T) {
	inner, err := enclave.NewMemorySized(8)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	defer func() {
		if err := inner.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	}()

	if err := freezePassphrase(unfreezable{inner}); !errors.Is(err, ErrPassphraseNotFreezable) {
		t.Fatalf("freezePassphrase = %v, want ErrPassphraseNotFreezable", err)
	}
}

// With the process budget filled by the source buffer, the copy must be
// refused with the budget's typed error: it is admitted, never made outside
// the budget.
func TestAdmitPassphraseCopy_RefusedByProcessBudget(t *testing.T) {
	if !enclavetest.RunWithBudget(t, int64(os.Getpagesize())) {
		return
	}

	const passphrase = "my-secret-passphrase"
	buf, err := secure.NewBufferFromBytes([]byte(passphrase))
	if err != nil {
		t.Fatalf("the source buffer must fit the one-page budget: %v", err)
	}
	defer buf.Destroy()

	alloc, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	lockedBefore := alloc.InUse()

	pass, err := admitPassphraseCopy(buf)
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Fatalf("err = %v, want enclave.ErrBudgetExhausted", err)
	}
	if pass != nil {
		t.Error("a refused admission returned an enclave")
	}
	if got := alloc.InUse(); got != lockedBefore {
		t.Errorf("locked bytes after refusal = %d, want %d", got, lockedBefore)
	}
	if err := buf.WithBytes(func(src []byte) error {
		if string(src) != passphrase {
			t.Errorf("source buffer changed by a refused admission: %q", src)
		}
		return nil
	}); err != nil {
		t.Fatalf("read source buffer: %v", err)
	}
}
