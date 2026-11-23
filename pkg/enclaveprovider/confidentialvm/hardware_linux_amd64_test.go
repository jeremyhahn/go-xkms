//go:build linux && amd64 && confidentialvm_hardware

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

package confidentialvm

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// The hardware tests run only inside an SEV-SNP guest, with
// -tags confidentialvm_hardware; no Makefile target or CI job sets the tag.
// They never print key bytes, blobs, nonces or reports.

func TestHardware_KeyProtectorRoundTripsAndRefusesATamperedBlob(t *testing.T) {
	ctx := context.Background()
	kp, err := NewKeyProtector()
	if err != nil {
		t.Fatalf("NewKeyProtector: %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blob, err := kp.Protect(ctx, key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	got := make([]byte, len(key))
	if err := kp.Unprotect(ctx, blob, got); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("Unprotect returned a different key")
	}
	bad := bytes.Clone(blob)
	bad[len(bad)-1] ^= 0x01
	if err := kp.Unprotect(ctx, bad, got); !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("Unprotect(tampered) = %v, want ErrSealedAuthentication", err)
	}
}

func TestHardware_AttesterReturnsAnSNPReport(t *testing.T) {
	a, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ev, err := a.Attest(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if ev.Format != "sev-snp-report" {
		t.Fatalf("Format = %q, want sev-snp-report", ev.Format)
	}
	if len(ev.Data) == 0 {
		t.Fatal("Attest returned empty Data")
	}
}
