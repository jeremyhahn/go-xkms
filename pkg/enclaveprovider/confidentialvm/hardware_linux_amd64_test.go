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
	// REPORT_DATA sits at 0x50 in the SEV-SNP ATTESTATION_REPORT (SEV-SNP ABI
	// table 22): the guest's 64 bytes, the nonce followed by zero padding.
	const offReportData = 0x50
	a, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	var seen [][]byte
	for _, n := range []int{32, 48} {
		nonce := make([]byte, n)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		ev, err := a.Attest(context.Background(), nonce)
		if err != nil {
			t.Fatalf("Attest(%d-byte nonce): %v", n, err)
		}
		if ev.Format != FormatSEVSNPReport {
			t.Fatalf("Format = %q, want %q", ev.Format, FormatSEVSNPReport)
		}
		if len(ev.Data) != snpReportSize {
			t.Fatalf("report of %d bytes, want %d", len(ev.Data), snpReportSize)
		}
		want := make([]byte, reportDataSize)
		copy(want, nonce)
		got := ev.Data[offReportData : offReportData+reportDataSize]
		if !bytes.Equal(got, want) {
			t.Fatalf("REPORT_DATA = %x, want the %d-byte nonce plus zero padding %x", got, n, want)
		}
		for _, prev := range seen {
			if bytes.Equal(prev, got) {
				t.Fatal("two distinct nonces gave the same REPORT_DATA")
			}
		}
		seen = append(seen, bytes.Clone(got))
	}
}
