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

package mldsa65

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestGenerateKeyPair_SucceedsUnderFIPS140Only is the compliance assertion
// for go-xkms #21: this package keeps no approved-algorithm list of its own,
// so ML-DSA-65 must work purely because crypto/mldsa (the Go Cryptographic
// Module's own implementation) permits it under the default/latest module
// this repository links. GODEBUG=fips140 is fixed when the process starts,
// so this re-execs, mirroring pkg/types.TestFIPSMode_RefusesNonApprovedAlgorithms
// and pkg/certstore.TestToString_UnderFIPSOnly.
//
// crypto/mldsa also documents itself as unavailable under the FIPS 140-3 Go
// Cryptographic Module v1.0.0, becoming available again only from v1.26.0:
// GOFIPS140 selects the linked module version at BUILD time, so exercising
// that boundary would mean compiling a second test binary from inside a
// test, which is exactly the kind of heavyweight, host-touching operation
// unit tests here must not do. This test instead pins the version this
// repository actually ships against, which links the current module and
// therefore does support ML-DSA.
func TestGenerateKeyPair_SucceedsUnderFIPS140Only(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		m, err := New()
		if err != nil {
			t.Fatalf("New() error = %v, want nil", err)
		}
		defer m.Clean()

		pub, err := m.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v, want nil under GODEBUG=fips140=only", err)
		}
		if len(pub) != PublicKeySize {
			t.Fatalf("len(pub) = %d, want %d", len(pub), PublicKeySize)
		}

		message := []byte("fips140=only smoke message")
		sig, err := m.Sign(message)
		if err != nil {
			t.Fatalf("Sign() error = %v, want nil under GODEBUG=fips140=only", err)
		}
		valid, err := m.Verify(message, sig, pub)
		if err != nil || !valid {
			t.Fatalf("Verify() = (%v, %v), want (true, nil)", valid, err)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGenerateKeyPair_SucceedsUnderFIPS140Only", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=only subprocess did not pass:\n%s", out)
	}
}
