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

package pkcs11test

import (
	"context"
	"crypto/fips140"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// rawSignSubprocess marks the re-exec'd child of the FIPS-only test below.
// GODEBUG=fips140 is fixed when the process starts, so the activated mode can
// only be exercised in a separate process.
const rawSignSubprocess = "XKMS_PKCS11TEST_RAW_SIGN_SUBPROCESS"

// rawSignKeyID names the RSA key the raw-sign tests generate in the mock.
const rawSignKeyID = "raw-pkcs1v15-rsa"

// rawSignData is the caller-built input CKM_RSA_PKCS carries verbatim into
// the PKCS#1 v1.5 block -- the input C_SignRecover hands the backend.
var rawSignData = []byte("recoverable data")

// The mock must answer for the process it runs in, so the raw form is
// asserted against crypto/fips140.Enforced rather than an expected constant:
// this test is meaningful with and without GODEBUG=fips140=only, and running
// the package under the only mode is the verification go-xkms#486 asks for.
func TestCryptoMockClient_RawPKCS1v15_AgreesWithRuntime(t *testing.T) {
	c := NewCryptoMockClient()
	ctx := context.Background()
	generateRawSignKey(t, c)

	signResp, signErr := c.Sign(ctx, &transport.SignRequest{
		KeyID: rawSignKeyID, Data: rawSignData, Hash: "NONE",
	})
	if fips140.Enforced() {
		if !errors.Is(signErr, types.ErrRawPKCS1v15Enforced) {
			t.Fatalf("Sign(NONE) under fips140=only = %v, want ErrRawPKCS1v15Enforced", signErr)
		}
		_, verifyErr := c.Verify(ctx, &transport.VerifyRequest{
			KeyID: rawSignKeyID, Data: rawSignData, Signature: make([]byte, 256), Hash: "NONE",
		})
		if !errors.Is(verifyErr, types.ErrRawPKCS1v15Enforced) {
			t.Fatalf("Verify(NONE) under fips140=only = %v, want ErrRawPKCS1v15Enforced", verifyErr)
		}
		return
	}

	if signErr != nil {
		t.Fatalf("Sign(NONE) outside fips140=only = %v, want a signature", signErr)
	}
	verifyResp, verifyErr := c.Verify(ctx, &transport.VerifyRequest{
		KeyID: rawSignKeyID, Data: rawSignData, Signature: signResp.Signature, Hash: "NONE",
	})
	if verifyErr != nil {
		t.Fatalf("Verify(NONE) outside fips140=only = %v, want a verdict", verifyErr)
	}
	if !verifyResp.Valid {
		t.Error("the mock's own raw signature must verify against its own key")
	}
}

// TestCryptoMockClient_RawPKCS1v15_FIPS140Only re-execs this binary with
// GODEBUG=fips140=only and asserts the raw sign and verify paths return the
// typed error and the process survives. Before go-xkms#486 the child died at
// crypto/rsa with "crypto: requested hash function #0 is unavailable", taking
// every test after it in the conformance suite down with it.
func TestCryptoMockClient_RawPKCS1v15_FIPS140Only(t *testing.T) {
	if os.Getenv(rawSignSubprocess) == "1" {
		if !fips140.Enforced() {
			t.Fatal("child is not enforcing FIPS 140-only mode; GODEBUG=fips140=only was not honored")
		}
		c := NewCryptoMockClient()
		ctx := context.Background()
		generateRawSignKey(t, c)

		_, err := c.Sign(ctx, &transport.SignRequest{KeyID: rawSignKeyID, Data: rawSignData, Hash: "NONE"})
		if !errors.Is(err, types.ErrRawPKCS1v15Enforced) {
			t.Errorf("Sign(NONE) = %v, want ErrRawPKCS1v15Enforced", err)
		}
		_, err = c.Verify(ctx, &transport.VerifyRequest{
			KeyID: rawSignKeyID, Data: rawSignData, Signature: make([]byte, 256), Hash: "NONE",
		})
		if !errors.Is(err, types.ErrRawPKCS1v15Enforced) {
			t.Errorf("Verify(NONE) = %v, want ErrRawPKCS1v15Enforced", err)
		}

		// Control: the approved form of the same mechanism still round-trips,
		// so the refusal is scoped to the absent digest and nothing wider.
		signResp, err := c.Sign(ctx, &transport.SignRequest{KeyID: rawSignKeyID, Data: rawSignData, Hash: "SHA-256"})
		if err != nil {
			t.Fatalf("Sign(SHA-256) under fips140=only = %v, want a signature", err)
		}
		verifyResp, err := c.Verify(ctx, &transport.VerifyRequest{
			KeyID: rawSignKeyID, Data: rawSignData, Signature: signResp.Signature, Hash: "SHA-256",
		})
		if err != nil {
			t.Fatalf("Verify(SHA-256) under fips140=only = %v, want a verdict", err)
		}
		if !verifyResp.Valid {
			t.Error("the SHA-256 signature must verify under fips140=only")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCryptoMockClient_RawPKCS1v15_FIPS140Only$", "-test.v")
	cmd.Env = append(os.Environ(), rawSignSubprocess+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("fips140=only child panicked:\n%s", out)
	}
	if err != nil {
		t.Fatalf("fips140=only child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=only child did not pass:\n%s", out)
	}
}

// generateRawSignKey creates the 2048-bit RSA key the raw-sign tests use: the
// smallest size every fips140 mode accepts, so the key is never what a
// refusal is about.
func generateRawSignKey(t *testing.T, c *CryptoMockClient) {
	t.Helper()
	_, err := c.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID: rawSignKeyID, KeyType: "rsa", Algorithm: "rsa", KeySize: 2048,
	})
	if err != nil {
		t.Fatalf("GenerateKey(rsa-2048): %v", err)
	}
}
