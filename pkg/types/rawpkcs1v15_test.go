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

package types

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// rawPKCS1v15Subprocess is the environment variable that marks a re-exec'd
// child of the FIPS-mode tests below. GODEBUG=fips140 is read once when the
// process starts, so the activated modes can only be exercised in a child.
const rawPKCS1v15Subprocess = "XKMS_RAW_PKCS1V15_SUBPROCESS"

// rawPKCS1v15Message is the caller-built input a raw PKCS#1 v1.5 signature
// covers verbatim. Its length is irrelevant to the refusal under test, which
// attaches to the absent digest, not to the data.
var rawPKCS1v15Message = []byte("caller-built DigestInfo stands in here")

// CheckRawPKCS1v15 must answer for the process it runs in, so it is asserted
// against the operation itself rather than an expected constant: the same
// test is meaningful with and without GODEBUG=fips140=only (go-xkms#486).
func TestCheckRawPKCS1v15_AgreesWithSigningAndVerifying(t *testing.T) {
	key := generateRawPKCS1v15Key(t)

	wantSign := canRawSign(key)
	if got := CheckRawPKCS1v15(key, crypto.Hash(0)) == nil; got != wantSign {
		t.Errorf("CheckRawPKCS1v15(*rsa.PrivateKey, Hash(0)) permits = %v, but raw signing %s",
			got, map[bool]string{true: "succeeds", false: "panics"}[wantSign])
	}

	wantVerify := canRawVerify(&key.PublicKey)
	if got := CheckRawPKCS1v15(&key.PublicKey, crypto.Hash(0)) == nil; got != wantVerify {
		t.Errorf("CheckRawPKCS1v15(*rsa.PublicKey, Hash(0)) permits = %v, but raw verification %s",
			got, map[bool]string{true: "succeeds", false: "panics"}[wantVerify])
	}
}

// A named digest, a non-RSA key, or a value that is not a crypto/rsa key never
// reaches the refused call, so the check must stay out of the way in every
// mode. If this fails, the guard is over-restricting.
func TestCheckRawPKCS1v15_OnlyRawRSAIsGoverned(t *testing.T) {
	rsaKey := generateRawPKCS1v15Key(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	cases := []struct {
		name string
		key  any
		hash crypto.Hash
	}{
		{"RSA private key with a named digest", rsaKey, crypto.SHA256},
		{"RSA public key with a named digest", &rsaKey.PublicKey, crypto.SHA256},
		{"ECDSA private key without a digest", ecKey, crypto.Hash(0)},
		{"ECDSA public key without a digest", &ecKey.PublicKey, crypto.Hash(0)},
		{"Ed25519 private key without a digest", edPriv, crypto.Hash(0)},
		{"Ed25519 public key without a digest", edPub, crypto.Hash(0)},
		{"nil key", nil, crypto.Hash(0)},
		{"not a key at all", "CKM_RSA_PKCS", crypto.Hash(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckRawPKCS1v15(tc.key, tc.hash); err != nil {
				t.Errorf("CheckRawPKCS1v15(%T, %v) = %v, want nil", tc.key, tc.hash, err)
			}
		})
	}
}

// TestCheckRawPKCS1v15_FIPS140Only re-execs this binary with
// GODEBUG=fips140=only and asserts the raw form is refused with the typed
// error -- and that the process survives, which is the whole point: the
// standard library's own answer at this site is a panic.
func TestCheckRawPKCS1v15_FIPS140Only(t *testing.T) {
	if os.Getenv(rawPKCS1v15Subprocess) == "only" {
		if !fips140.Enforced() {
			t.Fatal("child is not enforcing FIPS 140-only mode; GODEBUG=fips140=only was not honored")
		}
		key := generateRawPKCS1v15Key(t)

		if err := CheckRawPKCS1v15(key, crypto.Hash(0)); !errors.Is(err, ErrRawPKCS1v15Enforced) {
			t.Errorf("CheckRawPKCS1v15(*rsa.PrivateKey, Hash(0)) = %v, want ErrRawPKCS1v15Enforced", err)
		}
		if err := CheckRawPKCS1v15(&key.PublicKey, crypto.Hash(0)); !errors.Is(err, ErrRawPKCS1v15Enforced) {
			t.Errorf("CheckRawPKCS1v15(*rsa.PublicKey, Hash(0)) = %v, want ErrRawPKCS1v15Enforced", err)
		}

		// Control: the approved form is untouched, and actually works.
		if err := CheckRawPKCS1v15(key, crypto.SHA256); err != nil {
			t.Errorf("CheckRawPKCS1v15(*rsa.PrivateKey, SHA-256) = %v, want nil", err)
		}
		digest := sha256.Sum256(rawPKCS1v15Message)
		if _, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:]); err != nil {
			t.Errorf("SHA-256 PKCS#1 v1.5 signing must keep working under fips140=only: %v", err)
		}
		return
	}

	out := runRawPKCS1v15Child(t, "TestCheckRawPKCS1v15_FIPS140Only", "only")
	if strings.Contains(out, "panic:") {
		t.Fatalf("fips140=only child panicked:\n%s", out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("fips140=only child did not pass:\n%s", out)
	}
}

// TestCheckRawPKCS1v15_FIPS140On proves the guard does not fire under
// GODEBUG=fips140=on, where the identical raw signature is permitted. If this
// fails, a working capability has been withdrawn.
func TestCheckRawPKCS1v15_FIPS140On(t *testing.T) {
	if os.Getenv(rawPKCS1v15Subprocess) == "on" {
		if !fips140.Enabled() || fips140.Enforced() {
			t.Fatalf("child mode is enabled=%v enforced=%v; want fips140=on (enabled, not enforced)",
				fips140.Enabled(), fips140.Enforced())
		}
		key := generateRawPKCS1v15Key(t)

		if err := CheckRawPKCS1v15(key, crypto.Hash(0)); err != nil {
			t.Errorf("CheckRawPKCS1v15(*rsa.PrivateKey, Hash(0)) = %v under fips140=on, want nil", err)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), rawPKCS1v15Message)
		if err != nil {
			t.Fatalf("raw PKCS#1 v1.5 signing must work under fips140=on: %v", err)
		}
		if err := CheckRawPKCS1v15(&key.PublicKey, crypto.Hash(0)); err != nil {
			t.Errorf("CheckRawPKCS1v15(*rsa.PublicKey, Hash(0)) = %v under fips140=on, want nil", err)
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.Hash(0), rawPKCS1v15Message, sig); err != nil {
			t.Errorf("raw PKCS#1 v1.5 verification must work under fips140=on: %v", err)
		}
		return
	}

	out := runRawPKCS1v15Child(t, "TestCheckRawPKCS1v15_FIPS140On", "on")
	if strings.Contains(out, "panic:") {
		t.Fatalf("fips140=on child panicked:\n%s", out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("fips140=on child did not pass:\n%s", out)
	}
}

// runRawPKCS1v15Child re-execs the test binary for one test under the named
// GODEBUG=fips140 mode and returns its combined output. A non-zero exit is
// reported through the output rather than fatally, so the caller can tell a
// panic from an ordinary failure.
func runRawPKCS1v15Child(t *testing.T, test, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), rawPKCS1v15Subprocess+"="+mode, "GODEBUG=fips140="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\nchild exit: " + err.Error()
	}
	return string(out)
}

// generateRawPKCS1v15Key returns a 2048-bit key: the smallest size every
// fips140 mode accepts, so the key itself is never what a refusal is about.
func generateRawPKCS1v15Key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// canRawSign reports whether a raw PKCS#1 v1.5 signature survives in this
// process, converting the standard library's panic into false.
func canRawSign(key *rsa.PrivateKey) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	_, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.Hash(0), rawPKCS1v15Message)
	return err == nil
}

// canRawVerify reports whether a raw PKCS#1 v1.5 verification survives in
// this process. The signature is deliberately bogus: a verification failure
// is an error, which is a survival, while the refusal under test is a panic.
func canRawVerify(pub *rsa.PublicKey) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	err := rsa.VerifyPKCS1v15(pub, crypto.Hash(0), rawPKCS1v15Message, make([]byte, pub.Size()))
	return err == nil || errors.Is(err, rsa.ErrVerification)
}
