// Package fipstest lets a test exercise an algorithm that an external
// specification pins but the FIPS 140-3 module does not approve (SHA-1 in
// RFC 6238 or the AWS KMS RSAES_OAEP_SHA_1 import wrap, for example).
//
// Under GODEBUG=fips140=only the standard library refuses such an algorithm,
// which is the enforcement the project relies on (crypto/fips140). A test of
// the specified behaviour therefore runs in a child process of the same test
// binary with GODEBUG=fips140=off, so the suite still proves the algorithm
// works wherever the operator admits it, without a build tag or a skip.
package fipstest

import (
	"crypto/fips140"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// OutsideFIPS reports whether the calling test may exercise a non-approved
// algorithm in this process.
//
// It returns true when the FIPS 140-3 module is not enforcing its approved
// set. Under fips140=only it reruns the calling test in a child process with
// GODEBUG=fips140=off, fails t unless the child passes, and returns false so
// the caller returns at once:
//
//	if !fipstest.OutsideFIPS(t) {
//		return
//	}
func OutsideFIPS(t testing.TB) bool {
	t.Helper()
	if !fips140.Enforced() {
		return true
	}
	rerun(t, os.Args[0])
	return false
}

// moduleRefusal is the phrase in every refusal the Go Cryptographic Module
// returns under GODEBUG=fips140=only, as in "crypto/ecdh: use of X25519 is not
// allowed in FIPS 140-only mode". The standard library exports no sentinel.
const moduleRefusal = "not allowed in FIPS 140-only mode"

// OutsideFIPSAfterRefusal is OutsideFIPS for a test whose first step, which
// returned err, used an algorithm the FIPS 140-3 module does not approve.
// Under GODEBUG=fips140=only it first asserts that err is the refusal --
// errors.Is(err, want) for a package's typed error, or the module's own
// refusal when want is nil -- then re-runs the test with fips140=off and
// reports false. The caller carries on with its round trip only on true:
//
//	key, err := noiseproto.GenerateStaticKey()
//	if !fipstest.OutsideFIPSAfterRefusal(t, err, noiseproto.ErrFIPSUnsupported) {
//		return
//	}
//	require.NoError(t, err)
func OutsideFIPSAfterRefusal(t testing.TB, err, want error) bool {
	t.Helper()
	if !fips140.Enforced() {
		return true
	}
	if !isRefusal(err, want) {
		t.Fatalf("%s under GODEBUG=fips140=only: got error %v, want the refusal of a non-approved algorithm (%v)", t.Name(), err, want)
		return false
	}
	rerun(t, os.Args[0])
	return false
}

// isRefusal reports whether err is the refusal OutsideFIPSAfterRefusal
// expects: want anywhere in its chain, or the module's own refusal when want
// is nil.
func isRefusal(err, want error) bool {
	if err == nil {
		return false
	}
	if want != nil {
		return errors.Is(err, want)
	}
	return strings.Contains(err.Error(), moduleRefusal)
}

// rerun runs the test named t.Name() from the test binary at binary under
// GODEBUG=fips140=off and fails t unless that test ran and passed.
func rerun(t testing.TB, binary string) {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command(binary, "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	env = append(env, "GODEBUG=fips140=off")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s under GODEBUG=fips140=off failed: %v\n%s", t.Name(), err, out)
		return
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
		t.Fatalf("%s did not run under GODEBUG=fips140=off:\n%s", t.Name(), out)
	}
}
