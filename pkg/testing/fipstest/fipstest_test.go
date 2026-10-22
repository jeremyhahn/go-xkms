package fipstest

import (
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"testing"
)

// recordingTB captures the Fatalf a failed rerun reports instead of failing
// the real test.
type recordingTB struct {
	testing.TB
	name  string
	fatal string
}

func (r *recordingTB) Helper()      {}
func (r *recordingTB) Name() string { return r.name }
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}

func TestOutsideFIPS_RunsANonApprovedAlgorithm(t *testing.T) {
	if !OutsideFIPS(t) {
		return
	}
	// HMAC-SHA-1 is the RFC 6238 default the module refuses under
	// fips140=only; reaching it proves the child really ran outside it.
	mac := hmac.New(sha1.New, []byte("12345678901234567890"))
	mac.Write([]byte("message"))
	if got := len(mac.Sum(nil)); got != sha1.Size {
		t.Fatalf("HMAC-SHA-1 length = %d, want %d", got, sha1.Size)
	}
}

func TestRerun_FailsWhenTheChildCannotStart(t *testing.T) {
	tb := &recordingTB{TB: t, name: "TestOutsideFIPS_RunsANonApprovedAlgorithm"}
	rerun(tb, "/nonexistent/fipstest.test")
	if tb.fatal == "" {
		t.Fatal("rerun of a missing binary did not fail the test")
	}
}

func TestRerun_FailsWhenTheTestDidNotRun(t *testing.T) {
	tb := &recordingTB{TB: t, name: "TestNoSuchTest"}
	rerun(tb, os.Args[0])
	if tb.fatal == "" {
		t.Fatal("rerun of a test the binary does not hold did not fail the test")
	}
}

func TestRerun_PassesWhenTheChildPasses(t *testing.T) {
	tb := &recordingTB{TB: t, name: "TestOutsideFIPS_RunsANonApprovedAlgorithm"}
	rerun(tb, os.Args[0])
	if tb.fatal != "" {
		t.Fatalf("rerun of a passing test failed: %s", tb.fatal)
	}
}

func TestOutsideFIPSAfterRefusal_RunsTheRoundTripOutsideFIPS(t *testing.T) {
	// X25519 is refused under fips140=only with the module's own error,
	// which carries no sentinel; outside it the key generates.
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if !OutsideFIPSAfterRefusal(t, err, nil) {
		return
	}
	if err != nil {
		t.Fatalf("X25519 key generation outside fips140=only: %v", err)
	}
	if got := len(key.PublicKey().Bytes()); got != 32 {
		t.Fatalf("X25519 public key length = %d, want 32", got)
	}
}

func TestOutsideFIPSAfterRefusal_FailsOnAnotherError(t *testing.T) {
	tb := &recordingTB{TB: t, name: "TestOutsideFIPSAfterRefusal_FailsOnAnotherError"}
	ok := OutsideFIPSAfterRefusal(tb, errors.New("connection refused"), nil)
	if fips140.Enforced() {
		if ok || tb.fatal == "" {
			t.Fatalf("an error other than the refusal passed under fips140=only: ok=%v", ok)
		}
		return
	}
	if !ok || tb.fatal != "" {
		t.Fatalf("outside fips140=only the caller must carry on: ok=%v fatal=%q", ok, tb.fatal)
	}
}

func TestIsRefusal(t *testing.T) {
	errTyped := errors.New("pkg: algorithm unavailable under FIPS")
	moduleErr := errors.New("crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode")
	tests := []struct {
		name string
		err  error
		want error
		is   bool
	}{
		{"no error is never a refusal", nil, nil, false},
		{"no error with a typed want", nil, errTyped, false},
		{"the typed error, wrapped", fmt.Errorf("wrap: %w", errTyped), errTyped, true},
		{"another error with a typed want", moduleErr, errTyped, false},
		{"the module's refusal", moduleErr, nil, true},
		{"another error with no want", errors.New("connection refused"), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRefusal(tt.err, tt.want); got != tt.is {
				t.Fatalf("isRefusal(%v, %v) = %v, want %v", tt.err, tt.want, got, tt.is)
			}
		})
	}
}
