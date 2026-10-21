package fipstest

import (
	"crypto/hmac"
	"crypto/sha1"
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
