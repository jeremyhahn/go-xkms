package e2e

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fakeBoard serves the answers the i.MX 95 board gave on 2026-11-17:
// /health 200, the ACME directory 401 (no ACME listener) and SignCSR with
// the given status for a request without credentials.
func fakeBoard(t *testing.T, signCSRStatus int) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/acme/directory", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	})
	mux.HandleFunc("/api/v1/ca/sign-csr", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(signCSRStatus)
		_, _ = w.Write([]byte(`{"error":"no client certificate provided"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

// runScript runs test/e2e/enrolment-imx95.sh against board and returns its
// output and exit code.
func runScript(t *testing.T, board string, env ...string) (string, int) {
	t.Helper()
	for _, tool := range []string{"bash", "openssl", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	cmd := exec.Command("bash", "enrolment-imx95.sh")
	cmd.Env = append(os.Environ(), "BOARD="+board, "WORK="+t.TempDir(), "ACME_CLIENT=", "STRICT=")
	cmd.Env = append(cmd.Env, env...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		t.Fatal("script did not finish within 2 minutes")
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("run script: %v\n%s", err, out)
		return "", -1
	}
}

// The board run ends at the last working step with exit 0: step 0 works,
// the ACME path stops at the directory and SignCSR without credentials is
// rejected, which is the expected boundary and not a failure.
func TestEnrolmentScript_StopsAtLastWorkingStepWithExitZero(t *testing.T) {
	out, code := runScript(t, fakeBoard(t, http.StatusUnauthorized))
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	for _, want := range []string{"OK step 0", "STOP step 1:", "NOT REACHED step 2", "BOUNDARY ca:", "last working step: 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL ") {
		t.Errorf("partial-progress run reports a FAIL\n%s", out)
	}
}

// STRICT=1 keeps the strict behaviour: the first step that does not work
// ends the run with exit 1.
func TestEnrolmentScript_StrictFailsAtFirstStop(t *testing.T) {
	out, code := runScript(t, fakeBoard(t, http.StatusUnauthorized), "STRICT=1")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL step 1:") {
		t.Errorf("output lacks the strict failure of step 1\n%s", out)
	}
}

// A board that signs a CSR without any credential is a defect, never a
// boundary: the run fails even without STRICT.
func TestEnrolmentScript_SignCSRWithoutCredentialsAcceptedFails(t *testing.T) {
	out, code := runScript(t, fakeBoard(t, http.StatusOK))
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL step ca:") {
		t.Errorf("output lacks the SignCSR failure\n%s", out)
	}
}
