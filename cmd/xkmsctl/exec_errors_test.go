package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// restoreRootArgs puts rootCmd's argument source back to the process
// arguments once a test that drives run() ends.
func restoreRootArgs(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		commandStarted = false
	})
}

func TestRun_UnknownFlagPrintsErrorAndUsageHint(t *testing.T) {
	restoreRootArgs(t)

	var stderr bytes.Buffer
	code := run([]string{"key", "list", "--bogus"}, &stderr)

	if code == 0 {
		t.Fatalf("run exit code = 0, want non-zero")
	}
	out := stderr.String()
	if !strings.Contains(out, "unknown flag: --bogus") {
		t.Errorf("stderr = %q, want the unknown flag error", out)
	}
	if !strings.Contains(out, "Run 'xkmsctl key list --help' for usage.") {
		t.Errorf("stderr = %q, want the usage hint", out)
	}
}

func TestRun_MissingRequiredFlagPrintsErrorAndUsageHint(t *testing.T) {
	restoreRootArgs(t)

	var stderr bytes.Buffer
	code := run([]string{"ca", "issue"}, &stderr)

	if code == 0 {
		t.Fatalf("run exit code = 0, want non-zero")
	}
	out := stderr.String()
	if !strings.Contains(out, `required flag(s) "cn" not set`) {
		t.Errorf("stderr = %q, want the required flag error", out)
	}
	if !strings.Contains(out, "Run 'xkmsctl ca issue --help' for usage.") {
		t.Errorf("stderr = %q, want the usage hint", out)
	}
}

func TestRun_RuntimeErrorPrintsErrorWithoutUsage(t *testing.T) {
	restoreRootArgs(t)

	errSentinel := errors.New("sentinel runtime failure 2279")
	probe := &cobra.Command{
		Use: "exec-errors-probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errSentinel
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	var stderr bytes.Buffer
	code := run([]string{"exec-errors-probe"}, &stderr)

	if code == 0 {
		t.Fatalf("run exit code = 0, want non-zero")
	}
	out := stderr.String()
	if !strings.Contains(out, errSentinel.Error()) {
		t.Errorf("stderr = %q, want the runtime error", out)
	}
	if strings.Contains(out, "--help") || strings.Contains(out, "Usage:") {
		t.Errorf("stderr = %q, want no usage output for a runtime error", out)
	}
}
