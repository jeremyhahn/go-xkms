package buildgates

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// tmpdirTemplate is the per-job TMPDIR's mktemp template in ci.yml.
const tmpdirTemplate = "/tmp/XXXXXX"

// TestNativeGoTestJobsTakeAPerJobShortTMPDIR pins the #2183 sun_path fix: on
// the self-hosted pool TMPDIR is the runner's _work/_temp, so a Unix socket
// under t.TempDir (TestName + random suffix + /001/x.sock) overflowed
// sun_path and bind failed with "invalid argument" in 32 Race Detector tests
// and the Nested Module Tests. Runner units on one host share /tmp, so a
// fixed /tmp is not enough (Company Agent condition): every job with a native
// (runner.environment == 'self-hosted') go test step first runs
// mktemp -d /tmp/XXXXXX and exports it as TMPDIR and GOTMPDIR (which
// t.TempDir prefers in Go 1.27, and which the pool sets to _work/_temp)
// through $GITHUB_ENV, and its
// last step removes it under always(). No step pins TMPDIR in its env.
func TestNativeGoTestJobsTakeAPerJobShortTMPDIR(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	type step struct {
		Name string            `yaml:"name"`
		If   string            `yaml:"if"`
		Run  string            `yaml:"run"`
		Env  map[string]string `yaml:"env"`
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []step `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	native := func(s step) bool { return strings.Contains(s.If, "runner.environment == 'self-hosted'") }
	var jobs []string
	for name, job := range wf.Jobs {
		firstTest, setup := -1, -1
		for i, s := range job.Steps {
			if _, ok := s.Env["TMPDIR"]; ok {
				t.Errorf("job %s step %q pins TMPDIR in its env; it must come from the per-job mktemp step", name, s.Name)
			}
			if native(s) && strings.Contains(s.Run, "mktemp -d "+tmpdirTemplate) &&
				strings.Contains(s.Run, `echo "TMPDIR=$d" >> "$GITHUB_ENV"`) &&
				strings.Contains(s.Run, `echo "GOTMPDIR=$d" >> "$GITHUB_ENV"`) && setup < 0 {
				setup = i
			}
			runsTests := strings.Contains(s.Run, "go test ") || strings.Contains(s.Run, "make test")
			if native(s) && runsTests && firstTest < 0 {
				firstTest = i
			}
		}
		if firstTest < 0 {
			continue
		}
		jobs = append(jobs, name)
		if setup < 0 || setup > firstTest {
			t.Errorf("job %s runs go test natively without a prior mktemp -d %s step exporting TMPDIR and GOTMPDIR", name, tmpdirTemplate)
		}
		last := job.Steps[len(job.Steps)-1]
		if !strings.Contains(last.If, "always()") || !native(last) || !strings.Contains(last.Run, `rm -rf "$TMPDIR"`) {
			t.Errorf("job %s's last step %q does not remove the per-job TMPDIR under always()", name, last.Name)
		}
	}
	// build, Nested Module Tests, build-raft, Race Detector and the TPM 2.0
	// simulator job.
	if len(jobs) < 5 {
		t.Errorf("found native go test steps in jobs %v, want at least 5: the predicate no longer matches ci.yml", jobs)
	}

	// The worst case socket path: the template, t.TempDir's up to 74 bytes,
	// then /001/xkms.sock, within sun_path's 107 usable bytes.
	worst := fmt.Sprintf("%s/%074d/001/xkms.sock", tmpdirTemplate, 0)
	if len(worst) > 107 {
		t.Errorf("worst case socket path is %d bytes, want at most 107", len(worst))
	}
}
