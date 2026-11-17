package buildgates

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestNativeGoTestStepsSetAShortTMPDIR pins the #2183 sun_path fix: on the
// self-hosted pool TMPDIR is the runner's _work/_temp, so a Unix socket under
// t.TempDir (TestName + random suffix + /001/x.sock) overflowed sun_path's
// 108 bytes and bind failed with "invalid argument" in 32 Race Detector tests
// and the Nested Module Tests. Every native step (runner.environment ==
// 'self-hosted') that runs go test sets TMPDIR to /tmp; the toolchain image
// steps already test under /var/tmp.
func TestNativeGoTestStepsSetAShortTMPDIR(t *testing.T) {
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
	native := 0
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if !strings.Contains(s.If, "runner.environment == 'self-hosted'") || !strings.Contains(s.Run, "go test ") {
				continue
			}
			native++
			if got := s.Env["TMPDIR"]; got != "/tmp" {
				t.Errorf("job %s step %q runs go test natively with TMPDIR %q, want /tmp", name, s.Name, got)
			}
		}
	}
	// Nested Module Tests (2), build-raft, Race Detector and the TPM 2.0
	// simulator job.
	if native < 5 {
		t.Errorf("found %d native go test steps, want at least 5: the predicate no longer matches ci.yml", native)
	}
}
