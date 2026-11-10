package buildgates

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// coverageStep is the Devcontainer job's unit-suite step in ci.yml.
const coverageStep = "make coverage (unit tests and the threshold)"

// TestDevcontainerCoverageStepFitsTheHostedContainer pins the coverage step to
// one race test binary at a time under a GOMEMLIMIT below the 8g, no-swap
// container scripts/in-toolchain-image.sh gives a GitHub-hosted runner. The
// coverage target's own 10GiB and -p=2 outgrew it, and the stage hung until
// the job timeout (DS-8097).
func TestDevcontainerCoverageStepFitsTheHostedContainer(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}

	var runs []string
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			if s.Name == coverageStep {
				runs = append(runs, s.Run)
			}
		}
	}
	if len(runs) != 1 {
		t.Fatalf("ci.yml has %d steps named %q, want 1", len(runs), coverageStep)
	}

	_, cmd, ok := strings.Cut(runs[0], "make coverage ")
	if !ok {
		t.Fatalf("step %q does not run make coverage: %q", coverageStep, runs[0])
	}
	args := map[string]bool{}
	for _, f := range strings.Fields(cmd) {
		args[strings.Trim(f, `"'`)] = true
	}
	for _, want := range []string{"GOFLAGS=-p=1", "GOMEMLIMIT=6GiB"} {
		if !args[want] {
			t.Errorf("step %q: make coverage lacks %s: %q", coverageStep, want, runs[0])
		}
	}
}
