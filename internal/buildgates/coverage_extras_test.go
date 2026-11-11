package buildgates

import (
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCoverageExtrasRunOnceOutsideTheShards pins the #2042 shard balance:
// make test's parts beside test-go (shell, !frost, pkcs11, web, wailsjs) made
// coverage shard 1 run 85+ minutes against 22-27 for the others, so they run
// as their own matrix entry (SHARD=extras, make coverage-extras). Each part
// still runs exactly once: COVERAGE_EXTRAS is make test's list minus test-go,
// the package shards' recipe names none of them, and the coverage matrix
// carries one extras entry, which exports and uploads no profile.
func TestCoverageExtrasRunOnceOutsideTheShards(t *testing.T) {
	data, err := os.ReadFile(repoRoot + "/Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	var testParts []string
	if i := slices.Index(lines, "test:"); i < 0 {
		t.Fatal("Makefile has no test: target")
	} else {
		const sub = "\t@$(MAKE) --no-print-directory "
		for _, l := range lines[i+1:] {
			if !strings.HasPrefix(l, "\t") {
				break
			}
			if p, ok := strings.CutPrefix(l, sub); ok && p != "test-go" {
				testParts = append(testParts, p)
			}
		}
	}
	const extrasPrefix = "COVERAGE_EXTRAS := "
	i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, extrasPrefix) })
	if i < 0 {
		t.Fatalf("Makefile has no %q line", extrasPrefix)
	}
	extras := strings.Fields(strings.TrimPrefix(lines[i], extrasPrefix))
	if len(testParts) == 0 || !slices.Equal(extras, testParts) {
		t.Errorf("COVERAGE_EXTRAS = %v, want make test's parts beside test-go %v", extras, testParts)
	}

	text := string(data)
	start := strings.Index(text, "\ncoverage-shard: check-insecure-tls agsim\n")
	if start < 0 {
		t.Fatal("Makefile has no package-shard coverage-shard recipe")
	}
	end := strings.Index(text[start:], "\nendif\n")
	if end < 0 {
		t.Fatal("the package-shard coverage-shard recipe has no endif")
	}
	recipe := text[start : start+end]
	for _, p := range extras {
		if strings.Contains(recipe, p) {
			t.Errorf("the package shards' coverage-shard recipe still runs %s", p)
		}
	}
	if !strings.Contains(text, "ifeq ($(SHARD),extras)\ncoverage-shard: coverage-extras\nelse\n") {
		t.Error("make coverage-shard SHARD=extras does not run coverage-extras")
	}
	if !strings.Contains(text, "\t@for t in $(COVERAGE_EXTRAS); do $(MAKE) --no-print-directory $$t || exit 1; done\n") {
		t.Error("coverage-extras does not run every COVERAGE_EXTRAS part, stopping at the first failure")
	}

	wfData, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []map[string]string `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				If   string            `yaml:"if"`
				Run  string            `yaml:"run"`
				Uses string            `yaml:"uses"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(wfData, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	cov := wf.Jobs["coverage"]
	n := 0
	for _, inc := range cov.Strategy.Matrix.Include {
		if inc["shard"] == "extras" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("coverage matrix has %d include entries with shard: extras, want 1", n)
	}
	const notExtras = "matrix.shard != 'extras'"
	for _, s := range cov.Steps {
		if strings.Contains(s.Run, "make coverage-shard") && !strings.Contains(s.Env["IN_IMAGE_EXPORT"], notExtras) {
			t.Errorf("make coverage-shard step exports %q for the extras entry too", s.Env["IN_IMAGE_EXPORT"])
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") && !strings.Contains(s.If, notExtras) {
			t.Errorf("upload step if %q also runs for the extras entry, which has no profile", s.If)
		}
	}
}
