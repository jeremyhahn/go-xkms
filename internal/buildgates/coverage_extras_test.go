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
// as two extras matrix entries (SHARD=extras-nofrost and SHARD=extras-other,
// make coverage-extras). Each part still runs exactly once: the
// COVERAGE_EXTRAS_<shard> lists together are make test's list minus test-go,
// the package shards' recipe names none of them, and the coverage matrix
// carries one include entry per extras shard, which exports and uploads no
// profile.
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
	var extras, extraShards []string
	for _, l := range lines {
		name, parts, ok := strings.Cut(l, " := ")
		shard, isExtras := strings.CutPrefix(name, "COVERAGE_EXTRAS_")
		if !ok || !isExtras {
			continue
		}
		if !strings.HasPrefix(shard, "extras-") {
			t.Errorf("extras shard %q does not start with extras-", shard)
		}
		extraShards = append(extraShards, shard)
		extras = append(extras, strings.Fields(parts)...)
	}
	slices.Sort(extras)
	sortedParts := slices.Sorted(slices.Values(testParts))
	if len(testParts) == 0 || !slices.Equal(extras, sortedParts) {
		t.Errorf("COVERAGE_EXTRAS_* parts = %v, want make test's parts beside test-go, once each: %v", extras, sortedParts)
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
	if !strings.Contains(text, "ifneq ($(filter extras-%,$(SHARD)),)\ncoverage-shard: coverage-extras\nelse\n") {
		t.Error("make coverage-shard SHARD=extras-* does not run coverage-extras")
	}
	if !strings.Contains(text, "\t@for t in $(COVERAGE_EXTRAS_$(SHARD)); do $(MAKE) --no-print-directory $$t || exit 1; done\n") {
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
	var included []string
	for _, inc := range cov.Strategy.Matrix.Include {
		included = append(included, inc["shard"])
	}
	slices.Sort(included)
	slices.Sort(extraShards)
	if len(extraShards) == 0 || !slices.Equal(included, extraShards) {
		t.Errorf("coverage matrix include shards = %v, want the Makefile's extras shards %v", included, extraShards)
	}
	const notExtras = "!startsWith(matrix.shard, 'extras-')"
	for _, s := range cov.Steps {
		if strings.Contains(s.Run, "make coverage-shard") && !strings.Contains(s.Env["IN_IMAGE_EXPORT"], notExtras) {
			t.Errorf("make coverage-shard step exports %q for the extras entry too", s.Env["IN_IMAGE_EXPORT"])
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") && !strings.Contains(s.If, notExtras) {
			t.Errorf("upload step if %q also runs for the extras entry, which has no profile", s.If)
		}
	}
}
