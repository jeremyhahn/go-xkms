package buildgates

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestCoverageExtrasRunOnceOutsideTheShards pins each COVERAGE_EXTRAS part to make test's parts beside test-go, run once outside the package shards.
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
	var extras []string
	for _, l := range lines {
		name, parts, ok := strings.Cut(l, " := ")
		shard, isExtras := strings.CutPrefix(name, "COVERAGE_EXTRAS_")
		if !ok || !isExtras {
			continue
		}
		if !strings.HasPrefix(shard, "extras-") {
			t.Errorf("extras shard %q does not start with extras-", shard)
		}
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
}
