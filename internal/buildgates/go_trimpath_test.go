package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Issue #2309 (DS-9612): without -trimpath cmd/go hashes the package
// directory into each action ID, so every lane and verify clone builds new
// cache keys and the shared Go build cache grows without reuse.

// globalGOFLAGS matches an unconditional (not target-specific) export of
// GOFLAGS at the start of a Makefile line.
var globalGOFLAGS = regexp.MustCompile(`(?m)^export GOFLAGS\s*(?::=|\+=|=|\?=)(.*)$`)

// firstRule matches the first Makefile rule line (target: prerequisites).
var firstRule = regexp.MustCompile(`(?m)^[A-Za-z0-9_.%/-]+\s*:(?:[^=:\n]|$)`)

func TestMakefileExportsTrimpath(t *testing.T) {
	mk := readMakefile(t)
	m := globalGOFLAGS.FindStringSubmatchIndex(mk)
	if m == nil {
		t.Fatal("Makefile has no global `export GOFLAGS` line; every go build/test target needs -trimpath (#2309)")
	}
	if !strings.Contains(mk[m[2]:m[3]], "-trimpath") {
		t.Fatalf("Makefile global GOFLAGS export lacks -trimpath: %q", mk[m[0]:m[1]])
	}
	if r := firstRule.FindStringIndex(mk); r != nil && r[0] < m[0] {
		t.Fatalf("global GOFLAGS export must precede the first rule (found rule %q first)",
			strings.SplitN(mk[r[0]:], "\n", 2)[0])
	}
}

func TestMakefileCoverageKeepsGOFLAGS(t *testing.T) {
	mk := readMakefile(t)
	re := regexp.MustCompile(`(?m)^coverage:\s*export GOFLAGS\s*:=(.*)$`)
	m := re.FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("coverage target-specific GOFLAGS line not found")
	}
	if !strings.Contains(m[1], "$(GOFLAGS)") && !strings.Contains(m[1], "-trimpath") {
		t.Fatalf("coverage GOFLAGS drops the global -trimpath: %q", m[0])
	}
}

func TestCIWorkflowGOFLAGSTrimpath(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s+GOFLAGS:\s*([^#\n]*)`)
	all := re.FindAllStringSubmatch(string(data), -1)
	if len(all) == 0 {
		t.Fatal("ci.yml has no GOFLAGS env lines")
	}
	for _, m := range all {
		if !strings.Contains(m[1], "-trimpath") {
			t.Errorf("ci.yml GOFLAGS env lacks -trimpath: %q", strings.TrimSpace(m[0]))
		}
	}
}
