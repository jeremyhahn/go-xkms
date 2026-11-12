package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// lintGatesProbe is the expression the CI job `lint-gates` greps the Makefile
// with (.github/workflows/ci.yml, "Does the Makefile define lint-gates?").
// Without a match the job is green and runs no gate.
var lintGatesProbe = regexp.MustCompile(`(?m)^lint-gates[[:space:]]*:([^=]|$)`)

// notInPlace matches a command that starts Docker, calls sudo or installs a
// package. The bigdisk pool runs `make lint-gates` natively in a single-use
// container that has no Docker daemon and only the tools the workflow put
// there, so no recipe lint-gates reaches may hold one.
var notInPlace = regexp.MustCompile(`\bdocker\b|\bsudo\b|\bapt-get\b|\bapt install\b|\bapk add\b|\bdnf\b|\byum\b|\bpip3? install\b|\bnpm install\b|\bgo install\b|\binstall-[a-z]`)

// makePrerequisites returns the prerequisites the Makefile lists on the rule
// line of target, and whether the Makefile has that rule.
func makePrerequisites(makefile, target string) ([]string, bool) {
	rule := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(target) + `[ \t]*:([^=\n][^\n]*)?$`)
	m := rule.FindStringSubmatch(makefile)
	if m == nil {
		return nil, false
	}
	list, _, _ := strings.Cut(m[1], "#")
	return strings.Fields(strings.ReplaceAll(list, "|", " ")), true
}

// isTestTarget reports whether a make target runs tests.
func isTestTarget(name string) bool {
	return name == "test" || strings.HasPrefix(name, "test-") || strings.HasSuffix(name, "-test") ||
		strings.HasPrefix(name, "unit-test") || strings.HasPrefix(name, "integration-test")
}

func readMakefile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	return string(data)
}

func TestMakefileDefinesLintGates(t *testing.T) {
	makefile := readMakefile(t)
	if !lintGatesProbe.MatchString(makefile) {
		t.Fatalf("the Makefile has no lint-gates rule the CI probe %q finds: the lint-gates job runs no gate", lintGatesProbe)
	}
	phony := false
	for _, line := range strings.Split(makefile, "\n") {
		if rest, ok := strings.CutPrefix(line, ".PHONY:"); ok && slices.Contains(strings.Fields(rest), "lint-gates") {
			phony = true
		}
	}
	if !phony {
		t.Error("lint-gates is not .PHONY")
	}
	if !strings.Contains(makefile, "\n## lint-gates:") {
		t.Error("lint-gates has no `## lint-gates:` help line")
	}
}

func TestLintGatesRunInPlaceUnderNativeBuild(t *testing.T) {
	// The dry run expands the prerequisites, so it prints every command the
	// target reaches. The make that runs this test (test-buildgates is one of
	// the gates) must not hand its flags to this one.
	cmd := exec.Command("make", "-n", "lint-gates", "XKMS_NATIVE_BUILD=1")
	cmd.Dir = repoRoot
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "MAKEFLAGS" || name == "MFLAGS" || name == "MAKELEVEL" || name == "MAKEOVERRIDES" {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n lint-gates XKMS_NATIVE_BUILD=1: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatal("make -n lint-gates XKMS_NATIVE_BUILD=1 prints no command: the target runs no gate")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if hit := notInPlace.FindString(line); hit != "" {
			t.Errorf("lint-gates reaches %q under XKMS_NATIVE_BUILD=1; it must run in place: %q", hit, line)
		}
	}
}

func TestLintGatesAndLintDoNotOverlap(t *testing.T) {
	makefile := readMakefile(t)
	lint, ok := makePrerequisites(makefile, "lint")
	if !ok {
		t.Fatal("the Makefile has no lint rule")
	}
	if slices.Contains(lint, "lint-gates") {
		t.Error("lint lists lint-gates: CI runs the gates in the lint-gates job, so they would run twice")
	}
	gates, ok := makePrerequisites(makefile, "lint-gates")
	if !ok {
		t.Fatal("the Makefile has no lint-gates rule")
	}
	if len(gates) == 0 {
		t.Error("lint-gates lists no gate")
	}
	for _, gate := range gates {
		switch {
		case gate == "lint" || gate == "vet" || gate == "deps-check":
			t.Errorf("lint-gates lists %s, which has a CI job of its own", gate)
		case isTestTarget(gate) && gate != "test-buildgates":
			t.Errorf("lint-gates lists the test target %s", gate)
		case slices.Contains(lint, gate):
			t.Errorf("lint and lint-gates both list %s: it would run twice", gate)
		}
	}
}
