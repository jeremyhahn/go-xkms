package buildgates

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// modulePath is the root module of the repository.
const modulePath = "github.com/jeremyhahn/go-xkms"

// versionBinaries are the binaries the Makefile stamps with LDFLAGS and the
// arguments that make each print its version (#2255).
var versionBinaries = []struct {
	pkg  string
	args []string
}{
	{pkg: "cmd/xkmsctl", args: []string{"version"}},
	{pkg: "cmd/xkmsd", args: []string{"-version"}},
}

var ldflagsXTarget = regexp.MustCompile(`-X\s+([^=\s]+)=`)

// makefileLDFlagsTargets returns the -X targets of the Makefile's LDFLAGS
// variable, following backslash continuations.
func makefileLDFlagsTargets(t *testing.T) []string {
	t.Helper()
	var def strings.Builder
	in := false
	for _, line := range strings.Split(readMakefile(t), "\n") {
		if !in && !strings.HasPrefix(line, "LDFLAGS :=") {
			continue
		}
		in = true
		def.WriteString(line)
		def.WriteString(" ")
		if !strings.HasSuffix(strings.TrimSpace(line), "\\") {
			break
		}
	}
	var targets []string
	for _, m := range ldflagsXTarget.FindAllStringSubmatch(def.String(), -1) {
		targets = append(targets, m[1])
	}
	if len(targets) == 0 {
		t.Fatal("Makefile LDFLAGS has no -X targets")
	}
	return targets
}

// packageStringVars returns the package-level string variables declared in
// the non-test Go files of dir.
func packageStringVars(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	vars := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					vars[n.Name] = true
				}
			}
		}
	}
	return vars
}

// TestMakefileLDFlagsTargetsExist asserts every -X target of the Makefile
// names a package-level variable that exists: the linker silently ignores a
// target that does not, and the binaries then report "dev" (#2255).
func TestMakefileLDFlagsTargetsExist(t *testing.T) {
	for _, target := range makefileLDFlagsTargets(t) {
		dot := strings.LastIndex(target, ".")
		if dot <= 0 {
			t.Errorf("LDFLAGS target %q has no package", target)
			continue
		}
		pkg, name := target[:dot], target[dot+1:]
		var dirs []string
		switch {
		case pkg == "main":
			for _, b := range versionBinaries {
				dirs = append(dirs, b.pkg)
			}
		case strings.HasPrefix(pkg, modulePath+"/"):
			dirs = []string{strings.TrimPrefix(pkg, modulePath+"/")}
		default:
			t.Errorf("LDFLAGS target %q is outside module %s", target, modulePath)
			continue
		}
		for _, dir := range dirs {
			abs := filepath.Join(repoRoot, dir)
			if _, err := os.Stat(abs); err != nil {
				t.Errorf("LDFLAGS target %q: package dir %s does not exist", target, dir)
				continue
			}
			if !packageStringVars(t, abs)[name] {
				t.Errorf("LDFLAGS target %q: %s declares no variable %s", target, dir, name)
			}
		}
	}
}

// TestBinariesReportStampedVersion builds xkmsctl and xkmsd with the
// complete version target set (which the Makefile must stamp exactly), each
// set to a distinct probe, and asserts each binary prints every probe in
// its own field.
func TestBinariesReportStampedVersion(t *testing.T) {
	requireStampedTargetSet(t, "Makefile LDFLAGS", makefileLDFlagsTargets(t))
	var ldflags []string
	for _, f := range stampedFields {
		ldflags = append(ldflags, "-X", f.target+"="+f.probe)
	}
	bin := t.TempDir()
	for _, b := range versionBinaries {
		out := filepath.Join(bin, filepath.Base(b.pkg))
		build := exec.Command("go", "build", "-buildvcs=false",
			"-ldflags", strings.Join(ldflags, " "), "-o", out, "./"+b.pkg)
		build.Dir = repoRoot
		if msg, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, msg)
		}
		run := exec.Command(out, b.args...)
		msg, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", b.pkg, b.args, err, msg)
		}
		for _, f := range stampedFields {
			label := f.labels[b.pkg]
			got, ok := outputField(string(msg), label)
			if !ok {
				t.Errorf("%s %v prints no %q line for %s:\n%s", b.pkg, b.args, label, f.target, msg)
				continue
			}
			if got != f.probe {
				t.Errorf("%s %v: %q field = %q, want %q (stamped via %s)", b.pkg, b.args, label, got, f.probe, f.target)
			}
		}
	}
}

// stampedFields is the complete set of -X targets every daemon and CLI
// build path stamps, a distinct probe value per target, and the label under
// which each binary prints that value.
var stampedFields = []struct {
	target string
	probe  string
	labels map[string]string
}{
	{"main.Version", "v9.9.9-probe", map[string]string{"cmd/xkmsctl": "xkmsctl version", "cmd/xkmsd": "Version:"}},
	{"main.GitCommit", "c0ffee1-probe", map[string]string{"cmd/xkmsctl": "Git commit:", "cmd/xkmsd": "Git Commit:"}},
	{"main.BuildDate", "2099-01-02T03:04:05Z", map[string]string{"cmd/xkmsctl": "Build date:", "cmd/xkmsd": "Built:"}},
}

// outputField returns the value printed after label on the first output
// line that starts with it (leading whitespace ignored).
func outputField(out, label string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, label); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// requireStampedTargetSet fails unless got names exactly the stampedFields
// targets, each once.
func requireStampedTargetSet(t *testing.T, source string, got []string) {
	t.Helper()
	want := map[string]bool{}
	for _, f := range stampedFields {
		want[f.target] = true
	}
	seen := map[string]bool{}
	for _, g := range got {
		if !want[g] {
			t.Errorf("%s stamps %q, which is not one of the version targets", source, g)
		}
		if seen[g] {
			t.Errorf("%s stamps %q twice", source, g)
		}
		seen[g] = true
	}
	for w := range want {
		if !seen[w] {
			t.Errorf("%s does not stamp %s", source, w)
		}
	}
}

// releaseBuildPaths are the files that build xkmsd or xkmsctl directly
// with their own -ldflags rather than through the Makefile, with the
// number of go build -ldflags definitions each must carry.
var releaseBuildPaths = map[string]int{
	".github/workflows/release.yml": 3,
	"Dockerfile.cli":                1,
	"Dockerfile.grpc":               1,
	"Dockerfile.mcp":                1,
	"Dockerfile.quic":               1,
	"Dockerfile.rest":               1,
	"Dockerfile.server":             1,
}

// TestReleaseLDFlagsStampVersionTargets guards the release workflow and the
// Dockerfiles: each line that stamps package main must stamp exactly the
// Version, GitCommit and BuildDate variables both binaries declare. The
// linker ignores an -X target that names no variable, so a stale name
// ships a release that reports dev (#2255).
func TestReleaseLDFlagsStampVersionTargets(t *testing.T) {
	paths := map[string]int{}
	for p, n := range releaseBuildPaths {
		paths[p] = n
	}
	extra, err := filepath.Glob(filepath.Join(repoRoot, "Dockerfile*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, abs := range extra {
		rel := filepath.Base(abs)
		if _, ok := paths[rel]; !ok {
			paths[rel] = -1 // any count; checked only if it stamps main
		}
	}
	for rel, wantLines := range paths {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		lines := 0
		for i, line := range strings.Split(string(data), "\n") {
			var targets []string
			for _, m := range ldflagsXTarget.FindAllStringSubmatch(line, -1) {
				if strings.HasPrefix(m[1], "main.") {
					targets = append(targets, m[1])
				}
			}
			if len(targets) == 0 {
				continue
			}
			lines++
			if rel == releaseWorkflow {
				requireRecoveryTargetSet(t, fmt.Sprintf("%s:%d", rel, i+1), line)
				continue
			}
			requireStampedTargetSet(t, fmt.Sprintf("%s:%d", rel, i+1), targets)
		}
		if wantLines >= 0 && lines != wantLines {
			t.Errorf("%s: %d lines stamp package main, want %d", rel, lines, wantLines)
		}
	}
	t.Run("older-tag recovery stamps legacy names", func(t *testing.T) {
		for _, name := range legacyMainVars {
			if _, ok := releaseRecoveryTargets["main."+name]; !ok {
				t.Errorf("release.yml recovery targets lack main.%s, declared by tags cut before #2255", name)
			}
		}
	})
}

// releaseWorkflow builds from RELEASE_TAG on a workflow_dispatch repair, so
// its main.* stamps must cover the variable names of older tags too.
const releaseWorkflow = ".github/workflows/release.yml"

// legacyMainVars are the pre-#2255 cmd/xkmsd variable names (tag v0.64.2-alpha).
var legacyMainVars = []string{"version", "commit", "date"}

// releaseRecoveryTargets maps each main.* target a release.yml build line
// must stamp to its value variable: the current names and the legacy ones.
var releaseRecoveryTargets = map[string]string{
	"main.Version":   "VERSION",
	"main.GitCommit": "COMMIT",
	"main.BuildDate": "DATE",
	"main.version":   "VERSION",
	"main.commit":    "COMMIT",
	"main.date":      "DATE",
}

var ldflagsXMainValue = regexp.MustCompile(`-X\s+(main\.[^=\s]+)=\$\{?(\w+)\}?`)

// requireRecoveryTargetSet checks that line stamps exactly the
// releaseRecoveryTargets, each once and with its value variable.
func requireRecoveryTargetSet(t *testing.T, source, line string) {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range ldflagsXMainValue.FindAllStringSubmatch(line, -1) {
		target, value := m[1], m[2]
		want, ok := releaseRecoveryTargets[target]
		if !ok {
			t.Errorf("%s stamps %q, which is not one of the version targets", source, target)
			continue
		}
		if value != want {
			t.Errorf("%s stamps %s from %s, want %s", source, target, value, want)
		}
		if seen[target] {
			t.Errorf("%s stamps %q twice", source, target)
		}
		seen[target] = true
	}
	for target := range releaseRecoveryTargets {
		if !seen[target] {
			t.Errorf("%s does not stamp %s", source, target)
		}
	}
}
