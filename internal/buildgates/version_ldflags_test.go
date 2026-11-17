package buildgates

import (
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
// Makefile's -X targets set to a probe value and asserts each prints it.
func TestBinariesReportStampedVersion(t *testing.T) {
	const probe = "v9.9.9"
	var ldflags []string
	for _, target := range makefileLDFlagsTargets(t) {
		ldflags = append(ldflags, "-X", target+"="+probe)
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
		if !strings.Contains(string(msg), probe) {
			t.Errorf("%s %v does not print the stamped version %s:\n%s", b.pkg, b.args, probe, msg)
		}
	}
}
