package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docsPathsRoot is the repository root seen from this package directory.
var docsPathsRoot = filepath.Join("..", "..")

func docsPathsRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsPathsRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

var xkmsdExecStart = regexp.MustCompile(`(?m)^ExecStart=\S*/xkmsd(\s|$)`)

// xkmsdUnits returns every systemd unit under deploy/ and configs/ whose
// ExecStart runs xkmsd (go-xkms#2256: two such units named different
// config files).
func xkmsdUnits(t *testing.T) []string {
	t.Helper()
	var units []string
	for _, dir := range []string{"deploy", "configs"} {
		err := filepath.WalkDir(filepath.Join(docsPathsRoot, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(p) != ".service" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if xkmsdExecStart.Match(b) {
				rel, _ := filepath.Rel(docsPathsRoot, p)
				units = append(units, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return units
}

func TestOneXkmsdSystemdUnit(t *testing.T) {
	units := xkmsdUnits(t)
	if len(units) != 1 {
		t.Fatalf("want exactly one systemd unit running xkmsd under deploy/ and configs/, got %v", units)
	}
}

var (
	etcConfigRef  = regexp.MustCompile(`/etc/xkms/([\w.-]+\.ya?ml)`)
	repoConfigRef = regexp.MustCompile(`\bconfigs/([\w.-]+\.ya?ml)`)
)

// TestDeployConfigPathsExist asserts every config file the deploy README and
// the xkmsd unit name exists under configs/ by its base name.
func TestDeployConfigPathsExist(t *testing.T) {
	files := append([]string{"deploy/README.md"}, xkmsdUnits(t)...)
	for _, f := range files {
		text := docsPathsRead(t, f)
		var names []string
		for _, m := range etcConfigRef.FindAllStringSubmatch(text, -1) {
			names = append(names, m[1])
		}
		for _, m := range repoConfigRef.FindAllStringSubmatch(text, -1) {
			names = append(names, m[1])
		}
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(docsPathsRoot, "configs", n)); err != nil {
				t.Errorf("%s names config %s, but configs/%s does not exist", f, n, n)
			}
		}
	}
}

var (
	bundleJoin  = regexp.MustCompile(`filepath\.Join\(dataDir, "([^"]+)"\)`)
	initDataDir = regexp.MustCompile(`--data-dir\s+(\S+)`)
)

// docsPathsStep returns numbered step n of the "Bootstrap a new server"
// list in text, continuation lines included.
func docsPathsStep(t *testing.T, text string, n string) string {
	t.Helper()
	_, sec, ok := strings.Cut(text, "## Bootstrap a new server")
	if !ok {
		t.Fatal("user.md has no \"Bootstrap a new server\" section")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	var b strings.Builder
	in := false
	for _, line := range strings.Split(sec, "\n") {
		if regexp.MustCompile(`^\d+\. `).MatchString(line) {
			in = strings.HasPrefix(line, n+". ")
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		t.Fatalf("user.md has no step %s", n)
	}
	return b.String()
}

// TestInitCeremonyStep3NamesWrittenBundle asserts user.md step 3 names the
// bundle file persistCABundle writes, at the --data-dir step 2 passes.
func TestInitCeremonyStep3NamesWrittenBundle(t *testing.T) {
	src := docsPathsRead(t, "cmd/xkmsd/init_ceremony.go")
	_, body, ok := strings.Cut(src, "func persistCABundle(")
	if !ok {
		t.Fatal("persistCABundle not found in cmd/xkmsd/init_ceremony.go")
	}
	body, _, _ = strings.Cut(body, "\n}\n")
	m := bundleJoin.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("persistCABundle has no filepath.Join(dataDir, \"<name>\")")
	}
	bundle := m[1]

	doc := docsPathsRead(t, "docs/init-ceremony/user.md")
	dd := initDataDir.FindStringSubmatch(docsPathsStep(t, doc, "2"))
	if dd == nil {
		t.Fatal("user.md step 2 passes no --data-dir")
	}
	want := "`" + filepath.ToSlash(filepath.Join(dd[1], bundle)) + "`"
	if step3 := docsPathsStep(t, doc, "3"); !strings.Contains(step3, want) {
		t.Errorf("user.md step 3 must name %s (persistCABundle under --data-dir), got:\n%s", want, step3)
	}
}
