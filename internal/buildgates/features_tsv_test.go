package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// featuresTSV is the per-feature test map that `make test-feature`,
// `make integration-test-feature` and scripts/touched-features.sh read
// (Tenant ruling 1170): one row per feature of docs/SPEC.md whose Detail
// column links a feature folder.
const featuresTSV = "scripts/features.tsv"

// featureFolderLink matches a Detail-column link to a feature folder,
// `[name/](name/)`; the second group is the folder under docs/.
var featureFolderLink = regexp.MustCompile(`\[([a-z0-9-]+)/\]\(([a-z0-9-]+)/\)`)

// specFeature is one row of the docs/SPEC.md Features table.
type specFeature struct {
	name    string
	folders []string
}

// readSpecFeatures parses the `## Features` table of docs/SPEC.md.
func readSpecFeatures(t *testing.T) []specFeature {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "docs", "SPEC.md"))
	if err != nil {
		t.Fatalf("read docs/SPEC.md: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "## Features" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("docs/SPEC.md has no `## Features` section")
	}
	var out []specFeature
	inTable := false
	for _, l := range lines[start+1:] {
		if !strings.HasPrefix(l, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cols := strings.Split(strings.Trim(strings.TrimSpace(l), "|"), "|")
		name := strings.TrimSpace(cols[0])
		if name == "Feature" || strings.HasPrefix(name, "---") {
			continue
		}
		f := specFeature{name: name}
		for _, m := range featureFolderLink.FindAllStringSubmatch(cols[len(cols)-1], -1) {
			f.folders = append(f.folders, m[2])
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		t.Fatal("docs/SPEC.md Features table has no rows")
	}
	return out
}

// featureRow is one row of scripts/features.tsv.
type featureRow struct {
	line        int
	feature     string
	paths       []string
	unit        []string
	integration []string
}

// fieldList splits a space-separated TSV field; `-` is the empty list.
func fieldList(s string) []string {
	if strings.TrimSpace(s) == "-" {
		return nil
	}
	return strings.Fields(s)
}

// readFeatureRows parses scripts/features.tsv.
func readFeatureRows(t *testing.T) []featureRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, featuresTSV))
	if err != nil {
		t.Fatalf("read %s: %v", featuresTSV, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if want := "feature\tpaths\tunit\tintegration"; lines[0] != want {
		t.Fatalf("%s header = %q, want %q", featuresTSV, lines[0], want)
	}
	var rows []featureRow
	for i, l := range lines[1:] {
		cols := strings.Split(l, "\t")
		if len(cols) != 4 {
			t.Fatalf("%s:%d: %d tab-separated columns, want 4", featuresTSV, i+2, len(cols))
		}
		for j, c := range cols {
			if strings.TrimSpace(c) == "" {
				t.Fatalf("%s:%d: column %d is empty (use `-` for none)", featuresTSV, i+2, j+1)
			}
		}
		rows = append(rows, featureRow{
			line:        i + 2,
			feature:     cols[0],
			paths:       fieldList(cols[1]),
			unit:        fieldList(cols[2]),
			integration: fieldList(cols[3]),
		})
	}
	return rows
}

// TestFeaturesTSVCoversSpecFeatures fails when a SPEC feature that links a
// feature folder has no row, a row names no SPEC feature, or a feature is
// listed twice.
func TestFeaturesTSVCoversSpecFeatures(t *testing.T) {
	spec := readSpecFeatures(t)
	rows := readFeatureRows(t)

	known := map[string]specFeature{}
	for _, f := range spec {
		known[f.name] = f
	}
	seen := map[string]int{}
	for _, r := range rows {
		if prev, dup := seen[r.feature]; dup {
			t.Errorf("%s:%d: feature %q already listed on line %d", featuresTSV, r.line, r.feature, prev)
		}
		seen[r.feature] = r.line
		if _, ok := known[r.feature]; !ok {
			t.Errorf("%s:%d: %q is not a feature of the docs/SPEC.md Features table", featuresTSV, r.line, r.feature)
		}
	}
	for _, f := range spec {
		if len(f.folders) == 0 {
			continue
		}
		if _, ok := seen[f.name]; !ok {
			t.Errorf("SPEC feature %q links %v but has no row in %s", f.name, f.folders, featuresTSV)
		}
	}
}

// TestFeaturesTSVPathsExist fails when a `paths` prefix is not in the tree,
// or a row leaves out the docs folder its SPEC row links.
func TestFeaturesTSVPathsExist(t *testing.T) {
	spec := map[string]specFeature{}
	for _, f := range readSpecFeatures(t) {
		spec[f.name] = f
	}
	for _, r := range readFeatureRows(t) {
		if len(r.paths) == 0 {
			t.Errorf("%s:%d: %s has no paths", featuresTSV, r.line, r.feature)
		}
		has := map[string]bool{}
		for _, p := range r.paths {
			has[p] = true
			if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
				t.Errorf("%s:%d: %s path %q is not a repository-relative prefix", featuresTSV, r.line, r.feature, p)
				continue
			}
			info, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(p)))
			if err != nil {
				t.Errorf("%s:%d: %s path %q does not exist in the tree", featuresTSV, r.line, r.feature, p)
				continue
			}
			if strings.HasSuffix(p, "/") != info.IsDir() {
				t.Errorf("%s:%d: %s path %q: a directory prefix ends in `/`, a file does not", featuresTSV, r.line, r.feature, p)
			}
		}
		for _, folder := range spec[r.feature].folders {
			if want := "docs/" + folder + "/"; !has[want] {
				t.Errorf("%s:%d: %s paths leave out its docs folder %s", featuresTSV, r.line, r.feature, want)
			}
		}
	}
}

// TestFeaturesTSVUnitPatterns fails when a `unit` pattern is not a
// `./<dir>` or `./<dir>/...` Go package pattern of an existing directory.
func TestFeaturesTSVUnitPatterns(t *testing.T) {
	for _, r := range readFeatureRows(t) {
		for _, u := range r.unit {
			dir := strings.TrimSuffix(u, "/...")
			if !strings.HasPrefix(dir, "./") || strings.Contains(dir, "...") || strings.Contains(dir, "/..") {
				t.Errorf("%s:%d: %s unit pattern %q is not ./<dir> or ./<dir>/...", featuresTSV, r.line, r.feature, u)
				continue
			}
			info, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(dir)))
			if err != nil || !info.IsDir() {
				t.Errorf("%s:%d: %s unit pattern %q names no directory", featuresTSV, r.line, r.feature, u)
			}
		}
	}
}

// TestFeaturesTSVIntegrationTargets fails when an `integration` entry is not
// an explicit Makefile target (the `integration-test-%` pattern rule does not
// count: a name only it matches runs `go test` on a directory that may not
// exist).
func TestFeaturesTSVIntegrationTargets(t *testing.T) {
	makefile := readMakefile(t)
	for _, r := range readFeatureRows(t) {
		for _, target := range r.integration {
			if _, ok := makePrerequisites(makefile, target); !ok {
				t.Errorf("%s:%d: %s integration target %q is not a Makefile target", featuresTSV, r.line, r.feature, target)
			}
		}
	}
}

// TestMakefileDefinesFeatureTargets fails when the Makefile loses the two
// per-feature targets the factory's local verify calls.
func TestMakefileDefinesFeatureTargets(t *testing.T) {
	makefile := readMakefile(t)
	for _, target := range []string{"test-feature", "integration-test-feature"} {
		if _, ok := makePrerequisites(makefile, target); !ok {
			t.Errorf("Makefile has no %s target", target)
		}
	}
}
