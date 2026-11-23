package buildgates

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The handbook's testing-guidelines.md section 4 mapping (Tenant rulings 1170
// and 1171): a feature is a directory test/integration/<feature>/ holding
// _test.go files, run by `make integration-test-<feature>`, either through the
// integration-test-% pattern rule or an explicit rule that runs that
// directory. scripts/touched-features.sh reads the same mapping, so these
// tests keep the Makefile and the tree from drifting apart.

var (
	explicitIntegrationRule = regexp.MustCompile(`(?m)^(integration-test-[a-z0-9-]+):`)
	makeVarAssign           = regexp.MustCompile(`(?m)^([A-Za-z0-9_]+)\s*[:?+]?=\s*(.*)$`)
	makeVarRef              = regexp.MustCompile(`\$[({]([A-Za-z0-9_]+)[)}]`)
	integrationPathRef      = regexp.MustCompile(`((?:[A-Za-z0-9_.-]+/)*)test/integration/([A-Za-z0-9_.-]+)`)
	integrationDirCall      = regexp.MustCompile(`\$\(call integration_dir,([A-Za-z0-9_.-]+)\)`)
	makeDashC               = regexp.MustCompile(`\$\(MAKE\)[^\n;&|]*?\s-C\s+([^\s;&|]+)`)
	makeConditional         = regexp.MustCompile(`^(ifeq|ifneq|ifdef|ifndef|else|endif)\b`)
	recipeCd                = regexp.MustCompile(`\bcd\s+([^\s;&|]+)`)
)

// integrationFeatureDirs returns the directories directly under
// test/integration/ that hold _test.go files at any depth.
func integrationFeatureDirs(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot, "test", "integration")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read test/integration: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		hasTest := false
		err := filepath.WalkDir(filepath.Join(root, e.Name()), func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), "_test.go") {
				hasTest = true
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk test/integration/%s: %v", e.Name(), err)
		}
		if hasTest {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	return dirs
}

// makeRecipe returns the recipe lines of the first rule for target (tab
// lines and the ifeq/else/endif lines between them) and whether it exists.
func makeRecipe(makefile, target string) (string, bool) {
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, target+":") {
			continue
		}
		var b strings.Builder
		for _, r := range lines[i+1:] {
			if !strings.HasPrefix(r, "\t") && !makeConditional.MatchString(r) {
				break
			}
			b.WriteString(r)
			b.WriteString("\n")
		}
		return b.String(), true
	}
	return "", false
}

// integrationRuleText returns the recipe of target plus the recipes of its
// integration-test-* prerequisites, recursively: integration-test-storage
// runs test/integration/storage through integration-test-storage-file.
func integrationRuleText(makefile, target string, seen map[string]bool) string {
	if seen[target] {
		return ""
	}
	seen[target] = true
	recipe, _ := makeRecipe(makefile, target)
	prereqs, _ := makePrerequisites(makefile, target)
	for _, p := range prereqs {
		if strings.HasPrefix(p, "integration-test-") {
			recipe += integrationRuleText(makefile, p, seen)
		}
	}
	return recipe
}

// expandMakeVars substitutes simple Makefile variables (NAME := value) into
// text, a few levels deep, so a recipe that runs a directory through a
// variable still names it.
func expandMakeVars(makefile, text string) string {
	vars := map[string]string{}
	for _, m := range makeVarAssign.FindAllStringSubmatch(makefile, -1) {
		if _, seen := vars[m[1]]; !seen {
			vars[m[1]] = m[2]
		}
	}
	for range 4 {
		text = makeVarRef.ReplaceAllStringFunc(text, func(ref string) string {
			if v, ok := vars[makeVarRef.FindStringSubmatch(ref)[1]]; ok {
				return v
			}
			return ref
		})
	}
	return text
}

// explicitIntegrationTargets returns the explicit integration-test-<name>
// rules of the Makefile, without the integration-test-% pattern rule.
func explicitIntegrationTargets(makefile string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range explicitIntegrationRule.FindAllStringSubmatch(makefile, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// integrationDirExists reports whether <prefix>test/integration/<name> (the
// whole test/integration tree for "...") exists. A bare path resolves
// against the repository root or a directory the recipe changes into
// (`cd xkey && go test ./test/integration/uhid/...`).
func integrationDirExists(prefix, name string, cdDirs []string) bool {
	bases := []string{prefix}
	if prefix == "" || prefix == "./" {
		bases = append([]string{""}, cdDirs...)
	}
	for _, b := range bases {
		rel := filepath.Join(b, "test", "integration")
		if name != "..." {
			rel = filepath.Join(rel, name)
		}
		if fi, err := os.Stat(filepath.Join(repoRoot, rel)); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

func TestMakefileIntegrationPatternRuleRunsIntegrationDir(t *testing.T) {
	mk := readMakefile(t)
	recipe, ok := makeRecipe(mk, "integration-test-%")
	if !ok {
		t.Fatal("Makefile has no integration-test-% pattern rule")
	}
	if !strings.Contains(recipe, "$(call integration_dir,$*)") {
		t.Errorf("integration-test-%% must run $(call integration_dir,$*), the test/integration/<feature> directory; recipe:\n%s", recipe)
	}
	if !strings.Contains(mk, "integration_dir = ") || !strings.Contains(mk, "./test/integration/$(1)") {
		t.Error("Makefile must define integration_dir as ./test/integration/$(1)")
	}
}

func TestEveryIntegrationFeatureDirHasATarget(t *testing.T) {
	mk := readMakefile(t)
	dirs := integrationFeatureDirs(t)
	if len(dirs) == 0 {
		t.Fatal("no directory under test/integration/ holds _test.go files")
	}
	for _, d := range dirs {
		target := "integration-test-" + d
		if _, explicit := makeRecipe(mk, target); !explicit {
			continue // the integration-test-% pattern rule runs test/integration/<d>
		}
		text := expandMakeVars(mk, integrationRuleText(mk, target, map[string]bool{}))
		if !strings.Contains(text, "test/integration/"+d) &&
			!strings.Contains(text, "$(call integration_dir,"+d+")") {
			t.Errorf("test/integration/%s holds _test.go files but the explicit %s rule shadows the pattern rule and never runs that directory", d, target)
		}
	}
}

// nestedIntegrationSuites returns the directories below a feature directory
// (test/integration/<feature>/<dir>, relative to test/integration) that hold
// _test.go files: nested suites a target has to run on their own.
func nestedIntegrationSuites(t *testing.T) []string {
	t.Helper()
	root := filepath.Join(repoRoot, "test", "integration")
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), "_") || strings.HasPrefix(d.Name(), ".")) {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		if strings.Contains(filepath.ToSlash(rel), "/") {
			seen[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk test/integration: %v", err)
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

var (
	goTestCommand = regexp.MustCompile(`(^|[^A-Za-z0-9_])(go|\$\(GO\))\s+test(\s|$)`)
	goTestPath    = regexp.MustCompile(`(\S*?)test/integration/([A-Za-z0-9_.\-/]*)`)
	shellCmdSep   = regexp.MustCompile(`&&|;|\|\|`)
	// A YAML key or a Dockerfile instruction ends a folded go test command.
	composeKeyOrInstr = regexp.MustCompile(`^\s*([A-Za-z_][\w-]*:(\s|$)|-\s|[A-Z]+\s)`)
	shellCd           = regexp.MustCompile(`^[\s@(]*(?:\$\(call\s+[A-Za-z0-9_\-]+\s*,[\s@(]*)?cd\s+(\S+)`)
)

// goTestCovers reports whether a go test command in recipe runs the nested
// suite dir (relative to test/integration): it tests dir itself, or a parent
// of it with /... (test/integration/pkcs11 alone does not run
// test/integration/pkcs11/module).
func goTestCovers(recipe, dir string) bool {
	recipe = integrationDirCall.ReplaceAllString(recipe, "./test/integration/$1")
	recipe = strings.ReplaceAll(recipe, "\\\n", " ")
	for _, line := range strings.Split(recipe, "\n") {
		// Each recipe line is its own shell, starting at the repo root; a
		// cd moves later commands (cd xkey: into another module).
		cwd := "."
		for _, seg := range shellCmdSep.Split(line, -1) {
			if m := shellCd.FindStringSubmatch(seg); m != nil {
				dest := strings.Trim(m[1], `"'`)
				if strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "$") {
					cwd = "."
				} else {
					cwd = path.Join(cwd, dest)
				}
				continue
			}
			if !goTestCommand.MatchString(seg) {
				continue
			}
			for _, m := range goTestPath.FindAllStringSubmatch(seg, -1) {
				lead := strings.TrimLeft(m[1], `"'(`)
				rel := "test/integration/" + m[2]
				if !strings.HasPrefix(lead, "/") && !strings.HasPrefix(lead, "$") {
					rel = path.Join(cwd, lead, rel)
				}
				p, ok := strings.CutPrefix(rel, "test/integration/")
				if !ok {
					continue
				}
				p = strings.TrimSuffix(p, "/")
				if p == "..." {
					return true
				}
				if q, rec := strings.CutSuffix(p, "/..."); rec {
					if dir == q || strings.HasPrefix(dir, q+"/") {
						return true
					}
				} else if p == dir {
					return true
				}
			}
		}
	}
	return false
}

// TestEveryNestedIntegrationSuiteIsRun: a nested suite
// test/integration/<feature>/<dir> runs under make integration-test-<feature>
// only when that target (the pattern rule's <feature>/..., or an explicit
// rule and its prerequisites) runs go test on it or a parent with /...;
// scripts/touched-features.sh prints ALL for a change to any other nested
// suite, so some explicit integration-test-* target must run it.
func TestEveryNestedIntegrationSuiteIsRun(t *testing.T) {
	mk := readMakefile(t)
	if _, ok := makeRecipe(mk, "integration-test-%"); !ok {
		t.Fatal("Makefile has no integration-test-% pattern rule")
	}
	suites := nestedIntegrationSuites(t)
	delegated := map[string]string{}
	for _, d := range suites {
		feat := strings.SplitN(d, "/", 2)[0]
		if _, ok := delegated[feat]; !ok {
			delegated[feat] = composeGoTests(t, feat)
		}
	}
	missing := map[string]bool{}
	for _, d := range nestedSuitesWithoutRunner(mk, suites, delegated) {
		missing[d] = true
		if _, known := unrunNestedSuites[d]; !known {
			t.Errorf("test/integration/%s holds _test.go files but neither integration-test-%s (nor the Compose files it runs) nor any explicit integration-test-* target runs go test on it (or a parent with /...)", d, strings.SplitN(d, "/", 2)[0])
		}
	}
	for d := range unrunNestedSuites {
		if !missing[d] {
			t.Errorf("unrunNestedSuites lists %s, which a target now runs (or which is gone): drop the entry", d)
		}
	}
}

// unrunNestedSuites are the nested suites no make target runs today, each
// with the reason. The gate fails when one gains a runner, so the list only
// shrinks.
var unrunNestedSuites = map[string]string{
	"challenges/dns01":  "its own Compose stack (dns01/docker-compose.dns01.yml) builds against the pre-merge go-trusted-ca checkout; integration-test-challenges leaves it out (Makefile comment)",
	"challenges/http01": "its own Compose stack (http01/docker-compose.http01.yml) builds against the pre-merge go-trusted-ca checkout; integration-test-challenges leaves it out (Makefile comment)",
}

// composeGoTests returns the go test commands in the docker-compose.yml and
// Dockerfile of test/integration/<feat>, the files a target that delegates
// to Compose runs, one command per line (a folded YAML command joined).
func composeGoTests(t *testing.T, feat string) string {
	t.Helper()
	var out []string
	for _, name := range []string{"docker-compose.yml", "Dockerfile"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, "test", "integration", feat, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read test/integration/%s/%s: %v", feat, name, err)
		}
		lines := strings.Split(string(b), "\n")
		for i := 0; i < len(lines); i++ {
			if !goTestCommand.MatchString(lines[i]) {
				continue
			}
			cmd := lines[i]
			for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" && !composeKeyOrInstr.MatchString(lines[i+1]) {
				i++
				cmd += " " + strings.TrimSpace(lines[i])
			}
			out = append(out, cmd)
		}
	}
	return strings.Join(out, "\n")
}

// nestedSuitesWithoutRunner returns the nested suites (dirs relative to
// test/integration) that neither their feature's target nor any explicit
// integration-test-* target of mk runs go test on. delegated maps a feature
// to the go test commands of its Compose files, which count for a target
// that runs docker compose.
func nestedSuitesWithoutRunner(mk string, suites []string, delegated map[string]string) []string {
	pattern, _ := makeRecipe(mk, "integration-test-%")
	targets := explicitIntegrationTargets(mk)
	var missing []string
	for _, d := range suites {
		feat := strings.SplitN(d, "/", 2)[0]
		target := "integration-test-" + feat
		var own string
		if _, explicit := makeRecipe(mk, target); explicit {
			own = expandMakeVars(mk, integrationRuleText(mk, target, map[string]bool{}))
		} else {
			own = strings.ReplaceAll(pattern, "$*", feat)
		}
		if goTestCovers(own, d) {
			continue
		}
		if strings.Contains(own, "compose") && goTestCovers(delegated[feat], d) {
			continue
		}
		runner := ""
		for _, tg := range targets {
			recipe, _ := makeRecipe(mk, tg)
			if goTestCovers(expandMakeVars(mk, recipe), d) {
				runner = tg
				break
			}
		}
		if runner == "" {
			missing = append(missing, d)
		}
	}
	return missing
}

// A recursive ./test/integration/... runner inside a nested module (cd xkey)
// runs that module's suites, not the root's: a root nested suite with no
// runner of its own is still missing one.
func TestNestedSuiteGateIgnoresNestedModuleRunners(t *testing.T) {
	mk := "integration-test-%:\n" +
		"\tgo test -tags \"integration $*\" ./test/integration/$*\n" +
		"\n" +
		"integration-test-xkey-fido2:\n" +
		"\tcd xkey && go test -tags integration ./test/integration/...\n" +
		"\n" +
		"integration-test-xkey-wrapped:\n" +
		"\t$(call run_in_devcontainer,cd xkey && go test -tags integration ./test/integration/...,integration-test-xkey-wrapped)\n" +
		"\n" +
		"integration-test-pkcs11-module:\n" +
		"\tgo test -tags integration ./test/integration/pkcs11/module\n"
	got := nestedSuitesWithoutRunner(mk, []string{"challenges/dns01", "pkcs11/module"}, nil)
	if len(got) != 1 || got[0] != "challenges/dns01" {
		t.Errorf("nested suites without a runner = %q, want [challenges/dns01] (xkey's runner covers only xkey suites)", got)
	}
}

func TestExplicitIntegrationTargetsNameExistingDirs(t *testing.T) {
	mk := readMakefile(t)
	targets := explicitIntegrationTargets(mk)
	if len(targets) == 0 {
		t.Fatal("Makefile has no explicit integration-test-<name> rule")
	}
	for _, target := range targets {
		recipe, _ := makeRecipe(mk, target)
		text := expandMakeVars(mk, recipe)
		var cdDirs []string
		for _, m := range recipeCd.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(m[1], "test/integration") && !strings.Contains(m[1], "$") {
				cdDirs = append(cdDirs, m[1])
			}
		}
		for _, m := range integrationPathRef.FindAllStringSubmatch(text, -1) {
			if !integrationDirExists(m[1], m[2], cdDirs) {
				t.Errorf("%s names %stest/integration/%s, which does not exist", target, m[1], m[2])
			}
		}
		for _, m := range integrationDirCall.FindAllStringSubmatch(text, -1) {
			if !integrationDirExists("", m[1], nil) {
				t.Errorf("%s calls integration_dir,%s; test/integration/%s does not exist", target, m[1], m[1])
			}
		}
		for _, m := range makeDashC.FindAllStringSubmatch(text, -1) {
			if strings.Contains(m[1], "$") {
				continue
			}
			if fi, err := os.Stat(filepath.Join(repoRoot, m[1])); err != nil || !fi.IsDir() {
				t.Errorf("%s delegates to $(MAKE) -C %s, which is not a directory", target, m[1])
			}
		}
	}
}

func TestMakefileHasTestPkgTarget(t *testing.T) {
	mk := readMakefile(t)
	recipe, ok := makeRecipe(mk, "test-pkg")
	if !ok {
		t.Fatal("Makefile has no test-pkg rule (handbook testing-guidelines.md section 4: make test-pkg PKG=<dir>)")
	}
	if !strings.Contains(recipe, "$(GO) test") || !strings.Contains(recipe, "./$(PKG)") {
		t.Errorf("test-pkg must run $(GO) test on ./$(PKG); recipe:\n%s", recipe)
	}
}

// TestMakefileTestPkgUsesUnitTestTags: make test-pkg runs a package's unit
// tests, so it passes the unit-test tag set (TEST_FLAGS, built from
// TEST_TAGS: tpm_simulator, frost) and not the build tags of TAG_FLAGS;
// touched-packages.sh reads imports under the same tags.
func TestMakefileTestPkgUsesUnitTestTags(t *testing.T) {
	mk := readMakefile(t)
	recipe, ok := makeRecipe(mk, "test-pkg")
	if !ok {
		t.Fatal("Makefile has no test-pkg rule")
	}
	for _, line := range strings.Split(recipe, "\n") {
		if !strings.Contains(line, "$(GO) test") {
			continue
		}
		if !strings.Contains(line, "$(TEST_FLAGS)") && !strings.Contains(line, "$(TEST_TAGS)") {
			t.Errorf("test-pkg must pass the unit-test tags ($(TEST_FLAGS) or $(TEST_TAGS)); line:\n%s", line)
		}
		if strings.Contains(line, "$(TAG_FLAGS)") {
			t.Errorf("test-pkg passes $(TAG_FLAGS), the build tags, not the unit-test tags; line:\n%s", line)
		}
		return
	}
	t.Errorf("test-pkg has no $(GO) test line; recipe:\n%s", recipe)
}
