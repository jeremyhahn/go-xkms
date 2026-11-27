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

// golangci-lint's cgocall analysis re-reads cgo files by the paths the build
// records; under -trimpath they are module-relative and it stops with "can't
// parse raw cgo file". The lint recipe must export GOFLAGS without -trimpath
// before its first golangci-lint run (builds and tests keep it).
func TestLintRecipeStripsTrimpath(t *testing.T) {
	mk := readMakefile(t)
	start := regexp.MustCompile(`(?m)^lint:[^=\n]*$`).FindStringIndex(mk)
	if start == nil {
		t.Fatal("Makefile has no lint: rule")
	}
	var recipe []string
	for _, line := range strings.Split(mk[start[1]:], "\n")[1:] {
		if !strings.HasPrefix(line, "\t") {
			break
		}
		recipe = append(recipe, line)
	}
	body := strings.Join(recipe, "\n")
	run := strings.Index(body, "$$GOLANGCI_LINT_BIN run")
	if run < 0 {
		t.Fatal("lint recipe has no `$$GOLANGCI_LINT_BIN run`")
	}
	strip := strings.Index(body, `export GOFLAGS="$(filter-out -trimpath,$(GOFLAGS))"`)
	if strip < 0 || strip > run {
		t.Fatal(`lint recipe must export GOFLAGS="$(filter-out -trimpath,$(GOFLAGS))" before golangci-lint runs (#2309)`)
	}
}

// makeLogical returns the Makefile's logical lines: each backslash-continued
// line joined to the next.
func makeLogical(mk string) []string {
	var out []string
	cur := ""
	for _, line := range strings.Split(mk, "\n") {
		if strings.HasSuffix(line, "\\") {
			cur += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		out = append(out, cur+line)
		cur = ""
	}
	return out
}

// TestDockerBuildsForwardGOFLAGS pins Codex round 2 on #2322 (Makefile:21):
// outside XKMS_NATIVE_BUILD=1, build-server and lib run through CGO_RUN and
// build-xkey through its own docker run; the exported GOFLAGS (-trimpath)
// reaches those containers only through BUILDER_MODULE_ENV.
func TestDockerBuildsForwardGOFLAGS(t *testing.T) {
	lines := makeLogical(readMakefile(t))
	var env, cgoRun string
	for _, l := range lines {
		switch {
		case regexp.MustCompile(`^BUILDER_MODULE_ENV\s*:?=`).MatchString(l):
			env = l
		case regexp.MustCompile(`^CGO_RUN\s*:?=\s*docker run`).MatchString(l):
			cgoRun = l
		}
	}
	if env == "" {
		t.Fatal("Makefile has no BUILDER_MODULE_ENV definition")
	}
	if !regexp.MustCompile(`-e GOFLAGS(\s|=|$)`).MatchString(env) {
		t.Errorf("BUILDER_MODULE_ENV does not forward GOFLAGS into the builder containers: %q", env)
	}
	if cgoRun == "" || !strings.Contains(cgoRun, "$(BUILDER_MODULE_ENV)") {
		t.Errorf("Docker-backed CGO_RUN does not pass $(BUILDER_MODULE_ENV): %q", cgoRun)
	}

	in, goBuilds := false, 0
	for _, l := range lines {
		if strings.HasPrefix(l, "build-xkey:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(l, "\t") {
			break
		}
		if strings.Contains(l, "docker run") && strings.Contains(l, "go build") {
			goBuilds++
			if !strings.Contains(l, "$(BUILDER_MODULE_ENV)") {
				t.Errorf("build-xkey docker run of go build does not pass $(BUILDER_MODULE_ENV): %q", l)
			}
		}
	}
	if goBuilds == 0 {
		t.Error("build-xkey recipe has no docker run of go build")
	}
}

// TestDevcontainerHelpersForwardGOFLAGS pins Codex P2 on #2322 (Makefile:21):
// the global export does not reach commands run through `docker compose
// exec`, so run_in_devcontainer and run_with_server (integration-test-fido2,
// integration-test-pkcs11-module, ...) must forward the exported GOFLAGS into
// every exec and append them to the devcontainer's own (-mod=readonly).
func TestDevcontainerHelpersForwardGOFLAGS(t *testing.T) {
	lines := makeLogical(readMakefile(t))
	const forward = `-e XKMS_CALLER_GOFLAGS="$$GOFLAGS"`
	merge := ""
	for _, l := range lines {
		if regexp.MustCompile(`^devcontainer_goflags\s*:?=`).MatchString(l) {
			merge = l
		}
	}
	if !strings.Contains(merge, `export GOFLAGS=`) || !strings.Contains(merge, `XKMS_CALLER_GOFLAGS`) {
		t.Errorf("devcontainer_goflags does not append XKMS_CALLER_GOFLAGS to the devcontainer's GOFLAGS: %q", merge)
	}
	for _, name := range []string{"run_in_devcontainer", "run_with_server"} {
		in, execs := false, 0
		for _, l := range lines {
			if l == "define "+name {
				in = true
				continue
			}
			if !in {
				continue
			}
			if l == "endef" {
				break
			}
			parts := strings.Split(l, "$(DOCKER_COMPOSE) exec")
			for _, p := range parts[1:] {
				execs++
				dev := strings.Index(p, " devcontainer ")
				if dev < 0 || !strings.Contains(p[:dev], forward) {
					t.Errorf("%s: compose exec does not forward GOFLAGS (%s): %q", name, forward, p)
				}
				if !strings.Contains(p, "$(devcontainer_goflags)") {
					t.Errorf("%s: compose exec command does not apply $(devcontainer_goflags): %q", name, p)
				}
			}
		}
		if execs == 0 {
			t.Errorf("%s has no $(DOCKER_COMPOSE) exec", name)
		}
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

// ciJobBlock returns the text of the top-level job id in ci.yml, from its
// "  id:" line up to the next two-space-indented key.
func ciJobBlock(t *testing.T, ci, id string) string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(id) + `:\s*$`).FindStringIndex(ci)
	if start == nil {
		t.Fatalf("ci.yml has no job %q", id)
	}
	rest := ci[start[1]:]
	if end := regexp.MustCompile(`(?m)^  \S`).FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}
	return rest
}

// TestCIFullTierOnBuildFiles pins ruling 1041(4): a PR that changes a
// Makefile, a go.mod/go.sum or ci.yml (a build-flag change) runs the full
// matrix without the ci:full label.
func TestCIFullTierOnBuildFiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	ci := string(data)

	m := regexp.MustCompile(`(?m)^\s+FULL_TIER_PATTERN:\s*'([^']*)'`).FindStringSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml env lacks FULL_TIER_PATTERN")
	}
	pat, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("FULL_TIER_PATTERN %q: %v", m[1], err)
	}
	for _, p := range []string{"Makefile", "go.mod", "go.sum", "sdk/go/go.mod", "xkey/go.sum", ".github/workflows/ci.yml"} {
		if !pat.MatchString(p) {
			t.Errorf("FULL_TIER_PATTERN does not select %s", p)
		}
	}
	for _, p := range []string{"pkg/xkms/errors.go", "docs/SPEC.md"} {
		if pat.MatchString(p) {
			t.Errorf("FULL_TIER_PATTERN selects %s", p)
		}
	}

	ifRe := regexp.MustCompile(`(?m)^    if:\s*(.*)$`)
	needsRe := regexp.MustCompile(`(?m)^    needs:\s*(.*)$`)
	for _, id := range []string{"integration", "nested-module-test", "build-raft", "race", "tpm2-simulator"} {
		block := ciJobBlock(t, ci, id)
		cond := ifRe.FindStringSubmatch(block)
		if cond == nil || !strings.Contains(cond[1], "needs.preflight.outputs.full_paths == 'true'") {
			t.Errorf("job %s if: does not select on full_paths", id)
		}
		needs := needsRe.FindStringSubmatch(block)
		if needs == nil || !strings.Contains(needs[1], "preflight") {
			t.Errorf("job %s does not need preflight", id)
		}
	}

	gate := regexp.MustCompile(`(?m)^\s+FULL_TIER:\s*(.*)$`).FindStringSubmatch(ci)
	if gate == nil || !strings.Contains(gate[1], "needs.preflight.outputs.full_paths == 'true'") {
		t.Error("CI Gate FULL_TIER does not read full_paths")
	}
}

// TestCIFullTierFailsClosed pins Codex round 2 on #2322: on a pull_request
// the preflight diff step starts with full_paths=true and sets it false only
// after the git diff succeeded and no changed file matched FULL_TIER_PATTERN,
// so a failed diff (missing merge base, unavailable commit) runs the full tier.
func TestCIFullTierFailsClosed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	ci := string(data)
	start := strings.Index(ci, "        id: diff\n")
	if start < 0 {
		t.Fatal("ci.yml lacks the preflight diff step")
	}
	end := strings.Index(ci[start:], ">> \"$GITHUB_OUTPUT\"")
	if end < 0 {
		t.Fatal("diff step does not write GITHUB_OUTPUT")
	}
	step := ci[start : start+end]

	diffAt := strings.Index(step, "if files=$(git diff ")
	if diffAt < 0 {
		t.Fatal("diff step lacks the guarded git diff")
	}
	before, after := step[:diffAt], step[diffAt:]

	prRe := regexp.MustCompile(`if \[ "\$EVENT" = pull_request \][^\n]*; then\n\s+full_paths=true\n`)
	if !prRe.MatchString(before) {
		t.Error("diff step does not set full_paths=true on a pull_request before the git diff")
	}
	clearRe := regexp.MustCompile(`if ! printf '%s\\n' "\$files" \| grep -qE "\$FULL_TIER_PATTERN"; then\n\s+full_paths=false\n`)
	if !clearRe.MatchString(after) {
		t.Error("diff step does not clear full_paths only when the diff found no FULL_TIER_PATTERN file")
	}
	if strings.Count(after, "full_paths=false") != 1 {
		t.Error("diff step sets full_paths=false outside the successful-diff no-match branch")
	}
	if strings.Contains(after, "full_paths=true") {
		t.Error("diff step still sets full_paths=true after the git diff (fail open)")
	}
}
