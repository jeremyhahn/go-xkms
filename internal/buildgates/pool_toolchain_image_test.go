package buildgates

// #2299 (Tenant Agent ruling 981, DS-9518): a same-repo pull request whose
// toolchain hash has no `<hash>-main` on GHCR builds the CI images once, on
// the self-hosted docker pool, and pushes them to the in-network registry
// named by the CI_IMAGE_REGISTRY secret; consumer jobs pull that image by
// digest and never build their own. Every Dockerfile apt-get runs under
// `timeout 300`, and every "Take the toolchain image" step is bounded at
// 30 minutes, so a hung apt cache fetch fails the job instead of holding it
// for hours (PR #2183, run 44546824321).

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	ciWorkflowFile  = ".github/workflows/ci.yml"
	poolRegistrySh  = "scripts/ci-registry.sh"
	aptTimeoutGuard = "timeout 300 "
	takeToolchain   = "- name: Take the toolchain image"
	poolSecretEnv   = "CI_IMAGE_REGISTRY: ${{ secrets.CI_IMAGE_REGISTRY }}"
	sameRepoPR      = "github.event.pull_request.head.repo.full_name == github.repository"
	poolRunnerLabel = `"bigdisk-docker"`
)

// aptGetWord finds apt-get as a command word (not apt-get-something).
var aptGetWord = regexp.MustCompile(`(^|[^A-Za-z0-9_/-])apt-get([^A-Za-z0-9_-]|$)`)

// dockerfileInstructions returns the logical instructions of a Dockerfile:
// comment lines dropped, backslash continuations joined.
func dockerfileInstructions(src string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasSuffix(trim, "\\") {
			cur.WriteString(strings.TrimSuffix(trim, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(trim)
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// aptTimeoutProblems lists every apt-get call in a RUN instruction that is
// not preceded by `timeout 300`.
func aptTimeoutProblems(name, src string) []string {
	var problems []string
	for _, ins := range dockerfileInstructions(src) {
		if !strings.HasPrefix(strings.ToUpper(ins), "RUN ") {
			continue
		}
		for _, loc := range aptGetWord.FindAllStringIndex(ins, -1) {
			start := loc[0]
			if ins[start] != 'a' {
				start++
			}
			if !strings.HasSuffix(ins[:start], aptTimeoutGuard) {
				end := min(len(ins), start+60)
				problems = append(problems, name+": apt-get without `timeout 300`: "+ins[max(0, start-20):end])
			}
		}
	}
	return problems
}

func isDockerfile(base string) bool {
	return strings.HasPrefix(base, "Dockerfile") || strings.HasSuffix(base, ".Dockerfile")
}

func TestDockerfileAptGetRunsUnderTimeout(t *testing.T) {
	root, err := filepath.Abs(cachesRoot)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	var problems []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !isDockerfile(d.Name()) {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- the repository's own Dockerfiles
		if err != nil {
			return err
		}
		if !aptGetWord.Match(src) {
			return nil
		}
		seen++
		rel, _ := filepath.Rel(root, path)
		problems = append(problems, aptTimeoutProblems(rel, string(src))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 30 {
		t.Fatalf("found %d Dockerfiles calling apt-get; the walk missed the repository's", seen)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestAptTimeoutCheckCatchesARegression(t *testing.T) {
	good := "FROM debian\nRUN p=\"-o A=1\"; \\\n    timeout 300 apt-get $p update && timeout 300 apt-get $p install -y x\n# apt-get in a comment\n"
	if p := aptTimeoutProblems("good", good); len(p) != 0 {
		t.Fatalf("bounded apt-get flagged: %v", p)
	}
	bad := "FROM debian\nRUN timeout 300 apt-get update && \\\n    apt-get install -y x\n"
	if p := aptTimeoutProblems("bad", bad); len(p) != 1 {
		t.Fatalf("unbounded apt-get not flagged once: %v", p)
	}
}

func readWorkflow(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(cachesRoot, ciWorkflowFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// stepBlocks returns the YAML text of every step whose `- name:` line is
// header, up to the next step at the same indentation or a shallower line.
func stepBlocks(src, header string) []string {
	lines := strings.Split(src, "\n")
	var out []string
	for i, line := range lines {
		if strings.TrimSpace(line) != header {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		block := []string{line}
		for _, next := range lines[i+1:] {
			if strings.TrimSpace(next) == "" {
				block = append(block, next)
				continue
			}
			ni := len(next) - len(strings.TrimLeft(next, " "))
			if ni <= indent {
				break
			}
			block = append(block, next)
		}
		out = append(out, strings.Join(block, "\n"))
	}
	return out
}

// jobBlock returns the text of a top-level job (two-space indent).
func jobBlock(src, job string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if line != "  "+job+":" {
			continue
		}
		block := []string{line}
		for _, next := range lines[i+1:] {
			if len(next) > 2 && next[:2] == "  " && next[2] != ' ' && next[2] != '#' {
				break
			}
			block = append(block, next)
		}
		return strings.Join(block, "\n")
	}
	return ""
}

func TestTakeToolchainStepsAreBoundedAndPoolAware(t *testing.T) {
	src := readWorkflow(t)
	steps := stepBlocks(src, takeToolchain)
	if len(steps) < 5 {
		t.Fatalf("found %d %q steps", len(steps), takeToolchain)
	}
	for i, s := range steps {
		if !regexp.MustCompile(`(?m)^\s+timeout-minutes: 30\s*$`).MatchString(s) {
			t.Errorf("step %d %q has no timeout-minutes: 30", i, takeToolchain)
		}
		if !strings.Contains(s, poolSecretEnv) {
			t.Errorf("step %d %q does not read the pool registry (%s)", i, takeToolchain, poolSecretEnv)
		}
	}
}

// workflowJobs returns the names of the jobs under ci.yml's top-level jobs:.
func workflowJobs(src string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(src, "\n") {
		if line == "jobs:" {
			in = true
			continue
		}
		if !in {
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '#' {
			break
		}
		if m := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`).FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// jobNeeds returns the jobs a job block lists under needs:, inline or as a list.
func jobNeeds(block string) []string {
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(line, "    needs:")
		if !ok {
			continue
		}
		rest, _, _ = strings.Cut(rest, "#")
		rest = strings.TrimSpace(rest)
		if rest != "" {
			rest = strings.Trim(rest, "[]")
			var out []string
			for _, n := range strings.Split(rest, ",") {
				out = append(out, strings.TrimSpace(n))
			}
			return out
		}
		var out []string
		for _, next := range lines[i+1:] {
			item, ok := strings.CutPrefix(next, "      - ")
			if !ok {
				break
			}
			item, _, _ = strings.Cut(item, "#")
			out = append(out, strings.TrimSpace(item))
		}
		return out
	}
	return nil
}

// TestToolchainConsumersNeedCIImagesAndTakeItBounded: every job that runs
// `scripts/ci-registry.sh use` (the coverage jobs included) needs ci-images,
// whose output is the reference it takes, and runs it only in a "Take the
// toolchain image" step, which the test above holds to timeout-minutes: 30
// and the pool registry secret. A consumer step under another name, or a job
// without needs: ci-images, would wait unbounded or build on its own runner.
func TestToolchainConsumersNeedCIImagesAndTakeItBounded(t *testing.T) {
	src := readWorkflow(t)
	useLine := regexp.MustCompile(`(?m)^[^#\n]*scripts/ci-registry\.sh use `)
	consumers := 0
	for _, job := range workflowJobs(src) {
		block := jobBlock(src, job)
		uses := len(useLine.FindAllString(block, -1))
		if uses == 0 {
			continue
		}
		consumers++
		if !slices.Contains(jobNeeds(block), "ci-images") {
			t.Errorf("job %s runs ci-registry.sh use but does not need ci-images (needs %v)", job, jobNeeds(block))
		}
		taken := 0
		for _, s := range stepBlocks(block, takeToolchain) {
			taken += len(useLine.FindAllString(s, -1))
		}
		if taken != uses {
			t.Errorf("job %s runs ci-registry.sh use %d times, %d of them in a %q step", job, uses, taken, takeToolchain)
		}
	}
	if consumers < 5 {
		t.Fatalf("found %d jobs that run ci-registry.sh use", consumers)
	}
}

func TestCIImagesBuildsOnceOnThePoolForSameRepoPRs(t *testing.T) {
	src := readWorkflow(t)
	if !regexp.MustCompile(`(?m)^  CI_POOL: \$\{\{[^\n]*` + regexp.QuoteMeta(sameRepoPR) + `[^\n]*\}\}$`).MatchString(src) {
		t.Errorf("workflow env has no CI_POOL for same-repo pull requests")
	}
	job := jobBlock(src, "ci-images")
	if job == "" {
		t.Fatal("no ci-images job")
	}
	for _, line := range strings.Split(job, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "runs-on:") {
			if !strings.Contains(trim, sameRepoPR) || !strings.Contains(trim, poolRunnerLabel) {
				t.Errorf("ci-images does not run on the self-hosted docker pool for same-repo PRs: %s", trim)
			}
		}
	}
	pool := stepBlocks(job, "- name: Build the CI images on the pool")
	if len(pool) != 1 {
		t.Fatalf("ci-images has %d pool build steps, want 1", len(pool))
	}
	for _, want := range []string{"env.CI_POOL == 'true'", poolSecretEnv, "scripts/ci-registry.sh pool toolchain"} {
		if !strings.Contains(pool[0], want) {
			t.Errorf("the pool build step lacks %q", want)
		}
	}
	// No ci.yml job consumes the integration image's reference, so the pool
	// builds and pushes none (#2302 Codex P2).
	if strings.Contains(pool[0], "ci-registry.sh pool it") {
		t.Errorf("the pool build step builds the unconsumed integration image")
	}
	if !strings.Contains(job, "steps.pool.outputs.toolchain_ref") {
		t.Errorf("ci-images does not output steps.pool.outputs.toolchain_ref")
	}
	if strings.Contains(job, "steps.pool.outputs.it_ref") {
		t.Errorf("ci-images references steps.pool.outputs.it_ref")
	}
	mask := stepBlocks(job, "- name: Mask the pool registry")
	if len(mask) != 1 || !strings.Contains(mask[0], "::add-mask::") || !strings.Contains(mask[0], poolSecretEnv) {
		t.Errorf("ci-images does not mask the pool registry before it prints a reference")
	}
	// No consumer step builds the toolchain image itself.
	for n, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "make docker-build-toolchain") || strings.Contains(trim, "make --no-print-directory docker-build-toolchain") {
			t.Errorf("%s:%d runs make docker-build-toolchain: %s", ciWorkflowFile, n+1, trim)
		}
	}
}

// poolSelected is the test a ci-images step makes that preflight's scheduler
// put a consumer of the given runner output on the self-hosted pool; a hosted
// pick is the JSON string "ubuntu-latest" and names no self-hosted label.
func poolSelected(output string) string {
	return "contains(needs.preflight.outputs." + output + ", 'self-hosted')"
}

// TestPoolToolchainHandoffReachesOnlyPoolConsumers: the pool registry is on
// the LAN, so a pool reference handed to a GitHub-hosted consumer fails its
// pull (#2302 Codex round 3 P1). The pool step runs only when preflight put
// every consumer on the pool; otherwise toolchain_ref falls through to the
// resolved reference (a digest or "", the consumer-local build).
func TestPoolToolchainHandoffReachesOnlyPoolConsumers(t *testing.T) {
	src := readWorkflow(t)
	job := jobBlock(src, "ci-images")
	if job == "" {
		t.Fatal("no ci-images job")
	}
	if !slices.Contains(jobNeeds(job), "preflight") {
		t.Errorf("ci-images does not need preflight, so it cannot see the runner selection (needs %v)", jobNeeds(job))
	}
	pool := stepBlocks(job, "- name: Build the CI images on the pool")
	if len(pool) != 1 {
		t.Fatalf("ci-images has %d pool build steps, want 1", len(pool))
	}
	var poolIf string
	for _, line := range strings.Split(pool[0], "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "if:"); ok {
			poolIf = strings.TrimSpace(rest)
		}
	}
	if poolIf == "" {
		t.Fatal("the pool build step has no if:")
	}
	// The outputs every consumer of the ref takes runs-on from; runner and
	// runner_docker always, as image and lint-gates take the docker one.
	outputs := map[string]bool{"runner": true, "runner_docker": true}
	runsOnOutput := regexp.MustCompile(`needs\.preflight\.outputs\.([A-Za-z0-9_]+)`)
	consumers := 0
	for _, name := range workflowJobs(src) {
		block := jobBlock(src, name)
		if !strings.Contains(block, "needs.ci-images.outputs.toolchain_ref") {
			continue
		}
		consumers++
		for _, line := range strings.Split(block, "\n") {
			trim := strings.TrimSpace(line)
			if !strings.HasPrefix(trim, "runs-on:") {
				continue
			}
			for _, m := range runsOnOutput.FindAllStringSubmatch(trim, -1) {
				outputs[m[1]] = true
			}
		}
	}
	if consumers < 5 {
		t.Fatalf("found %d consumers of needs.ci-images.outputs.toolchain_ref", consumers)
	}
	for out := range outputs {
		if !strings.Contains(poolIf, poolSelected(out)) {
			t.Errorf("the pool build step runs although preflight may put a consumer on a hosted runner: its if: %s lacks %s", poolIf, poolSelected(out))
		}
	}
	if !strings.Contains(poolIf, "env.CI_POOL == 'true'") || !strings.Contains(poolIf, "&&") {
		t.Errorf("the pool build step's if: %s must require CI_POOL and the pool selection together", poolIf)
	}
	// Hosted consumers: the resolve step still runs on a pull request and
	// the output falls through to it.
	resolve := stepBlocks(job, "- name: Resolve main's CI images")
	if len(resolve) != 1 || !strings.Contains(resolve[0], "env.CI_PUBLISH != 'true'") {
		t.Errorf("ci-images has no resolve step for pull requests")
	}
	if !regexp.MustCompile(`toolchain_ref: \$\{\{[^\n]*steps\.pool\.outputs\.toolchain_ref \|\| steps\.resolve\.outputs\.toolchain_ref`).MatchString(job) {
		t.Errorf("ci-images' toolchain_ref does not fall through from the pool step to the resolved reference")
	}
	// Validate stays strict on the pool path only: it allows an empty
	// TOOLCHAIN_REF when the pool step did not run, by the same gate.
	validate := stepBlocks(job, "- name: Validate the image references")
	if len(validate) != 1 {
		t.Fatalf("ci-images has %d validate steps, want 1", len(validate))
	}
	for out := range outputs {
		if !strings.Contains(validate[0], poolSelected(out)) {
			t.Errorf("the validate step does not apply the pool gate %s to TOOLCHAIN_REF", poolSelected(out))
		}
	}
	if !strings.Contains(validate[0], `"$POOL_HANDOFF" != true`) {
		t.Errorf("the validate step does not allow an empty TOOLCHAIN_REF by POOL_HANDOFF")
	}
}

// stepExpr returns the ${{ }} expression of the first line of step that
// starts with key (after trimming), or "".
func stepExpr(step, key string) string {
	for _, line := range strings.Split(step, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), key)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if i := strings.Index(rest, " #"); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}
		rest, _ = strings.CutPrefix(rest, "${{")
		rest, _ = strings.CutSuffix(rest, "}}")
		return strings.TrimSpace(rest)
	}
	return ""
}

// actionsExpr evaluates the subset of the GitHub Actions expression language
// the pool gate uses: ||, &&, !, ==, !=, parentheses, 'strings', contains()
// and context paths looked up in ctx (a missing path is the empty string).
type actionsExpr struct {
	toks []string
	pos  int
	ctx  map[string]string
}

var actionsExprToken = regexp.MustCompile(`\s*('(?:[^']|'')*'|\|\||&&|==|!=|!|\(|\)|,|[A-Za-z_][A-Za-z0-9_.-]*)`)

func evalActionsExpr(t *testing.T, src string, ctx map[string]string) bool {
	t.Helper()
	e := &actionsExpr{ctx: ctx}
	rest := src
	for strings.TrimSpace(rest) != "" {
		m := actionsExprToken.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			t.Fatalf("cannot tokenize %q at %q", src, rest)
		}
		e.toks = append(e.toks, rest[m[2]:m[3]])
		rest = rest[m[1]:]
	}
	v := e.or(t)
	if e.pos != len(e.toks) {
		t.Fatalf("trailing tokens in %q: %v", src, e.toks[e.pos:])
	}
	return truthy(v)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	}
	return false
}

func (e *actionsExpr) peek() string {
	if e.pos < len(e.toks) {
		return e.toks[e.pos]
	}
	return ""
}

func (e *actionsExpr) next(t *testing.T, want string) {
	t.Helper()
	if e.peek() != want {
		t.Fatalf("expression: want %q, got %q", want, e.peek())
	}
	e.pos++
}

func (e *actionsExpr) or(t *testing.T) any {
	v := e.and(t)
	for e.peek() == "||" {
		e.pos++
		r := e.and(t)
		if !truthy(v) {
			v = r
		}
	}
	return v
}

func (e *actionsExpr) and(t *testing.T) any {
	v := e.cmp(t)
	for e.peek() == "&&" {
		e.pos++
		r := e.cmp(t)
		if truthy(v) {
			v = r
		}
	}
	return v
}

func (e *actionsExpr) cmp(t *testing.T) any {
	v := e.unary(t)
	if op := e.peek(); op == "==" || op == "!=" {
		e.pos++
		r := e.unary(t)
		eq := strings.EqualFold(fmt.Sprint(v), fmt.Sprint(r))
		return eq == (op == "==")
	}
	return v
}

func (e *actionsExpr) unary(t *testing.T) any {
	if e.peek() == "!" {
		e.pos++
		return !truthy(e.unary(t))
	}
	return e.primary(t)
}

func (e *actionsExpr) primary(t *testing.T) any {
	tok := e.peek()
	switch {
	case tok == "(":
		e.pos++
		v := e.or(t)
		e.next(t, ")")
		return v
	case strings.HasPrefix(tok, "'"):
		e.pos++
		return strings.ReplaceAll(tok[1:len(tok)-1], "''", "'")
	case tok == "contains":
		e.pos++
		e.next(t, "(")
		hay := fmt.Sprint(e.or(t))
		e.next(t, ",")
		needle := fmt.Sprint(e.or(t))
		e.next(t, ")")
		return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
	case tok == "true" || tok == "false":
		e.pos++
		return tok == "true"
	case tok != "" && tok != ")" && tok != ",":
		e.pos++
		return e.ctx[tok]
	}
	t.Fatalf("expression: unexpected token %q", tok)
	return nil
}

// TestPoolToolchainBuildRunsOnTheSelfHostedForge: off github.com (the
// self-hosted forge) preflight emits "ubuntu-latest" for both runner
// outputs, yet every toolchain consumer keeps its fixed self-hosted label
// there, so the pool step must still build the image once and hand it over
// (#2302 Codex round 4). On github.com the round-3 rule stays: the pool
// builds only when preflight puts both runner outputs on the pool.
func TestPoolToolchainBuildRunsOnTheSelfHostedForge(t *testing.T) {
	src := readWorkflow(t)
	job := jobBlock(src, "ci-images")
	pool := stepBlocks(job, "- name: Build the CI images on the pool")
	validate := stepBlocks(job, "- name: Validate the image references")
	if len(pool) != 1 || len(validate) != 1 {
		t.Fatalf("ci-images has %d pool build and %d validate steps, want 1 and 1", len(pool), len(validate))
	}
	poolIf := stepExpr(pool[0], "if:")
	handoff := stepExpr(validate[0], "POOL_HANDOFF:")
	if poolIf == "" || handoff == "" {
		t.Fatalf("pool step if: %q, POOL_HANDOFF: %q; want both", poolIf, handoff)
	}
	if poolIf != handoff {
		t.Errorf("the pool step's if: and POOL_HANDOFF differ:\n if:           %s\n POOL_HANDOFF: %s", poolIf, handoff)
	}
	const hosted = `"ubuntu-latest"`
	const selfHosted = `["self-hosted","linux","x64","bigdisk"]`
	cases := []struct {
		name, server, pool, runner, docker string
		want                               bool
	}{
		{"forge same-repo PR, preflight ubuntu-latest", "https://forge.example", "true", hosted, hosted, true},
		{"forge without the pool", "https://forge.example", "false", hosted, hosted, false},
		{"github.com, both outputs on the pool", "https://github.com", "true", selfHosted, selfHosted, true},
		{"github.com, docker output hosted", "https://github.com", "true", selfHosted, hosted, false},
		{"github.com, runner output hosted", "https://github.com", "true", hosted, selfHosted, false},
		{"github.com, both hosted", "https://github.com", "true", hosted, hosted, false},
		{"github.com without the pool", "https://github.com", "false", selfHosted, selfHosted, false},
	}
	for _, c := range cases {
		ctx := map[string]string{
			"github.server_url":                     c.server,
			"env.CI_POOL":                           c.pool,
			"needs.preflight.outputs.runner":        c.runner,
			"needs.preflight.outputs.runner_docker": c.docker,
		}
		for name, expr := range map[string]string{"if:": poolIf, "POOL_HANDOFF": handoff} {
			if got := evalActionsExpr(t, expr, ctx); got != c.want {
				t.Errorf("%s: pool step %s %s = %v, want %v", c.name, name, expr, got, c.want)
			}
		}
	}
	// Off github.com every consumer must run on a fixed self-hosted label,
	// which is what makes the forge case above true.
	fixed := regexp.MustCompile(`github\.server_url == 'https://github\.com' && .*\|\| '([A-Za-z0-9_-]+)' \}\}`)
	for _, name := range workflowJobs(src) {
		block := jobBlock(src, name)
		if !strings.Contains(block, "needs.ci-images.outputs.toolchain_ref") {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			trim := strings.TrimSpace(line)
			if !strings.HasPrefix(trim, "runs-on:") {
				continue
			}
			m := fixed.FindStringSubmatch(trim)
			if m == nil || strings.HasPrefix(m[1], "ubuntu") {
				t.Errorf("consumer %s does not keep a fixed self-hosted label off github.com: %s", name, trim)
			}
			break
		}
	}
}

// poolStubDocker records every call; `pull` of a pool tag fails (not pushed
// yet), image inspect answers an ID or a RepoDigest.
const poolStubDocker = `#!/bin/sh
echo "docker $*" >> "$STUB_DIR/calls"
case "$1" in
  pull)
    case "$*" in
      *@sha256:*) exit 0 ;;
      *) [ "${STUB_POOL_HAS_TAG:-}" = true ] && exit 0; exit 1 ;;
    esac ;;
  image)
    case "$*" in
      *RepoDigests*)
        echo "reg.example:5000/ci/go-xkms-ci-toolchain@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        echo "reg.example:5000/ci/go-xkms-ci-it@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ;;
      *) echo "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ;;
    esac ;;
esac
exit 0
`

const poolStubMake = `#!/bin/sh
echo "make $*" >> "$STUB_DIR/calls"
case "$*" in
  *toolchain-image*) echo "go-xkms-toolchain:0123456789abcdef" ;;
  *it-image*) echo "go-xkms-ci-it:0123456789abcdef" ;;
esac
exit 0
`

func runPoolRegistry(t *testing.T, extraEnv []string, args ...string) (stdout, stderr, calls string, err error) {
	t.Helper()
	stub := t.TempDir()
	for name, body := range map[string]string{"docker": poolStubDocker, "make": poolStubMake} {
		if werr := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o700); werr != nil { // #nosec G306 -- the stub must be executable
			t.Fatal(werr)
		}
	}
	script, aerr := filepath.Abs(filepath.Join(cachesRoot, poolRegistrySh))
	if aerr != nil {
		t.Fatal(aerr)
	}
	cmd := exec.Command(script, args...) // #nosec G204 -- the repository's own script
	cmd.Env = append(stubEnv(stub),
		"GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY_OWNER=example",
		"GITHUB_RUN_ID=1", "GITHUB_RUN_ATTEMPT=1", "CI_STACK_PREFIX=xkmsci",
		"CI_PUBLISH=false", "CI_REGISTRY_BACKOFF=0", "RUNNER_TEMP="+stub,
		// The lint-gates job sets CI_POOL=true on same-repo PRs; a test
		// opts in through extraEnv (the last value of a key wins).
		"CI_POOL=false",
		// A pool consumer by default; the GitHub-hosted tests opt out.
		"RUNNER_ENVIRONMENT=self-hosted")
	cmd.Env = append(cmd.Env, extraEnv...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	c, _ := os.ReadFile(filepath.Join(stub, "calls")) // #nosec G304 -- the test's own temp file
	return out.String(), errb.String(), string(c), err
}

func TestCIRegistryPoolUseNeverBuilds(t *testing.T) {
	_, stderr, calls, err := runPoolRegistry(t,
		[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci"}, "use", "toolchain", "")
	if err == nil {
		t.Errorf("use with an empty reference on a same-repo PR succeeded; it must fail")
	}
	if strings.Contains(calls, "docker-build-toolchain") {
		t.Errorf("use built the toolchain image on the consumer's runner:\n%s", calls)
	}
	if !strings.Contains(stderr, "same-repo pull request") {
		t.Errorf("use did not say why it failed: %s", stderr)
	}
}

func TestCIRegistryPoolUsePullsThePoolDigest(t *testing.T) {
	ref := "go-xkms-ci-toolchain@sha256:" + strings.Repeat("a", 64)
	stdout, stderr, calls, err := runPoolRegistry(t,
		[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci"}, "use", "toolchain", ref)
	if err != nil {
		t.Fatalf("use of a pool reference failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(calls, "docker pull --quiet reg.example:5000/ci/"+ref) {
		t.Errorf("use did not pull the pool image by digest:\n%s", calls)
	}
	if strings.Contains(calls, "docker-build-toolchain") {
		t.Errorf("use built the toolchain image:\n%s", calls)
	}
	if !strings.Contains(stdout, "TOOLCHAIN_IMAGE=reg.example:5000/ci/"+ref) {
		t.Errorf("use did not export the pool image: %s", stdout)
	}
}

// TestCIRegistryPoolUseRefusesAPoolRefOnAHostedRunner: a GitHub-hosted
// runner cannot reach the LAN pool registry, so a pool reference there is a
// workflow fault named at once, never a pull that times out or a build
// (#2302 Codex round 3 P1).
func TestCIRegistryPoolUseRefusesAPoolRefOnAHostedRunner(t *testing.T) {
	ref := "go-xkms-ci-toolchain@sha256:" + strings.Repeat("a", 64)
	_, stderr, calls, err := runPoolRegistry(t,
		[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci", "RUNNER_ENVIRONMENT=github-hosted"}, "use", "toolchain", ref)
	if err == nil {
		t.Errorf("use of a pool reference on a GitHub-hosted runner succeeded; it must fail")
	}
	if strings.Contains(calls, "docker pull") || strings.Contains(calls, "docker-build-toolchain") {
		t.Errorf("use pulled or built on a GitHub-hosted runner:\n%s", calls)
	}
	if !strings.Contains(stderr, "pool image reference on a GitHub-hosted runner") {
		t.Errorf("use did not say why it failed: %s", stderr)
	}
}

// TestCIRegistryPoolUseBuildsLocallyOnAHostedRunner: when preflight puts the
// consumers on GitHub-hosted runners, ci-images skips the pool step and hands
// "" for content main has not published; the consumer builds it as before
// the pool existed.
func TestCIRegistryPoolUseBuildsLocallyOnAHostedRunner(t *testing.T) {
	_, stderr, calls, err := runPoolRegistry(t,
		[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci", "RUNNER_ENVIRONMENT=github-hosted"}, "use", "toolchain", "")
	if err != nil {
		t.Fatalf("use with no reference on a GitHub-hosted runner failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(calls, "docker-build-toolchain") {
		t.Errorf("use did not build the toolchain image on the hosted runner:\n%s", calls)
	}
	if strings.Contains(calls, "docker push") {
		t.Errorf("use pushed from a consumer:\n%s", calls)
	}
}

func TestCIRegistryPoolBuildsOnceAndPushes(t *testing.T) {
	stdout, stderr, calls, err := runPoolRegistry(t,
		[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci"}, "pool", "toolchain")
	if err != nil {
		t.Fatalf("pool toolchain failed: %v\n%s", err, stderr)
	}
	if strings.Count(calls, "docker-build-toolchain") != 1 {
		t.Errorf("pool did not build the toolchain image exactly once:\n%s", calls)
	}
	if !strings.Contains(calls, "docker push reg.example:5000/ci/go-xkms-ci-toolchain:0123456789abcdef") {
		t.Errorf("pool did not push the hash tag to the pool registry:\n%s", calls)
	}
	want := "go-xkms-ci-toolchain@sha256:" + strings.Repeat("a", 64)
	if strings.TrimSpace(stdout) != want {
		t.Errorf("pool printed %q, want the registry-free digest reference %q", stdout, want)
	}
	if strings.Contains(stdout+stderr, "reg.example") {
		t.Errorf("pool printed the registry address:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

// TestCIRegistryPoolReusesAPublishedImage pins pool()'s cache hit: when the
// content-hash tag already pulls from the pool registry, pool returns that
// image's digest and neither builds, tags nor pushes (#2302 Codex P1).
func TestCIRegistryPoolReusesAPublishedImage(t *testing.T) {
	for family, hex := range map[string]string{"toolchain": "a", "it": "c"} {
		t.Run(family, func(t *testing.T) {
			stdout, stderr, calls, err := runPoolRegistry(t,
				[]string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci", "STUB_POOL_HAS_TAG=true"},
				"pool", family)
			if err != nil {
				t.Fatalf("pool %s failed: %v\n%s", family, err, stderr)
			}
			if !strings.Contains(calls, "docker pull --quiet reg.example:5000/ci/go-xkms-ci-"+family+":0123456789abcdef") {
				t.Errorf("pool did not look up the hash tag in the pool registry:\n%s", calls)
			}
			for _, forbidden := range []string{"docker-build-", "docker build", "docker tag", "docker push"} {
				if strings.Contains(calls, forbidden) {
					t.Errorf("pool ran %q although the image is in the pool registry:\n%s", forbidden, calls)
				}
			}
			want := "go-xkms-ci-" + family + "@sha256:" + strings.Repeat(hex, 64)
			if strings.TrimSpace(stdout) != want {
				t.Errorf("pool printed %q, want the existing digest reference %q", stdout, want)
			}
		})
	}
}

func TestCIRegistryPoolRefusesOutsideAPool(t *testing.T) {
	// The lint-gates job runs these tests with CI_POOL=true in its env on a
	// same-repo PR (Codex on #2302); the helper must not inherit it.
	t.Setenv("CI_POOL", "true")
	_, _, calls, err := runPoolRegistry(t, []string{"CI_IMAGE_REGISTRY=reg.example:5000/ci"}, "pool", "toolchain")
	if err == nil {
		t.Errorf("pool ran without CI_POOL=true")
	}
	if strings.Contains(calls, "docker push") {
		t.Errorf("pool pushed without CI_POOL=true:\n%s", calls)
	}
}
