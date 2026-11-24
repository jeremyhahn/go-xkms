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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	for _, want := range []string{"env.CI_POOL == 'true'", poolSecretEnv, "scripts/ci-registry.sh pool toolchain", "scripts/ci-registry.sh pool it"} {
		if !strings.Contains(pool[0], want) {
			t.Errorf("the pool build step lacks %q", want)
		}
	}
	for _, want := range []string{"steps.pool.outputs.toolchain_ref", "steps.pool.outputs.it_ref"} {
		if !strings.Contains(job, want) {
			t.Errorf("ci-images does not output %s", want)
		}
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

// poolStubDocker records every call; `pull` of a pool tag fails (not pushed
// yet), image inspect answers an ID or a RepoDigest.
const poolStubDocker = `#!/bin/sh
echo "docker $*" >> "$STUB_DIR/calls"
case "$1" in
  pull) [ -z "${STUB_PULL_FAIL:-}" ] || exit 1; case "$*" in *@sha256:*) exit 0 ;; *) exit 1 ;; esac ;;
  image)
    case "$*" in
      *RepoDigests*) echo "reg.example:5000/ci/go-xkms-ci-toolchain@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ;;
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
		"CI_PUBLISH=false", "CI_REGISTRY_BACKOFF=0", "RUNNER_TEMP="+stub)
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
