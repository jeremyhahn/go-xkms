package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// coverageShards is the coverage job's shard count in ci.yml.
const coverageShards = 6

// TestCoverageRunsAsShardsThenOneThreshold pins the unit suite to package
// shards, each its own job with its own timeout, whose profiles one threshold
// job merges. make coverage in the Devcontainer job never finished on a
// GitHub-hosted runner, even at -p=1 (DS-8139, CA m2406(2)).
func TestCoverageRunsAsShardsThenOneThreshold(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	type step struct {
		Run  string `yaml:"run"`
		Uses string `yaml:"uses"`
	}
	var wf struct {
		Jobs map[string]struct {
			Needs    needsList `yaml:"needs"`
			Timeout  int       `yaml:"timeout-minutes"`
			Strategy struct {
				Matrix struct {
					Shard []int `yaml:"shard"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []step `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	has := func(steps []step, pred func(step) bool) bool {
		return slices.ContainsFunc(steps, pred)
	}

	if has(wf.Jobs["image"].Steps, func(s step) bool { return strings.Contains(s.Run, "make coverage") }) {
		t.Error("the image job still runs make coverage")
	}

	cov, ok := wf.Jobs["coverage"]
	if !ok {
		t.Fatal("ci.yml has no coverage job")
	}
	if len(cov.Strategy.Matrix.Shard) != coverageShards {
		t.Errorf("coverage job matrix shard = %v, want %d shards", cov.Strategy.Matrix.Shard, coverageShards)
	}
	if cov.Timeout <= 0 {
		t.Error("coverage job has no timeout-minutes of its own")
	}
	shardRun := fmt.Sprintf("SHARDS=%d", coverageShards)
	if !has(cov.Steps, func(s step) bool {
		return strings.Contains(s.Run, "make coverage-shard") &&
			strings.Contains(s.Run, "SHARD=${{ matrix.shard }}") && strings.Contains(s.Run, shardRun)
	}) {
		t.Errorf("coverage job does not run make coverage-shard SHARD=${{ matrix.shard }} %s", shardRun)
	}
	if !has(cov.Steps, func(s step) bool { return strings.HasPrefix(s.Uses, "actions/upload-artifact@") }) {
		t.Error("coverage job does not upload its profile")
	}

	thr, ok := wf.Jobs["coverage-threshold"]
	if !ok {
		t.Fatal("ci.yml has no coverage-threshold job")
	}
	if !slices.Contains(thr.Needs, "coverage") {
		t.Errorf("coverage-threshold needs %v, want coverage", thr.Needs)
	}
	if thr.Timeout <= 0 {
		t.Error("coverage-threshold job has no timeout-minutes")
	}
	if !has(thr.Steps, func(s step) bool { return strings.HasPrefix(s.Uses, "actions/download-artifact@") }) {
		t.Error("coverage-threshold job does not download the profiles")
	}
	if !has(thr.Steps, func(s step) bool { return strings.Contains(s.Run, "make coverage-merge") }) {
		t.Error("coverage-threshold job does not run make coverage-merge")
	}

	for _, j := range []string{"coverage", "coverage-threshold"} {
		if !slices.Contains(wf.Jobs[gateJob].Needs, j) {
			t.Errorf("CI Gate does not need %s", j)
		}
	}
}

// inToolchainImage runs every CI stage in a disposable container that gets a
// copy of the checkout and is removed on exit.
const inToolchainImage = "../../scripts/in-toolchain-image.sh"

// TestCoverageShardProfileLeavesTheContainer pins the coverage shard's
// profile to a copy out of the toolchain container: in-toolchain-image.sh
// copies the checkout in and nothing back, so without IN_IMAGE_EXPORT the
// upload steps find no file (DS-8139, Codex P1).
func TestCoverageShardProfileLeavesTheContainer(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run  string            `yaml:"run"`
				Uses string            `yaml:"uses"`
				Env  map[string]string `yaml:"env"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	var export string
	var uploads []string
	for _, s := range wf.Jobs["coverage"].Steps {
		if strings.Contains(s.Run, "make coverage-shard") {
			export = s.Env["IN_IMAGE_EXPORT"]
		}
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
			uploads = append(uploads, s.With["path"])
		}
	}
	// The extras entry (#2042) writes no profile, so it exports none.
	const profile = "build/coverage/shard-${{ matrix.shard }}.out"
	const want = "${{ matrix.shard != 'extras' && format('build/coverage/shard-{0}.out', matrix.shard) || '' }}"
	if export != want {
		t.Errorf("make coverage-shard step IN_IMAGE_EXPORT = %q, want %q", export, want)
	}
	if len(uploads) == 0 {
		t.Error("coverage job has no upload step")
	}
	for _, p := range uploads {
		if p != profile {
			t.Errorf("upload path %q is not the exported %q", p, profile)
		}
	}

	script, err := os.ReadFile(inToolchainImage)
	if err != nil {
		t.Fatalf("read %s: %v", inToolchainImage, err)
	}
	text := string(script)
	start := strings.Index(text, `docker start -a "$name"`)
	cp := strings.Index(text, `docker cp "$name:/src/`)
	switch {
	case start < 0:
		t.Errorf("%s does not run docker start -a", inToolchainImage)
	case cp < 0:
		t.Errorf("%s never copies an IN_IMAGE_EXPORT path out with docker cp \"$name:/src/...", inToolchainImage)
	case cp < start:
		t.Errorf("%s copies the exports out before docker start -a", inToolchainImage)
	}
	if !strings.Contains(text, "IN_IMAGE_EXPORT") {
		t.Errorf("%s does not read IN_IMAGE_EXPORT", inToolchainImage)
	}
}

// makeLines runs make in the repository root and returns its output words.
func makeLines(t *testing.T, args ...string) []string {
	t.Helper()
	out, err := exec.Command("make", append([]string{"-s", "--no-print-directory", "-C", repoRoot}, args...)...).Output()
	if err != nil {
		t.Fatalf("make %v: %v", args, err)
	}
	return strings.Fields(string(out))
}

// TestCoverageTargetsRunOneTestBinary pins make coverage and make
// coverage-shard (what CI runs) to one test binary at a time under a 5GiB
// per-process GOMEMLIMIT: at -p=2 the pkg/fido2/authenticator binary was
// OOM-killed in the 8g swap-off container, at -p=1 it passed (#2042 Codex P1).
func TestCoverageTargetsRunOneTestBinary(t *testing.T) {
	data, err := os.ReadFile(repoRoot + "/Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, target := range []string{"coverage", "coverage-shard", "coverage-extras"} {
		memLimit := target + ": export GOMEMLIMIT := 5GiB"
		if !slices.Contains(lines, memLimit) {
			t.Errorf("Makefile has no line %q", memLimit)
		}
		prefix := target + ": export GOFLAGS := "
		i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, prefix) })
		if i < 0 {
			t.Errorf("Makefile has no %s GOFLAGS export", target)
			continue
		}
		if flags := strings.TrimSuffix(strings.TrimSpace(lines[i]), ")"); !strings.HasSuffix(flags, " -p=1") {
			t.Errorf("%s GOFLAGS = %q, want it to end with -p=1", target, lines[i])
		}
	}
}

// TestCoverageShardsPartitionTheUnitPackages proves the coverage shards are
// disjoint and together test every package make test's Go unit run covers.
func TestCoverageShardsPartitionTheUnitPackages(t *testing.T) {
	want := makeLines(t, "unit-test-pkgs")
	if len(want) == 0 {
		t.Fatal("make unit-test-pkgs printed no packages")
	}
	seen := map[string]int{}
	for i := 1; i <= coverageShards; i++ {
		pkgs := makeLines(t, "coverage-shard-pkgs", fmt.Sprintf("SHARD=%d", i), fmt.Sprintf("SHARDS=%d", coverageShards))
		if len(pkgs) == 0 {
			t.Errorf("shard %d/%d has no packages", i, coverageShards)
		}
		for _, p := range pkgs {
			if s, dup := seen[p]; dup {
				t.Errorf("package %s is in shard %d and shard %d", p, s, i)
			}
			seen[p] = i
		}
	}
	for _, p := range want {
		if _, ok := seen[p]; !ok {
			t.Errorf("package %s is in no shard", p)
		}
		delete(seen, p)
	}
	for p := range seen {
		t.Errorf("shard package %s is not in make unit-test-pkgs", p)
	}
}
