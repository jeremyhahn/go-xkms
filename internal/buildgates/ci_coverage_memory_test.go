package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// coverageShards is the number of make coverage-shard partitions.
const coverageShards = 10

// coverageShardTestTimeout is the go test bound of one coverage shard.
const coverageShardTestTimeout = 30 * time.Minute

func TestCoverageShardTimeoutsArePinned(t *testing.T) {
	got := makeLines(t, "--eval=print-coverage-shard-timeout: ; @echo $(COVERAGE_SHARD_TIMEOUT)", "print-coverage-shard-timeout")
	if len(got) != 1 {
		t.Fatalf("COVERAGE_SHARD_TIMEOUT = %q, want one duration", got)
	}
	bound, err := time.ParseDuration(got[0])
	if err != nil {
		t.Fatalf("COVERAGE_SHARD_TIMEOUT %q: %v", got[0], err)
	}
	if bound != coverageShardTestTimeout {
		t.Errorf("COVERAGE_SHARD_TIMEOUT = %s, want %s", bound, coverageShardTestTimeout)
	}

	makefile, err := os.ReadFile(repoRoot + "/Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if !strings.Contains(string(makefile), "$(GO) test $(TEST_FLAGS) -timeout $(COVERAGE_SHARD_TIMEOUT) -coverprofile=$(COVERAGE_DIR)/shard-$(SHARD).out") {
		t.Error("coverage-shard's go test does not run under -timeout $(COVERAGE_SHARD_TIMEOUT)")
	}
}

// inToolchainImage runs every CI stage in a disposable container that gets a
// copy of the checkout and is removed on exit.
const inToolchainImage = "../../scripts/in-toolchain-image.sh"

// TestCoverageShardProfileLeavesTheContainer pins in-toolchain-image.sh to copy IN_IMAGE_EXPORT paths out after the container runs.
func TestCoverageShardProfileLeavesTheContainer(t *testing.T) {
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
