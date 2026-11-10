package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// covFixtureFile is the source file the fixture profiles below describe
// (testdata/covfixture): Sign has three statements, Two has one.
const covFixtureFile = "github.com/jeremyhahn/go-xkms/internal/buildgates/testdata/covfixture/covfixture.go"

// Fixture shard profiles over covfixture. Together they cover 3 of its 4
// statements (75%); shard 1 holds Sign's blocks, shard 2 holds Two's.
var (
	shard1Records = []string{
		covFixtureFile + ":6.22,7.11 1 1",
		covFixtureFile + ":7.11,9.3 1 1",
		covFixtureFile + ":10.2,10.10 1 0",
	}
	shard2Records = []string{
		covFixtureFile + ":14.16,16.2 1 1",
	}
)

// writeProfile writes a shard profile with the given mode line and records.
func writeProfile(t *testing.T, dir, name, mode string, records []string) {
	t.Helper()
	body := strings.Join(append([]string{mode}, records...), "\n") + "\n"
	if mode == "" && len(records) == 0 {
		body = ""
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// runCoverageMerge runs the real `make coverage-merge` over dir with the given
// threshold, the advisory per-package report switched off (it would run the
// tagged coverage lanes), CI unset so the dirty-tree check is skipped and the
// extra make variables after those. It
// returns the merged file's path, the output and the error.
func runCoverageMerge(t *testing.T, dir string, threshold int, extra ...string) (string, string, error) {
	t.Helper()
	for _, tool := range []string{"make", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	merged := filepath.Join(t.TempDir(), "coverage.out")
	vars := []string{
		"COVERAGE_DIR=" + dir,
		"COVERAGE_FILE=" + merged,
		fmt.Sprintf("COVERAGE_THRESHOLD=%d", threshold),
		"COVERAGE_REPORT=",
	}
	vars = append(vars, extra...)
	// Never let the report run for real: it starts the tagged test lanes.
	dry, err := exec.Command("make", append([]string{"-n", "--no-print-directory", "-C", repoRoot, "coverage-gate"}, vars...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("make -n coverage-gate: %v\n%s", err, dry)
	}
	if strings.Contains(string(dry), "coverage-threshold-report") {
		t.Fatalf("coverage-gate runs coverage-threshold-report even with COVERAGE_REPORT= set; the merge cannot be tested without the tagged lanes")
	}
	cmd := exec.Command("make", append([]string{"--no-print-directory", "-C", repoRoot, "coverage-merge"}, vars...)...)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CI=") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return merged, string(out), err
}

func TestCoverageMergeKeepsEveryShardUnderOneMode(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "shard-1.out", "mode: atomic", shard1Records)
	// download-artifact v3 puts each shard in its own directory.
	sub := filepath.Join(dir, "coverage-shard-2")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	writeProfile(t, sub, "shard-2.out", "mode: atomic", shard2Records)

	merged, out, err := runCoverageMerge(t, dir, 75)
	if err != nil {
		t.Fatalf("make coverage-merge: %v\n%s", err, out)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatalf("merged profile: %v\n%s", err, out)
	}
	// The shards are merged in path order, so compare the records as a set.
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := append(append([]string{"mode: atomic"}, shard1Records...), shard2Records...)
	sort.Strings(lines[1:])
	sort.Strings(want[1:])
	if lines[0] != "mode: atomic" || strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("merged profile:\n%s\nwant:\n%s", data, strings.Join(want, "\n"))
	}
	if !strings.Contains(out, "Total coverage: 75.0%") {
		t.Errorf("coverage-merge did not run the threshold over the merged file:\n%s", out)
	}
}

func TestCoverageMergeFailsOnMissingOrMismatchedProfile(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"no shard profile": func(t *testing.T, dir string) {},
		"empty shard profile": func(t *testing.T, dir string) {
			writeProfile(t, dir, "shard-1.out", "mode: atomic", shard1Records)
			writeProfile(t, dir, "shard-2.out", "", nil)
		},
		"different mode": func(t *testing.T, dir string) {
			writeProfile(t, dir, "shard-1.out", "mode: atomic", shard1Records)
			writeProfile(t, dir, "shard-2.out", "mode: set", shard2Records)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			_, out, err := runCoverageMerge(t, dir, 0)
			if err == nil {
				t.Fatalf("make coverage-merge passed:\n%s", out)
			}
		})
	}
}

func TestCoverageMergeFailsUnderTheThreshold(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "shard-1.out", "mode: atomic", shard1Records)
	writeProfile(t, dir, "shard-2.out", "mode: atomic", shard2Records)
	if _, out, err := runCoverageMerge(t, dir, 76); err == nil {
		t.Errorf("75%% coverage passed a 76%% threshold:\n%s", out)
	}
	if _, out, err := runCoverageMerge(t, dir, 75); err != nil {
		t.Errorf("75%% coverage failed a 75%% threshold: %v\n%s", err, out)
	}
}

// writeShards writes shard-N.out for every N in shards, at the top of dir or,
// as download-artifact v3 lays them out, in dir/coverage-shard-N/.
func writeShards(t *testing.T, dir string, nested bool, shards ...int) {
	t.Helper()
	for _, n := range shards {
		d := dir
		if nested {
			d = filepath.Join(dir, fmt.Sprintf("coverage-shard-%d", n))
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		records := shard2Records
		if n == 1 {
			records = shard1Records
		}
		writeProfile(t, d, fmt.Sprintf("shard-%d.out", n), "mode: atomic", records)
	}
}

func TestCoverageMergeNeedsEveryShardOnce(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		names string // what the failure must name; "" means the merge passes
	}{
		{"shard 6 absent", func(t *testing.T, dir string) { writeShards(t, dir, false, 1, 2, 3, 4, 5) }, "shard 6 of 6"},
		{"shard 3 absent, one per directory", func(t *testing.T, dir string) { writeShards(t, dir, true, 1, 2, 4, 5, 6) }, "shard 3 of 6"},
		{"shard 2 twice", func(t *testing.T, dir string) {
			writeShards(t, dir, true, 1, 2, 3, 4, 5, 6)
			writeShards(t, dir, false, 2)
		}, "shard 2 of 6"},
		{"all six", func(t *testing.T, dir string) { writeShards(t, dir, true, 1, 2, 3, 4, 5, 6) }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.setup(t, dir)
			_, out, err := runCoverageMerge(t, dir, 0, "SHARDS=6")
			switch {
			case c.names == "" && err != nil:
				t.Fatalf("make coverage-merge SHARDS=6: %v\n%s", err, out)
			case c.names != "" && err == nil:
				t.Fatalf("make coverage-merge SHARDS=6 passed:\n%s", out)
			case c.names != "" && !strings.Contains(out, c.names):
				t.Fatalf("the failure does not name %q:\n%s", c.names, out)
			}
		})
	}
}

// TestCoverageThresholdJobPassesTheShardCount checks that the coverage-threshold
// job tells coverage-merge how many shard profiles to expect.
func TestCoverageThresholdJobPassesTheShardCount(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("SHARDS=%d", coverageShards)
	found := false
	for _, s := range wf.Jobs["coverage-threshold"].Steps {
		if strings.Contains(s.Run, "make coverage-merge") {
			found = true
			if !strings.Contains(s.Run, want) {
				t.Errorf("coverage-threshold runs coverage-merge without %s: %s", want, s.Run)
			}
		}
	}
	if !found {
		t.Error("coverage-threshold job does not run make coverage-merge")
	}
}
