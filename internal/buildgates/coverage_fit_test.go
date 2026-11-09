package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// hostedRunnerCPUs is the vCPU count of the GitHub-hosted ubuntu-latest
// runner the Coverage job runs on (#2023). make coverage must not run fewer
// test binaries in parallel than that: at -p=2 under -race it never finished
// inside the job's 180 minutes.
const hostedRunnerCPUs = 4

var (
	makeVarDef   = regexp.MustCompile(`^([A-Z0-9_]+)\s*(?::=|\?=|=)\s*(.*)$`)
	makeVarRef   = regexp.MustCompile(`\$\(([A-Z0-9_]+)\)`)
	coverageRule = regexp.MustCompile(`^coverage:(.*)$`)
	coverageP    = regexp.MustCompile(`^coverage: export GOFLAGS :=.*\s-p=(\d+)\b`)
	goTestCall   = regexp.MustCompile(`\$\(GO\) test\b|\$\(GOTEST\)`)
)

// makeVars returns the Makefile's unindented variable definitions; a later
// definition replaces an earlier one, as make does.
func makeVars(makefile string) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(makefile, "\n") {
		if m := makeVarDef.FindStringSubmatch(line); m != nil {
			vars[m[1]] = m[2]
		}
	}
	return vars
}

// expandMakeVars replaces each $(NAME) the Makefile defines with its value,
// until no defined reference is left.
func expandMakeVars(s string, vars map[string]string) string {
	for range 10 {
		next := makeVarRef.ReplaceAllStringFunc(s, func(ref string) string {
			if v, ok := vars[makeVarRef.FindStringSubmatch(ref)[1]]; ok {
				return v
			}
			return ref
		})
		if next == s {
			break
		}
		s = next
	}
	return s
}

// coverageRecipe returns the coverage rule's prerequisites and its recipe
// commands, continuation lines joined.
func coverageRecipe(makefile string) (prereqs, commands []string, found bool) {
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		m := coverageRule.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(strings.TrimSpace(m[1]), "export ") {
			continue
		}
		found = true
		prereqs = strings.Fields(m[1])
		var cmd strings.Builder
		for _, r := range lines[i+1:] {
			if !strings.HasPrefix(r, "\t") {
				break
			}
			cmd.WriteString(strings.TrimSuffix(r, "\\"))
			if strings.HasSuffix(r, "\\") {
				continue
			}
			commands = append(commands, cmd.String())
			cmd.Reset()
		}
		break
	}
	return prereqs, commands, found
}

// coverageFitProblems lists each way make coverage cannot finish on the
// hosted runner: it runs under the race detector (directly, or through the
// test target, whose flags carry -race), it runs fewer test binaries in
// parallel than the runner has vCPUs, or it no longer writes the profile.
func coverageFitProblems(makefile string) []string {
	var problems []string
	prereqs, commands, found := coverageRecipe(makefile)
	if !found {
		return []string{"no coverage rule"}
	}
	for _, p := range prereqs {
		if p == "test" || p == "test-go" {
			problems = append(problems, "coverage depends on "+p+", which runs -race")
		}
	}
	vars := makeVars(makefile)
	profile := false
	for _, c := range commands {
		if !goTestCall.MatchString(c) {
			continue
		}
		expanded := expandMakeVars(c, vars)
		for _, f := range strings.Fields(expanded) {
			if f == "-race" || strings.HasPrefix(f, "-race=") {
				problems = append(problems, "coverage's go test runs -race: "+strings.TrimSpace(c))
				break
			}
		}
		if strings.Contains(c, "-coverprofile=$(COVERAGE_FILE)") && strings.Contains(c, "-covermode=atomic") {
			profile = true
		}
	}
	if !profile {
		problems = append(problems, "coverage runs no go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic")
	}
	p := 0
	for _, line := range strings.Split(makefile, "\n") {
		if m := coverageP.FindStringSubmatch(line); m != nil {
			p, _ = strconv.Atoi(m[1])
		}
	}
	if p < hostedRunnerCPUs {
		problems = append(problems, "coverage sets GOFLAGS -p="+strconv.Itoa(p)+", below the runner's "+strconv.Itoa(hostedRunnerCPUs)+" vCPUs")
	}
	return problems
}

func TestCoverageRunsWithoutTheRaceDetector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, p := range coverageFitProblems(string(data)) {
		t.Error(p)
	}
}

func TestCoverageFitCatchesEachForm(t *testing.T) {
	const flags = "TEST_FLAGS := -v -race -timeout 75m\nCOVERAGE_TEST_FLAGS := -v -timeout 75m\n"
	const fits = "coverage: export GOFLAGS := $(strip $(GOFLAGS) -p=4)\ncoverage: agsim\n" +
		"\t$(GO) test $(COVERAGE_TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic \\\n\t\t./pkg/...\n"
	cases := map[string]struct {
		makefile string
		want     int
	}{
		"fits":                 {flags + fits, 0},
		"through test at -p=2": {flags + "coverage: export GOFLAGS := $(strip $(GOFLAGS) -p=2)\ncoverage: test\n\t@echo total\n", 3},
		"race flag":            {flags + strings.Replace(fits, "$(COVERAGE_TEST_FLAGS)", "$(TEST_FLAGS)", 1), 1},
		"literal race":         {flags + strings.Replace(fits, "test $(", "test -race $(", 1), 1},
		"GOTEST race":          {flags + strings.Replace(fits, "$(GO) test $(COVERAGE_TEST_FLAGS)", "$(GOTEST) $(TEST_FLAGS)", 1), 1},
		"-p below the runner":  {flags + strings.Replace(fits, "-p=4", "-p=3", 1), 1},
		"no -p":                {flags + strings.Replace(fits, " -p=4", "", 1), 1},
		"no profile":           {flags + strings.Replace(fits, " -coverprofile=$(COVERAGE_FILE)", "", 1), 1},
		"no rule":              {flags, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := coverageFitProblems(c.makefile); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}
