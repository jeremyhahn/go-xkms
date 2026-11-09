package buildgates

import (
	"maps"
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
	coverageP    = regexp.MustCompile(`^coverage: export GOFLAGS :=.*\s-p=(\d+)\b`)
	goTestCall   = regexp.MustCompile(`\$\(GO\) test\b|\$\(GOTEST\)`)
	subMake      = regexp.MustCompile(`\$\(MAKE\)(.*)$`)
	makeOverride = regexp.MustCompile(`^([A-Z0-9_]+)=(.*)$`)
)

// raceExempt names the submakes coverage may run under -race, and why.
var raceExempt = map[string]string{
	"test-pkcs11": "one package (./pkg/vaulttoken/...) that writes no profile",
}

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

// recipe returns target's prerequisites and its recipe commands,
// continuation lines joined.
func recipe(makefile, target string) (prereqs, commands []string, found bool) {
	rule := regexp.MustCompile(`^` + regexp.QuoteMeta(target) + `:(.*)$`)
	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		m := rule.FindStringSubmatch(line)
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

// subMakeCall returns the target a $(MAKE) command line runs and the
// variables it runs with: vars, with each NAME=value on the line expanded in
// the caller and put in their place, as make's command-line overrides are.
func subMakeCall(args string, vars map[string]string) (target string, subVars map[string]string) {
	subVars = maps.Clone(vars)
	for _, f := range strings.Fields(args) {
		if m := makeOverride.FindStringSubmatch(f); m != nil {
			subVars[m[1]] = expandMakeVars(strings.Trim(m[2], `'"`), vars)
		} else if target == "" && !strings.HasPrefix(f, "-") {
			target = f
		}
	}
	return target, subVars
}

// raceCommands returns the go test commands target runs under -race, its own
// and those of each submake it runs (but raceExempt), each expanded with the
// variables in force where it runs.
func raceCommands(makefile, target string, vars map[string]string, seen map[string]bool) []string {
	if seen[target] {
		return nil
	}
	seen[target] = true
	_, commands, _ := recipe(makefile, target)
	var race []string
	for _, c := range commands {
		if m := subMake.FindStringSubmatch(c); m != nil {
			if sub, subVars := subMakeCall(m[1], vars); sub != "" && raceExempt[sub] == "" {
				race = append(race, raceCommands(makefile, sub, subVars, seen)...)
			}
			continue
		}
		if !goTestCall.MatchString(c) {
			continue
		}
		for _, f := range strings.Fields(expandMakeVars(c, vars)) {
			if f == "-race" || strings.HasPrefix(f, "-race=") {
				race = append(race, target+": "+strings.TrimSpace(c))
				break
			}
		}
	}
	return race
}

// coverageFitProblems lists each way make coverage cannot finish on the
// hosted runner: it runs under the race detector (directly, or through the
// test target, whose flags carry -race), it runs fewer test binaries in
// parallel than the runner has vCPUs, or it no longer writes the profile.
func coverageFitProblems(makefile string) []string {
	var problems []string
	prereqs, commands, found := recipe(makefile, "coverage")
	if !found {
		return []string{"no coverage rule"}
	}
	for _, p := range prereqs {
		if p == "test" || p == "test-go" {
			problems = append(problems, "coverage depends on "+p+", which runs -race")
		}
	}
	for _, c := range raceCommands(makefile, "coverage", makeVars(makefile), map[string]bool{}) {
		problems = append(problems, "coverage's go test runs -race: "+c)
	}
	profile := false
	for _, c := range commands {
		if goTestCall.MatchString(c) && strings.Contains(c, "-coverprofile=$(COVERAGE_FILE)") && strings.Contains(c, "-covermode=atomic") {
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
	const flags = "TEST_FLAGS := -v -race -timeout 75m\nCOVERAGE_TEST_FLAGS := -v -timeout 75m\n" +
		"TEST_FLAGS_NOFROST := -v -race -timeout 75m\nCOVERAGE_TEST_FLAGS_NOFROST := -v -timeout 75m\n"
	const fits = "coverage: export GOFLAGS := $(strip $(GOFLAGS) -p=4)\ncoverage: agsim\n" +
		"\t$(GO) test $(COVERAGE_TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic \\\n\t\t./pkg/...\n" +
		"\t@$(MAKE) --no-print-directory test-nofrost TEST_FLAGS_NOFROST='$(COVERAGE_TEST_FLAGS_NOFROST)'\n" +
		"\t@$(MAKE) --no-print-directory test-pkcs11\n" +
		"test-nofrost:\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST) ./pkg/server/...\n" +
		"test-pkcs11:\n\t@$(GOTEST) -v -race ./pkg/vaulttoken/...\n"
	cases := map[string]struct {
		makefile string
		want     int
	}{
		"fits":                        {flags + fits, 0},
		"through test at -p=2":        {flags + "coverage: export GOFLAGS := $(strip $(GOFLAGS) -p=2)\ncoverage: test\n\t@echo total\n", 3},
		"race flag":                   {flags + strings.Replace(fits, "$(COVERAGE_TEST_FLAGS)", "$(TEST_FLAGS)", 1), 1},
		"literal race":                {flags + strings.Replace(fits, "test $(", "test -race $(", 1), 1},
		"GOTEST race":                 {flags + strings.Replace(fits, "$(GO) test $(COVERAGE_TEST_FLAGS)", "$(GOTEST) $(TEST_FLAGS)", 1), 1},
		"-p below the runner":         {flags + strings.Replace(fits, "-p=4", "-p=3", 1), 1},
		"no -p":                       {flags + strings.Replace(fits, " -p=4", "", 1), 1},
		"no profile":                  {flags + strings.Replace(fits, " -coverprofile=$(COVERAGE_FILE)", "", 1), 1},
		"no rule":                     {flags, 1},
		"!frost without the override": {flags + strings.Replace(fits, " TEST_FLAGS_NOFROST='$(COVERAGE_TEST_FLAGS_NOFROST)'", "", 1), 1},
		"!frost race flags":           {strings.Replace(flags, "COVERAGE_TEST_FLAGS_NOFROST := -v", "COVERAGE_TEST_FLAGS_NOFROST := -v -race", 1) + fits, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := coverageFitProblems(c.makefile); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}
