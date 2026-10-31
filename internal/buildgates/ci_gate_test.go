package buildgates

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciWorkflow is ci.yml, relative to this package's directory, where go test
// runs.
const ciWorkflow = "../../.github/workflows/ci.yml"

// gateJob is the one required check; every other job reports through it.
const gateJob = "ci-gate"

// fullTierIf is the full tier's selection (ci-template v1.23): every event but
// a pull request, or the ci:full label. The workflow's CI_FULL_TIER env is
// this expression and CI Gate's FULL_TIER reads it, so its skip rule matches
// the jobs'. Conditions are compared after collapsing whitespace and dropping
// a ${{ }} wrapper, so a folded `if: >-` matches.
const fullTierIf = "github.event_name != 'pull_request' ||" +
	" contains(github.event.pull_request.labels.*.name, 'ci:full')"

// draftIf is the draft guard (ci-template v1.26): a draft pull request runs no
// CI, so every job but CI Gate skips on one. A PR-tier job's whole if: is the
// guard, unless it needs another job and skips with it.
const draftIf = "!github.event.pull_request.draft"

// fullTierJobIf is the whole condition of a full-tier job: the full tier, and
// never a draft (ci-template v1.26).
const fullTierJobIf = "(" + fullTierIf + ") && " + draftIf

// gateDraft is CI Gate's DRAFT env, which fails the gate on a draft rather
// than let it pass on skipped jobs (ci-template v1.26).
const gateDraft = "${{ github.event.pull_request.draft == true }}"

// nightlyIf is the condition of a job CI Gate marks nightly: the schedule and
// workflow_dispatch only (ci-template v1.24).
const nightlyIf = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"

// scheduleGuardJob is the ci-template v1.29.3 job whose verdict holds a
// schedule run's bigdisk jobs off while a main push run is in flight.
const scheduleGuardJob = "schedule-guard"

// scheduleRun is the v1.29.3 clause a bigdisk job adds to its if:, so that on
// a schedule run it runs only on the schedule guard's `run`. A job may carry
// it only when it needs the schedule guard.
const scheduleRun = "github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict == 'run'"

// guardedNightlyIf is nightlyIf under the schedule guard (v1.29.3).
const guardedNightlyIf = "(github.event_name == 'schedule' && needs.schedule-guard.outputs.verdict == 'run') || github.event_name == 'workflow_dispatch'"

// gateLine matches one `check <job> "${{ needs.<job>.result }}" <tier>` line
// of CI Gate's script.
var gateLine = regexp.MustCompile(
	`^check\s+(\S+)\s+"\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}"\s+(\S+)$`)

type workflow struct {
	On struct {
		PullRequest struct {
			Types []string `yaml:"types"`
		} `yaml:"pull_request"`
	} `yaml:"on"`
	Env  map[string]string `yaml:"env"`
	Jobs map[string]job    `yaml:"jobs"`
}

type job struct {
	If             string    `yaml:"if"`
	Needs          needsList `yaml:"needs"`
	TimeoutMinutes int       `yaml:"timeout-minutes"`
	Steps          []struct {
		If  string            `yaml:"if"`
		Env map[string]string `yaml:"env"`
		Run string            `yaml:"run"`
	} `yaml:"steps"`
}

// needsList accepts both forms of `needs:`, a single job or a list.
type needsList []string

func (n *needsList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*n = needsList{node.Value}
		return nil
	}
	var list []string
	if err := node.Decode(&list); err != nil {
		return err
	}
	*n = list
	return nil
}

func parseWorkflow(t *testing.T, data []byte) workflow {
	t.Helper()
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	return wf
}

// collapse joins s's fields with single spaces.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// condition is a job's if: with its whitespace collapsed and any ${{ }}
// around the whole expression removed, so both spellings compare equal.
func condition(s string) string {
	c := collapse(s)
	if strings.HasPrefix(c, "${{ ") && strings.HasSuffix(c, " }}") {
		return strings.TrimSuffix(strings.TrimPrefix(c, "${{ "), " }}")
	}
	return c
}

// gateTiers reads the check lines out of CI Gate's steps, mapping each job
// to its tier and reporting any line that starts with `check ` but does not
// have the expected shape, and a FULL_TIER that is not the full-tier if:.
func gateTiers(gate job) (map[string]string, []string) {
	tiers := map[string]string{}
	var problems []string
	fullTier, nightly, draft := "", "", ""
	for _, step := range gate.Steps {
		if v, ok := step.Env["FULL_TIER"]; ok {
			fullTier = collapse(v)
		}
		if v, ok := step.Env["NIGHTLY"]; ok {
			nightly = collapse(v)
		}
		if v, ok := step.Env["DRAFT"]; ok {
			draft = collapse(v)
		}
		for _, raw := range strings.Split(step.Run, "\n") {
			line := strings.TrimSpace(raw)
			if !strings.HasPrefix(line, "check ") {
				continue
			}
			m := gateLine.FindStringSubmatch(line)
			if m == nil {
				problems = append(problems, fmt.Sprintf("CI Gate line %q is malformed", line))
				continue
			}
			name, ref, tier := m[1], m[2], m[3]
			if tier != "pr" && tier != "full" && tier != "nightly" {
				problems = append(problems, fmt.Sprintf("CI Gate tags %s %q, want pr, full or nightly", name, tier))
			}
			if name != ref {
				problems = append(problems, fmt.Sprintf("CI Gate line for %s reads needs.%s.result", name, ref))
			}
			if _, dup := tiers[name]; dup {
				problems = append(problems, fmt.Sprintf("CI Gate checks %s twice", name))
			}
			tiers[name] = tier
		}
	}
	if want := "${{ env.CI_FULL_TIER }}"; fullTier != want {
		problems = append(problems, fmt.Sprintf("CI Gate FULL_TIER is %q, want %q", fullTier, want))
	}
	if want := "${{ " + nightlyIf + " }}"; nightly != want {
		problems = append(problems, fmt.Sprintf("CI Gate NIGHTLY is %q, want %q", nightly, want))
	}
	if draft != gateDraft {
		problems = append(problems, fmt.Sprintf("CI Gate DRAFT is %q, want %q", draft, gateDraft))
	}
	return tiers, problems
}

// tierProblems lists every way wf breaks the tier contract.
func tierProblems(wf workflow) []string {
	gate, ok := wf.Jobs[gateJob]
	if !ok {
		return []string{"no " + gateJob + " job"}
	}
	tiers, problems := gateTiers(gate)

	if got, want := collapse(wf.Env["CI_FULL_TIER"]), "${{ "+fullTierIf+" }}"; got != want {
		problems = append(problems, fmt.Sprintf("env.CI_FULL_TIER is %q, want %q", got, want))
	}

	if slices.Contains(wf.On.PullRequest.Types, "labeled") {
		problems = append(problems, "on.pull_request.types has labeled, so every label change restarts the PR's run")
	}

	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		if name != gateJob {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		j := wf.Jobs[name]
		if !slices.Contains(gate.Needs, name) {
			problems = append(problems, fmt.Sprintf("%s is not in %s needs", name, gateJob))
		}
		tier, ok := tiers[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no check line in CI Gate", name))
			continue
		}
		cond := condition(j.If)
		guarded := slices.Contains(j.Needs, scheduleGuardJob)
		switch tier {
		case "full":
			if cond != fullTierJobIf && (!guarded || cond != fullTierJobIf+" && ("+scheduleRun+")") {
				problems = append(problems, fmt.Sprintf("%s is tagged full but its if: is %q, want %q", name, cond, fullTierJobIf))
			}
		case "nightly":
			if cond != nightlyIf && (!guarded || cond != guardedNightlyIf) {
				problems = append(problems, fmt.Sprintf("%s is tagged nightly but its if: is %q, want %q", name, cond, nightlyIf))
			}
		case "pr":
			guardedPR := guarded && (cond == scheduleRun || cond == draftIf+" && ("+scheduleRun+")")
			switch {
			case cond == "" && len(j.Needs) == 0:
				problems = append(problems, fmt.Sprintf("%s is tagged pr but has no if: %q and needs no job, so it runs on a draft", name, draftIf))
			case cond != "" && cond != draftIf && !guardedPR:
				problems = append(problems, fmt.Sprintf("%s is tagged pr but its if: is %q, want %q or none", name, cond, draftIf))
			}
			for _, need := range j.Needs {
				if t := tiers[need]; t == "full" || t == "nightly" {
					problems = append(problems, fmt.Sprintf("pr-tier %s needs %s-tier %s", name, t, need))
				}
			}
		}
	}

	for name := range tiers {
		if _, ok := wf.Jobs[name]; !ok || name == gateJob {
			problems = append(problems, fmt.Sprintf("CI Gate checks %s, which is not a gated job", name))
		}
	}
	for _, need := range gate.Needs {
		if _, ok := wf.Jobs[need]; !ok {
			problems = append(problems, fmt.Sprintf("%s needs %s, which is not a job", gateJob, need))
		}
	}
	return problems
}

// untimedJobs are the ci-template's own jobs that carry no timeout-minutes in
// the canonical go-quicraft ci.yml, which go-xkms's matches outside its
// CUSTOMIZE blocks (#1558). Each runs only short shell steps (a diff, greps,
// the gate's result check) and builds or tests nothing. The v1.29.3 schedule
// guard is one: two curl calls, each bounded by --max-time.
var untimedJobs = map[string]bool{
	"changes":        true,
	"arch-gates":     true,
	scheduleGuardJob: true,
	gateJob:          true,
}

// releasabilityRef is how the ci-template's docs-only releasability step
// (v1.26.1) names its go test arguments. The step runs only when the
// workflow's RELEASABILITY_TEST is set, so its -timeout belongs in that value.
const releasabilityRef = "$RELEASABILITY_TEST"

// boundProblems reports every job without a timeout-minutes, other than
// untimedJobs, and every go test invocation without a -timeout (#1587): an
// unbounded job or test binary hangs until the runner's implicit limit
// instead of failing. A line naming releasabilityRef is read with the
// workflow's value in its place, and skipped when that value is empty.
func boundProblems(wf workflow) []string {
	releasability := wf.Env["RELEASABILITY_TEST"]
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	for _, name := range names {
		j := wf.Jobs[name]
		if j.TimeoutMinutes <= 0 && !untimedJobs[name] {
			problems = append(problems, fmt.Sprintf("%s has no timeout-minutes", name))
		}
		for _, step := range j.Steps {
			for _, line := range strings.Split(step.Run, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || !strings.Contains(line, "go test ") {
					continue
				}
				if strings.Contains(line, releasabilityRef) {
					if releasability == "" {
						continue
					}
					line = strings.ReplaceAll(line, releasabilityRef, releasability)
				}
				if !strings.Contains(line, "-timeout ") {
					problems = append(problems, fmt.Sprintf("%s runs go test without -timeout: %q", name, line))
				}
			}
		}
	}
	return problems
}

func TestCIGateTiersMatchTheJobs(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	wf := parseWorkflow(t, data)
	if len(wf.Jobs) < 2 {
		t.Fatalf("%s parsed to %d jobs; the parser is not reading it", ciWorkflow, len(wf.Jobs))
	}
	for _, p := range tierProblems(wf) {
		t.Error(p)
	}
}

// fixture is a minimal workflow that satisfies the contract; each case below
// breaks it in one way.
const fixture = `
on:
  pull_request:
    types: [opened, synchronize, reopened]
env:
  CI_FULL_TIER: ${{ github.event_name != 'pull_request' || contains(github.event.pull_request.labels.*.name, 'ci:full') }}
  RELEASABILITY_TEST: ""
jobs:
  lint:
    runs-on: x
    if: ${{ !github.event.pull_request.draft }}
    timeout-minutes: 10
  build:
    needs: [lint]
    timeout-minutes: 20
    steps:
      - run: |
          # go test is bounded below
          go test -timeout 15m ./...
          go test -count=1 $RELEASABILITY_TEST
  race:
    needs: [build]
    if: >-
      ${{ (github.event_name != 'pull_request' ||
      contains(github.event.pull_request.labels.*.name, 'ci:full')) && !github.event.pull_request.draft }}
    timeout-minutes: 30
  soak:
    needs: [schedule-guard]
    if: ${{ (github.event_name == 'schedule' && needs.schedule-guard.outputs.verdict == 'run') || github.event_name == 'workflow_dispatch' }}
    timeout-minutes: 60
  schedule-guard:
    if: ${{ !github.event.pull_request.draft }}
  ci-gate:
    if: always()
    needs: [lint, build, race, soak, schedule-guard]
    timeout-minutes: 5
    steps:
      - env:
          FULL_TIER: ${{ env.CI_FULL_TIER }}
          NIGHTLY: ${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}
          DRAFT: ${{ github.event.pull_request.draft == true }}
        run: |
          check lint  "${{ needs.lint.result }}" pr
          check build "${{ needs.build.result }}" pr
          check race  "${{ needs.race.result }}" full
          check soak  "${{ needs.soak.result }}" nightly
          check schedule-guard "${{ needs.schedule-guard.result }}" pr
`

func TestCIGateTiersCatchEachMismatch(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"none", "", "", ""},
		{"full job tagged pr", `"${{ needs.race.result }}" full`, `"${{ needs.race.result }}" pr`, "race is tagged pr but its if:"},
		{"pr job tagged full", `"${{ needs.build.result }}" pr`, `"${{ needs.build.result }}" full`, "build is tagged full but its if:"},
		{"pr job with an if", "needs: [lint]\n", "needs: [lint]\n    if: github.event_name == 'push'\n", "build is tagged pr but its if:"},
		{"job missing from the gate", "          check race  \"${{ needs.race.result }}\" full\n", "", "race has no check line in CI Gate"},
		{"job missing from gate needs", "needs: [lint, build, race, soak, schedule-guard]", "needs: [lint, build, soak, schedule-guard]", "race is not in ci-gate needs"},
		{"unknown tier", `"${{ needs.build.result }}" pr`, `"${{ needs.build.result }}" fast`, `tags build "fast"`},
		{"tier missing", `"${{ needs.build.result }}" pr`, `"${{ needs.build.result }}"`, "is malformed"},
		{"line reads another job", `build "${{ needs.build.result }}"`, `build "${{ needs.race.result }}"`, "reads needs.race.result"},
		{"pr job needs a full job", "needs: [lint]\n", "needs: [lint, race]\n", "pr-tier build needs full-tier race"},
		{"pr job needs a nightly job", "needs: [lint]\n", "needs: [lint, soak]\n", "pr-tier build needs nightly-tier soak"},
		{"labeled trigger", "reopened]", "reopened, labeled]", "has labeled"},
		{"label missing from full if", " ||\n      contains(github.event.pull_request.labels.*.name, 'ci:full'))", ")", "race is tagged full but its if:"},
		{"full job without the draft guard", ")) && !github.event.pull_request.draft }}", ")) }}", "race is tagged full but its if:"},
		{"pr job without the draft guard or a need", "    if: ${{ !github.event.pull_request.draft }}\n", "", "lint is tagged pr but has no if:"},
		{"CI Gate without DRAFT", "          DRAFT: ${{ github.event.pull_request.draft == true }}\n", "", "CI Gate DRAFT is"},
		{"nightly job with another if", "if: ${{ (github.event_name == 'schedule' && needs.schedule-guard.outputs.verdict == 'run') || github.event_name == 'workflow_dispatch' }}", "if: ${{ github.event_name == 'schedule' }}", "soak is tagged nightly but its if:"},
		{"nightly job under the guard without needing it", "    needs: [schedule-guard]\n", "", "soak is tagged nightly but its if:"},
		{"full job under the guard without needing it", ")) && !github.event.pull_request.draft }}", ")) && !github.event.pull_request.draft && (github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict == 'run') }}", "race is tagged full but its if:"},
		{"pr job under the schedule guard", "needs: [lint]\n", "needs: [lint, schedule-guard]\n    if: ${{ !github.event.pull_request.draft && (github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict == 'run') }}\n", ""},
		{"pr job with a guard clause but no draft guard", "needs: [lint]\n", "needs: [lint, schedule-guard]\n    if: ${{ github.event_name != 'schedule' }}\n", "build is tagged pr but its if:"},
		{"FULL_TIER not read from CI_FULL_TIER", "FULL_TIER: ${{ env.CI_FULL_TIER }}", "FULL_TIER: ${{ github.event_name != 'pull_request' }}", "CI Gate FULL_TIER is"},
		{"CI_FULL_TIER drifts from the full if", "CI_FULL_TIER: ${{ github.event_name != 'pull_request' ||", "CI_FULL_TIER: ${{ github.event_name == 'push' ||", "env.CI_FULL_TIER is"},
		{"NIGHTLY drifts from the nightly if", "NIGHTLY: ${{ github.event_name == 'schedule' || ", "NIGHTLY: ${{ ", "CI Gate NIGHTLY is"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := fixture
			if tc.old != "" {
				if !strings.Contains(src, tc.old) {
					t.Fatalf("fixture has no %q to replace", tc.old)
				}
				src = strings.Replace(src, tc.old, tc.new, 1)
			}
			problems := tierProblems(parseWorkflow(t, []byte(src)))
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("valid fixture reported %q", problems)
				}
				return
			}
			for _, p := range problems {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
		})
	}
}

func TestCIJobsAreBounded(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range boundProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

func TestCIBoundsCatchEachMissingBound(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"none", "", "", ""},
		{"job without timeout-minutes", "    timeout-minutes: 30\n", "", "race has no timeout-minutes"},
		{"template job without timeout-minutes is exempt", "    timeout-minutes: 5\n", "", ""},
		{"go test without -timeout", "go test -timeout 15m ./...", "go test ./...", "build runs go test without -timeout"},
		{"releasability test set without -timeout", `RELEASABILITY_TEST: ""`, `RELEASABILITY_TEST: "./test/releasability/..."`, "build runs go test without -timeout"},
		{"releasability test set with -timeout", `RELEASABILITY_TEST: ""`, `RELEASABILITY_TEST: "-timeout 5m ./test/releasability/..."`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := fixture
			if tc.old != "" {
				if !strings.Contains(src, tc.old) {
					t.Fatalf("fixture has no %q to replace", tc.old)
				}
				src = strings.Replace(src, tc.old, tc.new, 1)
			}
			problems := boundProblems(parseWorkflow(t, []byte(src)))
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("valid fixture reported %q", problems)
				}
				return
			}
			for _, p := range problems {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
		})
	}
}

func TestCIGateTiersRejectAWorkflowWithoutAGate(t *testing.T) {
	wf := parseWorkflow(t, []byte("jobs:\n  build:\n    runs-on: x\n"))
	if got := tierProblems(wf); !slices.Equal(got, []string{"no ci-gate job"}) {
		t.Fatalf("got %q, want [no ci-gate job]", got)
	}
}
