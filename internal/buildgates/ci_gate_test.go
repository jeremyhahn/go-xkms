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

// docsOnlyIf is the clause a job carries when a docs-only diff stands it
// down. fullTierIf is the whole condition of a full-tier job (#1483): the
// event, the ci:full label, or the changes job's full_tier output, which is
// what keeps trains on the full tier. Both are compared after collapsing
// whitespace, so a folded `if: >-` matches.
const (
	docsOnlyIf = "needs.changes.outputs.docs_only != 'true'"
	fullTierIf = docsOnlyIf + " && (github.event_name == 'push' ||" +
		" github.event_name == 'workflow_dispatch' ||" +
		" contains(github.event.pull_request.labels.*.name, 'ci:full') ||" +
		" needs.changes.outputs.full_tier == 'true')"
)

// gateLine matches one `check <tier> <job> "${{ needs.<job>.result }}" [docs]`
// line of CI Gate's script.
var gateLine = regexp.MustCompile(
	`^check\s+(\S+)\s+(\S+)\s+"\$\{\{ needs\.([A-Za-z0-9_-]+)\.result \}\}"(?:\s+(\S+))?$`)

type workflow struct {
	On struct {
		PullRequest struct {
			Types []string `yaml:"types"`
		} `yaml:"pull_request"`
	} `yaml:"on"`
	Jobs map[string]job `yaml:"jobs"`
}

type job struct {
	If    string    `yaml:"if"`
	Needs needsList `yaml:"needs"`
	Steps []struct {
		Run string `yaml:"run"`
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

// gateEntry is one parsed CI Gate line.
type gateEntry struct {
	tier string
	docs bool
}

func parseWorkflow(t *testing.T, data []byte) workflow {
	t.Helper()
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	return wf
}

// gateEntries reads the check lines out of CI Gate's steps, reporting any
// line that starts with `check ` but does not have the expected shape.
func gateEntries(gate job) (map[string]gateEntry, []string) {
	entries := map[string]gateEntry{}
	var problems []string
	for _, step := range gate.Steps {
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
			tier, name, ref, flag := m[1], m[2], m[3], m[4]
			if tier != "pr" && tier != "full" {
				problems = append(problems, fmt.Sprintf("CI Gate tags %s %q, want pr or full", name, tier))
			}
			if name != ref {
				problems = append(problems, fmt.Sprintf("CI Gate line for %s reads needs.%s.result", name, ref))
			}
			if flag != "" && flag != "docs" {
				problems = append(problems, fmt.Sprintf("CI Gate line for %s ends in %q, want docs or nothing", name, flag))
			}
			if _, dup := entries[name]; dup {
				problems = append(problems, fmt.Sprintf("CI Gate checks %s twice", name))
			}
			entries[name] = gateEntry{tier: tier, docs: flag == "docs"}
		}
	}
	return entries, problems
}

// tierProblems lists every way wf breaks the tier contract (#1483).
func tierProblems(wf workflow) []string {
	gate, ok := wf.Jobs[gateJob]
	if !ok {
		return []string{"no " + gateJob + " job"}
	}
	entries, problems := gateEntries(gate)

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
		entry, ok := entries[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no check line in CI Gate", name))
			continue
		}
		cond := strings.Join(strings.Fields(j.If), " ")
		switch entry.tier {
		case "full":
			if cond != fullTierIf {
				problems = append(problems, fmt.Sprintf("%s is tagged full but its if: is %q, want %q", name, cond, fullTierIf))
			}
		case "pr":
			if cond != "" && cond != docsOnlyIf {
				problems = append(problems, fmt.Sprintf("%s is tagged pr but its if: is %q, want none or %q", name, cond, docsOnlyIf))
			}
			for _, need := range j.Needs {
				if entries[need].tier == "full" {
					problems = append(problems, fmt.Sprintf("pr-tier %s needs full-tier %s", name, need))
				}
			}
		}
		if hasDocs := strings.HasPrefix(cond, docsOnlyIf); hasDocs != entry.docs {
			problems = append(problems, fmt.Sprintf("%s: CI Gate docs flag is %t but its if: docs-only clause is %t", name, entry.docs, hasDocs))
		}
	}

	for name := range entries {
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
jobs:
  changes:
    runs-on: x
  build:
    needs: [changes]
    if: needs.changes.outputs.docs_only != 'true'
  race:
    needs: [changes, build]
    if: >-
      needs.changes.outputs.docs_only != 'true' &&
      (github.event_name == 'push' || github.event_name == 'workflow_dispatch' ||
      contains(github.event.pull_request.labels.*.name, 'ci:full') ||
      needs.changes.outputs.full_tier == 'true')
  ci-gate:
    if: always()
    needs: [changes, build, race]
    steps:
      - run: |
          check pr   changes "${{ needs.changes.result }}"
          check pr   build   "${{ needs.build.result }}" docs
          check full race    "${{ needs.race.result }}"  docs
`

func TestCIGateTiersCatchEachMismatch(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"none", "", "", ""},
		{"full job tagged pr", "check full race ", "check pr   race ", "race is tagged pr but its if:"},
		{"pr job tagged full", "check pr   build ", "check full build ", "build is tagged full but its if:"},
		{"job missing from the gate", "          check full race    \"${{ needs.race.result }}\"  docs\n", "", "race has no check line in CI Gate"},
		{"job missing from gate needs", "needs: [changes, build, race]", "needs: [changes, build]", "race is not in ci-gate needs"},
		{"unknown tier", "check pr   build ", "check fast build ", `tags build "fast"`},
		{"line reads another job", `build   "${{ needs.build.result }}"`, `build   "${{ needs.race.result }}"`, "reads needs.race.result"},
		{"docs flag dropped", `"${{ needs.build.result }}" docs`, `"${{ needs.build.result }}"`, "build: CI Gate docs flag is false"},
		{"pr job needs a full job", "needs: [changes]\n    if: needs.changes.outputs.docs_only", "needs: [changes, race]\n    if: needs.changes.outputs.docs_only", "pr-tier build needs full-tier race"},
		{"labeled trigger", "reopened]", "reopened, labeled]", "has labeled"},
		{"label missing from full if", "contains(github.event.pull_request.labels.*.name, 'ci:full') ||\n", "", "race is tagged full but its if:"},
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

func TestCIGateTiersRejectAWorkflowWithoutAGate(t *testing.T) {
	wf := parseWorkflow(t, []byte("jobs:\n  build:\n    runs-on: x\n"))
	if got := tierProblems(wf); !slices.Equal(got, []string{"no ci-gate job"}) {
		t.Fatalf("got %q, want [no ci-gate job]", got)
	}
}
