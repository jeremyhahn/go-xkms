package buildgates

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// raceJob is the Race Detector job. make coverage runs without -race (#2023),
// so this job is the PR tier's race check: it runs on every ready pull
// request, ci:full or not, and CI Gate fails the PR when it does not pass.
const raceJob = "race"

// raceTierProblems lists each way wf lets a ready pull request pass CI Gate
// with no race detection: the race job's if: is not the draft guard alone (so
// a PR without ci:full skips it), or CI Gate checks it on a tier but pr.
func raceTierProblems(wf workflow) []string {
	race, ok := wf.Jobs[raceJob]
	if !ok {
		return []string{"no " + raceJob + " job"}
	}
	var problems []string
	if cond := condition(race.If); cond != draftIf {
		problems = append(problems, fmt.Sprintf("%s's if: is %q, want %q, so it runs on every ready PR", raceJob, cond, draftIf))
	}
	tiers, _ := gateTiers(wf.Jobs[gateJob])
	if tier := tiers[raceJob]; tier != "pr" {
		problems = append(problems, fmt.Sprintf("CI Gate checks %s on tier %q, want pr", raceJob, tier))
	}
	return problems
}

func TestRaceDetectorRunsOnThePRTier(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range raceTierProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

func TestRaceTierCatchesEachForm(t *testing.T) {
	// raceHead anchors each rewrite on the race job: lint has the same if:.
	const raceHead = "  race:\n    needs: [build]\n"
	const fullIf = raceHead + "    if: >-\n      ${{ (github.event_name != 'pull_request' ||\n" +
		"      contains(github.event.pull_request.labels.*.name, 'ci:full')) && !github.event.pull_request.draft }}\n"
	const prIf = raceHead + "    if: ${{ !github.event.pull_request.draft }}\n"
	const fullLine = `check race  "${{ needs.race.result }}" full`
	const prLine = `check race  "${{ needs.race.result }}" pr`
	pr := strings.Replace(strings.Replace(fixture, fullIf, prIf, 1), fullLine, prLine, 1)
	cases := map[string]struct {
		workflow string
		want     int
	}{
		"pr tier":             {pr, 0},
		"full tier":           {fixture, 2},
		"ci:full if, gate pr": {strings.Replace(pr, prIf, fullIf, 1), 1},
		"pr if, gate full":    {strings.Replace(pr, prLine, fullLine, 1), 1},
		"no gate line":        {strings.Replace(pr, prLine, "", 1), 1},
		"runs on drafts too":  {strings.Replace(pr, prIf, raceHead, 1), 1},
		"no race job":         {"jobs:\n  ci-gate:\n    runs-on: x\n", 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(fixture, fullIf) || !strings.Contains(fixture, fullLine) {
				t.Fatal("ci_gate_test.go's fixture no longer has the full-tier race job this test rewrites")
			}
			if got := raceTierProblems(parseWorkflow(t, []byte(c.workflow))); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}
