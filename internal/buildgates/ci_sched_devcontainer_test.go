package buildgates

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The #2240 customizations of ci.yml: scheduled and dispatched main runs
// share the bigdisk-docker pool with main's push runs, so the preflight
// schedule guard must count main's active push runs on every server, and
// the Devcontainer job's coverage step must not run after a failed build.
const (
	devcontainerJob = "image"
	preflightJob    = "preflight"
	// devcontainerRunsOn sends push, schedule and workflow_dispatch on main
	// and same-repository pull requests to bigdisk-docker, and fork pull
	// requests to ubuntu-latest.
	devcontainerRunsOn = `${{ (((github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON('["self-hosted","linux","x64","bigdisk-docker"]') || 'ubuntu-latest' }}`
	buildStepID        = "build"
	coverageAfterBuild = "steps.build.outcome != 'failure'"
	// scheduleBranch opens the guard's chain of branches for a schedule run.
	scheduleBranch = `elif [ "$EVENT" != schedule ]; then`
)

func readDigestWorkflow(t *testing.T) digestWorkflow {
	t.Helper()
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var wf digestWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", ciWorkflow, err)
	}
	return wf
}

func TestCIDevcontainerRunsOnTheSharedPool(t *testing.T) {
	wf := readDigestWorkflow(t)
	j, ok := wf.Jobs[devcontainerJob]
	if !ok {
		t.Fatalf("ci.yml has no %s job", devcontainerJob)
	}
	if j.RunsOn != devcontainerRunsOn {
		t.Errorf("%s runs-on = %q, want %q", devcontainerJob, j.RunsOn, devcontainerRunsOn)
	}
}

func TestCIDevcontainerCoverageSkipsAfterFailedBuild(t *testing.T) {
	wf := readDigestWorkflow(t)
	j := wf.Jobs[devcontainerJob]
	build := -1
	for i, s := range j.Steps {
		if s.ID == buildStepID {
			build = i
		}
	}
	if build < 0 {
		t.Fatalf("%s has no step with id: %s", devcontainerJob, buildStepID)
	}
	found := false
	for _, s := range j.Steps[build+1:] {
		if !strings.Contains(s.Run, "make coverage") {
			continue
		}
		found = true
		if !strings.Contains(s.If, coverageAfterBuild) {
			t.Errorf("%s coverage step if: %q lacks %q", devcontainerJob, s.If, coverageAfterBuild)
		}
	}
	if !found {
		t.Fatalf("%s has no make coverage step after step %s", devcontainerJob, buildStepID)
	}
}

// scheduleGuardProblems lists every branch of the guard's schedule chain
// that names github.com and settles the verdict without counting runs.
func scheduleGuardProblems(script string) []string {
	lines := strings.Split(script, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == scheduleBranch {
			start = i
			break
		}
	}
	if start < 0 {
		return []string{"the schedule guard has no " + scheduleBranch + " branch"}
	}
	indent := len(lines[start]) - len(strings.TrimLeft(lines[start], " "))
	var problems []string
	var cond string
	var body []string
	flush := func() {
		if strings.Contains(cond, "https://github.com") && !strings.Contains(strings.Join(body, "\n"), `runs "`) {
			problems = append(problems, "the branch "+strings.TrimSpace(cond)+" settles a schedule run without counting main's active push runs")
		}
	}
	for _, l := range lines[start+1:] {
		lead := len(l) - len(strings.TrimLeft(l, " "))
		tl := strings.TrimSpace(l)
		if lead == indent && (strings.HasPrefix(tl, "elif ") || tl == "else" || tl == "fi") {
			flush()
			if tl == "fi" {
				return problems
			}
			cond, body = tl, nil
			continue
		}
		body = append(body, tl)
	}
	return append(problems, "the schedule guard's chain has no closing fi")
}

func TestCIScheduleGuardCountsRunsOnGitHub(t *testing.T) {
	wf := readDigestWorkflow(t)
	var script string
	for _, s := range wf.Jobs[preflightJob].Steps {
		if strings.Contains(s.Run, scheduleBranch) {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatalf("%s has no schedule guard step", preflightJob)
	}
	for _, p := range scheduleGuardProblems(script) {
		t.Error(p)
	}
}

func TestScheduleGuardProblemsCatchAnUncountedBranch(t *testing.T) {
	const bad = `if [ "$verdict" != run ]; then
  :
elif [ "$EVENT" != schedule ]; then
  echo "not a schedule run: no check"
elif [ "$SERVER" = https://github.com ]; then
  echo "no check"
elif runs "$JOB_TOKEN"; then
  echo counted
fi`
	if p := scheduleGuardProblems(bad); len(p) != 1 {
		t.Fatalf("want one problem, got %q", p)
	}
	good := strings.Replace(bad, `echo "no check"`, `runs "$JOB_TOKEN" || verdict=unreadable`, 1)
	if p := scheduleGuardProblems(good); len(p) != 0 {
		t.Fatalf("want no problem, got %q", p)
	}
}
