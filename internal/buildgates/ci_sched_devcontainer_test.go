package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	// devcontainerRunsOn is the v1.48 Docker-job runs-on (ruling 1024):
	// the preflight runner_docker output on github.com, so the job is
	// hosted unless the run overflows, and never self-hosted for a fork.
	devcontainerRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk' }}`
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

func TestCIDevcontainerReadsRunnerDocker(t *testing.T) {
	wf := readDigestWorkflow(t)
	j, ok := wf.Jobs[devcontainerJob]
	if !ok {
		t.Fatalf("ci.yml has no %s job", devcontainerJob)
	}
	if j.RunsOn != devcontainerRunsOn {
		t.Errorf("%s runs-on = %q, want %q", devcontainerJob, j.RunsOn, devcontainerRunsOn)
	}
	if !slices.Contains(j.Needs, preflightJob) {
		t.Errorf("%s reads needs.preflight.outputs.runner_docker but does not need %s", devcontainerJob, preflightJob)
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

// runnerSelectStep is the id of the preflight step that picks the hosted
// default or the overflow pools (ci-template v1.48, ruling 1024).
const runnerSelectStep = "runner"

// forkPRExpr is the step's FORK_PR env: true on a pull request whose head
// repository is not this repository (Codex #2323 P1).
const forkPRExpr = "${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}"

// stubCurl answers the selector's Actions API calls: one run, and a job
// list of HOSTED_JOBS_PER_REPO hosted jobs in progress (a full pool). Each
// URL it is asked for is appended to $STUB_LOG.
const stubCurl = `#!/bin/sh
out=; url=
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    -w|-H|--max-time) shift ;;
    *) url=$1 ;;
  esac
  shift
done
echo "$url" >> "$STUB_LOG"
case "$url" in
  */jobs*) cat "$STUB_DIR/jobs.json" > "$out" ;;
  *) cat "$STUB_DIR/runs.json" > "$out" ;;
esac
printf 200
`

// runRunnerSelect runs the selector script with the stub curl, as a pull
// request with FORK_PR=fork, and returns its GITHUB_OUTPUT and the API
// URLs it asked for.
func runRunnerSelect(t *testing.T, script, fork string) (output, calls string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(stubCurl), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runs.json"), []byte(`{"total_count":1,"workflow_runs":[{"id":7}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	jobs := make([]string, 12)
	for i := range jobs {
		jobs[i] = `{"status":"in_progress","labels":["ubuntu-latest"],"run_id":7}`
	}
	jobsJSON := fmt.Sprintf(`{"total_count":%d,"jobs":[%s]}`, len(jobs), strings.Join(jobs, ","))
	if err := os.WriteFile(filepath.Join(dir, "jobs.json"), []byte(jobsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "output")
	log := filepath.Join(dir, "calls")
	for _, f := range []string{out, log} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SERVER=https://github.com",
		"API=https://api.example/repos/o/r/actions",
		"RUN_ID=1",
		"JOB_TOKEN=x",
		"LIMIT=12",
		"GRACE=60",
		"FORK_PR="+fork,
		"GITHUB_OUTPUT="+out,
		"RUNNER_TEMP="+dir,
		"STUB_DIR="+dir,
		"STUB_LOG="+log,
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("selector (FORK_PR=%s): %v\n%s", fork, err, b)
	}
	o, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return string(o), string(c)
}

func TestCIRunnerSelectionKeepsForkPullRequestsHosted(t *testing.T) {
	wf := readDigestWorkflow(t)
	var step *digestStep
	for i, s := range wf.Jobs[preflightJob].Steps {
		if s.ID == runnerSelectStep {
			step = &wf.Jobs[preflightJob].Steps[i]
		}
	}
	if step == nil {
		t.Fatalf("%s has no step with id: %s", preflightJob, runnerSelectStep)
	}
	if got := step.Env["FORK_PR"]; got != forkPRExpr {
		t.Fatalf("%s step %s env FORK_PR = %q, want %q", preflightJob, runnerSelectStep, got, forkPRExpr)
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: the selector script needs it", tool)
		}
	}
	const hosted = "runner=\"ubuntu-latest\"\nrunner_docker=\"ubuntu-latest\"\n"
	const overflow = "runner=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]\nrunner_docker=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\n"

	// A same-repository run on a full pool overflows: the stub reaches the
	// overflow branch, so the fork case below tests the fork check.
	if out, _ := runRunnerSelect(t, step.Run, "false"); out != overflow {
		t.Errorf("same-repository run on a full pool: output %q, want %q", out, overflow)
	}
	for _, fork := range []string{"true", ""} {
		out, calls := runRunnerSelect(t, step.Run, fork)
		if out != hosted {
			t.Errorf("FORK_PR=%q on a full pool: output %q, want %q", fork, out, hosted)
		}
		if calls != "" {
			t.Errorf("FORK_PR=%q: the selector called the Actions API:\n%s", fork, calls)
		}
	}
}

// TestCIRunnerSelectionShortListIsLowerBound pins template v1.50 (handbook
// 52e70fd5, #84): a listing short of its total_count is a lower bound kept in
// SHORT, not a reason to stay hosted, so overflow still fires under load.
func TestCIRunnerSelectionShortListIsLowerBound(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, re := range []string{
		`(?m)^\s*SHORT=""\s*$`,
		`(?m)^\s*\[ "\$got" -ge "\$total" \] \|\| SHORT="\$\{SHORT:\+\$SHORT; \}\$1: \$got of \$total entries"\s*$`,
		`(?m)^\s*elif \[ -n "\$SHORT" \]; then\s*$`,
		`(?m)^\s*\[ -z "\$SHORT" \] \|\| why="\$why \(a lower bound: \$SHORT\)"\s*$`,
	} {
		if !regexp.MustCompile(re).MatchString(text) {
			t.Errorf("ci.yml: no line matches %s (v1.50 short-list lower bound)", re)
		}
	}
	if strings.Contains(text, `WHY="$1: $got of $total entries"; return 1;`) {
		t.Error("ci.yml: a short listing still returns 1 (pre-v1.50)")
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
