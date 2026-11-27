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
// coverage must not run after a failed build.
//
// Row #2261 (rulings 833-835): the Devcontainer `image` job, which ran
// lint, the go-xkms checks, gosec, build and coverage in one 240-minute job,
// is split into a hosted `lint` job, a hosted `image-build` job and a
// `coverage` job that needs image-build. Only coverage needs the 24 GB
// container (#2063), so only coverage takes the runner_docker routing.
const (
	preflightJob = "preflight"
	// splitLintJob, splitBuildJob and splitCoverageJob are the three jobs
	// that replace the image job (splitRemovedJob).
	splitRemovedJob  = "image"
	splitLintJob     = "lint"
	splitBuildJob    = "image-build"
	splitCoverageJob = "coverage"
	// devcontainerRunsOn is the v1.48 Docker-job runs-on (ruling 1024):
	// the preflight runner_docker output on github.com, so the job is
	// hosted unless the run overflows, and never self-hosted for a fork.
	devcontainerRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk' }}`
	// splitHostedRunsOn is the lint and image-build runs-on: ubuntu-latest
	// on github.com, whatever the hosted pool's load.
	splitHostedRunsOn = `${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}`
	buildStepID       = "build"
	// scheduleBranch opens the guard's chain of branches for a schedule run.
	scheduleBranch = `elif [ "$EVENT" != schedule ]; then`
)

// splitJob is the part of a ci.yml job the image split tests read.
type splitJob struct {
	RunsOn         string      `yaml:"runs-on"`
	Needs          needsList   `yaml:"needs"`
	If             string      `yaml:"if"`
	TimeoutMinutes int         `yaml:"timeout-minutes"`
	Steps          []splitStep `yaml:"steps"`
}

type splitStep struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
}

func readSplitJobs(t *testing.T) map[string]splitJob {
	t.Helper()
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var wf struct {
		Jobs map[string]splitJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", ciWorkflow, err)
	}
	return wf.Jobs
}

// stepRunning returns the index of the first step of j whose run contains
// s, or -1.
func stepRunning(j splitJob, s string) int {
	return slices.IndexFunc(j.Steps, func(st splitStep) bool { return strings.Contains(st.Run, s) })
}

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

func TestCIImageJobSplit(t *testing.T) {
	jobs := readSplitJobs(t)
	if _, ok := jobs[splitRemovedJob]; ok {
		t.Errorf("ci.yml still has the %s job: #2261 splits it into %s, %s and %s", splitRemovedJob, splitLintJob, splitBuildJob, splitCoverageJob)
	}
	for _, name := range []string{splitLintJob, splitBuildJob, splitCoverageJob} {
		j, ok := jobs[name]
		if !ok {
			t.Fatalf("ci.yml has no %s job", name)
		}
		for _, need := range []string{preflightJob, "ci-images"} {
			if !slices.Contains(j.Needs, need) {
				t.Errorf("%s does not need %s", name, need)
			}
		}
	}
}

func TestCIImageSplitRouting(t *testing.T) {
	jobs := readSplitJobs(t)
	for _, name := range []string{splitLintJob, splitBuildJob} {
		j := jobs[name]
		if j.RunsOn != splitHostedRunsOn {
			t.Errorf("%s runs-on = %q, want %q", name, j.RunsOn, splitHostedRunsOn)
		}
		for _, label := range []string{"self-hosted", "bigdisk-docker", "runner_docker"} {
			if strings.Contains(j.RunsOn, label) {
				t.Errorf("%s runs-on names %q: it stays hosted on github.com", name, label)
			}
		}
	}
	if got := jobs[splitCoverageJob].RunsOn; got != devcontainerRunsOn {
		t.Errorf("%s runs-on = %q, want %q", splitCoverageJob, got, devcontainerRunsOn)
	}
}

// integrationRunsOn is the integration job's runs-on (Tenant order
// 2026-11-27 17:18Z): the preflight runner_integration output, which is
// bigdisk-docker on a push to main or a same-repository pull request
// whatever the balance picks, so the integration image build never lands on
// a hosted runner's small disk; 'bigdisk' off github.com.
const integrationRunsOn = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_integration) || 'bigdisk' }}`

func TestCIIntegrationKeepsBigdiskDocker(t *testing.T) {
	wf := readDigestWorkflow(t)
	j, ok := wf.Jobs["integration"]
	if !ok {
		t.Fatal("ci.yml has no integration job")
	}
	if j.RunsOn != integrationRunsOn {
		t.Errorf("integration runs-on = %q, want %q", j.RunsOn, integrationRunsOn)
	}
	if !slices.Contains(j.Needs, preflightJob) {
		t.Errorf("integration reads needs.preflight.outputs.runner_integration but does not need %s", preflightJob)
	}
}

// TestCIDevcontainerCoverageSkipsAfterFailedBuild: #2240's rule, now at job
// level. coverage needs image-build and its if: carries no status function,
// so a failed, cancelled or skipped image-build skips coverage.
func TestCIDevcontainerCoverageSkipsAfterFailedBuild(t *testing.T) {
	jobs := readSplitJobs(t)
	cov := jobs[splitCoverageJob]
	if !slices.Contains(cov.Needs, splitBuildJob) {
		t.Errorf("%s does not need %s, so it runs after a failed build", splitCoverageJob, splitBuildJob)
	}
	for _, f := range []string{"always()", "!cancelled()", "failure()", "cancelled()"} {
		if strings.Contains(cov.If, f) {
			t.Errorf("%s if: %q contains %s, so it runs after a failed %s", splitCoverageJob, cov.If, f, splitBuildJob)
		}
	}
	if !strings.Contains(cov.If, "needs.preflight.outputs.verdict == 'run'") {
		t.Errorf("%s if: %q does not wait for the guard's run", splitCoverageJob, cov.If)
	}
	build := jobs[splitBuildJob]
	if i := slices.IndexFunc(build.Steps, func(s splitStep) bool { return s.ID == buildStepID }); i < 0 || !strings.Contains(build.Steps[i].Run, "make build") {
		t.Errorf("%s has no make build step with id: %s", splitBuildJob, buildStepID)
	}
}

func TestCIImageSplitStages(t *testing.T) {
	jobs := readSplitJobs(t)
	want := map[string][]string{
		splitLintJob:     {"make lint", "make test-buildgates", "make check-public-literals", "make gosec"},
		splitBuildJob:    {"scripts/assert-build-tags.sh", "make build"},
		splitCoverageJob: {"make coverage"},
	}
	for name, stages := range want {
		for _, s := range stages {
			if stepRunning(jobs[name], s) < 0 {
				t.Errorf("%s has no step running %q", name, s)
			}
		}
	}
	// Each stage runs once among the three: only coverage runs make
	// coverage, only lint lints, only image-build builds.
	for name := range want {
		j := jobs[name]
		for owner, stages := range want {
			if name == owner {
				continue
			}
			for _, s := range stages {
				if stepRunning(j, s) >= 0 {
					t.Errorf("%s runs %q, which only %s runs", name, s, owner)
				}
			}
		}
	}
	// coverage reads no step of the job it was split from.
	for _, s := range jobs[splitCoverageJob].Steps {
		if strings.Contains(s.If, "steps."+buildStepID+".") {
			t.Errorf("%s step %q if: reads steps.%s, a step of %s", splitCoverageJob, s.Name, buildStepID, splitBuildJob)
		}
	}
}

func TestCIImageSplitTimeouts(t *testing.T) {
	jobs := readSplitJobs(t)
	cov := jobs[splitCoverageJob].TimeoutMinutes
	if cov <= 0 {
		t.Fatalf("%s has no timeout-minutes", splitCoverageJob)
	}
	for _, name := range []string{splitLintJob, splitBuildJob} {
		tm := jobs[name].TimeoutMinutes
		if tm <= 0 || tm > 120 || tm >= cov {
			t.Errorf("%s timeout-minutes = %d, want 1-120 and below %s's %d", name, tm, splitCoverageJob, cov)
		}
	}
}

// runnerSelectStep is the id of the preflight step that picks the hosted
// or the self-hosted pools (ci-template v1.48, ruling 1024; since v1.54 the
// step `Balanced runner pool (ruling 1137)`).
const runnerSelectStep = "runner"

// forkEnv is the step's v1.52 fork env (template verbatim): a pull request
// whose head repository is not this repository, a deleted fork's empty one
// included, takes the hosted default with a ::notice and no API call.
var forkEnv = map[string]string{
	"EVENT":     "${{ github.event_name }}",
	"HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
	"REF":       "${{ github.ref }}",
	"REPO":      "${{ github.repository }}",
}

// headRepo maps the helpers' fork argument to the HEAD_REPO a pull request
// in repository o/r carries: "false" is the same repository, "true" a fork,
// "" a deleted fork.
func headRepo(fork string) string {
	switch fork {
	case "false":
		return "o/r"
	case "true":
		return "fork/r"
	}
	return ""
}

// stubCurl answers the selector's Actions API calls: one run, and a job
// list whose first page is $STUB_DIR/jobs.json; a later page is
// $STUB_DIR/jobs-more.json when it exists (an incomplete listing), else the
// first page again. Each URL it is asked for is appended to $STUB_LOG.
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
  */jobs*\&page=1) cat "$STUB_DIR/jobs.json" > "$out" ;;
  */jobs*) if [ -f "$STUB_DIR/jobs-more.json" ]; then cat "$STUB_DIR/jobs-more.json"; else cat "$STUB_DIR/jobs.json"; fi > "$out" ;;
  *) cat "$STUB_DIR/runs.json" > "$out" ;;
esac
printf 200
`

// runRunnerSelect runs the selector script with the stub curl, as a pull
// request with FORK_PR=fork, and returns its GITHUB_OUTPUT and the API
// URLs it asked for.
// preflightRunsOn is the preflight runs-on (Codex #2323 P1, ruling 999):
// hosted unless CI_PREFLIGHT_RUNS_ON is set, and never the variable on a
// pull request from a fork, so a fork never reaches a self-hosted pool.
// v1.52: the template's fork clause comes before the variable, so a fork's
// pull request (under pull_request or pull_request_target, a deleted fork
// included) takes ubuntu-latest whatever CI_PREFLIGHT_RUNS_ON holds.
// v1.60 (handbook 1bea157): the variable applies only to a push to main or
// a same-repository pull_request; every other event (workflow_dispatch,
// schedule, a push to another branch, pull_request_target) stays hosted.
const preflightRunsOn = "${{ github.server_url == 'https://github.com' && " +
	"((github.event_name == 'push' && github.ref == 'refs/heads/main') || " +
	"(github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository))" +
	" && vars.CI_PREFLIGHT_RUNS_ON != '' && fromJSON(vars.CI_PREFLIGHT_RUNS_ON) || 'ubuntu-latest' }}"

func TestCIPreflightRunsHostedByDefault(t *testing.T) {
	wf := readDigestWorkflow(t)
	j, ok := wf.Jobs[preflightJob]
	if !ok {
		t.Fatalf("ci.yml has no %s job", preflightJob)
	}
	if j.RunsOn != preflightRunsOn {
		t.Errorf("%s runs-on = %q, want %q", preflightJob, j.RunsOn, preflightRunsOn)
	}
	// No self-hosted label is written into the job: with the variable
	// unset, or on a fork, the only value it can resolve to is ubuntu-latest.
	for _, label := range []string{"self-hosted", "bigdisk"} {
		if strings.Contains(j.RunsOn, label) {
			t.Errorf("%s runs-on names %q: unset or on a fork it must stay hosted", preflightJob, label)
		}
	}
	if !strings.HasSuffix(strings.TrimSuffix(j.RunsOn, " }}"), "|| 'ubuntu-latest'") {
		t.Errorf("%s runs-on does not fall back to ubuntu-latest: %q", preflightJob, j.RunsOn)
	}
}

func runRunnerSelect(t *testing.T, script, fork string) (output, calls string) {
	t.Helper()
	output, calls, _ = runRunnerSelectListing(t, script, fork, 12, 12)
	return output, calls
}

// runRunnerSelectListing runs the selector as runRunnerSelect does, with a
// first job page of listed hosted jobs in progress under a total_count of
// total. When total exceeds listed, every later page is empty: the listing
// is incomplete. It also returns the selector's own log. The limits are
// v1.54's repository variables: CI_HOSTED_SHARE 12, so 12 hosted jobs fill
// the hosted pool, and 10 units of each self-hosted label, none in use.
func runRunnerSelectListing(t *testing.T, script, fork string, listed, total int) (output, calls, log string) {
	t.Helper()
	return runRunnerSelectEvent(t, script, fork, "pull_request", "refs/pull/1/merge", listed, total)
}

// runRunnerSelectEvent runs the selector for one event on one ref (v1.60
// reads "$EVENT:$REF" under set -u, so REF is always set).
func runRunnerSelectEvent(t *testing.T, script, fork, event, ref string, listed, total int) (output, calls, log string) {
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
	jobs := make([]string, listed)
	for i := range jobs {
		jobs[i] = `{"status":"in_progress","labels":["ubuntu-latest"],"run_id":7}`
	}
	jobsJSON := fmt.Sprintf(`{"total_count":%d,"jobs":[%s]}`, total, strings.Join(jobs, ","))
	if err := os.WriteFile(filepath.Join(dir, "jobs.json"), []byte(jobsJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if total > listed {
		more := fmt.Sprintf(`{"total_count":%d,"jobs":[]}`, total)
		if err := os.WriteFile(filepath.Join(dir, "jobs-more.json"), []byte(more), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "output")
	callLog := filepath.Join(dir, "calls")
	for _, f := range []string{out, callLog} {
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
		"HS=12",
		"C1=10",
		"C2=10",
		"EVENT="+event,
		"REF="+ref,
		"REPO=o/r",
		"HEAD_REPO="+headRepo(fork),
		"GITHUB_OUTPUT="+out,
		"RUNNER_TEMP="+dir,
		"STUB_DIR="+dir,
		"STUB_LOG="+callLog,
	)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("selector (fork=%s): %v\n%s", fork, err, b)
	}
	o, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	return string(o), string(c), string(b)
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
	for k, want := range forkEnv {
		if got := step.Env[k]; got != want {
			t.Fatalf("%s step %s env %s = %q, want %q", preflightJob, runnerSelectStep, k, got, want)
		}
	}
	if _, ok := step.Env["FORK_PR"]; ok {
		t.Errorf("%s step %s still sets FORK_PR: v1.52 reads EVENT, HEAD_REPO and REPO", preflightJob, runnerSelectStep)
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: the selector script needs it", tool)
		}
	}
	const hosted = "runner=\"ubuntu-latest\"\nrunner_docker=\"ubuntu-latest\"\nrunner_integration=\"ubuntu-latest\"\n"
	const overflow = "runner=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]\nrunner_docker=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\nrunner_integration=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\n"

	// A same-repository run on a full hosted pool goes self-hosted: the stub
	// reaches the self-hosted branch, so the fork case below tests the fork
	// check.
	if out, _ := runRunnerSelect(t, step.Run, "false"); out != overflow {
		t.Errorf("same-repository run on a full pool: output %q, want %q", out, overflow)
	}
	for _, fork := range []string{"true", ""} {
		out, calls := runRunnerSelect(t, step.Run, fork)
		if out != hosted {
			t.Errorf("fork=%q on a full pool: output %q, want %q", fork, out, hosted)
		}
		if calls != "" {
			t.Errorf("fork=%q: the selector called the Actions API:\n%s", fork, calls)
		}
	}
}

// TestCIRunnerSelectionRefusedEventsStayHosted pins v1.60 (handbook
// 1bea157): the self-hosted runners accept only a push to main or a pull
// request, so every other event takes the hosted default with a notice and
// no Actions API call, while a push to main on a full hosted pool still
// goes self-hosted.
func TestCIRunnerSelectionRefusedEventsStayHosted(t *testing.T) {
	wf := readDigestWorkflow(t)
	var script string
	for _, s := range wf.Jobs[preflightJob].Steps {
		if s.ID == runnerSelectStep {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatalf("%s has no step with id: %s", preflightJob, runnerSelectStep)
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: the selector script needs it", tool)
		}
	}
	const hosted = "runner=\"ubuntu-latest\"\nrunner_docker=\"ubuntu-latest\"\nrunner_integration=\"ubuntu-latest\"\n"
	const overflow = "runner=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]\nrunner_docker=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\nrunner_integration=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\n"
	for _, tc := range []struct {
		event, ref string
		want       string
		apiCall    bool
	}{
		{"push", "refs/heads/main", overflow, true},
		{"pull_request", "refs/pull/1/merge", overflow, true},
		{"workflow_dispatch", "refs/heads/main", hosted, false},
		{"workflow_dispatch", "refs/heads/feature", hosted, false},
		{"schedule", "refs/heads/main", hosted, false},
		{"push", "refs/heads/feature", hosted, false},
	} {
		t.Run(tc.event+" "+tc.ref, func(t *testing.T) {
			out, calls, log := runRunnerSelectEvent(t, script, "false", tc.event, tc.ref, 12, 12)
			if out != tc.want {
				t.Errorf("output %q, want %q\n%s", out, tc.want, log)
			}
			if got := calls != ""; got != tc.apiCall {
				t.Errorf("Actions API called = %v, want %v:\n%s", got, tc.apiCall, calls)
			}
			if !tc.apiCall {
				note := "::notice::runner selection: event " + tc.event + " on " + tc.ref + " is not a push to main or a pull request"
				if !strings.Contains(log, note) {
					t.Errorf("log lacks %q:\n%s", note, log)
				}
			}
		})
	}
}

// TestCIRunnerSelectionShortListIsALowerBound pins template v1.59 (handbook
// b18e6499, #113): a listing short of its total_count is a lower bound,
// named in a ::notice, and the choice still uses it; only a failed call goes
// hosted with a ::warning (v1.54 sent every short listing hosted).
func TestCIRunnerSelectionShortListIsALowerBound(t *testing.T) {
	wf := readDigestWorkflow(t)
	var script string
	for _, s := range wf.Jobs[preflightJob].Steps {
		if s.ID == runnerSelectStep {
			script = s.Run
		}
	}
	if script == "" {
		t.Fatalf("%s has no step with id: %s", preflightJob, runnerSelectStep)
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: the selector script needs it", tool)
		}
	}
	const overflow = "runner=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]\nrunner_docker=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\nrunner_integration=[\"self-hosted\",\"linux\",\"x64\",\"bigdisk-docker\"]\n"
	for _, tc := range []struct {
		name   string
		listed int
		want   string
		why    string
	}{
		// 12 of 20 listed: the listed jobs alone fill the hosted pool
		// (CI_HOSTED_SHARE 12), so the run goes self-hosted.
		{"short list that fills the hosted pool", 12, overflow, "::notice::runner selection: the hosted pool is full (12 of 12)"},
		// 5 of 20 listed: hosted use 5/12 against no self-hosted use, so
		// the run goes self-hosted on the balanced rule.
		{"short list below every limit", 5, overflow, "::notice::runner selection: use hosted 5/12, bigdisk 0/10, bigdisk-docker 0/10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, calls, log := runRunnerSelectListing(t, script, "false", tc.listed, 20)
			if out != tc.want {
				t.Errorf("%d of 20 jobs listed: output %q, want %q\n%s", tc.listed, out, tc.want, log)
			}
			if !strings.Contains(calls, "&page=2") {
				t.Errorf("%d of 20 jobs listed: the selector did not ask for the next page:\n%s", tc.listed, calls)
			}
			if strings.Contains(calls, "&page=3") {
				t.Errorf("%d of 20 jobs listed: the selector read past the empty page:\n%s", tc.listed, calls)
			}
			short := fmt.Sprintf("::notice::runner selection: the listing returned fewer entries than its total (runs/7/jobs?filter=latest: %d of 20 entries); the counts are a lower bound", tc.listed)
			for _, note := range []string{short, tc.why} {
				if !strings.Contains(log, note) {
					t.Errorf("%d of 20 jobs listed: log lacks %q:\n%s", tc.listed, note, log)
				}
			}
			if strings.Contains(log, "::warning::") {
				t.Errorf("%d of 20 jobs listed: a short listing printed a ::warning:\n%s", tc.listed, log)
			}
		})
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

// varsRef matches a repository variable reference, ${{ vars.NAME }}.
var varsRef = regexp.MustCompile(`\bvars\.[A-Za-z0-9_]+`)

// maskRegistryCase is the v1.53 case arm of ci-mask-lan.sh: every variable
// whose name ends in _REGISTRY is scanned.
const maskRegistryCase = "| *_REGISTRY |"

// TestCIMaskStepsReadNoRepositoryVariable: go-xkms deviates from template
// v1.53 (handbook 17803e85) on purpose. No Mask the LAN addresses step
// puts a repository variable in its env block, because Actions prints a
// step's env unredacted before the step runs, so an internal registry in a
// variable would be logged before any mask. An internal registry is a
// secret, never a variable (the template fix is with the Software
// Department). ci-mask-lan.sh still scans every *_REGISTRY variable.
func TestCIMaskStepsReadNoRepositoryVariable(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	var raw struct {
		Jobs map[string]yaml.Node `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse %s: %v", ciWorkflow, err)
	}
	masks := 0
	for name, node := range raw.Jobs {
		var job digestJob
		if err := node.Decode(&job); err != nil {
			t.Fatalf("decode job %s: %v", name, err)
		}
		for _, s := range job.Steps {
			if strings.TrimSpace(s.Run) != maskLANScript {
				continue
			}
			masks++
			for k, v := range s.Env {
				if varsRef.MatchString(v) {
					t.Errorf("%s mask step env %s = %q: a repository variable is printed unredacted before the mask runs", name, k, v)
				}
			}
		}
	}
	if masks == 0 {
		t.Fatalf("%s has no step running %s", ciWorkflow, maskLANScript)
	}
	if !varsRef.MatchString("${{ vars.CI_IMAGE_REGISTRY }}") {
		t.Fatal("varsRef does not match a repository variable reference")
	}
	script, err := os.ReadFile(filepath.Join(maskLANRoot, maskLANScript))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), maskRegistryCase) {
		t.Errorf("%s case pattern lacks %q: v1.53 scans every *_REGISTRY variable", maskLANScript, maskRegistryCase)
	}
}
