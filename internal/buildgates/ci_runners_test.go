package buildgates

import (
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 999 (with 833 and 921): CI runs on GitHub's standard hosted runners
// for everything possible. Every job of hostedWorkflows runs on hostedRunner;
// a job that leaves it states a measured reason (the hardware, or the hosted
// limit it exceeds: disk, memory, the 6-hour cap) in a
// `# self-hosted: <reason>` comment on its runs-on line. No forge fallback
// expression is left: Gitea CI is retired. A pool label no online runner
// serves left Preflight queued for over half an hour (ruling 920); a hosted
// job never waits on one.

const (
	hostedRunner     = "ubuntu-latest"
	selfHostedWaiver = "# self-hosted: "
)

// hostedWorkflows are the workflows ruling 999 puts on hostedRunner.
// code-review.yml and qwen-review.yml keep the pinned review template and the
// GPU review host; release.yml is out of the ruling's scope.
var hostedWorkflows = []string{
	".github/workflows/ci.yml",
	".github/workflows/coverage.yml",
	".github/workflows/docker-tests.yml",
	".github/workflows/nightly.yml",
}

// runnerProblems lists each job that is neither on hostedRunner nor waived
// with a reason.
func runnerProblems(body []byte) []string {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return []string{"workflow does not parse"}
	}
	var jobs *yaml.Node
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "jobs" {
			jobs = root.Content[i+1]
		}
	}
	if jobs == nil || len(jobs.Content) == 0 {
		return []string{"workflow has no jobs"}
	}
	var problems []string
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		var runsOn *yaml.Node
		for k := 0; k+1 < len(job.Content); k += 2 {
			if job.Content[k].Value == "runs-on" {
				runsOn = job.Content[k+1]
			}
		}
		switch {
		case runsOn == nil:
			problems = append(problems, "job "+name+" has no runs-on")
		case runsOn.Kind == yaml.ScalarNode && runsOn.Value == hostedRunner:
		default:
			c := strings.TrimSpace(runsOn.LineComment)
			if !strings.HasPrefix(c, selfHostedWaiver) || strings.TrimSpace(strings.TrimPrefix(c, selfHostedWaiver)) == "" {
				problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+" without `"+selfHostedWaiver+"<reason>` on its runs-on line; every other job runs on "+hostedRunner+" (ruling 999)")
			}
		}
	}
	return problems
}

func TestCIJobsRunHostedFirst(t *testing.T) {
	for _, f := range hostedWorkflows {
		for _, p := range runnerProblems([]byte(readCacheFile(t, f))) {
			t.Error(f + ": " + p)
		}
	}
	job := func(name, runsOn string) string { return "  " + name + ":\n    runs-on: " + runsOn + "\n" }
	wf := func(jobs ...string) []byte { return []byte("jobs:\n" + strings.Join(jobs, "")) }
	good := wf(job("preflight", hostedRunner), job("ci-images", hostedRunner),
		job("image", "[self-hosted, linux, x64, bigdisk]  "+selfHostedWaiver+"a stated reason"))
	if p := runnerProblems(good); len(p) != 0 {
		t.Fatalf("a hosted-first workflow fails: %v", p)
	}
	for name, bad := range map[string][]byte{
		"a pool expression with no reason": wf(job("preflight", "${{ cond && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]') || 'ubuntu-latest' }}")),
		"a forge fallback expression":      wf(job("coverage", "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}")),
		"a pool label with no reason":      wf(job("build", "bigdisk")),
		"an empty reason":                  wf(job("build", "bigdisk  "+strings.TrimSpace(selfHostedWaiver))),
		"another comment":                  wf(job("build", "bigdisk  # pool")),
		"a larger hosted runner":           wf(job("build", "ubuntu-latest-8-cores")),
		"no runs-on":                       []byte("jobs:\n  build:\n    steps: []\n"),
	} {
		if len(runnerProblems(bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}
