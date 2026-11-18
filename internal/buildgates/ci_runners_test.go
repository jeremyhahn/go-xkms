package buildgates

import (
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rulings 833 and 921: CI runs on GitHub's hosted runners first. Every ci.yml
// job runs on hostedRunner; a job that leaves it states why with a
// `# self-hosted: <reason>` comment on its runs-on line. ci-images keeps the
// form that is hostedRunner on github.com and the forge's own labels there
// (ruling 169). A pool label no online runner serves left Preflight queued
// for over half an hour (ruling 920); a hosted job never waits on one.

const (
	hostedRunner     = "ubuntu-latest"
	selfHostedWaiver = "# self-hosted: "
)

// forgeSplitJobs keep a runs-on that is hostedRunner on github.com.
var forgeSplitJobs = map[string]string{
	"ci-images": `${{ github.server_url == 'https://github.com' && '` + hostedRunner + `' || (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'release' || 'bigdisk' }}`,
}

// runnerProblems lists each ci.yml job that is neither on hostedRunner, nor
// one of forgeSplitJobs in its form, nor waived with a reason.
func runnerProblems(body []byte) []string {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil || len(doc.Content) == 0 {
		return []string{"ci.yml does not parse"}
	}
	var jobs *yaml.Node
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "jobs" {
			jobs = root.Content[i+1]
		}
	}
	if jobs == nil || len(jobs.Content) == 0 {
		return []string{"ci.yml has no jobs"}
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
		case forgeSplitJobs[name] != "":
			if runsOn.Value != forgeSplitJobs[name] {
				problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+"; want "+strconv.Quote(forgeSplitJobs[name]))
			}
		default:
			c := strings.TrimSpace(runsOn.LineComment)
			if !strings.HasPrefix(c, selfHostedWaiver) || strings.TrimSpace(strings.TrimPrefix(c, selfHostedWaiver)) == "" {
				problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+" without `"+selfHostedWaiver+"<reason>` on its runs-on line; every other job runs on "+hostedRunner+" (rulings 833, 921)")
			}
		}
	}
	return problems
}

func TestCIJobsRunHostedFirst(t *testing.T) {
	for _, p := range runnerProblems([]byte(readCacheFile(t, ".github/workflows/ci.yml"))) {
		t.Error(p)
	}
	job := func(name, runsOn string) string { return "  " + name + ":\n    runs-on: " + runsOn + "\n" }
	wf := func(jobs ...string) []byte { return []byte("jobs:\n" + strings.Join(jobs, "")) }
	good := wf(job("preflight", hostedRunner), job("ci-images", forgeSplitJobs["ci-images"]),
		job("image", "[self-hosted, linux, x64, bigdisk]  "+selfHostedWaiver+"a stated reason"))
	if p := runnerProblems(good); len(p) != 0 {
		t.Fatalf("a hosted-first workflow fails: %v", p)
	}
	for name, bad := range map[string][]byte{
		"a pool expression with no reason": wf(job("preflight", "${{ cond && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]') || 'ubuntu-latest' }}")),
		"a pool label with no reason":      wf(job("build", "bigdisk")),
		"an empty reason":                  wf(job("build", "bigdisk  "+strings.TrimSpace(selfHostedWaiver))),
		"another comment":                  wf(job("build", "bigdisk  # pool")),
		"ci-images in another form":        wf(job("ci-images", "bigdisk")),
		"no runs-on":                       []byte("jobs:\n  build:\n    steps: []\n"),
	} {
		if len(runnerProblems(bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}
