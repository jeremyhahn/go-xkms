package buildgates

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Rulings 833 and 921: CI runs on GitHub's hosted runners first. Every job of
// every workflow runs on hostedRunner, or on forgeSplit, which is hostedRunner
// on github.com and a forge label elsewhere; a job that leaves both states why
// with `# self-hosted: <reason>` in its runs-on line's comment (after another
// waiver, as the code-review template's review runners put it). ci-images
// keeps its own form, hostedRunner on github.com and the forge's release and
// bigdisk labels there (ruling 169). A pool label no online runner serves left Preflight queued
// for over half an hour (ruling 920); a hosted job never waits on one.

const (
	hostedRunner     = "ubuntu-latest"
	selfHostedWaiver = "# self-hosted: "
)

// forgeSplit is a runs-on that is hostedRunner on github.com and a forge
// label (group 1) on the forge.
var forgeSplit = regexp.MustCompile(`^\$\{\{ github\.server_url == 'https://github\.com' && '` + hostedRunner + `' \|\| '([a-z0-9-]+)' \}\}$`)

// selfHostedReason finds the waiver and its reason in a line comment.
var selfHostedReason = regexp.MustCompile(`(^|\s)# self-hosted: *\S`)

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
		case runsOn.Kind == yaml.ScalarNode && (runsOn.Value == hostedRunner || forgeSplit.MatchString(runsOn.Value)):
		case forgeSplitJobs[name] != "":
			if runsOn.Value != forgeSplitJobs[name] {
				problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+"; want "+strconv.Quote(forgeSplitJobs[name]))
			}
		default:
			c := strings.TrimSpace(runsOn.LineComment)
			if !selfHostedReason.MatchString(c) {
				problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+" without `"+selfHostedWaiver+"<reason>` on its runs-on line; every other job runs on "+hostedRunner+" (rulings 833, 921)")
			}
		}
	}
	return problems
}

func TestCIJobsRunHostedFirst(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(cachesRoot, ".github", "workflows", "*.yml"))
	if err != nil || len(files) < 5 {
		t.Fatalf("found %d workflow files (%v); want every one", len(files), err)
	}
	for _, f := range files {
		rel, _ := filepath.Rel(cachesRoot, f)
		for _, p := range runnerProblems([]byte(readCacheFile(t, filepath.ToSlash(rel)))) {
			t.Error(filepath.Base(f) + ": " + p)
		}
	}
	job := func(name, runsOn string) string { return "  " + name + ":\n    runs-on: " + runsOn + "\n" }
	wf := func(jobs ...string) []byte { return []byte("jobs:\n" + strings.Join(jobs, "")) }
	good := wf(job("preflight", hostedRunner), job("ci-images", forgeSplitJobs["ci-images"]),
		job("image", "[self-hosted, linux, x64, bigdisk]  "+selfHostedWaiver+"a stated reason"),
		job("scope", "${{ github.server_url == 'https://github.com' && '"+hostedRunner+"' || 'bigdisk' }}"),
		job("review", "codex  # lab-string-ok: a label waiver "+selfHostedWaiver+"a stated reason"))
	if p := runnerProblems(good); len(p) != 0 {
		t.Fatalf("a hosted-first workflow fails: %v", p)
	}
	for name, bad := range map[string][]byte{
		"a pool expression with no reason":       wf(job("preflight", "${{ cond && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]') || 'ubuntu-latest' }}")),
		"a pool label with no reason":            wf(job("build", "bigdisk")),
		"an empty reason":                        wf(job("build", "bigdisk  "+strings.TrimSpace(selfHostedWaiver))),
		"another comment":                        wf(job("build", "bigdisk  # pool")),
		"ci-images in another form":              wf(job("ci-images", "bigdisk")),
		"no runs-on":                             []byte("jobs:\n  build:\n    steps: []\n"),
		"a review runner with no reason":         wf(job("review", "codex  # lab-string-ok: a label waiver")),
		"a split that is the pool on github.com": wf(job("scope", "${{ github.server_url == 'https://github.com' && 'bigdisk' || 'ubuntu-latest' }}")),
	} {
		if len(runnerProblems(bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}
