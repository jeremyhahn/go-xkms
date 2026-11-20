package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 999 (with 833 and 921): CI runs on GitHub's standard hosted runners
// for everything possible. Every job of hostedWorkflows runs on hostedRunner;
// a job that leaves it states a measured reason in a categorised
// `# self-hosted: <category>: <reason>` comment on its runs-on line. No forge
// fallback expression is left there: Gitea CI is retired. A pool label no
// online runner serves left Preflight queued for over half an hour (ruling
// 920); a hosted job never waits on one.
//
// ci-template v1.46 (handbook 19ce487, DS-9551), over every workflow in
// .github/workflows: a self-hosted runs-on names its reason's category,
// hardware: (a device, GPU, dedicated host), oversize: (more than 4 vCPU,
// 16 GB, ~45 GB disk or 6 hours, measured) or credential: (the Codex review
// job only). A `# self-hosted:` reason with no category is finding (e).

const (
	hostedRunner     = "ubuntu-latest"
	selfHostedWaiver = "# self-hosted: "
	workflowsDir     = ".github/workflows"
	// codexReviewFile and codexRunnerLabel name the one job that may give
	// credential: as its reason: code-review.yml's Codex review on the runner
	// that holds the reviewer token.
	codexReviewFile  = "code-review.yml"
	codexRunnerLabel = "codex"
	// forgeFallbackPrefix is the pinned review template's runs-on form, which
	// is hostedRunner on github.com; only files outside hostedWorkflows keep it.
	forgeFallbackPrefix = "${{ github.server_url == 'https://github.com' && '" + hostedRunner + "' ||"
)

var (
	// runnerWaiver is the v1.46 Runner labels (ruling 633) WAIVER regex.
	runnerWaiver = regexp.MustCompile(`#\s*self-hosted:\s*(hardware|oversize|credential)\s*:\s*\S`)
	// bareWaiver is the v1.46 BARE regex: a reason with no category.
	bareWaiver = regexp.MustCompile(`#\s*self-hosted:`)
)

// hostedWorkflows are the workflows ruling 999 puts on hostedRunner with no
// forge fallback.
var hostedWorkflows = map[string]bool{
	"ci.yml":           true,
	"coverage.yml":     true,
	"docker-tests.yml": true,
	"nightly.yml":      true,
}

// runnerExempt are the jobs v1.46 leaves out of the rule: release.yml's
// release job.
var runnerExempt = map[string]bool{"release.yml/release": true}

// runnerProblems lists each job of the workflow file that is neither on
// hostedRunner nor waived with a categorised reason.
func runnerProblems(file string, body []byte) []string {
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
		if runnerExempt[file+"/"+name] {
			continue
		}
		var runsOn *yaml.Node
		for k := 0; k+1 < len(job.Content); k += 2 {
			if job.Content[k].Value == "runs-on" {
				runsOn = job.Content[k+1]
			}
		}
		if runsOn == nil {
			problems = append(problems, "job "+name+" has no runs-on")
			continue
		}
		c := runsOn.LineComment
		m := runnerWaiver.FindStringSubmatch(c)
		switch {
		case m == nil && bareWaiver.MatchString(c):
			problems = append(problems, "job "+name+": finding (e): its `# self-hosted:` reason names no category (hardware:, oversize: or credential:; ci-template v1.46)")
			continue
		case m != nil && m[1] == "credential" && (file != codexReviewFile || runsOn.Value != codexRunnerLabel):
			problems = append(problems, "job "+name+": credential: is the Codex review job's reason only (ci-template v1.46)")
			continue
		}
		switch {
		case runsOn.Kind == yaml.ScalarNode && runsOn.Value == hostedRunner:
		case m != nil:
		case !hostedWorkflows[file] && runsOn.Kind == yaml.ScalarNode && strings.HasPrefix(runsOn.Value, forgeFallbackPrefix):
		default:
			problems = append(problems, "job "+name+" runs on "+strconv.Quote(runsOn.Value)+" without `"+selfHostedWaiver+"<hardware|oversize|credential>: <reason>` on its runs-on line; every other job runs on "+hostedRunner+" (ruling 999, ci-template v1.46)")
		}
	}
	return problems
}

func TestCIJobsRunHostedFirst(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(cachesRoot, workflowsDir))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		f := e.Name()
		if e.IsDir() || (filepath.Ext(f) != ".yml" && filepath.Ext(f) != ".yaml") {
			continue
		}
		seen[f] = true
		for _, p := range runnerProblems(f, []byte(readCacheFile(t, workflowsDir+"/"+f))) {
			t.Error(f + ": " + p)
		}
	}
	for f := range hostedWorkflows {
		if !seen[f] {
			t.Errorf("%s/%s is missing; the hosted-first gate no longer sees it", workflowsDir, f)
		}
	}
	job := func(name, runsOn string) string { return "  " + name + ":\n    runs-on: " + runsOn + "\n" }
	wf := func(jobs ...string) []byte { return []byte("jobs:\n" + strings.Join(jobs, "")) }
	good := map[string][]byte{
		"ci.yml": wf(job("preflight", hostedRunner), job("ci-images", hostedRunner),
			job("image", "[self-hosted, linux, x64, bigdisk]  "+selfHostedWaiver+"oversize: 60 GB of layers, measured"),
			job("tpm", "tpm-host  # self-hosted:hardware:a TPM 2.0 device")),
		codexReviewFile: wf(job("review-codex", codexRunnerLabel+"  "+selfHostedWaiver+"credential: the reviewer token is mounted there"),
			job("tier", "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}")),
		"release.yml": wf(job("release", "release")),
	}
	for f, body := range good {
		if p := runnerProblems(f, body); len(p) != 0 {
			t.Errorf("a hosted-first %s fails: %v", f, p)
		}
	}
	for name, bad := range map[string]struct {
		file string
		body []byte
	}{
		"a pool expression with no reason": {"ci.yml", wf(job("preflight", "${{ cond && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"bigdisk\"]') || 'ubuntu-latest' }}"))},
		"a forge fallback in ci.yml":       {"ci.yml", wf(job("coverage", "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}"))},
		"a pool label with no reason":      {"batch.yml", wf(job("bench", "batch"))},
		"an empty reason":                  {"ci.yml", wf(job("build", "bigdisk  "+strings.TrimSpace(selfHostedWaiver)))},
		"a bare reason, finding (e)":       {"qwen-review.yml", wf(job("review", "qwen  # self-hosted: x"))},
		"a category with no reason":        {"ci.yml", wf(job("build", "bigdisk  # self-hosted: oversize:"))},
		"an unknown category":              {"ci.yml", wf(job("build", "bigdisk  # self-hosted: speed: faster"))},
		"credential outside Codex":         {"ci.yml", wf(job("build", "bigdisk  # self-hosted: credential: a token"))},
		"credential on another review job": {codexReviewFile, wf(job("review-opencode", "qwen  # self-hosted: credential: a token"))},
		"credential on a hosted job":       {"ci.yml", wf(job("build", hostedRunner+"  # self-hosted: credential: a token"))},
		"a bare reason on a hosted job":    {"ci.yml", wf(job("build", hostedRunner+"  # self-hosted: x"))},
		"another comment":                  {"ci.yml", wf(job("build", "bigdisk  # pool"))},
		"a larger hosted runner":           {"ci.yml", wf(job("build", "ubuntu-latest-8-cores"))},
		"release.yml's other jobs":         {"release.yml", wf(job("publish", "release"))},
		"no runs-on":                       {"ci.yml", []byte("jobs:\n  build:\n    steps: []\n")},
	} {
		if len(runnerProblems(bad.file, bad.body)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}
