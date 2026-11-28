package buildgates

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestReleaseAssetsAPIRoot pins the forge API root release.yml hands to
// scripts/release-assets.sh. The script classifies RELEASE_API by its form:
// GitHub's REST root is github.api_url (https://api.github.com), while
// github.server_url + /api/v1 is Gitea's and reads as Gitea on GitHub too.
// Every job that runs release-assets.sh must therefore set RELEASE_API to
// github.api_url, and no RELEASE_API line may name another root.
func TestReleaseAssetsAPIRoot(t *testing.T) {
	const releaseWorkflow = "../../.github/workflows/release.yml"
	raw, err := os.ReadFile(releaseWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", releaseWorkflow, err)
	}
	const want = "RELEASE_API: ${{ github.api_url }}"
	for _, m := range regexp.MustCompile(`(?m)^\s*RELEASE_API:.*$`).FindAll(raw, -1) {
		if got := strings.TrimSpace(string(m)); got != want {
			t.Errorf("%s: %q, want %q", releaseWorkflow, got, want)
		}
	}

	jobsAt := regexp.MustCompile(`(?m)^jobs:\n`).FindIndex(raw)
	if jobsAt == nil {
		t.Fatalf("%s: no jobs: key", releaseWorkflow)
	}
	jobs := raw[jobsAt[1]:]
	starts := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\s*$`).FindAllIndex(jobs, -1)
	call := regexp.MustCompile(`scripts/release-assets\.sh (upload|download|verify|verify-complete)\b`)
	callers := 0
	for i, s := range starts {
		end := len(jobs)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		job := string(jobs[s[0]:end])
		if !call.MatchString(job) {
			continue
		}
		callers++
		if !strings.Contains(job, want) {
			name := strings.TrimSpace(strings.SplitN(job, "\n", 2)[0])
			t.Errorf("%s: job %s runs release-assets.sh without %q", releaseWorkflow, name, want)
		}
	}
	if callers == 0 {
		t.Errorf("%s: no job runs scripts/release-assets.sh", releaseWorkflow)
	}
}
