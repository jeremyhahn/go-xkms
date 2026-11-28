package buildgates

import (
	"os"
	"regexp"
	"testing"
)

// TestCITemplateV151Note pins the ci.yml half of the handbook 86 pair
// (c4de1f7d): ci.yml v1.51 has no job change (its Runner labels step is one
// go-xkms does not take). The code-review.yml half is not part of this file.
func TestCITemplateV151Note(t *testing.T) {
	const ciWorkflow = "../../.github/workflows/ci.yml"
	ci, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# ci-template: v1\.(5[1-9]|[6-9][0-9]) `),
		regexp.MustCompile(`(?m)^# v1\.51 \(handbook c4de1f7d, #86\): `),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
}

// TestCITemplateV161MainPushGroup pins ci.yml v1.61 (#2435) on v1.53's
// groups (handbook 88c10e76, ruling 1087), under v1.61's header (v1.60's
// runner selection, handbook 1ad68ab8, b18e6499 and 1bea157, ruling 1137):
// each push to main runs in its own group, main-push-{sha}, so a later main
// push no longer cancels it; any other main run shares one group per event;
// a schedule run keeps its repository group and every other ref keeps
// github.ref. CI Gate runs on !cancelled() off pull_request, so a cancelled
// main run posts a skipped gate; a pull request keeps always().
func TestCITemplateV161MainPushGroup(t *testing.T) {
	const ciWorkflow = "../../.github/workflows/ci.yml"
	ci, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# ci-template: v1\.61 runner selection on v1\.34\.1 \+ v1\.42 hermetic gate \(customized\)\n`),
		regexp.MustCompile(`(?m)^# v1\.60 \(handbook 1bea157, #123\): `),
		regexp.MustCompile(`(?m)^# v1\.59 \(handbook b18e6499, #113\): `),
		regexp.MustCompile(`(?m)^# v1\.54 \(handbook 1ad68ab8, #104; Tenant Agent ruling 1137\): `),
		regexp.MustCompile(`(?m)^# v1\.52 `),
		regexp.MustCompile(`(?m)^# v1\.53 \(handbook 17803e85\): `),
		regexp.MustCompile(`(?m)^concurrency:\n  group: \$\{\{ github\.workflow \}\}-\$\{\{ github\.event_name == 'schedule' && format\('schedule-\{0\}', github\.repository\) \|\| \(github\.event_name == 'push' && github\.ref == 'refs/heads/main'\) && format\('main-push-\{0\}', github\.sha\) \|\| github\.ref == 'refs/heads/main' && format\('main-\{0\}', github\.event_name\) \|\| github\.ref \}\}\n  cancel-in-progress: true\n`),
		regexp.MustCompile(`(?m)^    if: \$\{\{ \(startsWith\(github\.event_name, 'pull_request'\) && always\(\) \|\| !cancelled\(\)\) && \(github\.event_name != 'schedule' \|\| needs\.preflight\.outputs\.verdict != 'busy'\) \}\}\n`),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
	if n := len(regexp.MustCompile(`github\.sha`).FindAll(regexp.MustCompile(`(?m)^  group: [^\n]*`).Find(ci), -1)); n != 1 {
		t.Errorf("%s: the concurrency group names github.sha %d times, want once (v1.61: main-push-{sha} only)", ciWorkflow, n)
	}
}
