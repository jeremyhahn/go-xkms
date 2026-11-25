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
		regexp.MustCompile(`\A# ci-template: v1\.5[1-9] `),
		regexp.MustCompile(`(?m)^# v1\.51 \(handbook c4de1f7d, #86\): `),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
}

// TestCITemplateV153MainEventGroup pins ci.yml v1.53 (handbook 88c10e76,
// ruling 1087), under v1.54's header (its runner selection, handbook
// 1ad68ab8, ruling 1137): main runs share one concurrency group per event, so a newer
// main push cancels the older run; a schedule run keeps its repository group
// and every other ref keeps github.ref. CI Gate runs on !cancelled() off
// pull_request, so a cancelled main run posts a skipped gate; a pull request
// keeps always().
func TestCITemplateV153MainEventGroup(t *testing.T) {
	const ciWorkflow = "../../.github/workflows/ci.yml"
	ci, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# ci-template: v1\.54 runner selection on v1\.34\.1 \+ v1\.42 hermetic gate \(customized\)\n`),
		regexp.MustCompile(`(?m)^# v1\.54 \(handbook 1ad68ab8, #104; Tenant Agent ruling 1137\): `),
		regexp.MustCompile(`(?m)^# v1\.52 `),
		regexp.MustCompile(`(?m)^# v1\.53 \(handbook 17803e85\): `),
		regexp.MustCompile(`(?m)^concurrency:\n  group: \$\{\{ github\.workflow \}\}-\$\{\{ github\.event_name == 'schedule' && format\('schedule-\{0\}', github\.repository\) \|\| github\.ref == 'refs/heads/main' && format\('main-\{0\}', github\.event_name\) \|\| github\.ref \}\}\n  cancel-in-progress: true\n`),
		regexp.MustCompile(`(?m)^    if: \$\{\{ \(startsWith\(github\.event_name, 'pull_request'\) && always\(\) \|\| !cancelled\(\)\) && \(github\.event_name != 'schedule' \|\| needs\.preflight\.outputs\.verdict != 'busy'\) \}\}\n`),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
	if regexp.MustCompile(`(?m)^  group: [^\n]*github\.sha`).Match(ci) {
		t.Errorf("%s: the concurrency group still names github.sha (v1.53: main-{event})", ciWorkflow)
	}
}

// TestCodeReviewNoSupersedeCancel asserts code-review.yml has no run-cancel step, no actions: write and no preflight runner variable.
func TestCodeReviewNoSupersedeCancel(t *testing.T) {
	const crWorkflow = "../../.github/workflows/code-review.yml"
	cr, err := os.ReadFile(crWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", crWorkflow, err)
	}
	for _, absent := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*actions:\s*write\b`),
		regexp.MustCompile(`actions/runs/[^\s"']*/cancel`),
		regexp.MustCompile(`(?mi)^\s*-?\s*name:.*(supersede|cancel)`),
		regexp.MustCompile(`vars\.CI_PREFLIGHT_RUNS_ON`),
	} {
		if loc := absent.FindIndex(cr); loc != nil {
			t.Errorf("%s matches %s at byte %d", crWorkflow, absent, loc[0])
		}
	}
}
