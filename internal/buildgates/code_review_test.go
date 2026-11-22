package buildgates

import (
	"os"
	"regexp"
	"testing"
)

// codeReviewWorkflow is the handbook's code-review template, copied verbatim.
const codeReviewWorkflow = "../../.github/workflows/code-review.yml"

// TestCodeReviewGateRerunsNewerTwin pins code-review template v5.12.7
// (Codex's P1 on #2327): GitHub reads the required context from the newest
// check suite, so a passing gate re-runs a newer twin's red gate, which needs
// `actions: write` on the gate job. At v5.12.11 the gate's name is the
// draft-aware expression v5.12.9 brought.
func TestCodeReviewGateRerunsNewerTwin(t *testing.T) {
	data, err := os.ReadFile(codeReviewWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", codeReviewWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# code-review-template: v5\.12\.11 `),
		regexp.MustCompile(`(?m)^      - name: Re-run a newer twin's failed gate on this head$`),
		// v5.12.9+: the gate's name is an expression, `Code Review (codex)`
		// unless the pull request is a draft.
		regexp.MustCompile(`(?m)^    name: >-\n      \$\{\{[^\n]*\n      && 'Code Review \(codex\)' [^\n]*\n(?:    .*\n|\s*\n)*?      actions: write\n`),
	} {
		if !want.Match(data) {
			t.Errorf("%s does not match %s", codeReviewWorkflow, want)
		}
	}
}

// TestCodeReviewTemplateV5128 pins the code-review half of the handbook 86
// pair (c4de1f7d): template v5.12.8 (a new head cancels the PR's older-head
// runs in the `supersede` job), now at v5.12.11 (handbook PR 94, 11933b6f).
// The ci.yml half is TestCITemplateV151Note.
func TestCodeReviewTemplateV5128(t *testing.T) {
	cr, err := os.ReadFile(codeReviewWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", codeReviewWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# code-review-template: v5\.12\.11 `),
		regexp.MustCompile(`(?m)^  supersede:\n    name: Cancel superseded runs$`),
		regexp.MustCompile(`(?m)^      - name: Cancel this PR's runs on an older head$`),
	} {
		if !want.Match(cr) {
			t.Errorf("%s does not match %s", codeReviewWorkflow, want)
		}
	}
}

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
