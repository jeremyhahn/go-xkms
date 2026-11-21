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
// `actions: write` on the gate job.
func TestCodeReviewGateRerunsNewerTwin(t *testing.T) {
	data, err := os.ReadFile(codeReviewWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", codeReviewWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# code-review-template: v5\.12\.[78] `),
		regexp.MustCompile(`(?m)^      - name: Re-run a newer twin's failed gate on this head$`),
		regexp.MustCompile(`(?m)^    name: Code Review \(codex\)\n(?:    .*\n|\s*\n)*?      actions: write\n`),
	} {
		if !want.Match(data) {
			t.Errorf("%s does not match %s", codeReviewWorkflow, want)
		}
	}
}

// TestCodeReviewTemplateV5128 pins the handbook 86 pair (c4de1f7d): the
// code-review template v5.12.8 (a new head cancels the PR's older-head runs
// in the `supersede` job) and ci.yml v1.51 (no job change: its Runner labels
// step is one go-xkms does not take).
func TestCodeReviewTemplateV5128(t *testing.T) {
	cr, err := os.ReadFile(codeReviewWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", codeReviewWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# code-review-template: v5\.12\.8 `),
		regexp.MustCompile(`(?m)^  supersede:\n    name: Cancel superseded runs$`),
		regexp.MustCompile(`(?m)^      - name: Cancel this PR's runs on an older head$`),
	} {
		if !want.Match(cr) {
			t.Errorf("%s does not match %s", codeReviewWorkflow, want)
		}
	}
	const ciWorkflow = "../../.github/workflows/ci.yml"
	ci, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# ci-template: v1\.51 `),
		regexp.MustCompile(`(?m)^# v1\.51 \(handbook c4de1f7d, #86\): `),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
}
