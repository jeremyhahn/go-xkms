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
		regexp.MustCompile(`\A# code-review-template: v5\.12\.7 `),
		regexp.MustCompile(`(?m)^      - name: Re-run a newer twin's failed gate on this head$`),
		regexp.MustCompile(`(?m)^    name: Code Review \(codex\)\n(?:    .*\n|\s*\n)*?      actions: write\n`),
	} {
		if !want.Match(data) {
			t.Errorf("%s does not match %s", codeReviewWorkflow, want)
		}
	}
}
