package buildgates

import (
	"os"
	"strings"
	"testing"
)

// qwenWorkflow is qwen-review.yml, relative to this package's directory. It
// runs on pull_request_target on the self-hosted qwen runner with the
// repository's secrets, so a fork head must never reach it (DS-8068).
const qwenWorkflow = "../../.github/workflows/qwen-review.yml"

const (
	qwenLabelIf    = "contains(github.event.pull_request.labels.*.name,'agent:opencode')"
	qwenSameRepoIf = "github.event.pull_request.head.repo.full_name==github.repository"
)

// squeeze drops every whitespace character, so a condition compares the same
// however it is spaced or folded.
func squeeze(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// qwenIfProblems names each job whose `if:` does not require both the label
// and a head in this repository, joined by && with no || to bypass either.
func qwenIfProblems(wf workflow) []string {
	var problems []string
	for name, j := range wf.Jobs {
		c := squeeze(condition(j.If))
		switch {
		case !strings.Contains(c, qwenLabelIf):
			problems = append(problems, name+": the if: does not check the agent:opencode label")
		case !strings.Contains(c, qwenSameRepoIf):
			problems = append(problems, name+": the if: does not require head.repo.full_name == github.repository")
		case strings.Contains(c, "||"):
			problems = append(problems, name+": the if: has an || that can bypass the head-repo check")
		}
	}
	return problems
}

func TestQwenReviewRunsOnlyForSameRepoHeads(t *testing.T) {
	data, err := os.ReadFile(qwenWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", qwenWorkflow, err)
	}
	wf := parseWorkflow(t, data)
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s parsed to no jobs; the parser is not reading it", qwenWorkflow)
	}
	for _, p := range qwenIfProblems(wf) {
		t.Errorf("%s: %s", qwenWorkflow, p)
	}
}

func TestQwenReviewIfCatchesEachMissingCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		cond string
		bad  bool
	}{
		"both":           {cond: "contains(github.event.pull_request.labels.*.name, 'agent:opencode') && github.event.pull_request.head.repo.full_name == github.repository"},
		"both, folded":   {cond: "${{ contains(github.event.pull_request.labels.*.name, 'agent:opencode')\n  && github.event.pull_request.head.repo.full_name   ==   github.repository }}"},
		"label only":     {cond: "contains(github.event.pull_request.labels.*.name, 'agent:opencode')", bad: true},
		"head repo only": {cond: "github.event.pull_request.head.repo.full_name == github.repository", bad: true},
		"or":             {cond: "contains(github.event.pull_request.labels.*.name, 'agent:opencode') || github.event.pull_request.head.repo.full_name == github.repository", bad: true},
		"none":           {bad: true},
	} {
		wf := workflow{Jobs: map[string]job{"review": {If: tc.cond}}}
		if got := len(qwenIfProblems(wf)) > 0; got != tc.bad {
			t.Errorf("%s: problems reported = %v, want %v", name, got, tc.bad)
		}
	}
}
