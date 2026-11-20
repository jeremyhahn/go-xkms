package buildgates

import (
	"regexp"
	"strings"
	"testing"
)

// #2307 (DS-9567): an apt-get update hung on the apt cache's 503 race, and
// BuildKit merged a second run's identical step into the hung one, so both
// stalled until the job bound. TestDockerfileAptGetRunsUnderTimeout bounds
// every Dockerfile apt-get; these gates bound every step of the Integration
// job, whose image build and suite otherwise wait out the 180-minute job.

const integrationJob = "integration"

var stepTimeout = regexp.MustCompile(`(?m)^\s+timeout-minutes: [1-9][0-9]*\s*(#.*)?$`)

// jobSteps splits a job block into its steps (each "      - " item), with
// comment lines dropped.
func jobSteps(job string) []string {
	var out []string
	var cur []string
	in := false
	for _, line := range strings.Split(job, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(line, "      - ") {
			if len(cur) > 0 {
				out = append(out, strings.Join(cur, "\n"))
			}
			cur, in = []string{line}, true
			continue
		}
		if in {
			cur = append(cur, line)
		}
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, "\n"))
	}
	return out
}

var stepName = regexp.MustCompile(`(?m)^      (?:- |  )name: (.*)$`)

func stepTitle(step string) string {
	if m := stepName.FindStringSubmatch(step); m != nil {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(strings.SplitN(step, "\n", 2)[0])
}

// untimedSteps names each step of the job without its own timeout-minutes.
func untimedSteps(job string) []string {
	var out []string
	for _, s := range jobSteps(job) {
		if !stepTimeout.MatchString(s) {
			out = append(out, stepTitle(s))
		}
	}
	return out
}

func TestIntegrationStepsCarryTimeoutMinutes(t *testing.T) {
	job := jobBlock(readWorkflow(t), integrationJob)
	if job == "" {
		t.Fatalf("no %q job in %s", integrationJob, ciWorkflowFile)
	}
	if n := len(jobSteps(job)); n < 8 {
		t.Fatalf("found %d steps in the %q job; the split missed some", n, integrationJob)
	}
	for _, s := range untimedSteps(job) {
		t.Errorf("Integration step %q has no timeout-minutes", s)
	}
}

func TestStepTimeoutCheckCatchesARegression(t *testing.T) {
	job := "  integration:\n    steps:\n" +
		"      - uses: actions/checkout@v6\n        timeout-minutes: 10\n" +
		"      # timeout-minutes: 5 in a comment does not count\n" +
		"      - name: make integration-test\n        run: make integration-test\n" +
		"        # timeout-minutes: 45\n"
	got := untimedSteps(job)
	if len(got) != 1 || got[0] != "make integration-test" {
		t.Errorf("untimedSteps = %q, want the one untimed step", got)
	}
}
