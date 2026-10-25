package buildgates

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// integrationRun matches a step that runs integration suites and so starts the
// devcontainer stack and the suites' own compose projects.
var integrationRun = regexp.MustCompile(`\bmake integration-test\b`)

// composeRunID captures the IT_PROJECT a make invocation names its compose
// projects with (ci-template v1.25); the Makefile derives COMPOSE_RUN_ID
// from it.
var composeRunID = regexp.MustCompile(`IT_PROJECT=("[^"]*"|\S+)`)

// teardownTargets remove what an integration job starts: clean-test-containers
// the suites' projects, devcontainer-clean the devcontainer project, which
// clean-test-containers deliberately leaves to it.
var teardownTargets = []string{"clean-test-containers", "devcontainer-clean"}

// teardownProblems lists every integration job that does not tear down each
// stack it starts in an if: always() step naming the same IT_PROJECT.
func teardownProblems(wf workflow) []string {
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	for _, name := range names {
		steps := wf.Jobs[name].Steps
		start := -1
		for i, step := range steps {
			if integrationRun.MatchString(step.Run) {
				start = i
				break
			}
		}
		if start < 0 {
			continue
		}
		id := composeRunID.FindStringSubmatch(steps[start].Run)
		if id == nil {
			problems = append(problems, fmt.Sprintf("%s runs integration suites without an IT_PROJECT", name))
			continue
		}
		for _, target := range teardownTargets {
			want := "make " + target + " " + id[0]
			found := false
			for _, step := range steps[start+1:] {
				if strings.Contains(step.If, "always()") && strings.Contains(step.Run, want) {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, fmt.Sprintf("%s has no if: always() step running %q", name, want))
			}
		}
	}
	return problems
}

func TestCIIntegrationJobsTearDownTheirStacks(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range teardownProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

// teardownFixture is a minimal integration job that tears down both stacks.
const teardownFixture = `
jobs:
  unit:
    steps:
      - run: make test
  integration:
    steps:
      - run: make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT" IT_IMAGE="$IT_IMAGE"
      - if: always()
        run: make clean-test-containers IT_PROJECT="$IT_PROJECT"
      - if: always()
        run: make devcontainer-clean IT_PROJECT="$IT_PROJECT"
`

func TestCITeardownCatchEachMissingTeardown(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"none", "", "", ""},
		{"devcontainer not torn down", "make devcontainer-clean", "make devcontainer-down", `running "make devcontainer-clean`},
		{"suites not torn down", "make clean-test-containers", "true", `running "make clean-test-containers`},
		{"teardown skipped on failure", "      - if: always()\n        run: make devcontainer-clean", "      - run: make devcontainer-clean", `running "make devcontainer-clean`},
		{"teardown under another run id", `devcontainer-clean IT_PROJECT="$IT_PROJECT"`, `devcontainer-clean IT_PROJECT=go-xkms-local`, `running "make devcontainer-clean`},
		{"teardown names COMPOSE_RUN_ID instead", `devcontainer-clean IT_PROJECT="$IT_PROJECT"`, `devcontainer-clean COMPOSE_RUN_ID="$IT_RUN_ID"`, `running "make devcontainer-clean`},
		{"suites without a run id", `make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT"`, "make integration-test", "without an IT_PROJECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := teardownFixture
			if tc.old != "" {
				if !strings.Contains(src, tc.old) {
					t.Fatalf("fixture has no %q to replace", tc.old)
				}
				src = strings.Replace(src, tc.old, tc.new, 1)
			}
			problems := teardownProblems(parseWorkflow(t, []byte(src)))
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("valid fixture reported %q", problems)
				}
				return
			}
			for _, p := range problems {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
		})
	}
}
