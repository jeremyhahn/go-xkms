package buildgates

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// imageJob is the Devcontainer image job (CA m2536 item 2).
const imageJob = "image"

type stepBoundWorkflow struct {
	Jobs map[string]struct {
		TimeoutMinutes int `yaml:"timeout-minutes"`
		Steps          []struct {
			Name           string `yaml:"name"`
			Run            string `yaml:"run"`
			TimeoutMinutes int    `yaml:"timeout-minutes"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// stepBoundProblems lists each step of the image job that runs in the
// toolchain image without its own timeout-minutes below the job's bound.
// Without one, a hung step holds the job until the job bound ends it (main
// run 42965847875 sat 2 h in make coverage).
func stepBoundProblems(data []byte) ([]string, error) {
	var wf stepBoundWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}
	j, ok := wf.Jobs[imageJob]
	if !ok {
		return []string{"jobs." + imageJob + " is missing"}, nil
	}
	var problems []string
	sawCoverage := false
	for _, s := range j.Steps {
		if !strings.Contains(s.Run, "scripts/in-toolchain-image.sh") {
			continue
		}
		if strings.Contains(s.Run, "make coverage") {
			sawCoverage = true
		}
		switch {
		case s.TimeoutMinutes <= 0:
			problems = append(problems, fmt.Sprintf("jobs.%s step %q has no timeout-minutes", imageJob, s.Name))
		case s.TimeoutMinutes >= j.TimeoutMinutes:
			problems = append(problems, fmt.Sprintf("jobs.%s step %q timeout-minutes %d is not below the job's %d", imageJob, s.Name, s.TimeoutMinutes, j.TimeoutMinutes))
		}
	}
	if !sawCoverage {
		problems = append(problems, "jobs."+imageJob+" has no make coverage step")
	}
	return problems, nil
}

func TestCIImageStepsAreBounded(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	problems, err := stepBoundProblems(data)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflow, err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestCIImageStepBoundsCatchEachMissingBound(t *testing.T) {
	cases := map[string]string{
		"unbounded": `jobs:
  image:
    timeout-minutes: 240
    steps:
      - name: make coverage
        run: scripts/in-toolchain-image.sh img "make coverage"
`,
		"not below the job": `jobs:
  image:
    timeout-minutes: 240
    steps:
      - name: make coverage
        timeout-minutes: 240
        run: scripts/in-toolchain-image.sh img "make coverage"
`,
		"no coverage step": `jobs:
  image:
    timeout-minutes: 240
    steps:
      - name: make lint
        timeout-minutes: 20
        run: scripts/in-toolchain-image.sh img "make lint"
`,
	}
	for name, doc := range cases {
		problems, err := stepBoundProblems([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(problems) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
	ok := `jobs:
  image:
    timeout-minutes: 240
    steps:
      - name: make coverage
        timeout-minutes: 60
        run: scripts/in-toolchain-image.sh img "make coverage"
`
	if problems, err := stepBoundProblems([]byte(ok)); err != nil || len(problems) != 0 {
		t.Errorf("bounded fixture: %v %v", problems, err)
	}
}
