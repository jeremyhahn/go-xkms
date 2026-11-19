package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// toolchainImageProblems names each step that uses $TOOLCHAIN_IMAGE in a job
// whose only step setting it (scripts/ci-registry.sh use toolchain) runs on
// hosted runners alone, when the using step lacks that same hosted-only
// condition. On the self-hosted pools the setter is skipped, TOOLCHAIN_IMAGE
// is unset and the container helper fails before the native steps run
// (Codex P1 on #2020: the standalone pkg/fido2/authenticator race step).
func toolchainImageProblems(file string, data []byte) []string {
	var wf poolWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return []string{fmt.Sprintf("%s: parse: %v", file, err)}
	}
	var out []string
	for name, job := range wf.Jobs {
		setters, hostedSetters := 0, 0
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "ci-registry.sh use toolchain") {
				setters++
				if poolConjunct(s.If, poolHostedTerm) {
					hostedSetters++
				}
			}
		}
		if setters == 0 || hostedSetters != setters {
			continue
		}
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "ci-registry.sh use toolchain") {
				continue
			}
			if strings.Contains(s.Run, "$TOOLCHAIN_IMAGE") && !poolConjunct(s.If, poolHostedTerm) {
				out = append(out, fmt.Sprintf("%s: job %s step %q uses $TOOLCHAIN_IMAGE, set only on hosted runners, without the hosted-only condition", file, name, s.Name))
			}
		}
	}
	return out
}

func TestCIToolchainImageStepsMatchTheirSetter(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range toolchainImageProblems(filepath.Base(f), data) {
			t.Error(p)
		}
	}
}

func TestToolchainImageProblems(t *testing.T) {
	const wf = `
jobs:
  race:
    steps:
      - name: Take the toolchain image
        if: runner.environment == 'github-hosted'
        run: scripts/ci-registry.sh use toolchain "$REF" >> "$GITHUB_ENV"
      - name: gated
        if: runner.environment == 'github-hosted'
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" 'true'
      - name: ungated
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" 'true'
  pool:
    steps:
      - name: Take the toolchain image
        run: scripts/ci-registry.sh use toolchain "$REF" >> "$GITHUB_ENV"
      - name: ungated
        run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" 'true'
`
	got := toolchainImageProblems("wf.yml", []byte(wf))
	if len(got) != 1 || !strings.Contains(got[0], `job race step "ungated"`) {
		t.Fatalf("problems = %q, want one for race/ungated", got)
	}
}
