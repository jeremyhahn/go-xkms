package buildgates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Codex P1 on #2296 (ci.yml): on a same-repo pull request ci-images pushes
// the toolchain image to the in-network pool registry alone, while the
// coverage and coverage-threshold jobs run on ubuntu-latest on GitHub
// (ruling 999), with no network path to it. A hosted consumer that cannot
// pull the pool image builds the toolchain on its own runner instead of
// failing before the tests; a pool consumer still never builds its own.

const poolUnreachableRef = "go-xkms-ci-toolchain@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// poolUnreachable makes the stub docker fail every pull, the way a hosted
// runner with no route to the pool registry does.
var poolUnreachable = []string{"CI_POOL=true", "CI_IMAGE_REGISTRY=reg.example:5000/ci", "STUB_PULL_FAIL=1"}

func TestCIRegistryPoolUseHostedFallsBackToALocalBuild(t *testing.T) {
	stdout, stderr, calls, err := runPoolRegistry(t,
		append([]string{"RUNNER_ENVIRONMENT=github-hosted"}, poolUnreachable...), "use", "toolchain", poolUnreachableRef)
	if err != nil {
		t.Fatalf("a hosted consumer that cannot reach the pool registry failed: %v\n%s", err, stderr)
	}
	if n := strings.Count(calls, "docker pull"); n != 1 {
		t.Errorf("a hosted consumer tried the unreachable pool registry %d times, want once:\n%s", n, calls)
	}
	if n := strings.Count(calls, "docker-build-toolchain"); n != 1 {
		t.Errorf("a hosted consumer did not build the toolchain image exactly once:\n%s", calls)
	}
	if !strings.Contains(stdout, "TOOLCHAIN_IMAGE=sha256:"+strings.Repeat("b", 64)) {
		t.Errorf("use did not export the locally built image: %s", stdout)
	}
	if strings.Contains(stdout+stderr, "reg.example") {
		t.Errorf("use printed the pool registry:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

func TestCIRegistryPoolUseSelfHostedNeverBuilds(t *testing.T) {
	_, stderr, calls, err := runPoolRegistry(t,
		append([]string{"RUNNER_ENVIRONMENT=self-hosted"}, poolUnreachable...), "use", "toolchain", poolUnreachableRef)
	if err == nil {
		t.Errorf("a pool consumer that cannot pull the pool image succeeded; it must fail")
	}
	if strings.Contains(calls, "docker-build-toolchain") {
		t.Errorf("a pool consumer built the toolchain image on its own runner:\n%s", calls)
	}
	if strings.Contains(stderr, "reg.example") {
		t.Errorf("use printed the pool registry: %s", stderr)
	}
}

// TestCICoverageJobsTakeTheImageThroughTheFallback holds the two hosted
// coverage jobs to ubuntu-latest on GitHub and to scripts/ci-registry.sh use,
// where the fallback lives, with no image reference of their own.
func TestCICoverageJobsTakeTheImageThroughTheFallback(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(maskLANRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			RunsOn string `yaml:"runs-on"`
			Steps  []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &wf); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"coverage", "coverage-threshold"} {
		job, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("ci.yml has no %s job", name)
			continue
		}
		if !strings.Contains(job.RunsOn, "github.server_url == 'https://github.com' && 'ubuntu-latest'") {
			t.Errorf("%s does not run on ubuntu-latest on GitHub (ruling 999): %s", name, job.RunsOn)
		}
		took := false
		for _, s := range job.Steps {
			if strings.HasPrefix(strings.TrimSpace(s.Run), "scripts/ci-registry.sh use toolchain ") {
				took = true
				if s.Env["TOOLCHAIN_REF"] != "${{ needs.ci-images.outputs.toolchain_ref }}" {
					t.Errorf("%s takes a toolchain reference other than ci-images' output: %q", name, s.Env["TOOLCHAIN_REF"])
				}
			}
		}
		if !took {
			t.Errorf("%s does not take its toolchain image through scripts/ci-registry.sh use", name)
		}
	}
}
