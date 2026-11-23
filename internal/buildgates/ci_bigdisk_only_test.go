package buildgates

import (
	"slices"
	"testing"
)

// bigdiskOnlyRunsOn is ci-template v1.60's runs-on for an oversize Docker
// job (DS-10367): the bigdisk-docker pool when the CI_BIGDISK_ONLY
// repository variable names the job on a same-repository run, else the
// preflight's runner_docker output on github.com. #2271's Integration died
// of "No space left on device" on ubuntu-latest.
func bigdiskOnlyRunsOn(job string) string {
	return `${{ github.server_url == 'https://github.com' && fromJSON(contains(format(' {0} ', vars.CI_BIGDISK_ONLY), ' ` + job +
		` ') && (!startsWith(github.event_name, 'pull_request') || github.event.pull_request.head.repo.full_name == github.repository) && '["self-hosted","linux","x64","bigdisk-docker"]' || needs.preflight.outputs.runner_docker) || 'bigdisk' }}`
}

func TestCIOversizeJobsTakeTheBigdiskOnlyRunsOn(t *testing.T) {
	if got := bigdiskOnlyRunsOn(devcontainerJob); got != devcontainerRunsOn {
		t.Fatalf("bigdiskOnlyRunsOn(%q) = %q, want %q", devcontainerJob, got, devcontainerRunsOn)
	}
	wf := readDigestWorkflow(t)
	for _, name := range []string{"image", "integration", "soak"} {
		j, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("ci.yml has no %s job", name)
			continue
		}
		if want := bigdiskOnlyRunsOn(name); j.RunsOn != want {
			t.Errorf("%s runs-on = %q, want %q", name, j.RunsOn, want)
		}
		if !slices.Contains(j.Needs, preflightJob) {
			t.Errorf("%s reads needs.preflight.outputs.runner_docker but does not need %s", name, preflightJob)
		}
	}
}
