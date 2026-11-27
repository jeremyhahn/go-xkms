package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Codex P1 on #2296 (ci.yml): the pool registry is the CI_IMAGE_REGISTRY
// secret. Actions masks a secret's complete value only, so a Docker error
// that names just the registry host, or the private address it resolved to,
// printed the internal address in a public log. Every job that hands the
// secret to a step therefore runs scripts/ci-mask-lan.sh with the secret in
// that step's env, before the step that uses it, and the script masks the
// secret registry's host forms and resolved addresses whatever its name.

// maskRegistrySecret is the expression a step takes the pool registry from.
const maskRegistrySecret = "${{ secrets.CI_IMAGE_REGISTRY }}"

// maskRegistryProblems lists each job that passes CI_IMAGE_REGISTRY to a
// step without first running the masker with the secret in its env.
func maskRegistryProblems(body []byte) []string {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	for name, job := range wf.Jobs {
		mask, use := -1, -1
		for i, s := range job.Steps {
			if strings.TrimSpace(s.Run) == maskLANScript {
				if mask < 0 && strings.TrimSpace(s.Env["CI_IMAGE_REGISTRY"]) == maskRegistrySecret {
					mask = i
				}
				continue
			}
			if use < 0 {
				for _, v := range s.Env {
					if strings.Contains(v, "secrets.CI_IMAGE_REGISTRY") {
						use = i
						break
					}
				}
			}
		}
		switch {
		case use < 0:
		case mask < 0:
			problems = append(problems, "job "+name+" uses the CI_IMAGE_REGISTRY secret but never runs "+maskLANScript+" with it in the step env")
		case use < mask:
			problems = append(problems, "job "+name+" runs "+strings.TrimSpace(job.Steps[use].Name)+" before "+maskLANScript+" masks the registry")
		}
	}
	slices.Sort(problems)
	return problems
}

func TestCIRegistryConsumersMaskTheRegistry(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(maskLANRoot, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range maskRegistryProblems(body) {
		t.Error(p)
	}

	const job = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
	const masked = "      - run: " + maskLANScript + "\n        env:\n          CI_IMAGE_REGISTRY: " + maskRegistrySecret + "\n"
	const take = "      - name: Take the image\n        env:\n          CI_IMAGE_REGISTRY: " + maskRegistrySecret + "\n        run: scripts/ci-registry.sh use toolchain x\n"
	if p := maskRegistryProblems([]byte(job + masked + take)); len(p) != 0 {
		t.Fatalf("a consumer that masks the registry first fails: %v", p)
	}
	for name, body := range map[string]string{
		"the masker without the secret": job + "      - run: " + maskLANScript + "\n" + take,
		"no masker":                     job + take,
		"the masker after the consumer": job + take + masked,
	} {
		if len(maskRegistryProblems([]byte(body))) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	if p := maskRegistryProblems([]byte(job + "      - run: make build\n")); len(p) != 0 {
		t.Fatalf("a job without the registry was held to the rule: %v", p)
	}
}

// TestCIMaskLANScriptSecretRegistry runs the masker on a pool registry whose
// name looks public: as a secret its every host form is masked, and so is
// each address the runner resolves it to, the form a Docker dial error
// prints. A stub getent stands in for the runner's resolver.
func TestCIMaskLANScriptSecretRegistry(t *testing.T) {
	script, err := filepath.Abs(filepath.Join(maskLANRoot, maskLANScript))
	if err != nil {
		t.Fatal(err)
	}
	stub := t.TempDir()
	getent := "#!/bin/sh\n[ \"$1\" = ahosts ] && [ \"$2\" = registry.example.test ] || exit 2\n" +
		"echo '10.20.30.40     STREAM registry.example.test'\necho '10.20.30.40     DGRAM'\necho 'fd00::7         STREAM'\n" // lab-string-ok: placeholder private addresses; the test proves the resolved registry address is masked
	if err := os.WriteFile(filepath.Join(stub, "getent"), []byte(getent), 0o755); err != nil { // #nosec G306 -- an executable test stub
		t.Fatal(err)
	}
	path := "PATH=" + stub + string(os.PathListSeparator) + os.Getenv("PATH")

	for _, tc := range []struct {
		name, env string
		want      []string
	}{
		{"a public-looking secret registry and its resolved addresses", "CI_IMAGE_REGISTRY=registry.example.test:5000/pool",
			[]string{"registry.example.test:5000/pool", "registry.example.test:5000", "registry.example.test", "10.20.30.40", "fd00::7"}},
		{"a secret registry the runner cannot resolve", "CI_IMAGE_REGISTRY=unresolved.example.test:5000",
			[]string{"unresolved.example.test:5000", "unresolved.example.test"}},
		{"an address-literal secret registry", "CI_IMAGE_REGISTRY=10.20.30.41:5000/pool", // lab-string-ok: placeholder private address
			[]string{"10.20.30.41:5000/pool", "10.20.30.41:5000", "10.20.30.41"}},
		{"a public release registry stays unmasked", "RELEASE_REGISTRY=registry.example.test:5000",
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", script) // #nosec G204 -- the repository's own script
			cmd.Env = []string{path, tc.env}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v\n%s", maskLANScript, err, out)
			}
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if l != "" {
					got = append(got, strings.TrimPrefix(l, "::add-mask::"))
				}
			}
			slices.Sort(got)
			got = slices.Compact(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("%s: masks %q, want %q", tc.env, got, want)
			}
		})
	}
}
