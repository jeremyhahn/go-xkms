package buildgates

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// firstPartyGlob is the Gitea-era GOPRIVATE value: with it, go fetches every
// github.com/jeremyhahn module direct from its repository and skips
// sum.golang.org, so a tag moved upstream reaches the build as a go.sum
// checksum mismatch (main 18cd92a3a33a, Integration and Soak).
const firstPartyGlob = "github.com/jeremyhahn/*"

// serviceEnvironment returns a compose service's environment, whichever of
// the two compose forms (a list of KEY=value, or a mapping) it is written in.
func serviceEnvironment(raw any) map[string]string {
	env := map[string]string{}
	switch e := raw.(type) {
	case []any:
		for _, item := range e {
			key, value, _ := strings.Cut(fmt.Sprint(item), "=")
			env[key] = value
		}
	case map[string]any:
		for key, value := range e {
			env[key] = fmt.Sprint(value)
		}
	}
	return env
}

// giteaOnlyGoPrivate matches the one GOPRIVATE form the fold keeps (main's
// #2057 rule): a caller's GOMODAUTH_GOPRIVATE, else the first-party glob only
// when GITEA_HOST names a Gitea rewrite. Without either it expands to empty,
// so every module still resolves from proxy.golang.org.
var giteaOnlyGoPrivate = regexp.MustCompile(`^\$\{GOMODAUTH_GOPRIVATE:-\$\{GITEA_HOST:\+[^}]*\}\}$`)

// moduleResolutionProblems reports every service of the compose file that
// takes module resolution off proxy.golang.org and sum.golang.org.
func moduleResolutionProblems(composePath string) ([]string, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, err
	}
	var cf struct {
		Services map[string]struct {
			Environment any `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", composePath, err)
	}
	if len(cf.Services) == 0 {
		return nil, fmt.Errorf("%s declares no services", composePath)
	}

	var problems []string
	for name, svc := range cf.Services {
		env := serviceEnvironment(svc.Environment)
		for _, key := range []string{"GOPRIVATE", "GONOSUMDB", "GONOPROXY"} {
			if value, ok := env[key]; ok {
				if key == "GOPRIVATE" && giteaOnlyGoPrivate.MatchString(value) {
					continue // #2057: empty unless a Gitea rewrite is configured
				}
				problems = append(problems, fmt.Sprintf(
					"%s: service %s sets %s=%s: modules resolve from proxy.golang.org and sum.golang.org only",
					composePath, name, key, value))
			}
		}
		if env["GOSUMDB"] == "off" {
			problems = append(problems, fmt.Sprintf(
				"%s: service %s sets GOSUMDB=off: every module is verified against sum.golang.org",
				composePath, name))
		}
		for _, proxy := range strings.FieldsFunc(env["GOPROXY"], func(r rune) bool { return r == ',' || r == '|' }) {
			if proxy == "direct" {
				problems = append(problems, fmt.Sprintf(
					"%s: service %s has direct in GOPROXY=%s: a direct fetch takes whatever a moved tag points at",
					composePath, name, env["GOPROXY"]))
			}
		}
	}
	sort.Strings(problems)
	return problems, nil
}

func TestDevcontainerDoesNotMakeFirstPartyModulesPrivate(t *testing.T) {
	composePath := filepath.Join(devcontainerComposeDir, "compose.yaml")
	problems, err := moduleResolutionProblems(composePath)
	if err != nil {
		t.Fatalf("check %s: %v", composePath, err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestModuleResolutionProblemsCatchEachOverride(t *testing.T) {
	cases := map[string]string{
		"GOPRIVATE": "    environment:\n      - GOPRIVATE=" + firstPartyGlob + "\n",
		"GONOSUMDB": "    environment:\n      - GONOSUMDB=" + firstPartyGlob + "\n",
		"GONOPROXY": "    environment:\n      GONOPROXY: \"" + firstPartyGlob + "\"\n",
		"GOSUMDB":   "    environment:\n      GOSUMDB: \"off\"\n",
		"GOPROXY":   "    environment:\n      - GOPROXY=https://proxy.golang.org,direct\n",
	}
	for key, environment := range cases {
		t.Run(key, func(t *testing.T) {
			composePath := filepath.Join(t.TempDir(), "compose.yaml")
			content := "services:\n  devcontainer:\n    image: example\n" + environment
			if err := os.WriteFile(composePath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			problems, err := moduleResolutionProblems(composePath)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != 1 || !strings.Contains(problems[0], key) {
				t.Fatalf("problems = %q, want one naming %s", problems, key)
			}
		})
	}

	composePath := filepath.Join(t.TempDir(), "compose.yaml")
	content := "services:\n  test:\n    image: example\n    environment:\n      GOPROXY: \"off\"\n      GOFLAGS: -mod=readonly\n" +
		"  gitea:\n    image: example\n    environment:\n      - GOPRIVATE=${GOMODAUTH_GOPRIVATE:-${GITEA_HOST:+" + firstPartyGlob + "}}\n"
	if err := os.WriteFile(composePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	problems, err := moduleResolutionProblems(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("problems = %q, want none for an offline service or a Gitea-only GOPRIVATE", problems)
	}
}

// makefileGoPrivate returns the GOMODAUTH_GOPRIVATE the Makefile resolves when
// run with exactly the given module-fetch environment.
func makefileGoPrivate(t *testing.T, moduleEnv ...string) string {
	t.Helper()
	cmd := exec.Command("make", "-s", "--no-print-directory", "-C", repoRoot,
		"--eval", "buildgates-print-goprivate: ; @printf '%s\\n' '$(GOMODAUTH_GOPRIVATE)'",
		"buildgates-print-goprivate")
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		// A parent make (make test-buildgates, make race) exports the
		// GOMODAUTH_* it derived from its own environment; none may leak in.
		if strings.HasPrefix(key, "GOMODAUTH_") {
			continue
		}
		switch key {
		case "GOPRIVATE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
			"FORGE_MODULE_TOKEN", "GITEA_HOST", "MAKEFLAGS", "MFLAGS", "MAKELEVEL":
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, moduleEnv...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("make buildgates-print-goprivate: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestMakefileGoPrivateDefaultIsEmpty(t *testing.T) {
	ciRewrite := []string{
		"GIT_CONFIG_KEY_0=url.http://x:token@forge.example/jeremyhahn/.insteadOf",
		"GIT_CONFIG_VALUE_0=https://github.com/jeremyhahn/",
	}
	hostToken := []string{"FORGE_MODULE_TOKEN=token", "GITEA_HOST=forge.example"}

	for name, moduleEnv := range map[string][]string{
		"the runner's injected rewrite": ciRewrite,
		"the host token":                hostToken,
		"no credentials":                nil,
	} {
		t.Run(name, func(t *testing.T) {
			if got := makefileGoPrivate(t, moduleEnv...); got != "" {
				t.Errorf("GOMODAUTH_GOPRIVATE = %q with GOPRIVATE unset, want it empty", got)
			}
		})
	}

	// The values a parent make derived and exported do not reach the case.
	t.Run("a parent make's derived GOMODAUTH_ exports", func(t *testing.T) {
		t.Setenv("GOPRIVATE", firstPartyGlob)
		t.Setenv("GOMODAUTH_GOPRIVATE", firstPartyGlob)
		t.Setenv("GOMODAUTH_GIT_CONFIG_COUNT", "1")
		if got := makefileGoPrivate(t); got != "" {
			t.Errorf("GOMODAUTH_GOPRIVATE = %q with the parent's exported, want it empty", got)
		}
	})

	// A caller that sets GOPRIVATE itself still gets it passed through.
	for name, moduleEnv := range map[string][]string{
		"the runner's injected rewrite": ciRewrite,
		"the host token":                hostToken,
	} {
		t.Run("caller GOPRIVATE with "+name, func(t *testing.T) {
			const own = "example.com/private/*"
			if got := makefileGoPrivate(t, append([]string{"GOPRIVATE=" + own}, moduleEnv...)...); got != own {
				t.Errorf("GOMODAUTH_GOPRIVATE = %q, want the caller's %q", got, own)
			}
		})
	}
}
