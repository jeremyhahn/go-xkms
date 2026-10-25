package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// devcontainerComposeDir holds the devcontainer stack's compose.yaml,
// relative to this package's directory.
const devcontainerComposeDir = "../../build/docker/devcontainer"

// gomodauthMount is how a Dockerfile step reads the module credentials. Compose
// hands a build that secret only when the service's build declares it.
const gomodauthMount = "--mount=type=secret,id=gomodauth"

type composeFile struct {
	Services map[string]struct {
		Build struct {
			Context    string `yaml:"context"`
			Dockerfile string `yaml:"dockerfile"`
			Secrets    []any  `yaml:"secrets"`
		} `yaml:"build"`
	} `yaml:"services"`
}

// declaresSecret reports whether a build's secrets list names id, in either
// the short (`- id`) or the long (`- source: id`) form.
func declaresSecret(secrets []any, id string) bool {
	for _, s := range secrets {
		switch v := s.(type) {
		case string:
			if v == id {
				return true
			}
		case map[string]any:
			if v["source"] == id {
				return true
			}
		}
	}
	return false
}

// buildSecretProblems lists every service in dir/compose.yaml whose Dockerfile
// mounts the gomodauth secret but whose build does not declare it. Build
// contexts outside root belong to another repository and are not checked.
func buildSecretProblems(root, dir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		return nil, err
	}
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(cf.Services))
	for name := range cf.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	for _, name := range names {
		build := cf.Services[name].Build
		if build.Context == "" {
			continue
		}
		context, err := filepath.Abs(filepath.Join(dir, build.Context))
		if err != nil {
			return nil, err
		}
		if rel, err := filepath.Rel(absRoot, context); err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		dockerfile := build.Dockerfile
		if dockerfile == "" {
			dockerfile = "Dockerfile"
		}
		body, err := os.ReadFile(filepath.Join(context, dockerfile))
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", name, err)
		}
		if strings.Contains(string(body), gomodauthMount) && !declaresSecret(build.Secrets, "gomodauth") {
			problems = append(problems, fmt.Sprintf("%s builds %s, which mounts the gomodauth secret, without declaring it", name, dockerfile))
		}
	}
	return problems, nil
}

func TestDevcontainerBuildsDeclareTheModuleSecret(t *testing.T) {
	problems, err := buildSecretProblems(repoRoot, devcontainerComposeDir)
	if err != nil {
		t.Fatalf("check %s: %v", devcontainerComposeDir, err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestBuildSecretProblemsCatchAnUndeclaredSecret(t *testing.T) {
	const compose = `
services:
  short:
    build:
      context: .
      dockerfile: Dockerfile.secret
      secrets: [gomodauth]
  long:
    build:
      context: .
      dockerfile: Dockerfile.secret
      secrets:
        - source: gomodauth
  plain:
    build:
      context: .
      dockerfile: Dockerfile.plain
  missing:
    build:
      context: .
      dockerfile: Dockerfile.secret
  foreign:
    build:
      context: ../elsewhere
  image-only:
    image: busybox
`
	root := t.TempDir()
	files := map[string]string{
		"compose.yaml":      compose,
		"Dockerfile.secret": "FROM scratch\nRUN " + gomodauthMount + " true\n",
		"Dockerfile.plain":  "FROM scratch\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	problems, err := buildSecretProblems(root, root)
	if err != nil {
		t.Fatalf("buildSecretProblems: %v", err)
	}
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "missing ") {
		t.Fatalf("want one problem for service missing, got %q", problems)
	}
}

func TestBuildSecretProblemsReportAMissingDockerfile(t *testing.T) {
	root := t.TempDir()
	compose := "services:\n  gone:\n    build:\n      context: .\n      dockerfile: Dockerfile.gone\n"
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(compose), 0o600); err != nil {
		t.Fatalf("write compose.yaml: %v", err)
	}
	if _, err := buildSecretProblems(root, root); err == nil {
		t.Fatal("want an error for a Dockerfile that does not exist")
	}
	if _, err := buildSecretProblems(root, filepath.Join(root, "absent")); err == nil {
		t.Fatal("want an error for a directory without compose.yaml")
	}
}
