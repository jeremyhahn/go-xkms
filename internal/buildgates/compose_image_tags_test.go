package buildgates

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// integrationComposeRoot holds the integration suites' compose files.
const integrationComposeRoot = "test/integration"

// composeBuildImages is the part of a compose file the image-tag gate reads:
// whether each service builds, and the image it tags the build with.
type composeBuildImages struct {
	Services map[string]struct {
		Build any    `yaml:"build"`
		Image string `yaml:"image"`
	} `yaml:"services"`
}

// isComposeFile reports whether name is a compose file name.
func isComposeFile(name string) bool {
	if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
		return false
	}
	return strings.HasPrefix(name, "docker-compose") || strings.HasPrefix(name, "compose")
}

// sharedBuildImageProblems lists, for one compose document, every image that
// two or more build targets export to: bake refuses the second export with
// "image ... already exists" (ruling 981).
func sharedBuildImageProblems(path string, data []byte) ([]string, error) {
	var cf composeBuildImages
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	owners := map[string]string{}
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(cf.Services)) {
		svc := cf.Services[name]
		if svc.Build == nil || svc.Image == "" {
			continue
		}
		if first, ok := owners[svc.Image]; ok {
			problems = append(problems, path+": services "+first+" and "+name+
				" both build image "+svc.Image)
			continue
		}
		owners[svc.Image] = name
	}
	return problems, nil
}

func TestIntegrationComposeBuildTargetsHaveDistinctImages(t *testing.T) {
	root := filepath.Join(repoRoot, integrationComposeRoot)
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isComposeFile(d.Name()) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		problems, err := sharedBuildImageProblems(path, data)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		checked++
		for _, p := range problems {
			t.Error(p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if checked == 0 {
		t.Fatalf("no compose files found under %s", root)
	}
}

func TestSharedBuildImageProblemsCatchesTwoBuildsOnOneImage(t *testing.T) {
	compose := `services:
  a:
    build:
      context: .
    image: go-xkms-x:${XKMS_IMAGE_TAG:-latest}
  b:
    build: .
    image: go-xkms-x:${XKMS_IMAGE_TAG:-latest}
  c:
    image: go-xkms-x:${XKMS_IMAGE_TAG:-latest}
`
	problems, err := sharedBuildImageProblems("compose.yml", []byte(compose))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(problems) != 1 {
		t.Fatalf("want one problem (a and b), got %q", problems)
	}
}

// integrationTestPrereqs returns the prerequisites of the Makefile
// integration-test rule, joining backslash continuations.
func integrationTestPrereqs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := strings.ReplaceAll(string(data), "\\\n", " ")
	m := regexp.MustCompile(`(?m)^integration-test:([^\n]*)$`).FindStringSubmatch(text)
	if m == nil {
		t.Fatal("Makefile has no integration-test: rule")
	}
	return strings.Fields(m[1])
}

func TestIntegrationTestRunsBootstrapFirst(t *testing.T) {
	prereqs := integrationTestPrereqs(t)
	if len(prereqs) < 2 || prereqs[0] != "clean-test-containers" ||
		prereqs[1] != "integration-test-bootstrap" {
		t.Errorf("integration-test must run clean-test-containers then "+
			"integration-test-bootstrap first, so a bootstrap image build failure "+
			"costs minutes, not hours; prerequisites are %q", prereqs)
	}
}
