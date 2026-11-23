package buildgates

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// inHouseModulePath is the first-party module prefix. A GO* private
// variable that defaults to it sends first-party modules around
// proxy.golang.org and sum.golang.org (DS-7944), so no build file may name
// it: private modules come only from the caller's GOPRIVATE.
const inHouseModulePath = "github.com/jeremyhahn"

// goPrivateAssignment matches an assignment (make, shell, Dockerfile ENV/ARG,
// compose list or map form) of one of the variables that mark modules
// private, capturing the assigned value.
var goPrivateAssignment = regexp.MustCompile(`\b(GOPRIVATE|GONOSUMDB|GONOPROXY|GOINSECURE|GOMODAUTH_GOPRIVATE)\s*(?::=|\?=|\+=|=|:\s)(.*)$`)

// goPrivateDefaultProblems reports each non-comment line of body that
// assigns a GO* private variable a value naming the in-house module path.
func goPrivateDefaultProblems(name, body string) []string {
	var problems []string
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := goPrivateAssignment.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], inHouseModulePath) {
			problems = append(problems, fmt.Sprintf("%s:%d: %s defaults to the in-house module path: %s", name, i+1, m[1], trimmed))
		}
	}
	return problems
}

// goPrivateFiles lists the build files whose module environment the gate
// checks, relative to root.
func goPrivateFiles(root string) ([]string, error) {
	files := []string{"Makefile", filepath.Join("scripts", "in-toolchain-image.sh")}
	walk := func(dir string, keep func(name string) bool) error {
		return filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !keep(d.Name()) {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
			return nil
		})
	}
	isDockerOrCompose := func(name string) bool {
		return strings.HasPrefix(name, "Dockerfile") || strings.HasSuffix(name, ".Dockerfile") ||
			strings.HasPrefix(name, "compose") || strings.HasPrefix(name, "docker-compose")
	}
	if err := walk(filepath.Join("build", "docker"), isDockerOrCompose); err != nil {
		return nil, err
	}
	if err := walk(filepath.Join("test", "integration"), func(name string) bool { return name == "docker-compose.yml" }); err != nil {
		return nil, err
	}
	return files, nil
}

func TestNoGoPrivateDefaultsToTheInHouseModulePath(t *testing.T) {
	files, err := goPrivateFiles(repoRoot)
	if err != nil {
		t.Fatalf("list build files: %v", err)
	}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, p := range goPrivateDefaultProblems(rel, string(body)) {
			t.Error(p)
		}
	}
}

func TestGoPrivateDefaultProblemsCatchAnInHouseDefault(t *testing.T) {
	for _, line := range []string{
		"GOMODAUTH_GOPRIVATE := $(if $(GOPRIVATE),$(GOPRIVATE),github.com/jeremyhahn/*)",
		"GOMODAUTH_GOPRIVATE := github.com/jeremyhahn/*",
		"      - GOPRIVATE=${GOMODAUTH_GOPRIVATE:-${GITEA_HOST:+github.com/jeremyhahn/*}}",
		"      GONOSUMDB: github.com/jeremyhahn/*",
		"ENV GONOPROXY=github.com/jeremyhahn/*",
		"ARG GOINSECURE=github.com/jeremyhahn/*",
		`export GOPRIVATE="${GOPRIVATE:-github.com/jeremyhahn/*}"`,
	} {
		if got := goPrivateDefaultProblems("f", line); len(got) != 1 {
			t.Errorf("%q: got %d problems, want 1", line, len(got))
		}
	}
}

func TestGoPrivateDefaultProblemsAllowAPassThrough(t *testing.T) {
	for _, line := range []string{
		"GOMODAUTH_GOPRIVATE := $(GOPRIVATE)",
		"      - GOPRIVATE=${GOMODAUTH_GOPRIVATE:-}",
		`export GOPRIVATE="${GOPRIVATE:-}"`,
		"                    -e GOPRIVATE='$(GOMODAUTH_GOPRIVATE)' \\",
		"# GOPRIVATE=github.com/jeremyhahn/* was the old default",
		"\t$(call run_in_devcontainer,go env -json GOPRIVATE GONOSUMDB; ls /go/pkg/mod/cache/download/github.com/jeremyhahn/)",
	} {
		if got := goPrivateDefaultProblems("f", line); len(got) != 0 {
			t.Errorf("%q: got %v, want none", line, got)
		}
	}
}
