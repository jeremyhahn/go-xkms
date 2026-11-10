package buildgates

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// inHouseModules is the module prefix no GO* private variable may name:
// go-xkms and its dependencies resolve from proxy.golang.org and
// sum.golang.org (DS-7944), so a default that sends them around the proxy and
// the checksum database is a defect (DS-7983).
const inHouseModules = "github.com/jeremyhahn"

// goPrivateAssign matches an assignment of a variable that takes modules off
// the proxy or the checksum database: NAME=v, NAME:=v, NAME?=v, NAME+=v (shell,
// Makefile, compose list, `docker run -e`, Dockerfile ENV), `ENV NAME v`
// (Dockerfile) and `NAME: v` (compose map).
var goPrivateAssign = regexp.MustCompile(
	`(?:^|[^A-Za-z0-9_])(?:(GOPRIVATE|GONOSUMDB|GONOPROXY|GOINSECURE|GOMODAUTH_GOPRIVATE)(?:\s*(?::=|\?=|\+=|=)\s*|:\s+)|ENV\s+(GOPRIVATE|GONOSUMDB|GONOPROXY|GOINSECURE)\s+)(.*)`)

// goPrivateProblems reports each line of src (named name) that assigns one of
// the variables above a value naming an in-house module. A comment line, or
// the comment after ` #`, does not count; a value passed through from the
// caller's environment (`${GOPRIVATE:-}`, `$(GOPRIVATE)`) names no module.
func goPrivateProblems(name, src string) []string {
	var problems []string
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		for _, m := range goPrivateAssign.FindAllStringSubmatch(line, -1) {
			if strings.Contains(m[3], inHouseModules) {
				problems = append(problems, name+":"+strconv.Itoa(i+1)+": "+m[1]+m[2]+" names an in-house module")
			}
		}
	}
	return problems
}

// imageBuildFiles lists, relative to root, every file that builds or runs an
// image: the Makefile, the Dockerfiles and compose files under build/docker,
// the integration compose files and the toolchain-image wrapper.
func imageBuildFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{"Makefile", filepath.Join("scripts", "in-toolchain-image.sh")}
	walk := func(dir string, keep func(base string) bool) {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
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
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	walk(filepath.Join("build", "docker"), func(base string) bool {
		return strings.HasPrefix(base, "Dockerfile") ||
			strings.HasPrefix(base, "compose") && (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) ||
			strings.HasPrefix(base, "docker-compose")
	})
	walk(filepath.Join("test", "integration"), func(base string) bool {
		return base == "docker-compose.yml"
	})
	return files
}

func TestGoPrivateNamesNoInHouseModule(t *testing.T) {
	files := imageBuildFiles(t, repoRoot)
	if len(files) < 4 {
		t.Fatalf("found only %d image-build files: %v", len(files), files)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range goPrivateProblems(f, string(data)) {
			t.Error(p)
		}
	}
}

func TestGoPrivateProblemsCatchEachForm(t *testing.T) {
	bad := []string{
		"GOMODAUTH_GOPRIVATE := $(if $(GOPRIVATE),$(GOPRIVATE)," + inHouseModules + "/*)",
		"GOMODAUTH_GOPRIVATE := " + inHouseModules + "/*",
		"      - GOPRIVATE=" + inHouseModules + "/*",
		"      GONOSUMDB: " + inHouseModules + "/*",
		"ENV GONOPROXY=" + inHouseModules + "/*",
		"ENV GOINSECURE " + inHouseModules + "/*",
		"export GOPRIVATE=" + inHouseModules + "/* # in-house",
		"docker run -e GOPRIVATE='" + inHouseModules + "/*' img",
	}
	for _, line := range bad {
		if got := goPrivateProblems("f", line); len(got) != 1 {
			t.Errorf("%q: got %d problems, want 1", line, len(got))
		}
	}
	good := []string{
		"GOMODAUTH_GOPRIVATE := $(GOPRIVATE)",
		"      - GOPRIVATE=${GOPRIVATE:-}",
		"                    -e GOPRIVATE='$(GOMODAUTH_GOPRIVATE)' \\",
		"# GOPRIVATE=" + inHouseModules + "/* was the old default",
		"      - GOWORK=off # GOPRIVATE=" + inHouseModules + "/*",
		"ENV GONOSUMDB=*",
		"go list -m " + inHouseModules + "/trusted-firmware/sdk/go",
		"go env GOPRIVATE GONOSUMDB; ls /go/pkg/mod/cache/download/" + inHouseModules + "/",
	}
	for _, line := range good {
		if got := goPrivateProblems("f", line); len(got) != 0 {
			t.Errorf("%q: got %v, want none", line, got)
		}
	}
}
