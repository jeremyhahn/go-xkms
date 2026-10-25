package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot is the repository root, relative to this package's directory.
const repoRoot = "../.."

// buildDirWipe matches a recipe line that removes the whole build directory.
// build/docker/ is tracked source, so a clean may sweep build/'s generated
// entries (clean-build-dir) but never the directory itself.
var buildDirWipe = regexp.MustCompile(`^\t@?-?rm -[a-zA-Z]*r[a-zA-Z]* +("?)(\$\(BUILD_DIR\)|\./build|build)/?("?)(\s*$|\s*;|\s+&&)`)

// buildDirWipes returns the Makefile recipe lines that delete the build
// directory outright.
func buildDirWipes(makefile string) []string {
	var wipes []string
	for _, line := range strings.Split(makefile, "\n") {
		if buildDirWipe.MatchString(line) {
			wipes = append(wipes, strings.TrimSpace(line))
		}
	}
	return wipes
}

func TestMakefileNeverWipesTheBuildDir(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, line := range buildDirWipes(string(data)) {
		t.Errorf("recipe deletes build/ and with it the tracked build/docker/ sources: %q", line)
	}
}

func TestBuildDirWipesCatchEachForm(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"\t@rm -rf $(BUILD_DIR)", true},
		{"\trm -rf build", true},
		{"\t@rm -rf ./build/", true},
		{"\t@rm -fr \"$(BUILD_DIR)\" && echo done", true},
		{"\t@rm -rf $(BUILD_DIR)/bin", false},
		{"\t@rm -rf $(COVERAGE_DIR)", false},
		{"\t@$(MAKE) --no-print-directory clean-build-dir", false},
	}
	for _, tc := range cases {
		got := len(buildDirWipes(tc.line)) == 1
		if got != tc.want {
			t.Errorf("buildDirWipes(%q) flagged=%v, want %v", tc.line, got, tc.want)
		}
	}
}

// runCleanBuildDir runs `make clean-build-dir` against buildDir.
func runCleanBuildDir(t *testing.T, buildDir string) {
	t.Helper()
	cmd := exec.Command("make", "--no-print-directory", "-C", repoRoot, "clean-build-dir", "BUILD_DIR="+buildDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make clean-build-dir: %v\n%s", err, out)
	}
}

func TestCleanBuildDirKeepsBuildDocker(t *testing.T) {
	buildDir := filepath.Join(t.TempDir(), "build")
	kept := []string{
		"docker/devcontainer/Dockerfile",
		"docker/devcontainer/scripts/post-create.sh",
		"docker/devcontainer/gomodauth.env",
		"docker/devcontainer/.env",
	}
	removed := []string{
		"bin/xkmsd",
		"lib/libxkms_pkcs11.so",
		"coverage/coverage.out",
		"gosec-report.txt",
	}
	for _, rel := range append(append([]string{}, kept...), removed...) {
		path := filepath.Join(buildDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(rel), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	runCleanBuildDir(t, buildDir)

	for _, rel := range kept {
		if _, err := os.Stat(filepath.Join(buildDir, rel)); err != nil {
			t.Errorf("clean-build-dir removed source %s: %v", rel, err)
		}
	}
	for _, rel := range removed {
		top := strings.SplitN(rel, "/", 2)[0]
		if _, err := os.Stat(filepath.Join(buildDir, top)); !os.IsNotExist(err) {
			t.Errorf("clean-build-dir left generated %s (stat err %v)", top, err)
		}
	}
}

func TestCleanBuildDirWithoutABuildDir(t *testing.T) {
	buildDir := filepath.Join(t.TempDir(), "absent")
	runCleanBuildDir(t, buildDir)
	if _, err := os.Stat(buildDir); !os.IsNotExist(err) {
		t.Fatalf("clean-build-dir created %s (stat err %v)", buildDir, err)
	}
}
