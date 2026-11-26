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
)

// integrationRun matches a step that runs integration suites and so starts the
// devcontainer stack and the suites' own compose projects.
var integrationRun = regexp.MustCompile(`\bmake integration-test\b`)

// composeRunID captures the IT_PROJECT a make invocation names its compose
// projects with (ci-template v1.25); the Makefile derives COMPOSE_RUN_ID
// from it.
var composeRunID = regexp.MustCompile(`IT_PROJECT=("[^"]*"|\S+)`)

// teardownTargets remove what an integration job starts: clean-test-containers
// the suites' projects, devcontainer-clean the devcontainer project, which
// clean-test-containers deliberately leaves to it.
var teardownTargets = []string{"clean-test-containers", "devcontainer-clean"}

// teardownProblems lists every integration job that does not tear down each
// stack it starts in an if: always() step naming the same IT_PROJECT.
func teardownProblems(wf workflow) []string {
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	for _, name := range names {
		steps := wf.Jobs[name].Steps
		start := -1
		for i, step := range steps {
			if integrationRun.MatchString(step.Run) {
				start = i
				break
			}
		}
		if start < 0 {
			continue
		}
		id := composeRunID.FindStringSubmatch(steps[start].Run)
		if id == nil {
			problems = append(problems, fmt.Sprintf("%s runs integration suites without an IT_PROJECT", name))
			continue
		}
		for _, target := range teardownTargets {
			want := "make " + target + " " + id[0]
			found := false
			for _, step := range steps[start+1:] {
				if strings.Contains(step.If, "always()") && strings.Contains(step.Run, want) {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, fmt.Sprintf("%s has no if: always() step running %q", name, want))
			}
		}
	}
	return problems
}

func TestCIIntegrationJobsTearDownTheirStacks(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range teardownProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

// teardownFixture is a minimal integration job that tears down both stacks.
const teardownFixture = `
jobs:
  unit:
    steps:
      - run: make test
  integration:
    steps:
      - run: make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT" IT_IMAGE="$IT_IMAGE"
      - if: always()
        run: make clean-test-containers IT_PROJECT="$IT_PROJECT"
      - if: always()
        run: make devcontainer-clean IT_PROJECT="$IT_PROJECT"
`

func TestCITeardownCatchEachMissingTeardown(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"none", "", "", ""},
		{"devcontainer not torn down", "make devcontainer-clean", "make devcontainer-down", `running "make devcontainer-clean`},
		{"suites not torn down", "make clean-test-containers", "true", `running "make clean-test-containers`},
		{"teardown skipped on failure", "      - if: always()\n        run: make devcontainer-clean", "      - run: make devcontainer-clean", `running "make devcontainer-clean`},
		{"teardown under another run id", `devcontainer-clean IT_PROJECT="$IT_PROJECT"`, `devcontainer-clean IT_PROJECT=go-xkms-local`, `running "make devcontainer-clean`},
		{"teardown names COMPOSE_RUN_ID instead", `devcontainer-clean IT_PROJECT="$IT_PROJECT"`, `devcontainer-clean COMPOSE_RUN_ID="$IT_RUN_ID"`, `running "make devcontainer-clean`},
		{"suites without a run id", `make integration-test MODULE_ENV_FILE="$RUNNER_TEMP/gomodauth.env" IT_PROJECT="$IT_PROJECT"`, "make integration-test", "without an IT_PROJECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := teardownFixture
			if tc.old != "" {
				if !strings.Contains(src, tc.old) {
					t.Fatalf("fixture has no %q to replace", tc.old)
				}
				src = strings.Replace(src, tc.old, tc.new, 1)
			}
			problems := teardownProblems(parseWorkflow(t, []byte(src)))
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("valid fixture reported %q", problems)
				}
				return
			}
			for _, p := range problems {
				if strings.Contains(p, tc.want) {
					return
				}
			}
			t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
		})
	}
}

// runImagesFlag asks clean-test-containers to also remove this run's images.
const runImagesFlag = "CLEAN_RUN_IMAGES=1"

// imageTeardownProblems lists every if: always() clean-test-containers line
// that does not also remove its run's images, and fails when there is none.
func imageTeardownProblems(wf workflow) []string {
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []string
	seen := 0
	for _, name := range names {
		for _, step := range wf.Jobs[name].Steps {
			if !strings.Contains(step.If, "always()") {
				continue
			}
			for _, line := range strings.Split(step.Run, "\n") {
				if !strings.Contains(line, "make clean-test-containers ") {
					continue
				}
				seen++
				if !strings.Contains(line, runImagesFlag) {
					problems = append(problems, fmt.Sprintf("%s: %q does not pass %s", name, strings.TrimSpace(line), runImagesFlag))
				}
			}
		}
	}
	if seen == 0 {
		problems = append(problems, "no if: always() step runs make clean-test-containers")
	}
	return problems
}

// runImageRecipeProblems lists what the clean-test-containers recipe lacks to
// remove this run's IT_PROJECT images without failing or touching IT_IMAGE.
func runImageRecipeProblems(recipe string) []string {
	var problems []string
	for _, want := range []string{"CLEAN_RUN_IMAGES", "$(IT_PROJECT)", "docker image ls", "docker image rm -f", "|| true"} {
		if !strings.Contains(recipe, want) {
			problems = append(problems, fmt.Sprintf("clean-test-containers recipe has no %q", want))
		}
	}
	if !strings.Contains(recipe, `!= '$(IT_IMAGE)'`) {
		problems = append(problems, "clean-test-containers recipe does not skip IT_IMAGE")
	}
	if !strings.Contains(recipe, `"$$p"-soak-*`) {
		problems = append(problems, "clean-test-containers recipe does not skip the soak job's images")
	}
	if strings.Contains(recipe, "prune") {
		problems = append(problems, "clean-test-containers recipe prunes the Docker store")
	}
	return problems
}

func TestCITeardownRemovesThisRunsImages(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range imageTeardownProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
	mk, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(repoRoot, "Makefile"), err)
	}
	recipe, ok := makeRecipe(string(mk), "clean-test-containers")
	if !ok {
		t.Fatal("Makefile has no clean-test-containers target")
	}
	for _, p := range runImageRecipeProblems(recipe) {
		t.Error(p)
	}
}

func TestCITeardownCatchesKeptRunImages(t *testing.T) {
	kept := strings.Replace(teardownFixture, `clean-test-containers IT_PROJECT="$IT_PROJECT"`, `clean-test-containers IT_PROJECT="$IT_PROJECT" `+runImagesFlag, 1)
	if got := imageTeardownProblems(parseWorkflow(t, []byte(kept))); len(got) != 0 {
		t.Fatalf("valid fixture reported %q", got)
	}
	if got := imageTeardownProblems(parseWorkflow(t, []byte(teardownFixture))); len(got) == 0 {
		t.Fatal("teardown without the image flag was not reported")
	}
	good := "\t@if [ \"$(CLEAN_RUN_IMAGES)\" = 1 ]; then p='$(IT_PROJECT)'; for ref in $$(docker image ls); do [ \"$$ref\" != '$(IT_IMAGE)' ] || continue; case \"$$ref\" in \"$$p\"-soak-*) continue;; esac; done; docker image rm -f $$refs || true; fi\n"
	if got := runImageRecipeProblems(good); len(got) != 0 {
		t.Fatalf("valid recipe reported %q", got)
	}
	for _, bad := range []string{
		strings.Replace(good, " || true", "", 1),
		strings.Replace(good, `[ "$$ref" != '$(IT_IMAGE)' ] || continue; `, "", 1),
		strings.Replace(good, "docker image rm -f $$refs", "docker image prune -af", 1),
		strings.Replace(good, `case "$$ref" in "$$p"-soak-*) continue;; esac; `, "", 1),
	} {
		if got := runImageRecipeProblems(bad); len(got) == 0 {
			t.Errorf("recipe %q was not reported", bad)
		}
	}
}

// fakeDocker answers image listings from IMAGES (one ref per line), logs each
// removed ref to RMLOG, and succeeds silently on every other command.
const fakeDocker = `#!/usr/bin/env bash
case "$1" in
images|image)
	if [ "$1" = image ]; then shift; fi
	case "$1" in
	rm|rmi) shift; for a in "$@"; do [ "$a" = -f ] || echo "$a" >>"$RMLOG"; done; exit 0;;
	esac
	pat=""
	for a in "$@"; do case "$a" in --filter=reference=*) pat="${a#--filter=reference=}";; esac; done
	while IFS= read -r ref; do
		[ -n "$ref" ] || continue
		if [ -z "$pat" ] || [[ "$ref" == $pat ]]; then echo "$ref"; fi
	done <"$IMAGES"
	exit 0;;
rmi) shift; for a in "$@"; do [ "$a" = -f ] || echo "$a" >>"$RMLOG"; done; exit 0;;
esac
exit 0
`

func TestCITeardownRemovesOnlyOwnedRunImages(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatalf("make not on PATH: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	const project = "go-xkms-ci-7-1"
	const itImage = "go-xkms-ci-it:0123456789abcdef"
	owned := []string{
		"go-xkms-server:" + project,
		"go-xkms/cli:" + project,
		"go-quicbaas-server:" + project,
	}
	kept := []string{
		itImage,
		"go-xkms-server:" + project + "-soak-1",
		"go-xkms-server:go-xkms-ci-7-10",
		"other/tool:" + project,
		project + "-cache:latest",
		"registry.example/" + project + "-tool:v1",
	}
	images := filepath.Join(dir, "images")
	if err := os.WriteFile(images, []byte(strings.Join(append(append([]string{}, owned...), kept...), "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rmlog := filepath.Join(dir, "rm.log")
	cmd := exec.Command("make", "-s", "-C", repoRoot, "clean-test-containers",
		"IT_PROJECT="+project, "IT_IMAGE="+itImage, "CLEAN_RUN_IMAGES=1", "BUILD_DIR="+filepath.Join(dir, "build"))
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "PATH", "XKMS_IMAGE_TAG", "COMPOSE_RUN_ID", "IT_PROJECT", "IT_IMAGE", "MAKEFLAGS":
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"IMAGES="+images, "RMLOG="+rmlog)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make clean-test-containers: %v\n%s", err, out)
	}
	data, err := os.ReadFile(rmlog)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	removed := map[string]bool{}
	for _, ref := range strings.Fields(string(data)) {
		removed[ref] = true
	}
	for _, ref := range owned {
		if !removed[ref] {
			t.Errorf("teardown kept this run's image %s", ref)
		}
	}
	for _, ref := range kept {
		if removed[ref] {
			t.Errorf("teardown removed %s, which this run does not own", ref)
		}
	}
}
