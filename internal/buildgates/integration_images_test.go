package buildgates

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Issue #2266: every PKCS#11 sub-suite of `make integration-test` started the
// compose xkms-server with `up -d --build`, which rebuilt the softhsm, swtpm
// and xkms-server images each time (7-14 min per sub-suite on a loaded
// runner). integration-test now builds the three images once, through the
// integration-images target, and its suites start the prebuilt per-run tags.

// xkmsServerUpBuildVar is the one variable compose_up_xkms_server passes the
// compose build flag through.
const xkmsServerUpBuildVar = "XKMS_SERVER_UP_BUILD"

// makeRuleRecipe returns the prerequisites and the recipe lines of target's
// rule (not a target-specific variable assignment).
func makeRuleRecipe(makefile, target string) (prereqs, recipe []string, ok bool) {
	lines := strings.Split(strings.ReplaceAll(makefile, "\\\n", " "), "\n")
	head := regexp.MustCompile(`^` + regexp.QuoteMeta(target) + `[ \t]*:([^=]*)$`)
	for i, line := range lines {
		m := head.FindStringSubmatch(line)
		if m == nil || strings.Contains(m[1], "=") {
			continue
		}
		list, _, _ := strings.Cut(m[1], "#")
		prereqs = strings.Fields(strings.ReplaceAll(list, "|", " "))
		for _, r := range lines[i+1:] {
			if !strings.HasPrefix(r, "\t") {
				break
			}
			recipe = append(recipe, strings.TrimSpace(r))
		}
		return prereqs, recipe, true
	}
	return nil, nil, false
}

// makeDefine returns the body of `define name ... endef`.
func makeDefine(makefile, name string) (string, bool) {
	m := regexp.MustCompile(`(?ms)^define ` + regexp.QuoteMeta(name) + `\n(.*?)^endef`).
		FindStringSubmatch(makefile)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// composeUpXkmsServerProblems lists why a compose_up_xkms_server body would
// rebuild the images on every suite: a literal `up -d --build`, or an `up`
// of xkms-server that does not take its build flag from XKMS_SERVER_UP_BUILD.
func composeUpXkmsServerProblems(body string) []string {
	var problems []string
	if strings.Contains(body, "up -d --build") {
		problems = append(problems, "compose_up_xkms_server runs a literal `up -d --build`")
	}
	ups := regexp.MustCompile(`\$\(DOCKER_COMPOSE\) up [^;|]*xkms-server`).FindAllString(body, -1)
	if len(ups) == 0 {
		problems = append(problems, "compose_up_xkms_server starts no xkms-server with $(DOCKER_COMPOSE) up")
	}
	want := "$(DOCKER_COMPOSE) up -d $(" + xkmsServerUpBuildVar + ") xkms-server"
	for _, up := range ups {
		if up != want {
			problems = append(problems, "compose_up_xkms_server runs "+up+", want "+want)
		}
	}
	return problems
}

func TestIntegrationImagesTargetBuildsTheThreeImagesOnce(t *testing.T) {
	makefile := readMakefile(t)
	if !regexp.MustCompile(`(?m)^\.PHONY:.*\bintegration-images\b`).MatchString(makefile) {
		t.Error("integration-images must be a .PHONY target")
	}
	_, recipe, ok := makeRuleRecipe(makefile, "integration-images")
	if !ok {
		t.Fatal("Makefile has no integration-images: rule")
	}
	builds := 0
	for _, line := range recipe {
		rest, found := strings.CutPrefix(line, "$(DOCKER_COMPOSE) build ")
		if !found {
			continue
		}
		builds++
		fields := strings.Fields(rest)
		for _, svc := range []string{"softhsm", "swtpm", "xkms-server"} {
			if !slices.Contains(fields, svc) {
				t.Errorf("integration-images build %q does not name %s", line, svc)
			}
		}
	}
	if builds != 1 {
		t.Errorf("integration-images must run one $(DOCKER_COMPOSE) build of softhsm, "+
			"swtpm and xkms-server; recipe is %q", recipe)
	}
}

func TestIntegrationTestBuildsImagesBeforeTheFirstSuite(t *testing.T) {
	prereqs, _, ok := makeRuleRecipe(readMakefile(t), "integration-test")
	if !ok {
		t.Fatal("Makefile has no integration-test: rule")
	}
	if len(prereqs) < 3 || prereqs[0] != "clean-test-containers" ||
		prereqs[1] != "integration-images" ||
		!strings.HasPrefix(prereqs[2], "integration-test-") {
		t.Errorf("integration-test must run clean-test-containers, then "+
			"integration-images, then its suites; prerequisites are %q", prereqs)
	}
}

func TestComposeUpXkmsServerTakesBuildFlagFromVariable(t *testing.T) {
	makefile := readMakefile(t)
	body, ok := makeDefine(makefile, "compose_up_xkms_server")
	if !ok {
		t.Fatal("Makefile has no compose_up_xkms_server define")
	}
	for _, p := range composeUpXkmsServerProblems(body) {
		t.Error(p)
	}
	if !regexp.MustCompile(`(?m)^` + xkmsServerUpBuildVar + `[ \t]*\?=[ \t]*--build[ \t]*$`).
		MatchString(makefile) {
		t.Errorf("Makefile must default %s ?= --build, so a sub-suite run on its "+
			"own still builds", xkmsServerUpBuildVar)
	}
	if !regexp.MustCompile(`(?m)^integration-test[ \t]*:[ \t]*` + xkmsServerUpBuildVar +
		`[ \t]*:=[ \t]*$`).MatchString(makefile) {
		t.Errorf("integration-test must set %s empty (integration-test: %s :=), so its "+
			"suites start the images integration-images built", xkmsServerUpBuildVar,
			xkmsServerUpBuildVar)
	}
}

// TestComposeUpXkmsServerProblemsCatchesRebuildEverySuite feeds the define as
// it was before #2266 and expects the gate to fail it.
func TestComposeUpXkmsServerProblemsCatchesRebuildEverySuite(t *testing.T) {
	before := `	@$(MAKE) --no-print-directory stage-gomodauth
	@case "$(XKMS_COMPOSE_SERVER)" in \
		1|yes|on) \
			$(DOCKER_COMPOSE) up -d --build xkms-server; \
			$(MAKE) --no-print-directory devcontainer-server-wait ;; \
		*) \
			if docker image inspect $(XKMS_SERVER_IMAGE) >/dev/null 2>&1; then \
				$(DOCKER_COMPOSE) up -d --build xkms-server || true; \
			fi ;; \
	esac
`
	if len(composeUpXkmsServerProblems(before)) == 0 {
		t.Fatal("the pre-#2266 define (up -d --build in every suite) must fail the gate")
	}
	after := strings.ReplaceAll(before, "up -d --build", "up -d $("+xkmsServerUpBuildVar+")")
	if p := composeUpXkmsServerProblems(after); len(p) != 0 {
		t.Fatalf("the fixed define must pass the gate, got %q", p)
	}
}
