package buildgates

import (
	"fmt"
	"go/build/constraint"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// raceJob is the Race Detector job. make coverage runs without -race (#2023),
// so this job is the PR tier's race check: it runs on every ready pull
// request, ci:full or not, and CI Gate fails the PR when it does not pass.
const raceJob = "race"

// raceTierProblems lists each way wf lets a ready pull request pass CI Gate
// with no race detection: the race job's if: is not the draft guard alone (so
// a PR without ci:full skips it), or CI Gate checks it on a tier but pr.
func raceTierProblems(wf workflow) []string {
	race, ok := wf.Jobs[raceJob]
	if !ok {
		return []string{"no " + raceJob + " job"}
	}
	var problems []string
	if cond := condition(race.If); cond != draftIf {
		problems = append(problems, fmt.Sprintf("%s's if: is %q, want %q, so it runs on every ready PR", raceJob, cond, draftIf))
	}
	tiers, _ := gateTiers(wf.Jobs[gateJob])
	if tier := tiers[raceJob]; tier != "pr" {
		problems = append(problems, fmt.Sprintf("CI Gate checks %s on tier %q, want pr", raceJob, tier))
	}
	return problems
}

func TestRaceDetectorRunsOnThePRTier(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range raceTierProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

func TestRaceTierCatchesEachForm(t *testing.T) {
	// raceHead anchors each rewrite on the race job: lint has the same if:.
	const raceHead = "  race:\n    needs: [build]\n"
	const fullIf = raceHead + "    if: >-\n      ${{ (github.event_name != 'pull_request' ||\n" +
		"      contains(github.event.pull_request.labels.*.name, 'ci:full')) && !github.event.pull_request.draft }}\n"
	const prIf = raceHead + "    if: ${{ !github.event.pull_request.draft }}\n"
	const fullLine = `check race  "${{ needs.race.result }}" full`
	const prLine = `check race  "${{ needs.race.result }}" pr`
	pr := strings.Replace(strings.Replace(fixture, fullIf, prIf, 1), fullLine, prLine, 1)
	cases := map[string]struct {
		workflow string
		want     int
	}{
		"pr tier":             {pr, 0},
		"full tier":           {fixture, 2},
		"ci:full if, gate pr": {strings.Replace(pr, prIf, fullIf, 1), 1},
		"pr if, gate full":    {strings.Replace(pr, prLine, fullLine, 1), 1},
		"no gate line":        {strings.Replace(pr, prLine, "", 1), 1},
		"runs on drafts too":  {strings.Replace(pr, prIf, raceHead, 1), 1},
		"no race job":         {"jobs:\n  ci-gate:\n    runs-on: x\n", 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(fixture, fullIf) || !strings.Contains(fixture, fullLine) {
				t.Fatal("ci_gate_test.go's fixture no longer has the full-tier race job this test rewrites")
			}
			if got := raceTierProblems(parseWorkflow(t, []byte(c.workflow))); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}

var (
	quotedTags  = regexp.MustCompile(`-tags=(?:"([^"]*)"|(\S+))`)
	makeTagCall = regexp.MustCompile(`^\$\(call go_tags,(.*)\)$`)
	filterOut   = regexp.MustCompile(`\$\(filter-out ([^,()]+),([^()]*)\)`)
	makeRunsArg = regexp.MustCompile(`(?m)^\s*(?:\S+=\S+\s+)*make\b.*\s(race-nofrost)\b`)
)

// tagsValue returns the -tags value in cmd, if it passes one.
func tagsValue(cmd string) (string, bool) {
	m := quotedTags.FindStringSubmatch(cmd)
	if m == nil {
		return "", false
	}
	return m[1] + m[2], true
}

// tagSet reads a -tags value, a Makefile $(call go_tags,...) or a plain
// comma-separated list, with the Makefile's variables and filter-outs
// expanded.
func tagSet(value string, vars map[string]string) map[string]bool {
	v := filterOut.ReplaceAllStringFunc(expandMakeVars(value, vars), func(call string) string {
		m := filterOut.FindStringSubmatch(call)
		drop := strings.Fields(m[1])
		var kept []string
		for _, w := range strings.Fields(m[2]) {
			if !slices.Contains(drop, w) {
				kept = append(kept, w)
			}
		}
		return strings.Join(kept, " ")
	})
	if m := makeTagCall.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	v = strings.ReplaceAll(v, "$(comma)", ",")
	tags := map[string]bool{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		tags[f] = true
	}
	return tags
}

// missingTags lists the tags of want that the -tags in cmd lack, or reports
// that cmd passes no -tags at all.
func missingTags(where, cmd string, want []string, vars map[string]string) []string {
	value, ok := tagsValue(expandMakeVars(cmd, vars))
	if !ok {
		return []string{where + " passes no -tags"}
	}
	got := tagSet(value, vars)
	var problems []string
	for _, tag := range want {
		if !got[tag] {
			problems = append(problems, fmt.Sprintf("%s's -tags lack %s, so its tests never run under -race", where, tag))
		}
	}
	return problems
}

// goTestCommand returns target's first go test command.
func goTestCommand(makefile, target string) (string, bool) {
	_, commands, _ := recipe(makefile, target)
	for _, c := range commands {
		if goTestCall.MatchString(c) {
			return c, true
		}
	}
	return "", false
}

// raceCoverageProblems lists each unit lane make coverage ran under -race
// before #2023 that the Race Detector no longer runs under -race: a TEST_TAGS
// tag missing from the race target or the race job's go test, or the !frost
// stub lane (test-nofrost's packages with TEST_TAGS_NOFROST) not run as
// race-nofrost by the race job.
func raceCoverageProblems(makefile string, wf workflow) []string {
	vars := makeVars(makefile)
	testTags := strings.Fields(expandMakeVars(vars["TEST_TAGS"], vars))
	if len(testTags) == 0 {
		return []string{"the Makefile defines no TEST_TAGS"}
	}
	var problems []string
	if c, ok := goTestCommand(makefile, "race"); ok {
		problems = append(problems, missingTags("make race", c, testTags, vars)...)
	} else {
		problems = append(problems, "make race runs no go test")
	}

	nofrost, ok := goTestCommand(makefile, "race-nofrost")
	if !ok {
		problems = append(problems, "no race-nofrost target runs go test")
	} else {
		fields := strings.Fields(expandMakeVars(nofrost, vars))
		if !slices.Contains(fields, "-race") {
			problems = append(problems, "race-nofrost runs go test without -race")
		}
		value, ok := tagsValue(expandMakeVars(nofrost, vars))
		if !ok {
			problems = append(problems, "race-nofrost passes no -tags")
		} else if got, want := tagSet(value, vars), tagSet(vars["TEST_TAGS_NOFROST"], vars); !maps.Equal(got, want) || want["frost"] {
			problems = append(problems, fmt.Sprintf("race-nofrost's -tags are %v, want TEST_TAGS_NOFROST %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want))))
		}
		lane, _ := goTestCommand(makefile, "test-nofrost")
		for _, f := range strings.Fields(lane) {
			if strings.HasPrefix(f, "./") && !slices.Contains(fields, f) {
				problems = append(problems, "race-nofrost does not run test-nofrost's "+f)
			}
		}
	}

	race, ok := wf.Jobs[raceJob]
	if !ok {
		return append(problems, "no "+raceJob+" job")
	}
	runsNofrost, goTests := false, 0
	for _, step := range race.Steps {
		run := strings.ReplaceAll(step.Run, "\\\n", " ")
		if makeRunsArg.MatchString(run) {
			runsNofrost = true
		}
		for _, line := range strings.Split(run, "\n") {
			if strings.Contains(line, "go test ") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				goTests++
				problems = append(problems, missingTags(raceJob+" job's go test", line, testTags, vars)...)
			}
		}
	}
	if goTests == 0 {
		problems = append(problems, raceJob+" job runs no go test")
	}
	if !runsNofrost {
		problems = append(problems, raceJob+" job does not run make race-nofrost")
	}
	return problems
}

func TestRaceDetectorCoversTheUnitTags(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range raceCoverageProblems(string(makefile), parseWorkflow(t, data)) {
		t.Error(p)
	}
}

func TestRaceCoverageCatchesEachForm(t *testing.T) {
	const vars = "comma := ,\nTEST_TAGS := codec_cbor tpm_simulator frost\n" +
		"TEST_TAGS_NOFROST := $(filter-out frost,$(TEST_TAGS))\n" +
		"TEST_FLAGS_NOFROST := -v -race -timeout 75m -tags=\"$(call go_tags,$(TEST_TAGS_NOFROST))\"\n"
	const covers = vars +
		"test-nofrost:\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST) ./pkg/api/rest/... ./pkg/server/...\n" +
		"race: agsim\n\t@CGO_ENABLED=1 $(GO) test -race -tags=\"$(call go_tags,pkcs11$(comma)codec_cbor$(comma)tpm_simulator$(comma)frost)\" ./...\n" +
		"race-nofrost: agsim\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST) ./pkg/api/rest/... ./pkg/server/...\n"
	const job = "jobs:\n  race:\n    steps:\n      - run: |\n          make agsim\n" +
		"          GOMEMLIMIT=10GiB go test -race -timeout 75m \\\n            -tags=\"pkcs11,codec_cbor,tpm_simulator,frost\" ./...\n" +
		"          GOMEMLIMIT=10GiB make race-nofrost\n"
	cases := map[string]struct {
		makefile, workflow string
		want               int
	}{
		"covers":                      {covers, job, 0},
		"race lacks tpm_simulator":    {strings.Replace(covers, "$(comma)tpm_simulator$(comma)", "$(comma)", 1), job, 1},
		"race via TEST_TAGS":          {strings.Replace(covers, "pkcs11$(comma)codec_cbor$(comma)tpm_simulator$(comma)frost", "pkcs11 $(TEST_TAGS)", 1), job, 0},
		"no race-nofrost":             {strings.Replace(covers, "race-nofrost:", "other:", 1), job, 1},
		"race-nofrost without -race":  {strings.Replace(covers, "race-nofrost: agsim\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST)", "race-nofrost: agsim\n\t@$(GOTEST) -tags=\"$(call go_tags,$(TEST_TAGS_NOFROST))\"", 1), job, 1},
		"race-nofrost with frost":     {strings.Replace(covers, "race-nofrost: agsim\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST)", "race-nofrost: agsim\n\t@$(GOTEST) -race -tags=\"$(call go_tags,$(TEST_TAGS))\"", 1), job, 1},
		"race-nofrost misses package": {strings.Replace(covers, "race-nofrost: agsim\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST) ./pkg/api/rest/... ", "race-nofrost: agsim\n\t@$(GOTEST) $(TEST_FLAGS_NOFROST) ", 1), job, 1},
		"job lacks tpm_simulator":     {covers, strings.Replace(job, ",tpm_simulator,", ",", 1), 1},
		"job runs no race-nofrost":    {covers, strings.Replace(job, "make race-nofrost", "make race", 1), 1},
		"job runs no go test":         {covers, strings.Replace(job, "go test", "true", 1), 1},
		"no race job":                 {covers, "jobs:\n  lint:\n    runs-on: x\n", 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := raceCoverageProblems(c.makefile, parseWorkflow(t, []byte(c.workflow))); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}

// backendTags are the tags make race and the race job's go test add to
// TEST_TAGS. A file built only without one of them never runs there.
var backendTags = []string{"pkcs8", "awskms", "gcpkms", "azurekv", "pkcs11", "vault"}

var makeRunsStubs = regexp.MustCompile(`(?m)^\s*(?:\S+=\S+\s+)*make\b.*\s(race-stubs)\b`)

// negatesBackend reports whether expr is false whenever some backend tag is
// set, counting a tag under an odd number of negations.
func negatesBackend(expr constraint.Expr, negated bool) bool {
	switch e := expr.(type) {
	case *constraint.NotExpr:
		return negatesBackend(e.X, !negated)
	case *constraint.AndExpr:
		return negatesBackend(e.X, negated) || negatesBackend(e.Y, negated)
	case *constraint.OrExpr:
		return negatesBackend(e.X, negated) || negatesBackend(e.Y, negated)
	case *constraint.TagExpr:
		return negated && slices.Contains(backendTags, e.Tag)
	}
	return false
}

// stubPackages returns, relative to root, the package directories under dirs
// holding a .go file whose //go:build line negates a backend tag. It skips
// directories exclude matches, testdata and nested modules, as go list does.
func stubPackages(root string, dirs []string, exclude *regexp.Regexp) ([]string, error) {
	found := map[string]bool{}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != dir {
					if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
						return filepath.SkipDir
					}
				}
				if d.Name() == "testdata" || exclude.MatchString(rel) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "package ") {
					break
				}
				if !constraint.IsGoBuild(line) {
					continue
				}
				expr, err := constraint.Parse(line)
				if err != nil {
					return fmt.Errorf("%s: %w", rel, err)
				}
				if negatesBackend(expr, false) {
					found[filepath.ToSlash(filepath.Dir(rel))] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return slices.Sorted(maps.Keys(found)), nil
}

// raceStubProblems lists what keeps the backend-stub files under stubs from
// running under -race: RACE_STUB_PKGS must name exactly those packages, make
// race-stubs must run them with -race and TEST_TAGS, and the race job must
// run make race-stubs.
func raceStubProblems(makefile string, wf workflow, stubs []string) []string {
	vars := makeVars(makefile)
	var listed []string
	for _, p := range strings.Fields(expandMakeVars(vars["RACE_STUB_PKGS"], vars)) {
		listed = append(listed, strings.TrimSuffix(strings.TrimPrefix(p, "./"), "/"))
	}
	var problems []string
	for _, dir := range stubs {
		if !slices.Contains(listed, dir) {
			problems = append(problems, fmt.Sprintf("RACE_STUB_PKGS lacks %s, whose backend-stub files never run under -race", dir))
		}
	}
	for _, dir := range listed {
		if !slices.Contains(stubs, dir) {
			problems = append(problems, fmt.Sprintf("RACE_STUB_PKGS names %s, which holds no backend-stub file", dir))
		}
	}

	if cmd, ok := goTestCommand(makefile, "race-stubs"); !ok {
		problems = append(problems, "no race-stubs target runs go test")
	} else {
		fields := strings.Fields(expandMakeVars(cmd, vars))
		if !slices.Contains(fields, "-race") {
			problems = append(problems, "race-stubs runs go test without -race")
		}
		if value, ok := tagsValue(expandMakeVars(cmd, vars)); !ok {
			problems = append(problems, "race-stubs passes no -tags")
		} else if got, want := tagSet(value, vars), tagSet(vars["TEST_TAGS"], vars); !maps.Equal(got, want) {
			problems = append(problems, fmt.Sprintf("race-stubs's -tags are %v, want TEST_TAGS %v", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want))))
		}
		for _, dir := range listed {
			if !slices.Contains(fields, "./"+dir) && !slices.Contains(fields, "./"+dir+"/") {
				problems = append(problems, "race-stubs does not run "+dir)
			}
		}
	}

	race, ok := wf.Jobs[raceJob]
	if !ok {
		return append(problems, "no "+raceJob+" job")
	}
	for _, step := range race.Steps {
		if makeRunsStubs.MatchString(strings.ReplaceAll(step.Run, "\\\n", " ")) {
			return problems
		}
	}
	return append(problems, raceJob+" job does not run make race-stubs")
}

func TestRaceDetectorCoversTheBackendStubs(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	vars := makeVars(string(makefile))
	exclude, err := regexp.Compile(strings.ReplaceAll(vars["UNIT_TEST_EXCLUDE"], "$$", "$"))
	if err != nil || vars["UNIT_TEST_EXCLUDE"] == "" {
		t.Fatalf("the Makefile's UNIT_TEST_EXCLUDE %q is no regexp: %v", vars["UNIT_TEST_EXCLUDE"], err)
	}
	stubs, err := stubPackages(repoRoot, []string{"pkg", "cmd", "sdk"}, exclude)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(stubs) == 0 {
		t.Fatal("found no backend-stub file: the walk is broken")
	}
	for _, p := range raceStubProblems(string(makefile), parseWorkflow(t, data), stubs) {
		t.Error(p)
	}
}

func TestStubPackagesFindsEachForm(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"pkg/a/a_stub.go":           "//go:build !pkcs11\n\npackage a\n",
		"pkg/b/b_test.go":           "//go:build !(vault && cgo)\n\npackage b\n",
		"pkg/c/c.go":                "//go:build pkcs11\n\npackage c\n",
		"pkg/d/d.go":                "//go:build !frost\n\npackage d\n",
		"pkg/e/e.go":                "package e\n\n//go:build !vault\n",
		"pkg/mocks/m.go":            "//go:build !awskms\n\npackage mocks\n",
		"pkg/f/testdata/t.go":       "//go:build !gcpkms\n\npackage t\n",
		"sdk/go/go.mod":             "module x\n",
		"sdk/go/s.go":               "//go:build !azurekv\n\npackage s\n",
		"cmd/g/g.go":                "//go:build linux && !pkcs8\n\npackage main\n",
		"cmd/g/notes.txt":           "//go:build !pkcs8\n",
		"pkg/h/h.go":                "//go:build !(!pkcs11)\n\npackage h\n",
		"pkg/i/deeper/i_vault_a.go": "//go:build !vault || !cgo\n\npackage deeper\n",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	got, err := stubPackages(root, []string{"pkg", "cmd", "sdk"}, regexp.MustCompile(`/mocks`))
	if err != nil {
		t.Fatalf("stubPackages: %v", err)
	}
	want := []string{"cmd/g", "pkg/a", "pkg/b", "pkg/i/deeper"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRaceStubsCatchEachForm(t *testing.T) {
	const covers = "comma := ,\nTEST_TAGS := codec_cbor tpm_simulator frost\n" +
		"TEST_FLAGS := -v -race -timeout 75m -tags=\"$(call go_tags,$(TEST_TAGS))\"\n" +
		"RACE_STUB_PKGS := ./pkg/a/ ./pkg/b/\n" +
		"race-stubs: agsim\n\t@$(GOTEST) $(TEST_FLAGS) $(RACE_STUB_PKGS)\n"
	const job = "jobs:\n  race:\n    steps:\n      - run: |\n          make race-nofrost\n" +
		"          GOMEMLIMIT=10GiB GOMAXPROCS=8 make race-stubs\n"
	stubs := []string{"pkg/a", "pkg/b"}
	cases := map[string]struct {
		makefile, workflow string
		stubs              []string
		want               int
	}{
		"covers":                  {covers, job, stubs, 0},
		"package not listed":      {covers, job, append(slices.Clone(stubs), "pkg/c"), 1},
		"stale entry":             {covers, job, stubs[:1], 1},
		"no race-stubs":           {strings.Replace(covers, "race-stubs:", "other:", 1), job, stubs, 1},
		"race-stubs without race": {strings.Replace(covers, "TEST_FLAGS := -v -race", "TEST_FLAGS := -v", 1), job, stubs, 1},
		"race-stubs with pkcs11":  {strings.Replace(covers, "$(GOTEST) $(TEST_FLAGS)", "$(GOTEST) -race -tags=\"$(call go_tags,$(TEST_TAGS) pkcs11)\"", 1), job, stubs, 1},
		"race-stubs one package":  {strings.Replace(covers, "$(RACE_STUB_PKGS)", "./pkg/a/", 1), job, stubs, 1},
		"job runs no race-stubs":  {covers, strings.Replace(job, "make race-stubs", "make race", 1), stubs, 1},
		"no race job":             {covers, "jobs:\n  lint:\n    runs-on: x\n", stubs, 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := raceStubProblems(c.makefile, parseWorkflow(t, []byte(c.workflow)), c.stubs); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}

// raceLane finds a go test or make race-* command on a line of the race job;
// raceBound finds a -p 2 bound on that line, as a flag or appended to GOFLAGS.
var (
	raceLane  = regexp.MustCompile(`\bgo test\b|\bmake\s+race-\S+`)
	raceBound = regexp.MustCompile(`(?:^|[\s"}=])-p(?:=|\s+)2(?:[\s"]|$)`)
)

// raceParallelismProblems reports each go test or make race-* line of the race
// job that runs without a -p 2 bound. in-toolchain-image.sh sets
// GOFLAGS=-p=<CPU count>, and GOMEMLIMIT is per process, so only the package
// bound keeps the -race test binaries of the REST/MCP/gRPC/server suites inside
// the runner (#2023).
func raceParallelismProblems(wf workflow) []string {
	race, ok := wf.Jobs[raceJob]
	if !ok {
		return []string{"no " + raceJob + " job"}
	}
	var problems []string
	lanes := 0
	for _, step := range race.Steps {
		for _, line := range strings.Split(strings.ReplaceAll(step.Run, "\\\n", " "), "\n") {
			cmd := raceLane.FindString(line)
			if cmd == "" {
				continue
			}
			lanes++
			if !raceBound.MatchString(line) {
				problems = append(problems, fmt.Sprintf("%s job runs %s without -p 2", raceJob, cmd))
			}
		}
	}
	if lanes == 0 {
		problems = append(problems, raceJob+" job runs no go test or make race-* line")
	}
	return problems
}

func TestRaceJobBoundsPackageParallelism(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range raceParallelismProblems(parseWorkflow(t, data)) {
		t.Error(p)
	}
}

func TestRaceParallelismCatchesEachForm(t *testing.T) {
	const job = "jobs:\n  race:\n    steps:\n      - run: |\n" +
		"          GOMEMLIMIT=10GiB go test -race -p 2 -timeout 75m \\\n            -tags=frost ./...\n" +
		"          GOFLAGS=\"${GOFLAGS:+$GOFLAGS }-p=2\" GOMEMLIMIT=10GiB make race-nofrost\n" +
		"          GOFLAGS=-p=2 make race-stubs\n"
	cases := map[string]struct {
		workflow string
		want     int
	}{
		"bounded":              {job, 0},
		"go test unbounded":    {strings.Replace(job, " -p 2", "", 1), 1},
		"go test -p 20":        {strings.Replace(job, " -p 2", " -p 20", 1), 1},
		"go test -p=2":         {strings.Replace(job, " -p 2", " -p=2", 1), 0},
		"make lane unbounded":  {strings.Replace(job, "GOFLAGS=\"${GOFLAGS:+$GOFLAGS }-p=2\" ", "", 1), 1},
		"both make lanes bare": {strings.ReplaceAll(strings.Replace(job, "GOFLAGS=\"${GOFLAGS:+$GOFLAGS }-p=2\" ", "", 1), "GOFLAGS=-p=2 ", ""), 2},
		"make lane -p=4":       {strings.Replace(job, "GOFLAGS=-p=2", "GOFLAGS=-p=4", 1), 1},
		"no lane":              {"jobs:\n  race:\n    steps:\n      - run: make agsim\n", 1},
		"no race job":          {"jobs:\n  lint:\n    runs-on: x\n", 1},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := raceParallelismProblems(parseWorkflow(t, []byte(c.workflow))); len(got) != c.want {
				t.Errorf("got %d problems, want %d: %q", len(got), c.want, got)
			}
		})
	}
}
