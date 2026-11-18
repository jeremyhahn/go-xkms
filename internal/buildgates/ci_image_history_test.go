package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ruling 888: a pool build takes the LAN caches as BuildKit secrets, never as
// build arguments, whose values BuildKit records in the image history. A
// pool-built image may one day be pushed beyond the LAN, and ruling 887 covers
// its metadata. scripts/ci-image-history.sh reads an image's history and
// config and fails on any private (RFC 1918) address; it names the image and
// the history entry, never the address.

const imageHistoryScript = "scripts/ci-image-history.sh"

// fakeHistoryDocker answers `docker history` with $STUB_DIR/<n>.history and
// `docker image inspect` with $STUB_DIR/<n>.config, n being the image name
// with ":" and "/" turned to "_". A missing file is a docker failure.
// `docker images --filter=reference=<repo pattern>:<tag>` prints the refs
// $STUB_DIR/images lists for that filter.
const fakeHistoryDocker = `#!/bin/sh
for a; do image=$a; done
n=$(printf '%s' "$image" | tr ':/' '__')
case "$1 $2" in
"history --no-trunc") f="$STUB_DIR/$n.history" ;;
"image inspect") f="$STUB_DIR/$n.config" ;;
images\ --filter=reference=*)
	# the run's images: $STUB_DIR/images lists "<repo pattern>:<tag> <ref>" lines;
	# with $STUB_DIR/images-fail present the listing fails
	[ ! -f "$STUB_DIR/images-fail" ] || { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
	pattern=${2#--filter=reference=}
	[ -f "$STUB_DIR/images" ] || exit 0
	awk -v p="$pattern" '$1 == p { print $2 }' "$STUB_DIR/images"
	exit 0 ;;
*) echo "stub docker: unexpected $*" >&2; exit 99 ;;
esac
[ -f "$f" ] || { echo "Error: No such image: $image" >&2; exit 1; }
cat "$f"
`

const cleanHistory = `RUN |0 /bin/sh -c apk-mirror add --no-cache git # buildkit
RUN /bin/sh -c go install golang.org/x/tools@v0.30.1 # go1.27.4, libfoo 1.10.2.3
ENV PATH=/usr/local/go/bin:/usr/bin
ADD alpine-minirootfs-3.22.1-x86_64.tar.gz / # buildkit`

const cleanConfig = `{"Env":["PATH=/usr/bin","LISTEN=127.0.0.1:8080","PEER=172.32.0.5"],"Labels":{"v":"10.2"}}`

// historyStub writes the stub docker and files into a new directory.
func historyStub(t *testing.T, files map[string]string) string {
	t.Helper()
	stub := t.TempDir()
	if err := os.WriteFile(filepath.Join(stub, "docker"), []byte(fakeHistoryDocker), 0o700); err != nil { // #nosec G306 -- the stub must be executable
		t.Fatalf("write stub docker: %v", err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return stub
}

// stubEnv runs a command with the stub docker first on PATH.
func stubEnv(stub string) []string {
	return append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_DIR="+stub)
}

func runImageHistory(t *testing.T, files map[string]string, images ...string) (string, error) {
	t.Helper()
	stub := historyStub(t, files)
	script, err := filepath.Abs(filepath.Join(cachesRoot, imageHistoryScript))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script, images...) // #nosec G204 -- the repository's own script
	cmd.Env = stubEnv(stub)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestCIImageHistoryScript(t *testing.T) {
	clean := map[string]string{"a_1.history": cleanHistory, "a_1.config": cleanConfig}
	if out, err := runImageHistory(t, clean, "a:1"); err != nil {
		t.Fatalf("a clean image fails: %v\n%s", err, out)
	}
	for _, tc := range []struct {
		name, history, config, want string
	}{
		{name: "an apk mirror build argument", history: "RUN |1 APK_MIRROR=http://192.168.77.7:3143/alpine /bin/sh -c apk-mirror add git", config: cleanConfig, want: "history entry 1"},
		{name: "an apt proxy in a later entry", history: cleanHistory + "\nRUN |1 APT_PROXY=http://10.20.30.40:3142 /bin/sh -c apt-get update", config: cleanConfig, want: "history entry 5"},
		{name: "a 172.16/12 address", history: "ENV REG=172.20.0.5:5005", config: cleanConfig, want: "history entry 1"},
		{name: "an address at the start of an entry", history: "192.168.1.1", config: cleanConfig, want: "history entry 1"},
		{name: "an address in the config", history: cleanHistory, config: `{"Env":["GOPROXY=http://10.0.0.7:3000|https://proxy.golang.org"]}`, want: "config"},
		{name: "an address in a label", history: cleanHistory, config: `{"Labels":{"cache":"192.168.77.7"}}`, want: "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runImageHistory(t, map[string]string{"a_1.history": tc.history, "a_1.config": tc.config}, "a:1")
			if err == nil {
				t.Fatalf("an image carrying a private address passes:\n%s", out)
			}
			if !strings.Contains(out, "a:1") || !strings.Contains(out, tc.want) {
				t.Fatalf("the failure does not name the image and %q:\n%s", tc.want, out)
			}
			for _, addr := range []string{"192.168.", "10.20.30.40", "10.0.0.7", "172.20.0.5"} {
				if strings.Contains(out, addr) {
					t.Fatalf("the failure prints the address %s it should keep out of the log:\n%s", addr, out)
				}
			}
		})
	}
	t.Run("every image is read", func(t *testing.T) {
		files := map[string]string{"a_1.history": cleanHistory, "a_1.config": cleanConfig,
			"b_2.history": "RUN |1 APK_MIRROR=http://192.168.77.7:3143/alpine x", "b_2.config": cleanConfig}
		if out, err := runImageHistory(t, files, "a:1", "b:2"); err == nil || !strings.Contains(out, "b:2") {
			t.Fatalf("a private address in the second image passes (%v):\n%s", err, out)
		}
	})
	t.Run("an unreadable image fails closed", func(t *testing.T) {
		if out, err := runImageHistory(t, clean, "a:1", "missing:1"); err == nil || !strings.Contains(out, "missing:1") {
			t.Fatalf("an image docker cannot read passes (%v):\n%s", err, out)
		}
	})
	t.Run("no image is a usage error", func(t *testing.T) {
		if out, err := runImageHistory(t, clean); err == nil || !strings.Contains(out, "usage") {
			t.Fatalf("no image passes (%v):\n%s", err, out)
		}
	})
}

// runMake runs a make target in the repository with the stub docker.
func runMake(t *testing.T, stub string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("make", append([]string{"-s"}, args...)...) // #nosec G204 -- fixed targets
	cmd.Dir = cachesRoot
	cmd.Env = stubEnv(stub)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestCheckRunImages: make check-run-images reads the integration image and
// every image this run tagged (a repository on XKMS_IMAGE_REPOS carrying
// XKMS_IMAGE_TAG), the same selection clean-run-images removes, and fails
// on a private address in any of them. With no per-run tag there is no
// selection, and it fails rather than check nothing.
func TestCheckRunImages(t *testing.T) {
	clean := map[string]string{
		"images":                    "go-xkms-*:go-xkms-77 go-xkms-swtpm:go-xkms-77\ngo-xkms-*:go-xkms-77 go-xkms-server:go-xkms-77\ngo-quicbaas-server:go-xkms-77 go-quicbaas-server:go-xkms-77\ngo-xkms-*:other go-xkms-swtpm:other",
		"go-xkms-ci-it_abc.history": cleanHistory, "go-xkms-ci-it_abc.config": cleanConfig,
		"go-xkms-swtpm_go-xkms-77.history": cleanHistory, "go-xkms-swtpm_go-xkms-77.config": cleanConfig,
		"go-xkms-server_go-xkms-77.history": cleanHistory, "go-xkms-server_go-xkms-77.config": cleanConfig,
		"go-quicbaas-server_go-xkms-77.history": cleanHistory, "go-quicbaas-server_go-xkms-77.config": cleanConfig,
	}
	args := []string{"check-run-images", "XKMS_IMAGE_TAG=go-xkms-77", "IT_IMAGE=go-xkms-ci-it:abc"}
	if out, err := runMake(t, historyStub(t, clean), args...); err != nil {
		t.Fatalf("make check-run-images fails on clean images: %v\n%s", err, out)
	}
	for _, dirty := range []string{"go-xkms-ci-it_abc", "go-xkms-swtpm_go-xkms-77", "go-quicbaas-server_go-xkms-77"} {
		t.Run(dirty, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range clean {
				files[k] = v
			}
			files[dirty+".history"] = "RUN |1 APT_PROXY=http://192.168.77.7:3142 /bin/sh -c apt-get update"
			out, err := runMake(t, historyStub(t, files), args...)
			if err == nil {
				t.Fatalf("make check-run-images passes with a private address in %s:\n%s", dirty, out)
			}
			if strings.Contains(out, "192.168.") {
				t.Fatalf("make check-run-images prints the address:\n%s", out)
			}
		})
	}
	// integration and soak never build IT_IMAGE (Codex P1 on #2273): a daemon
	// without it is checked on the run's own images alone.
	t.Run("no integration image on the daemon", func(t *testing.T) {
		files := map[string]string{}
		for k, v := range clean {
			if !strings.HasPrefix(k, "go-xkms-ci-it_") {
				files[k] = v
			}
		}
		if out, err := runMake(t, historyStub(t, files), args...); err != nil {
			t.Fatalf("make check-run-images fails when the daemon holds no integration image: %v\n%s", err, out)
		}
		files["go-xkms-swtpm_go-xkms-77.history"] = "RUN |1 APT_PROXY=http://192.168.77.7:3142 /bin/sh -c apt-get update"
		if out, err := runMake(t, historyStub(t, files), args...); err == nil {
			t.Fatalf("make check-run-images passes a dirty run image when the daemon holds no integration image:\n%s", out)
		}
	})
	// A listing that fails selects nothing; the check must fail, not pass on
	// the integration image alone (Codex P1 on #2273).
	t.Run("the image listing fails", func(t *testing.T) {
		files := map[string]string{"images-fail": ""}
		for k, v := range clean {
			files[k] = v
		}
		if out, err := runMake(t, historyStub(t, files), args...); err == nil {
			t.Fatalf("make check-run-images passes when docker cannot list the run's images:\n%s", out)
		}
	})
	t.Run("nothing to check", func(t *testing.T) {
		if out, err := runMake(t, historyStub(t, map[string]string{}), args...); err == nil {
			t.Fatalf("make check-run-images passes with no image of the run on the daemon:\n%s", out)
		}
	})
	t.Run("no per-run tag", func(t *testing.T) {
		if out, err := runMake(t, historyStub(t, clean), "check-run-images", "XKMS_IMAGE_TAG=", "IT_IMAGE=go-xkms-ci-it:abc"); err == nil {
			t.Fatalf("make check-run-images passes with no per-run tag:\n%s", out)
		}
	})
	// A soak iteration runs its suite with IT_PROJECT=<job project>-<i>, and
	// the Makefile tags that iteration's images go-xkms-<run>-<i>: the check
	// given the same IT_PROJECT selects exactly those (Codex P1 on #2273).
	t.Run("an iteration's project selects its images", func(t *testing.T) {
		files := map[string]string{
			"images":                    "go-xkms-*:go-xkms-77-2 go-xkms-swtpm:go-xkms-77-2\ngo-xkms-*:go-xkms-77 go-xkms-swtpm:go-xkms-77",
			"go-xkms-ci-it_abc.history": cleanHistory, "go-xkms-ci-it_abc.config": cleanConfig,
			"go-xkms-swtpm_go-xkms-77.history": cleanHistory, "go-xkms-swtpm_go-xkms-77.config": cleanConfig,
			"go-xkms-swtpm_go-xkms-77-2.history": "RUN |1 APT_PROXY=http://192.168.77.7:3142 /bin/sh -c apt-get update",
			"go-xkms-swtpm_go-xkms-77-2.config":  cleanConfig,
		}
		if out, err := runMake(t, historyStub(t, files), "check-run-images", "IT_PROJECT=go-xkms-77-2", "IT_IMAGE=go-xkms-ci-it:abc"); err == nil || !strings.Contains(out, "go-xkms-77-2") {
			t.Fatalf("make check-run-images IT_PROJECT=go-xkms-77-2 does not read the iteration's image (%v):\n%s", err, out)
		}
	})
}

var (
	// suiteProject is the IT_PROJECT a suite step passes make; suiteVar
	// resolves a shell variable it names to that variable's assignment.
	suiteProject = regexp.MustCompile(`IT_PROJECT="([^"]+)"`)
	suiteVar     = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)
)

// suiteProjectOf is the project a suite step runs under, with a variable it
// names resolved from the step's own assignment (the soak's p="...").
func suiteProjectOf(run string) string {
	m := suiteProject.FindStringSubmatch(run)
	if m == nil {
		return "$IT_PROJECT"
	}
	if v := suiteVar.FindStringSubmatch(m[1]); v != nil {
		if a := regexp.MustCompile(`(?m)^\s*` + v[1] + `="([^"]+)"`).FindStringSubmatch(run); a != nil {
			return a[1]
		}
	}
	return m[1]
}

// poolCheckJobs are the ci.yml pool jobs that build images on GitHub: the
// integration suite and the soak build the integration image and the
// stack's service images (the other pool jobs take the toolchain image
// ci-images builds on a hosted runner).
var poolCheckJobs = []string{"integration", "soak"}

const checkRunImagesCall = "make check-run-images"

// checkStep is the part of a workflow step poolCheckProblems reads.
type checkStep struct {
	Name string `yaml:"name"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
}

// suiteRun is a step that builds the integration image and runs a suite on
// it: make with the job's IT_IMAGE (integration-test, the soak's target).
var suiteRun = regexp.MustCompile(`(?m)^\s*make .*IT_IMAGE="\$IT_IMAGE"`)

// poolCheckProblems: each of poolCheckJobs runs make check-run-images on a
// pool runner whatever the suite's result, after the step that builds and
// runs the suite and before any teardown removes the images.
func poolCheckProblems(body []byte) []string {
	var wf struct {
		Jobs map[string]struct {
			Steps []checkStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(body, &wf); err != nil {
		return []string{"ci.yml does not parse: " + err.Error()}
	}
	var problems []string
	for _, name := range poolCheckJobs {
		job, ok := wf.Jobs[name]
		if !ok {
			problems = append(problems, "ci.yml has no "+name+" job")
			continue
		}
		check := slices.IndexFunc(job.Steps, func(s checkStep) bool {
			return strings.Contains(s.Run, checkRunImagesCall)
		})
		if check < 0 {
			problems = append(problems, name+" never runs "+checkRunImagesCall)
			continue
		}
		s := job.Steps[check]
		if !strings.Contains(s.If, "runner.environment != 'github-hosted'") || !strings.Contains(s.If, "!cancelled()") {
			problems = append(problems, name+": the image check runs under "+s.If+"; want !cancelled() and runner.environment != 'github-hosted'")
		}
		suite := ""
		for _, before := range job.Steps[:check] {
			if suiteRun.MatchString(before.Run) {
				suite = before.Run
			}
			if strings.HasPrefix(before.Name, "Tear down") {
				problems = append(problems, name+": "+before.Name+" runs before the image check: the images would be gone")
			}
		}
		if suite == "" {
			problems = append(problems, name+": the image check runs before the suite builds the images")
			continue
		}
		// The check selects the images by the tag the Makefile derives from
		// IT_PROJECT, so it runs under the suite's project: the job's own
		// needs no argument; a per-iteration one is passed, in a loop.
		project := suiteProjectOf(suite)
		if project != "$IT_PROJECT" {
			if !strings.Contains(s.Run, `IT_PROJECT="`+project+`"`) {
				problems = append(problems, name+": the suite runs under IT_PROJECT="+project+" but the image check does not, so it selects another tag's images")
			}
			if strings.Contains(project, "$i") && !strings.Contains(s.Run, "for i in") {
				problems = append(problems, name+": the suite runs one project per iteration but the image check does not loop over them")
			}
		}
	}
	return problems
}

func TestPoolBuildsCheckTheirImages(t *testing.T) {
	for _, p := range poolCheckProblems([]byte(readCacheFile(t, ".github/workflows/ci.yml"))) {
		t.Error(p)
	}
	const cond = "${{ !cancelled() && runner.environment != 'github-hosted' }}"
	step := func(name, ifc, run string) string {
		s := "      - name: " + name + "\n"
		if ifc != "" {
			s += "        if: " + ifc + "\n"
		}
		return s + "        run: " + run + "\n"
	}
	wf := func(steps ...string) []byte {
		var b strings.Builder
		b.WriteString("jobs:\n")
		for _, j := range poolCheckJobs {
			b.WriteString("  " + j + ":\n    steps:\n" + strings.Join(steps, ""))
		}
		return []byte(b.String())
	}
	suite := step("Suite", "", `make "$SOAK_TARGET" IT_IMAGE="$IT_IMAGE"`)
	check := step("Check the images", cond, checkRunImagesCall+` IT_IMAGE="$IT_IMAGE"`)
	down := step("Tear down", "always()", "docker compose down")
	if p := poolCheckProblems(wf(suite, check, down)); len(p) != 0 {
		t.Fatalf("a correct workflow fails: %v", p)
	}
	for name, bad := range map[string][]byte{
		"no check":                     wf(suite, down),
		"the check after teardown":     wf(suite, down, check),
		"the check before the suite":   wf(check, suite, down),
		"no suite builds the image":    wf(step("Name", "", "make -s it-image"), check, down),
		"skipped when the suite fails": wf(suite, step("Check the images", "${{ runner.environment != 'github-hosted' }}", checkRunImagesCall), down),
		"run on hosted runners":        wf(suite, step("Check the images", "${{ !cancelled() }}", checkRunImagesCall), down),
	} {
		if len(poolCheckProblems(bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
	// The soak: one project per iteration, checked per iteration.
	soak := "      - name: Soak\n        run: |\n          p=\"$IT_PROJECT-$i\"\n          make \"$SOAK_TARGET\" IT_PROJECT=\"$p\" IT_IMAGE=\"$IT_IMAGE\"\n"
	loop := "      - name: Check the images\n        if: " + cond + "\n        run: |\n          for i in $(seq 1 3); do\n            " + checkRunImagesCall + " IT_IMAGE=\"$IT_IMAGE\" IT_PROJECT=\"$IT_PROJECT-$i\"\n          done\n"
	if p := poolCheckProblems(wf(soak, loop, down)); len(p) != 0 {
		t.Fatalf("a per-iteration check fails: %v", p)
	}
	for name, bad := range map[string][]byte{
		"the job's project for a per-iteration suite": wf(soak, check, down),
		"the iteration's project, no loop":            wf(soak, step("Check the images", cond, checkRunImagesCall+` IT_PROJECT="$IT_PROJECT-$i"`), down),
	} {
		if len(poolCheckProblems(bad)) == 0 {
			t.Errorf("%s passed", name)
		}
	}
}
