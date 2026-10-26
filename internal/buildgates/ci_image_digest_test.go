package buildgates

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The CI image handoff (ruling 169; the go-qrdb #1135 pattern). One job,
// ci-images, publishes the CI images from the release runner on a push to
// main and resolves main's copy on every other event. Every job that runs a
// stage in an image takes it from ci-images' outputs through
// `scripts/ci-registry.sh use` before its first stage, which pulls a digest
// and holds it, or builds the image locally with no push when the output is
// empty, and releases the hold in an if: always() teardown. Only ci-images
// writes to the registry, only under the push-to-main condition, and no env
// sets the release runner's own credential names (ruling 173).

const (
	imageProducer = "ci-images"
	// publishCond is CI_PUBLISH's value: a push to main alone publishes.
	publishCond = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
	publishTerm = "env.CI_PUBLISH == 'true'"
	resolveTerm = "env.CI_PUBLISH != 'true'"
	// producerRunsOn puts ci-images on the release runner for a push to main
	// and on the pull-request pool otherwise.
	producerRunsOn   = "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'release' || 'bigdisk' }}"
	digestRefPattern = `^[^@ ]+@sha256:[0-9a-f]{64}$`
	// consumerFloor is the number of jobs in ci.yml that run a stage in the
	// toolchain image; a parse that finds fewer has stopped seeing them.
	consumerFloor = 9
)

var (
	releaseLabel  = regexp.MustCompile(`(^|')release('|$)`)
	imageRebuild  = regexp.MustCompile(`docker image inspect "?\$\{?(TOOLCHAIN|IT)_|make (-s )?docker-build(-toolchain|-it)?\b|devcontainer/Dockerfile`)
	registryWrite = regexp.MustCompile(`ci-registry\.sh publish|docker (login|push)\b`)
	// runnerCredential is the release runner's credential contract (ruling
	// 173): the runner exports it, and no workflow env may set it.
	runnerCredential = []string{"RELEASE_REGISTRY", "RELEASE_REGISTRY_USER", "RELEASE_REGISTRY_TOKEN"}
)

// imageFamily is one CI image: the producer's output that names it, the
// variable its hold is recorded in, and the steps that run in it.
type imageFamily struct {
	name   string
	output string
	hold   string
	stage  *regexp.Regexp
	use    *regexp.Regexp
}

var imageFamilies = []imageFamily{
	{
		name:   "toolchain",
		output: "toolchain_ref",
		hold:   "TOOLCHAIN_HOLD",
		stage:  regexp.MustCompile(`scripts/(in-toolchain-image|trim-ci-caches)\.sh`),
		use:    regexp.MustCompile(`scripts/ci-registry\.sh use toolchain "\$([A-Z_]+)"`),
	},
	{
		name:   "it",
		output: "it_ref",
		hold:   "IT_HOLD",
		stage:  regexp.MustCompile(`docker save [^\n]*"\$IT_IMAGE"`),
		use:    regexp.MustCompile(`scripts/ci-registry\.sh use it "\$([A-Z_]+)"`),
	},
}

type digestWorkflow struct {
	Env  map[string]string    `yaml:"env"`
	Jobs map[string]digestJob `yaml:"jobs"`
}

type digestJob struct {
	RunsOn      string            `yaml:"runs-on"`
	Needs       needsList         `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Outputs     map[string]string `yaml:"outputs"`
	Env         map[string]string `yaml:"env"`
	Steps       []digestStep      `yaml:"steps"`
}

type digestStep struct {
	If  string            `yaml:"if"`
	Run string            `yaml:"run"`
	Env map[string]string `yaml:"env"`
}

func parseDigestWorkflow(t *testing.T, data []byte) digestWorkflow {
	t.Helper()
	var wf digestWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	return wf
}

// condHasTerm reports whether condition cond requires term: it names the
// term and offers no alternative to it.
func condHasTerm(cond, term string) bool {
	c := condition(cond)
	return strings.Contains(c, term) && !strings.Contains(c, "||") && !strings.Contains(c, "!(")
}

// credentialProblems names each release-runner credential env sets.
func credentialProblems(where string, env map[string]string) []string {
	var problems []string
	for _, name := range runnerCredential {
		if _, ok := env[name]; ok {
			problems = append(problems, fmt.Sprintf("%s: env sets %s, the release runner's own credential (ruling 173)", where, name))
		}
	}
	return problems
}

// producerProblems checks ci-images: where it runs, what it may write, and
// that each output is a step's validated reference.
func producerProblems(job digestJob) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(imageProducer+": "+format, args...))
	}
	if collapse(job.RunsOn) != producerRunsOn {
		add("runs on %q, want %q", job.RunsOn, producerRunsOn)
	}
	if job.Permissions["packages"] != "write" {
		add("has no packages: write to publish the images")
	}
	validated := false
	for _, fam := range imageFamilies {
		if !strings.Contains(job.Outputs[fam.output], "steps.") {
			add("output %s is %q, not a step's reference", fam.output, job.Outputs[fam.output])
		}
		published, resolved := false, false
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "ci-registry.sh publish "+fam.name) && condHasTerm(step.If, publishTerm) {
				published = true
			}
			if strings.Contains(step.Run, "ci-registry.sh resolve "+fam.name) && condHasTerm(step.If, resolveTerm) {
				resolved = true
			}
		}
		if !published {
			add("no step publishes the %s image under %q", fam.name, publishTerm)
		}
		if !resolved {
			add("no step resolves the %s image under %q", fam.name, resolveTerm)
		}
	}
	for _, step := range job.Steps {
		if registryWrite.MatchString(step.Run) && !condHasTerm(step.If, publishTerm) {
			add("publishes outside a push to main (if: %q)", step.If)
		}
		if strings.Contains(step.Run, digestRefPattern) {
			validated = true
		}
	}
	if !validated {
		add("no step validates the references against %s", digestRefPattern)
	}
	return problems
}

// consumerProblems checks job name's use of family fam's image. It reports
// whether the job runs a stage in that image at all.
func consumerProblems(name string, job digestJob, fam imageFamily) ([]string, bool) {
	stage := slices.IndexFunc(job.Steps, func(s digestStep) bool { return fam.stage.MatchString(s.Run) })
	if stage < 0 {
		return nil, false
	}
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(name+": "+format, args...))
	}
	if !slices.Contains(job.Needs, imageProducer) {
		add("does not need %s, whose %s it runs", imageProducer, fam.output)
	}
	if job.Permissions["packages"] != "read" {
		add("has no packages: read to pull the %s image", fam.name)
	}
	if releaseLabel.MatchString(job.RunsOn) {
		add("runs on the release runner, which serves the publish alone")
	}
	taken := false
	for _, step := range job.Steps[:stage] {
		m := fam.use.FindStringSubmatch(step.Run)
		if m == nil {
			continue
		}
		taken = true
		want := "${{ needs." + imageProducer + ".outputs." + fam.output + " }}"
		if got := collapse(step.Env[m[1]]); got != want {
			add("binds %s to %q, want %q", m[1], got, want)
		}
	}
	if !taken {
		add("runs a %s stage without taking the image from %s (scripts/ci-registry.sh use %s) before it", fam.name, imageProducer, fam.name)
	}
	released := slices.ContainsFunc(job.Steps[stage:], func(s digestStep) bool {
		return strings.Contains(s.If, "always()") && strings.Contains(s.Run, "ci-registry.sh release") && strings.Contains(s.Run, fam.hold)
	})
	if !released {
		add("never releases %s in an if: always() teardown", fam.hold)
	}
	return problems, true
}

// digestProblems lists every way workflow wf breaks the handoff, with floor
// the fewest toolchain consumers it must find.
func digestProblems(wf digestWorkflow, floor int) []string {
	var problems []string
	if got := collapse(wf.Env["CI_PUBLISH"]); got != publishCond {
		problems = append(problems, fmt.Sprintf("workflow: CI_PUBLISH is %q, want %q", got, publishCond))
	}
	problems = append(problems, credentialProblems("workflow", wf.Env)...)

	if producer, ok := wf.Jobs[imageProducer]; ok {
		problems = append(problems, producerProblems(producer)...)
	} else {
		problems = append(problems, imageProducer+": no such job; nothing publishes or resolves the CI images")
	}

	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)

	toolchainConsumers := 0
	for _, name := range names {
		job := wf.Jobs[name]
		problems = append(problems, credentialProblems(name, job.Env)...)
		for _, step := range job.Steps {
			problems = append(problems, credentialProblems(name, step.Env)...)
		}
		if name != imageProducer {
			if job.Permissions["packages"] == "write" {
				problems = append(problems, fmt.Sprintf("%s: has packages: write; only %s publishes", name, imageProducer))
			}
			for _, step := range job.Steps {
				if registryWrite.MatchString(step.Run) {
					problems = append(problems, fmt.Sprintf("%s: writes to the registry; only %s publishes", name, imageProducer))
				}
			}
		}

		consumer := false
		for _, fam := range imageFamilies {
			p, uses := consumerProblems(name, job, fam)
			problems = append(problems, p...)
			consumer = consumer || uses
			if uses && fam.name == "toolchain" {
				toolchainConsumers++
			}
		}
		if !consumer {
			continue
		}
		for _, step := range job.Steps {
			if imageRebuild.MatchString(step.Run) {
				problems = append(problems, fmt.Sprintf("%s: rebuilds or probes a CI image itself instead of taking it from %s", name, imageProducer))
			}
		}
	}
	if toolchainConsumers < floor {
		problems = append(problems, fmt.Sprintf("found %d toolchain consumers, want at least %d", toolchainConsumers, floor))
	}
	return problems
}

func TestCIImageDigest_EveryConsumerTakesTheProducersImage(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, p := range digestProblems(parseDigestWorkflow(t, data), consumerFloor) {
		t.Error(p)
	}
}

// TestCIImageDigest_RevertedConsumerFails reverts the image job to the
// inspect-or-rebuild step the handoff replaced and requires the gate to fail.
func TestCIImageDigest_RevertedConsumerFails(t *testing.T) {
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	take := `run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"`
	revert := `run: docker image inspect "$TOOLCHAIN_REF" >/dev/null 2>&1 || make docker-build-toolchain TOOLCHAIN_IMAGE="$TOOLCHAIN_REF"`
	src := string(data)
	if !strings.Contains(src, take) {
		t.Fatalf("%s has no %q to revert", ciWorkflow, take)
	}
	src = strings.Replace(src, take, revert, 1)
	problems := digestProblems(parseDigestWorkflow(t, []byte(src)), consumerFloor)
	for _, want := range []string{"image: runs a toolchain stage without", "image: rebuilds or probes"} {
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, want) }) {
			t.Errorf("reverted image job: want a problem %q, got %q", want, problems)
		}
	}
}

// digestFixture is a minimal workflow that hands both images over correctly.
const digestFixture = `
env:
  CI_PUBLISH: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
jobs:
  ci-images:
    runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'release' || 'bigdisk' }}
    permissions:
      contents: read
      packages: write
    outputs:
      toolchain_ref: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}
      it_ref: ${{ steps.publish.outputs.it_ref || steps.resolve.outputs.it_ref }}
    steps:
      - if: ${{ env.CI_PUBLISH == 'true' }}
        run: |
          scripts/ci-registry.sh publish toolchain
          scripts/ci-registry.sh publish it
      - if: ${{ env.CI_PUBLISH != 'true' }}
        run: |
          scripts/ci-registry.sh resolve toolchain
          scripts/ci-registry.sh resolve it
      - run: |
          re='^[^@ ]+@sha256:[0-9a-f]{64}$'
  lint:
    runs-on: bigdisk
    needs: ci-images
    permissions:
      packages: read
    steps:
      - env:
          TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}
        run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"
      - run: scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" make lint
      - if: always()
        run: scripts/ci-registry.sh release "${TOOLCHAIN_HOLD:-}"
  scan:
    runs-on: bigdisk
    needs: [changes, ci-images]
    permissions:
      packages: read
    steps:
      - env:
          TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}
        run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"
      - env:
          IT_REF: ${{ needs.ci-images.outputs.it_ref }}
        run: scripts/ci-registry.sh use it "$IT_REF" >> "$GITHUB_ENV"
      - run: |
          docker save -o it-image.tar "$IT_IMAGE"
          scripts/in-toolchain-image.sh "$TOOLCHAIN_IMAGE" trivy image --input it-image.tar
      - if: always()
        run: scripts/ci-registry.sh release "${TOOLCHAIN_HOLD:-}" "${IT_HOLD:-}"
`

func TestCIImageDigest_FixtureIsValid(t *testing.T) {
	wf := parseDigestWorkflow(t, []byte(digestFixture))
	if problems := digestProblems(wf, 2); len(problems) != 0 {
		t.Fatalf("valid fixture reported %q", problems)
	}
	problems := digestProblems(wf, 3)
	if len(problems) != 1 || !strings.Contains(problems[0], "found 2 toolchain consumers") {
		t.Fatalf("a floor above the consumers found: want one floor problem, got %q", problems)
	}
}

// TestCIImageDigest_CanFail makes one mutation of the fixture per case and
// requires the gate to report it.
func TestCIImageDigest_CanFail(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"publish on every event", publishCond, `"true"`, "workflow: CI_PUBLISH is"},
		{"producer missing", "  ci-images:\n", "  images:\n", "ci-images: no such job"},
		{"producer on the pull-request pool", producerRunsOn, "bigdisk", "ci-images: runs on"},
		{"producer cannot push", "packages: write", "packages: read", "no packages: write"},
		{"publish on a pull request", "if: ${{ env.CI_PUBLISH == 'true' }}", "if: ${{ env.CI_PUBLISH == 'true' || github.event_name == 'pull_request' }}", "publishes outside a push to main"},
		{"publish under a negation", "if: ${{ env.CI_PUBLISH == 'true' }}", "if: ${{ !(env.CI_PUBLISH == 'true') }}", "no step publishes the toolchain image"},
		{"no resolve", "scripts/ci-registry.sh resolve it", "true", "no step resolves the it image"},
		{"references not validated", "re='^[^@ ]+@sha256:[0-9a-f]{64}$'", "true", "no step validates"},
		{"output not a step's", "toolchain_ref: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}", "toolchain_ref: main", "output toolchain_ref"},
		{"consumer rebuilds", `run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"`, "run: make docker-build-toolchain", "lint: runs a toolchain stage without"},
		{"consumer probes and rebuilds", `run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"`, `run: docker image inspect "$TOOLCHAIN_REF" >/dev/null 2>&1 || make docker-build-toolchain TOOLCHAIN_IMAGE="$TOOLCHAIN_REF"`, "lint: rebuilds or probes"},
		{"consumer pulls a fixed tag", "TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}", "TOOLCHAIN_REF: ghcr.io/o/go-xkms-ci-toolchain:latest", "lint: binds TOOLCHAIN_REF"},
		{"consumer reads the wrong output", "TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}", "TOOLCHAIN_REF: ${{ needs.ci-images.outputs.it_ref }}", "lint: binds TOOLCHAIN_REF"},
		{"consumer without the producer", "    needs: ci-images\n", "    needs: changes\n", "lint: does not need ci-images"},
		{"consumer cannot pull", "    permissions:\n      packages: read\n", "    permissions:\n      contents: read\n", "lint: has no packages: read"},
		{"consumer can push", "    permissions:\n      packages: read\n", "    permissions:\n      packages: write\n", "lint: has packages: write"},
		{"consumer on the release runner", "    runs-on: bigdisk\n", "    runs-on: release\n", "lint: runs on the release runner"},
		{"consumer writes the registry", `"$TOOLCHAIN_IMAGE" make lint`, `"$TOOLCHAIN_IMAGE" make lint && docker push x`, "lint: writes to the registry"},
		{"hold released before the teardown", "      - if: always()\n        run: scripts/ci-registry.sh release \"${TOOLCHAIN_HOLD:-}\"\n", "      - run: scripts/ci-registry.sh release \"${TOOLCHAIN_HOLD:-}\"\n", "lint: never releases TOOLCHAIN_HOLD"},
		{"integration image hold never released", `"${TOOLCHAIN_HOLD:-}" "${IT_HOLD:-}"`, `"${TOOLCHAIN_HOLD:-}"`, "scan: never releases IT_HOLD"},
		{"integration image not taken", `run: scripts/ci-registry.sh use it "$IT_REF" >> "$GITHUB_ENV"`, "run: true", "scan: runs a it stage without"},
		{"release credential in a step", "          IT_REF: ${{ needs.ci-images.outputs.it_ref }}\n", "          IT_REF: ${{ needs.ci-images.outputs.it_ref }}\n          RELEASE_REGISTRY_TOKEN: x\n", "scan: env sets RELEASE_REGISTRY_TOKEN"},
		{"release credential in the workflow", "env:\n  CI_PUBLISH:", "env:\n  RELEASE_REGISTRY: x\n  CI_PUBLISH:", "workflow: env sets RELEASE_REGISTRY,"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(digestFixture, tc.old) {
				t.Fatalf("fixture has no %q to replace", tc.old)
			}
			src := strings.Replace(digestFixture, tc.old, tc.new, 1)
			problems := digestProblems(parseDigestWorkflow(t, []byte(src)), 2)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
			}
		})
	}
}
