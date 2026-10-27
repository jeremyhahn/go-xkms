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
// sets the release runner's own credential names (ruling 173). Every read
// step hands the script the run's token: a read of the forge's public
// agent-ci-images namespace is anonymous (go-xkms #1730), and a read of GHCR,
// where a package is private when published, logs in with the token. No read
// uses buildx imagetools.

const (
	imageProducer = "ci-images"
	// publishCond is CI_PUBLISH's value: a push to main alone publishes.
	publishCond = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
	publishTerm = "env.CI_PUBLISH == 'true'"
	resolveTerm = "env.CI_PUBLISH != 'true'"
	// publishStep and resolveStep are the ids of the producer's steps whose
	// outputs the producer's outputs name.
	publishStep = "publish"
	resolveStep = "resolve"
	// producerRunsOn puts ci-images on the release runner for a push to main
	// and on the pull-request pool otherwise.
	producerRunsOn   = "${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'release' || 'bigdisk' }}"
	digestRefPattern = `^[^@ ]+@sha256:[0-9a-f]{64}$`
	// consumerFloor is the number of jobs in ci.yml that run a stage in the
	// toolchain image; a parse that finds fewer has stopped seeing them.
	consumerFloor = 9
	// registryScript hands the images over; forgeNamespace is the forge's
	// public namespace main publishes them under (go-xkms #1730), which
	// ci.yml alone names, as CI_REGISTRY_OWNER (ownerCond; ruling 217).
	registryScript = "../../scripts/ci-registry.sh"
	forgeNamespace = "agent-ci-images"
	// forgeAnonymous is read_credential's guard that reads any registry but
	// GHCR, the forge's public namespace, with no credential (ruling 217).
	forgeAnonymous = `[ "$host" = ghcr.io ] || return 0`
	ownerCond      = "${{ github.server_url != 'https://github.com' && '" + forgeNamespace + "' || '' }}"
)

var (
	releaseLabel  = regexp.MustCompile(`(^|')release('|$)`)
	imageRebuild  = regexp.MustCompile(`docker image inspect "?\$\{?(TOOLCHAIN|IT)_|make (-s )?docker-build(-toolchain|-it)?\b|devcontainer/Dockerfile`)
	registryWrite = regexp.MustCompile(`ci-registry\.sh publish|docker (login|push)\b`)
	// runnerCredential is the release runner's credential contract (ruling
	// 173): the runner exports it, and no workflow env may set it.
	runnerCredential = []string{"RELEASE_REGISTRY", "RELEASE_REGISTRY_USER", "RELEASE_REGISTRY_TOKEN"}
	// readCredential is the run's token: every read step hands it to the
	// script, which logs in with it on GHCR, where a package is private when
	// published, and reads the forge's public namespace anonymously.
	readCredential = []string{"CI_REGISTRY_USER", "CI_REGISTRY_TOKEN"}
	// registryRead is a step that reads main's images.
	registryRead = regexp.MustCompile(`ci-registry\.sh (resolve|use)\b`)
	// loginFuncs are the functions of ci-registry.sh that run docker login,
	// and credentialFuncs those that name the run's token.
	loginFuncs      = []string{"push_login", "read_login"}
	credentialFuncs = []string{"push_login", "read_credential"}
	// imagetools speaks https alone, so it never reaches a forge registry
	// served over http; the reads use the registry API and docker pull.
	imagetools = regexp.MustCompile(`\bimagetools\b`)
	shellFunc  = regexp.MustCompile(`^([a-z_]+)\(\) \{$`)
)

// imageFamily is one CI image: the producer's output that names it, the
// variable the producer validates it in, the variable its hold is recorded
// in, and the steps that run in it.
type imageFamily struct {
	name   string
	output string
	ref    string
	hold   string
	stage  *regexp.Regexp
	use    *regexp.Regexp
}

var imageFamilies = []imageFamily{
	{
		name:   "toolchain",
		output: "toolchain_ref",
		ref:    "TOOLCHAIN_REF",
		hold:   "TOOLCHAIN_HOLD",
		stage:  regexp.MustCompile(`scripts/(in-toolchain-image|trim-ci-caches)\.sh`),
		use:    regexp.MustCompile(`scripts/ci-registry\.sh use toolchain "\$([A-Z_]+)"`),
	},
	{
		name:   "it",
		output: "it_ref",
		ref:    "IT_REF",
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
	ID  string            `yaml:"id"`
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

// writesOutput reports whether script run writes output name to the step's
// outputs.
func writesOutput(run, name string) bool {
	return strings.Contains(run, `echo "`+name+`=$ref" >> "$GITHUB_OUTPUT"`)
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
	for _, fam := range imageFamilies {
		// Both paths feed one output: publish on a push to main, resolve on
		// any other event. A step counts only under its id, writing that
		// output.
		want := "${{ steps." + publishStep + ".outputs." + fam.output + " || steps." + resolveStep + ".outputs." + fam.output + " }}"
		if got := collapse(job.Outputs[fam.output]); got != want {
			add("output %s is %q, want %q", fam.output, got, want)
		}
		published, resolved, validated := false, false, false
		for _, step := range job.Steps {
			if step.ID == publishStep && strings.Contains(step.Run, "ci-registry.sh publish "+fam.name) &&
				writesOutput(step.Run, fam.output) && condHasTerm(step.If, publishTerm) {
				published = true
			}
			if step.ID == resolveStep && strings.Contains(step.Run, "ci-registry.sh resolve "+fam.name) &&
				writesOutput(step.Run, fam.output) && condHasTerm(step.If, resolveTerm) {
				resolved = true
			}
			if strings.Contains(step.Run, digestRefPattern) && collapse(step.Env[fam.ref]) == want {
				validated = true
			}
		}
		if !published {
			add("no step publishes the %s image under %q as steps.%s.outputs.%s", fam.name, publishTerm, publishStep, fam.output)
		}
		if !resolved {
			add("no step resolves the %s image under %q as steps.%s.outputs.%s", fam.name, resolveTerm, resolveStep, fam.output)
		}
		if !validated {
			add("no step validates %s (%s) against %s", fam.ref, want, digestRefPattern)
		}
	}
	for _, step := range job.Steps {
		if registryWrite.MatchString(step.Run) && !condHasTerm(step.If, publishTerm) {
			add("publishes outside a push to main (if: %q)", step.If)
		}
		if step.ID != publishStep {
			problems = append(problems, readProblems(imageProducer, step)...)
		}
	}
	return problems
}

// readProblems reports a step that reads main's images (ci-registry.sh
// resolve or use) without the run's token, which a GHCR read logs in with,
// or any step that reads with buildx imagetools.
func readProblems(where string, step digestStep) []string {
	var problems []string
	if registryRead.MatchString(step.Run) {
		for _, name := range readCredential {
			if step.Env[name] == "" {
				problems = append(problems, fmt.Sprintf("%s: env does not set %s, which a GHCR read logs in with", where, name))
			}
		}
	}
	if imagetools.MatchString(step.Run) {
		problems = append(problems, fmt.Sprintf("%s: reads with buildx imagetools, not the registry API and docker pull", where))
	}
	return problems
}

// registryScriptProblems reports a ci-registry.sh whose reads leave main's
// forge namespace or log in: forgeNamespace is not written, since ci.yml's
// CI_REGISTRY_OWNER names it; every repository and every pull is under
// registry_owner, which takes CI_REGISTRY_OWNER; docker
// login lives in push_login and read_login alone, and the run's token in
// push_login and read_credential alone; read_credential reads the forge
// anonymously, and resolve and pull_ref read GHCR with the run's token; and
// no code line names imagetools.
func registryScriptProblems(src string) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("ci-registry.sh: "+format, args...))
	}
	funcs := map[string]string{}
	fn, written := "", 0
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if m := shellFunc.FindStringSubmatch(line); m != nil {
			fn = m[1]
			continue
		}
		if line == "}" {
			fn = ""
			continue
		}
		funcs[fn] += line + "\n"
		written += strings.Count(line, forgeNamespace)
		where := fn
		if where == "" {
			where = "the top level"
		}
		if !slices.Contains(loginFuncs, fn) && strings.Contains(line, "docker login") {
			add("%s logs in; push_login and read_login alone log in", where)
		}
		if !slices.Contains(credentialFuncs, fn) && slices.ContainsFunc(readCredential, func(name string) bool { return strings.Contains(line, name) }) {
			add("%s takes the run's token; push_login and read_credential alone take it", where)
		}
		if imagetools.MatchString(line) {
			add("%s reads with buildx imagetools, not the registry API and docker pull", where)
		}
	}
	if written != 0 {
		add("%s is written %d times, want none: ci.yml names it, as CI_REGISTRY_OWNER", forgeNamespace, written)
	}
	if !strings.Contains(funcs["registry_owner"], "var=CI_REGISTRY_OWNER") {
		add("registry_owner does not take CI_REGISTRY_OWNER")
	}
	if !strings.Contains(funcs["main_repo"], "$(registry_owner)") {
		add("main_repo does not name its repository under registry_owner")
	}
	if !strings.Contains(funcs["pull_ref"], "$(registry_owner)") {
		add("pull_ref pulls a reference outside registry_owner")
	}
	if !strings.Contains(funcs["read_credential"], forgeAnonymous) {
		add("read_credential does not read the forge anonymously")
	}
	if !strings.Contains(funcs["read_login"], `read_credential "$host"`) {
		add("read_login does not take read_credential's credential")
	}
	if !strings.Contains(funcs["pull_ref"], `read_login "$host"`) {
		add("pull_ref does not log in to GHCR with the run's token")
	}
	if !strings.Contains(funcs["resolve"], `read_credential "$host"`) {
		add("resolve does not read GHCR with the run's token")
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
	if got := collapse(wf.Env["CI_REGISTRY_OWNER"]); got != ownerCond {
		problems = append(problems, fmt.Sprintf("workflow: CI_REGISTRY_OWNER is %q, want %q", got, ownerCond))
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
			problems = append(problems, readProblems(name, step)...)
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
  CI_REGISTRY_OWNER: ${{ github.server_url != 'https://github.com' && 'agent-ci-images' || '' }}
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
      - id: publish
        if: ${{ env.CI_PUBLISH == 'true' }}
        run: |
          ref=$(scripts/ci-registry.sh publish toolchain)
          echo "toolchain_ref=$ref" >> "$GITHUB_OUTPUT"
          ref=$(scripts/ci-registry.sh publish it)
          echo "it_ref=$ref" >> "$GITHUB_OUTPUT"
      - id: resolve
        if: ${{ env.CI_PUBLISH != 'true' }}
        env:
          CI_REGISTRY_USER: ${{ github.actor }}
          CI_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ref=$(scripts/ci-registry.sh resolve toolchain)
          echo "toolchain_ref=$ref" >> "$GITHUB_OUTPUT"
          ref=$(scripts/ci-registry.sh resolve it)
          echo "it_ref=$ref" >> "$GITHUB_OUTPUT"
      - env:
          TOOLCHAIN_REF: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}
          IT_REF: ${{ steps.publish.outputs.it_ref || steps.resolve.outputs.it_ref }}
        run: |
          re='^[^@ ]+@sha256:[0-9a-f]{64}$'
  lint:
    runs-on: bigdisk
    needs: ci-images
    permissions:
      packages: read
    steps:
      - env:
          TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}
          CI_REGISTRY_USER: ${{ github.actor }}
          CI_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
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
          CI_REGISTRY_USER: ${{ github.actor }}
          CI_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: scripts/ci-registry.sh use toolchain "$TOOLCHAIN_REF" >> "$GITHUB_ENV"
      - env:
          IT_REF: ${{ needs.ci-images.outputs.it_ref }}
          CI_REGISTRY_USER: ${{ github.actor }}
          CI_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
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
		{"images under the repository's owner", "  CI_REGISTRY_OWNER: " + ownerCond + "\n", "", "workflow: CI_REGISTRY_OWNER is"},
		{"images under another namespace", ownerCond, "${{ github.server_url != 'https://github.com' && 'jeremyhahn' || '' }}", "workflow: CI_REGISTRY_OWNER is"},
		{"producer missing", "  ci-images:\n", "  images:\n", "ci-images: no such job"},
		{"producer on the pull-request pool", producerRunsOn, "bigdisk", "ci-images: runs on"},
		{"producer cannot push", "packages: write", "packages: read", "no packages: write"},
		{"publish on a pull request", "if: ${{ env.CI_PUBLISH == 'true' }}", "if: ${{ env.CI_PUBLISH == 'true' || github.event_name == 'pull_request' }}", "publishes outside a push to main"},
		{"publish under a negation", "if: ${{ env.CI_PUBLISH == 'true' }}", "if: ${{ !(env.CI_PUBLISH == 'true') }}", "no step publishes the toolchain image"},
		{"no resolve", "scripts/ci-registry.sh resolve it", "true", "no step resolves the it image"},
		{"references not validated", "re='^[^@ ]+@sha256:[0-9a-f]{64}$'", "true", "no step validates"},
		{"output not a step's", "toolchain_ref: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}", "toolchain_ref: main", "output toolchain_ref"},
		{"output drops the pull-request path", "it_ref: ${{ steps.publish.outputs.it_ref || steps.resolve.outputs.it_ref }}", "it_ref: ${{ steps.publish.outputs.it_ref }}", "output it_ref"},
		{"output drops the main path", "toolchain_ref: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}", "toolchain_ref: ${{ steps.resolve.outputs.toolchain_ref }}", "output toolchain_ref"},
		{"publish step under another id", "- id: publish\n", "- id: push\n", "no step publishes the toolchain image"},
		{"resolve step under another id", "- id: resolve\n", "- id: lookup\n", "no step resolves the it image"},
		{"publish writes another output", "ref=$(scripts/ci-registry.sh publish toolchain)\n          echo \"toolchain_ref=$ref\"", "ref=$(scripts/ci-registry.sh publish toolchain)\n          echo \"toolchain=$ref\"", "no step publishes the toolchain image"},
		{"resolve never writes its output", "ref=$(scripts/ci-registry.sh resolve it)\n          echo \"it_ref=$ref\" >> \"$GITHUB_OUTPUT\"", "ref=$(scripts/ci-registry.sh resolve it)\n          echo \"it_ref=$ref\"", "no step resolves the it image"},
		{"validation reads the pull-request path alone", "TOOLCHAIN_REF: ${{ steps.publish.outputs.toolchain_ref || steps.resolve.outputs.toolchain_ref }}", "TOOLCHAIN_REF: ${{ steps.resolve.outputs.toolchain_ref }}", "no step validates TOOLCHAIN_REF"},
		{"validation without the integration image", "          IT_REF: ${{ steps.publish.outputs.it_ref || steps.resolve.outputs.it_ref }}\n", "", "no step validates IT_REF"},
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
		{"resolve without the run's token", "          CI_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", "", "ci-images: env does not set CI_REGISTRY_TOKEN, which a GHCR read logs in with"},
		{"resolve logs in", "scripts/ci-registry.sh resolve it)", "scripts/ci-registry.sh resolve it; docker login x)", "ci-images: publishes outside a push to main"},
		{"resolve reads with imagetools", "scripts/ci-registry.sh resolve it)", "docker buildx imagetools inspect x)", "ci-images: reads with buildx imagetools"},
		{"consumer without the run's token", "          TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}\n          CI_REGISTRY_USER: ${{ github.actor }}\n", "          TOOLCHAIN_REF: ${{ needs.ci-images.outputs.toolchain_ref }}\n", "lint: env does not set CI_REGISTRY_USER, which a GHCR read logs in with"},
		{"consumer logs in", `"$TOOLCHAIN_IMAGE" make lint`, `"$TOOLCHAIN_IMAGE" make lint && docker login x`, "lint: writes to the registry"},
		{"consumer reads with imagetools", `"$TOOLCHAIN_IMAGE" make lint`, `"$TOOLCHAIN_IMAGE" make lint && docker buildx imagetools inspect x`, "lint: reads with buildx imagetools"},
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

// TestCIImageDigest_RegistryReads holds scripts/ci-registry.sh to reading
// main's images from registry_owner's namespace with no imagetools,
// anonymously on the forge (go-xkms #1730, ruling 217) and with the run's
// token on GHCR, where a package is private when published (ruling 169).
func TestCIImageDigest_RegistryReads(t *testing.T) {
	data, err := os.ReadFile(registryScript)
	if err != nil {
		t.Fatalf("read %s: %v", registryScript, err)
	}
	for _, p := range registryScriptProblems(string(data)) {
		t.Error(p)
	}
}

// TestCIImageDigest_RegistryScriptCanFail proves the script check catches
// each way a read can leave the namespace, log in or return to imagetools.
func TestCIImageDigest_RegistryScriptCanFail(t *testing.T) {
	data, err := os.ReadFile(registryScript)
	if err != nil {
		t.Fatalf("read %s: %v", registryScript, err)
	}
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"namespace written in the script", `printf '%s/%s/go-xkms-ci-%s\n' "$2" "$namespace" "$1"`, `printf '%s/agent-ci-images/go-xkms-ci-%s\n' "$2" "$1"`, "agent-ci-images is written 1 times"},
		{"owner override ignored", `[ -z "${CI_REGISTRY_OWNER:-}" ] || var=CI_REGISTRY_OWNER` + "\n", "", "registry_owner does not take CI_REGISTRY_OWNER"},
		{"repository outside the owner", `namespace=$(registry_owner) || exit 1`, `namespace=$GITHUB_REPOSITORY_OWNER`, "main_repo does not name its repository under registry_owner"},
		{"pull outside the namespace", `repos=$host/$(registry_owner)/`, `repos=$host/`, "pull_ref pulls a reference outside registry_owner"},
		{"forge read takes the run's token", forgeAnonymous + "\n", "", "read_credential does not read the forge anonymously"},
		{"pull skips the GHCR login", "  private_config\n  read_login \"$host\"\n", "  private_config\n", "pull_ref does not log in to GHCR"},
		{"resolve reads GHCR anonymously", "  read_credential \"$host\"\n  if [ -n \"$user\" ]; then", "  if [ -n \"$user\" ]; then", "resolve does not read GHCR with the run's token"},
		{"read login ignores the credential", "  read_credential \"$host\"\n  [ -n \"$user\" ] || return 0", "  [ -n \"$user\" ] || return 0", "read_login does not take read_credential's credential"},
		{"pull logs in itself", "  private_config\n  read_login \"$host\"\n", "  private_config\n  printf '%s' \"$CI_REGISTRY_TOKEN\" | docker login \"$host\" -u \"$CI_REGISTRY_USER\" --password-stdin\n", "pull_ref logs in"},
		{"resolve returns to imagetools", `    remote_digest "$target" "$scheme" || rc=$?`, `  digest=$(docker buildx imagetools inspect "$target" --format '{{json .Manifest}}') || rc=$?`, "resolve reads with buildx imagetools"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(string(data), tc.old) {
				t.Fatalf("%s has no %q to replace", registryScript, tc.old)
			}
			problems := registryScriptProblems(strings.Replace(string(data), tc.old, tc.new, 1))
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("want a problem containing %q, got %q", tc.want, problems)
			}
		})
	}
}
