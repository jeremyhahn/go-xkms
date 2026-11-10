package buildgates

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// DS-8210 (Company Agent m2450 (2)): the coverage shards and Integration are
// the two jobs a hosted runner does not carry, so on github.com they run on
// the self-hosted bigdisk runner. That runner is persistent, so it runs only
// code from this repository: a push to refs/heads/main, or a pull request
// whose head repository is this repository. A fork PR, another ref,
// workflow_dispatch and the schedule stay on ubuntu-latest. The tests below
// evaluate each job's runs-on expression; they do not look for the label.

const (
	runnerRepository = "jeremyhahn/go-xkms"
	runnerGitHub     = "https://github.com"
	runnerOtherForge = "https://git.example.test"
	// runnerScheduleIf is the v1.29.3 clause that keeps a schedule run's
	// bigdisk jobs off unless the schedule guard says `run`.
	runnerScheduleIf = "github.event_name != 'schedule' || needs.schedule-guard.outputs.verdict == 'run'"
	// runnerTrimRun and runnerTrimIf are the v1.22 cache trim step as the
	// image and build jobs write it.
	runnerTrimRun = `scripts/trim-ci-caches.sh "$CI_STACK_PREFIX" "$TOOLCHAIN_IMAGE"`
	runnerTrimIf  = "${{ !cancelled() && env.TOOLCHAIN_IMAGE != '' }}"
	// runnerCleanImages removes the images a run tagged; the Makefile derives
	// the tag from IT_PROJECT, so the step passes the job's own.
	runnerCleanImages = `make clean-run-images IT_PROJECT="$IT_PROJECT"`
)

var (
	// bigdiskJobs are the jobs that take the bigdisk runner.
	bigdiskJobs = []string{"coverage", "integration"}
	// bigdiskLabels is the label set of the owner's self-hosted runner.
	bigdiskLabels = []string{"self-hosted", "linux", "x64", "bigdisk"}
	hostedLabels  = []string{"ubuntu-latest"}
	// hostPackages matches a step that changes the persistent host.
	hostPackages = regexp.MustCompile(`\b(sudo|apt-get)\b`)
)

type runnerWorkflow struct {
	On   yaml.Node            `yaml:"on"`
	Jobs map[string]runnerJob `yaml:"jobs"`
}

type runnerJob struct {
	RunsOn yaml.Node    `yaml:"runs-on"`
	Needs  needsList    `yaml:"needs"`
	If     string       `yaml:"if"`
	Steps  []runnerStep `yaml:"steps"`
}

type runnerStep struct {
	Name string               `yaml:"name"`
	Uses string               `yaml:"uses"`
	If   string               `yaml:"if"`
	Run  string               `yaml:"run"`
	With map[string]yaml.Node `yaml:"with"`
}

func parseRunnerWorkflow(t *testing.T, data []byte) runnerWorkflow {
	t.Helper()
	var wf runnerWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	return wf
}

func readRunnerWorkflow(t *testing.T) runnerWorkflow {
	t.Helper()
	data, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	return parseRunnerWorkflow(t, data)
}

// runnerEvent is the part of the github context a runs-on expression reads.
type runnerEvent struct {
	serverURL string
	eventName string
	ref       string
	headRepo  string
}

func (e runnerEvent) context() map[string]string {
	return map[string]string{
		"github.server_url": e.serverURL,
		"github.event_name": e.eventName,
		"github.ref":        e.ref,
		"github.repository": runnerRepository,
		"github.event.pull_request.head.repo.full_name": e.headRepo,
	}
}

type exprToken struct {
	kind string // "string", "name" or the operator itself
	text string
}

// lexExpr splits an expression into string literals, names and the operators
// ==, !=, &&, ||, ( and ). Any other character is an error.
func lexExpr(src string) ([]exprToken, error) {
	var toks []exprToken
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')':
			toks = append(toks, exprToken{kind: string(c)})
			i++
		case strings.HasPrefix(src[i:], "=="), strings.HasPrefix(src[i:], "!="),
			strings.HasPrefix(src[i:], "&&"), strings.HasPrefix(src[i:], "||"):
			toks = append(toks, exprToken{kind: src[i : i+2]})
			i += 2
		case c == '\'':
			var b strings.Builder
			j := i + 1
			for {
				if j >= len(src) {
					return nil, fmt.Errorf("unterminated string at offset %d", i)
				}
				if src[j] == '\'' {
					if j+1 < len(src) && src[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(src[j])
				j++
			}
			toks = append(toks, exprToken{kind: "string", text: b.String()})
			i = j + 1
		case isNameByte(c) && (c < '0' || c > '9'):
			j := i
			for j < len(src) && (isNameByte(src[j]) || src[j] == '.') {
				j++
			}
			toks = append(toks, exprToken{kind: "name", text: src[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", c, i)
		}
	}
	return toks, nil
}

func isNameByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// exprParser evaluates the subset of the Actions expression language the
// bigdisk runs-on lines use: string literals, context names, ==, !=, &&, ||,
// parentheses and fromJSON of a literal string array. A value is a string, a
// bool or a []string. Both sides of && and || are evaluated, so an error in
// the branch an event does not take is still an error.
type exprParser struct {
	toks []exprToken
	pos  int
	ctx  map[string]string
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos].kind
	}
	return ""
}

func (p *exprParser) expect(kind string) (exprToken, error) {
	if p.peek() != kind {
		return exprToken{}, fmt.Errorf("token %d: want %s, got %q", p.pos, kind, p.peek())
	}
	p.pos++
	return p.toks[p.pos-1], nil
}

func exprTruthy(v any) bool {
	switch x := v.(type) {
	case string:
		return x != ""
	case bool:
		return x
	}
	return true
}

func (p *exprParser) or() (any, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "||" {
		p.pos++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		if !exprTruthy(l) {
			l = r
		}
	}
	return l, nil
}

func (p *exprParser) and() (any, error) {
	l, err := p.compare()
	if err != nil {
		return nil, err
	}
	for p.peek() == "&&" {
		p.pos++
		r, err := p.compare()
		if err != nil {
			return nil, err
		}
		if exprTruthy(l) {
			l = r
		}
	}
	return l, nil
}

func (p *exprParser) compare() (any, error) {
	l, err := p.primary()
	if err != nil {
		return nil, err
	}
	op := p.peek()
	if op != "==" && op != "!=" {
		return l, nil
	}
	p.pos++
	r, err := p.primary()
	if err != nil {
		return nil, err
	}
	ls, lok := l.(string)
	rs, rok := r.(string)
	if !lok || !rok {
		return nil, fmt.Errorf("token %d: %s compares %T with %T, want two strings", p.pos, op, l, r)
	}
	// The expression language compares strings without regard to case.
	return strings.EqualFold(ls, rs) == (op == "=="), nil
}

func (p *exprParser) primary() (any, error) {
	switch p.peek() {
	case "string":
		p.pos++
		return p.toks[p.pos-1].text, nil
	case "(":
		p.pos++
		v, err := p.or()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(")"); err != nil {
			return nil, err
		}
		return v, nil
	case "name":
		name := p.toks[p.pos].text
		p.pos++
		if name == "fromJSON" {
			if _, err := p.expect("("); err != nil {
				return nil, err
			}
			lit, err := p.expect("string")
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(")"); err != nil {
				return nil, err
			}
			var labels []string
			if err := json.Unmarshal([]byte(lit.text), &labels); err != nil || labels == nil {
				return nil, fmt.Errorf("fromJSON(%q): not a string array (%v)", lit.text, err)
			}
			return labels, nil
		}
		v, ok := p.ctx[name]
		if !ok {
			return nil, fmt.Errorf("unknown name %q", name)
		}
		return v, nil
	}
	return nil, fmt.Errorf("token %d: unexpected %q", p.pos, p.peek())
}

// runsOnLabels evaluates a runs-on scalar for one event and returns the
// runner labels it selects.
func runsOnLabels(runsOn string, ev runnerEvent) ([]string, error) {
	if !strings.Contains(runsOn, "${{") {
		return []string{runsOn}, nil
	}
	body, ok := strings.CutPrefix(runsOn, "${{")
	if ok {
		body, ok = strings.CutSuffix(body, "}}")
	}
	if !ok || strings.Contains(body, "${{") || strings.Contains(body, "}}") {
		return nil, fmt.Errorf("runs-on %q is not one ${{ }} expression", runsOn)
	}
	toks, err := lexExpr(body)
	if err != nil {
		return nil, err
	}
	p := &exprParser{toks: toks, ctx: ev.context()}
	v, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(toks) {
		return nil, fmt.Errorf("token %d: unexpected %q after the expression", p.pos, p.peek())
	}
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}, nil
		}
	case []string:
		if len(x) > 0 {
			return x, nil
		}
	}
	return nil, fmt.Errorf("runs-on evaluates to %#v, not a runner label or a label list", v)
}

// workflowTriggers lists the events of the workflow's on: block.
func workflowTriggers(on yaml.Node) []string {
	var events []string
	switch on.Kind {
	case yaml.ScalarNode:
		events = append(events, on.Value)
	case yaml.SequenceNode:
		for _, n := range on.Content {
			events = append(events, n.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			events = append(events, on.Content[i].Value)
		}
	}
	return events
}

func TestCIBigdiskRunner_OnlyThisRepositorysCode(t *testing.T) {
	wf := readRunnerWorkflow(t)
	cases := []struct {
		name string
		ev   runnerEvent
		want []string
	}{
		{"github.com push to main", runnerEvent{runnerGitHub, "push", "refs/heads/main", ""}, bigdiskLabels},
		{"github.com same-repo PR", runnerEvent{runnerGitHub, "pull_request", "refs/pull/7/merge", runnerRepository}, bigdiskLabels},
		{"github.com fork PR", runnerEvent{runnerGitHub, "pull_request", "refs/pull/7/merge", "mallory/go-xkms"}, hostedLabels},
		{"github.com PR with an empty head repository", runnerEvent{runnerGitHub, "pull_request", "refs/pull/7/merge", ""}, hostedLabels},
		{"github.com fork PR whose ref reads refs/heads/main", runnerEvent{runnerGitHub, "pull_request", "refs/heads/main", "mallory/go-xkms"}, hostedLabels},
		{"github.com push to refs/heads/main-x", runnerEvent{runnerGitHub, "push", "refs/heads/main-x", ""}, hostedLabels},
		{"github.com push to refs/tags/main", runnerEvent{runnerGitHub, "push", "refs/tags/main", ""}, hostedLabels},
		{"github.com workflow_dispatch", runnerEvent{runnerGitHub, "workflow_dispatch", "refs/heads/main", ""}, hostedLabels},
		{"github.com schedule", runnerEvent{runnerGitHub, "schedule", "refs/heads/main", ""}, hostedLabels},
		{"another forge push to main", runnerEvent{runnerOtherForge, "push", "refs/heads/main", ""}, []string{"bigdisk"}},
		{"another forge same-repo PR", runnerEvent{runnerOtherForge, "pull_request", "refs/pull/7/head", runnerRepository}, []string{"bigdisk"}},
		{"another forge fork PR", runnerEvent{runnerOtherForge, "pull_request", "refs/pull/7/head", "mallory/go-xkms"}, []string{"bigdisk"}},
		{"another forge workflow_dispatch", runnerEvent{runnerOtherForge, "workflow_dispatch", "refs/heads/main", ""}, []string{"bigdisk"}},
		{"another forge schedule", runnerEvent{runnerOtherForge, "schedule", "refs/heads/main", ""}, []string{"bigdisk"}},
	}
	for _, name := range bigdiskJobs {
		j, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("%s: no such job", name)
			continue
		}
		if j.RunsOn.Kind != yaml.ScalarNode {
			t.Errorf("%s: runs-on is not a scalar", name)
			continue
		}
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				got, err := runsOnLabels(j.RunsOn.Value, tc.ev)
				if err != nil {
					t.Fatalf("evaluate runs-on: %v", err)
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("runs on %v, want %v", got, tc.want)
				}
			})
		}
	}
}

func TestCIBigdiskRunner_JobsKeepThePersistentHostClean(t *testing.T) {
	wf := readRunnerWorkflow(t)
	if slices.Contains(workflowTriggers(wf.On), "pull_request_target") {
		t.Error("the workflow triggers on pull_request_target, which runs a fork's PR with this repository's token")
	}
	for _, name := range bigdiskJobs {
		j, ok := wf.Jobs[name]
		if !ok {
			t.Errorf("%s: no such job", name)
			continue
		}
		if !slices.Contains(j.Needs, scheduleGuardJob) {
			t.Errorf("%s: needs %v, want %s among them", name, []string(j.Needs), scheduleGuardJob)
		}
		if !strings.Contains(j.If, runnerScheduleIf) {
			t.Errorf("%s: if %q lacks %q", name, j.If, runnerScheduleIf)
		}
		checkouts := 0
		for i, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "actions/checkout@") {
				checkouts++
				if v := s.With["persist-credentials"]; v.Value != "false" {
					t.Errorf("%s: step %d (%s) has persist-credentials %q, want false", name, i, s.Uses, v.Value)
				}
			}
			if m := hostPackages.FindString(s.Run); m != "" {
				t.Errorf("%s: step %d (%s) runs %s on the persistent runner", name, i, s.Name, m)
			}
		}
		if checkouts == 0 {
			t.Errorf("%s: no actions/checkout step", name)
		}
	}
}

// stepsRunning returns the indexes of the steps whose run: carries one of the
// commands.
func stepsRunning(steps []runnerStep, commands ...string) []int {
	var at []int
	for i, s := range steps {
		for _, c := range commands {
			if strings.Contains(s.Run, c) {
				at = append(at, i)
				break
			}
		}
	}
	return at
}

// residueProblems reports what a bigdisk job would leave on the persistent
// runner, which a hosted VM threw away with itself: Integration's run-tagged
// images and the coverage shards' growth of the CI cache volumes.
func residueProblems(wf runnerWorkflow) []string {
	var problems []string

	integration := wf.Jobs["integration"].Steps
	teardowns := stepsRunning(integration, "docker compose", "make clean-test-containers", "make devcontainer-clean")
	if len(teardowns) < 2 {
		problems = append(problems, fmt.Sprintf("integration: %d compose tear-down steps, want at least 2", len(teardowns)))
	}
	switch clean := stepsRunning(integration, "make clean-run-images"); {
	case len(clean) != 1:
		problems = append(problems, fmt.Sprintf("integration: %d steps run make clean-run-images, want 1", len(clean)))
	default:
		s := integration[clean[0]]
		if strings.TrimSpace(s.Run) != runnerCleanImages {
			problems = append(problems, fmt.Sprintf("integration: step %q runs %q, want %q", s.Name, s.Run, runnerCleanImages))
		}
		if condition(s.If) != "always()" {
			problems = append(problems, fmt.Sprintf("integration: step %q has if %q, want always()", s.Name, s.If))
		}
		if len(teardowns) > 0 && clean[0] < teardowns[len(teardowns)-1] {
			problems = append(problems, fmt.Sprintf("integration: step %q comes before the compose tear-down %q", s.Name, integration[teardowns[len(teardowns)-1]].Name))
		}
	}

	coverage := wf.Jobs["coverage"].Steps
	shard := stepsRunning(coverage, "make coverage-shard")
	image := stepsRunning(coverage, "ci-registry.sh use toolchain")
	if len(shard) != 1 || len(image) != 1 {
		problems = append(problems, fmt.Sprintf("coverage: %d coverage-shard steps and %d toolchain image steps, want 1 of each", len(shard), len(image)))
	}
	switch trim := stepsRunning(coverage, "trim-ci-caches.sh"); {
	case len(trim) != 1:
		problems = append(problems, fmt.Sprintf("coverage: %d steps run scripts/trim-ci-caches.sh, want 1", len(trim)))
	default:
		s := coverage[trim[0]]
		if strings.TrimSpace(s.Run) != runnerTrimRun {
			problems = append(problems, fmt.Sprintf("coverage: step %q runs %q, want %q", s.Name, s.Run, runnerTrimRun))
		}
		if collapse(s.If) != runnerTrimIf {
			problems = append(problems, fmt.Sprintf("coverage: step %q has if %q, want %q", s.Name, s.If, runnerTrimIf))
		}
		if len(shard) == 1 && trim[0] > shard[0] {
			problems = append(problems, fmt.Sprintf("coverage: step %q comes after the shard runs", s.Name))
		}
		if len(image) == 1 && trim[0] < image[0] {
			problems = append(problems, fmt.Sprintf("coverage: step %q comes before the toolchain image it names", s.Name))
		}
	}
	return problems
}

func TestCIBigdiskRunner_JobsLeaveNoResidue(t *testing.T) {
	for _, p := range residueProblems(readRunnerWorkflow(t)) {
		t.Error(p)
	}
}

// TestCIBigdiskRunner_EvaluatorCanFail proves the evaluator rejects what it
// does not know instead of reading it as a pass.
func TestCIBigdiskRunner_EvaluatorCanFail(t *testing.T) {
	ev := runnerEvent{runnerGitHub, "push", "refs/heads/main", ""}
	for _, tc := range []struct{ name, runsOn string }{
		{"unknown context", "${{ github.actor == 'x' && 'bigdisk' || 'ubuntu-latest' }}"},
		{"unknown function", "${{ contains(github.ref, 'main') && 'bigdisk' || 'ubuntu-latest' }}"},
		{"negation", "${{ !github.ref && 'bigdisk' || 'ubuntu-latest' }}"},
		{"number", "${{ 1 == 1 && 'bigdisk' || 'ubuntu-latest' }}"},
		{"fromJSON of a name", "${{ fromJSON(github.ref) }}"},
		{"fromJSON of an object", "${{ fromJSON('{\"a\":1}') }}"},
		{"fromJSON of null", "${{ fromJSON('null') }}"},
		{"array compared", "${{ fromJSON('[\"a\"]') == 'a' && 'bigdisk' || 'ubuntu-latest' }}"},
		{"unterminated string", "${{ github.ref == 'refs/heads/main }}"},
		{"unbalanced parenthesis", "${{ (github.ref == 'refs/heads/main' && 'bigdisk' || 'ubuntu-latest' }}"},
		{"trailing token", "${{ 'bigdisk' 'ubuntu-latest' }}"},
		{"error in the branch not taken", "${{ 'bigdisk' || github.actor }}"},
		{"two expressions", "${{ 'bigdisk' }}${{ 'x' }}"},
		{"a bool", "${{ github.ref == 'refs/heads/main' }}"},
		{"an empty label", "${{ github.event.pull_request.head.repo.full_name }}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := runsOnLabels(tc.runsOn, ev); err == nil {
				t.Errorf("runs-on %q evaluates to %v, want an error", tc.runsOn, got)
			}
		})
	}
	for _, tc := range []struct {
		name, runsOn string
		want         []string
	}{
		{"plain label", "bigdisk", []string{"bigdisk"}},
		{"case-insensitive ==", "${{ github.event_name == 'PUSH' && 'a' || 'b' }}", []string{"a"}},
		{"&& binds tighter than ||", "${{ 'a' || 'b' && 'c' }}", []string{"a"}},
		{"quote escape", "${{ 'it''s' }}", []string{"it's"}},
		{"label list", "${{ github.ref != 'x' && fromJSON('[\"a\",\"b\"]') || 'c' }}", []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runsOnLabels(tc.runsOn, ev)
			if err != nil {
				t.Fatalf("evaluate %q: %v", tc.runsOn, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("runs-on %q evaluates to %v, want %v", tc.runsOn, got, tc.want)
			}
		})
	}
}
