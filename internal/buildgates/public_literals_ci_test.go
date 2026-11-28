package buildgates

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

// publicLiteralsSecret is the Actions secret that carries the private
// pattern list (class<TAB>regex lines). make check-public-literals refuses
// without it (Makefile check-public-literals), so every ci.yml step that runs
// the target, alone or under make lint-gates, hands it over.
const publicLiteralsSecret = "${{ secrets.RELEASABILITY_PATTERNS }}"

// publicLiteralsForkOptOut is the one explicit opt-out the target accepts: a
// pull request without the secret (a fork) runs the other gates and skips
// this one with a notice. A push without the secret is an error.
const publicLiteralsForkOptOut = "PUBLIC_LITERALS_SKIP=fork-pr"

// publicLiteralsCallerProblems lists every step of wf that runs
// check-public-literals (directly or through make lint-gates) without the
// pattern input in its env, or without the explicit empty-secret rule.
func publicLiteralsCallerProblems(wf digestWorkflow) (problems []string, callers int) {
	jobs := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		jobs = append(jobs, name)
	}
	sort.Strings(jobs)
	for _, name := range jobs {
		for i, s := range wf.Jobs[name].Steps {
			if !strings.Contains(s.Run, "check-public-literals") && !strings.Contains(s.Run, "make lint-gates") {
				continue
			}
			callers++
			where := name + " step " + strconv.Itoa(i)
			if got := s.Env["RELEASABILITY_PATTERNS"]; got != publicLiteralsSecret {
				problems = append(problems, where+": env RELEASABILITY_PATTERNS = "+strconv.Quote(got)+", want "+publicLiteralsSecret)
			}
			if got := s.Env["EVENT"]; got != "${{ github.event_name }}" {
				problems = append(problems, where+": env EVENT = "+strconv.Quote(got)+", want ${{ github.event_name }}")
			}
			for _, want := range []string{
				`if [ -z "$RELEASABILITY_PATTERNS" ]; then`,
				`if [ "$EVENT" = push ]; then`,
				"::error::",
				"::notice::",
				publicLiteralsForkOptOut,
			} {
				if !strings.Contains(s.Run, want) {
					problems = append(problems, where+": the empty-secret rule lacks "+strconv.Quote(want))
				}
			}
		}
	}
	return problems, callers
}

// TestCIPublicLiteralsCallersPassThePatternInput: the three callers on main
// (go-xkms checks, make lint-gates, make lint-gates (native)) ran the target
// without RELEASABILITY_PATTERNS, so the gate refused in every run (Codex
// #2203 Makefile:4066, lane-verify hy1082i).
func TestCIPublicLiteralsCallersPassThePatternInput(t *testing.T) {
	problems, callers := publicLiteralsCallerProblems(readDigestWorkflow(t))
	if callers < 3 {
		t.Fatalf("ci.yml has %d steps running check-public-literals or make lint-gates, want at least 3", callers)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestPublicLiteralsCallerProblemsCatchAMissingInput(t *testing.T) {
	good := digestStep{
		Run: "if [ -z \"$RELEASABILITY_PATTERNS\" ]; then\n  if [ \"$EVENT\" = push ]; then echo ::error::x; exit 1; fi\n" +
			"  echo ::notice::y\n  export " + publicLiteralsForkOptOut + "\nfi\nmake lint-gates\n",
		Env: map[string]string{"RELEASABILITY_PATTERNS": publicLiteralsSecret, "EVENT": "${{ github.event_name }}"},
	}
	bare := digestStep{Run: "make check-public-literals\n"}
	wf := digestWorkflow{Jobs: map[string]digestJob{"lint": {Steps: []digestStep{good}}}}
	if p, n := publicLiteralsCallerProblems(wf); n != 1 || len(p) != 0 {
		t.Fatalf("wired step: callers %d, problems %q", n, p)
	}
	wf.Jobs["lint"] = digestJob{Steps: []digestStep{good, bare}}
	p, n := publicLiteralsCallerProblems(wf)
	if n != 2 || len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), "lint step 1: env RELEASABILITY_PATTERNS") {
		t.Fatalf("bare step: callers %d, problems %q", n, p)
	}
}
