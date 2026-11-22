package buildgates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stubAPICurl answers the code-review steps' API calls from files in
// STUB_DIR named by stubKey(method, path): the n-th call of a key reads
// <key>.<n> when that file exists, else <key>; a key with no file answers
// HTTP 404. Each call is logged to STUB_LOG as "METHOD path".
const stubAPICurl = `#!/bin/sh
out=; url=; method=GET
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    -X) method=$2; shift ;;
    -w|-H|--max-time|--retry|--proto) shift ;;
    http://*|https://*) url=$1 ;;
  esac
  shift
done
path=${url#"$REPO_API"}
echo "$method $path" >> "$STUB_LOG"
key=$(printf '%s %s' "$method" "$path" | tr -c 'A-Za-z0-9' '_')
n=$(( $(cat "$STUB_DIR/count.$key" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_DIR/count.$key"
if [ -f "$STUB_DIR/$key.$n" ]; then f="$STUB_DIR/$key.$n"; else f="$STUB_DIR/$key"; fi
if [ -f "$f" ]; then cat "$f" > "$out"; printf 200; else echo '{}' > "$out"; printf 404; fi
`

// stubKey is the file name stubAPICurl reads for a call.
func stubKey(method, path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, method+" "+path)
}

// stepRun is one run of a code-review step against stubAPICurl.
type stepRun struct {
	output string
	calls  []string
	code   int
}

// posts are the run's write calls.
func (r stepRun) posts() []string {
	var p []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, "POST ") {
			p = append(p, c)
		}
	}
	return p
}

// runCodeReviewStep runs script under bash with stubAPICurl first on PATH.
// responses maps "METHOD path" (path below REPO_API, a sequence number
// suffixed as "#n" for the n-th call only) to the body answered with HTTP 200.
func runCodeReviewStep(t *testing.T, script string, responses map[string]string, env ...string) stepRun {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	stub := filepath.Join(dir, "stub")
	for _, d := range []string{bin, stub} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(stubAPICurl), 0o755); err != nil {
		t.Fatal(err)
	}
	for call, body := range responses {
		method, path, ok := strings.Cut(call, " ")
		if !ok {
			t.Fatalf("response key %q is not \"METHOD path\"", call)
		}
		suffix := ""
		if p, n, ok := strings.Cut(path, "#"); ok {
			path, suffix = p, "."+n
		}
		if err := os.WriteFile(filepath.Join(stub, stubKey(method, path)+suffix), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	callLog := filepath.Join(dir, "calls")
	if err := os.WriteFile(callLog, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_API_TOKEN=x",
		"REPO_API=https://api.example/repos/o/r",
		"PR_NUM=7",
		"EVENT_SHA="+headA,
		"GITHUB_RUN_ID=100",
		"BASE_REF=main",
		"STUB_DIR="+stub,
		"STUB_LOG="+callLog,
	)
	cmd.Env = append(cmd.Env, env...)
	b, err := cmd.CombinedOutput()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run step: %v\n%s", err, b)
	}
	c, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	if s := strings.TrimSpace(string(c)); s != "" {
		calls = strings.Split(s, "\n")
	}
	return stepRun{output: string(b), calls: calls, code: code}
}

// crRun is one workflow run in a runs listing of the code-review workflow.
func crRun(id, pr int, head string) string {
	return fmt.Sprintf(`{"id":%d,"head_sha":%q,"display_title":"Code Review: PR #%d into main at %s"}`, id, head, pr, head)
}

// TestCodeReviewSupersedeCancelsOnlyOlderHeads runs the template's
// supersede step (Codex round 5 P1 on #2323): the live head's run cancels
// only an older-head run of the same PR with a lower run id whose review is
// not in progress, and an API error is a warning that cancels nothing.
func TestCodeReviewSupersedeCancelsOnlyOlderHeads(t *testing.T) {
	script := extractCodeReviewStep(t, "Cancel this PR's runs on an older head")
	const runs = "GET /actions/workflows/5/runs?event=pull_request_target&status="
	base := func(live string) map[string]string {
		r := map[string]string{
			"GET /pulls/7":          fmt.Sprintf(`{"state":"open","head":{"sha":%q}}`, live),
			"GET /actions/runs/100": `{"workflow_id":5}`,
			runs + "in_progress&per_page=100": `{"workflow_runs":[` + strings.Join([]string{
				crRun(90, 7, headB),  // older head, lower id, idle: cancelled
				crRun(91, 7, headA),  // a twin on this head
				crRun(110, 7, headB), // newer run
				crRun(92, 8, headB),  // another PR
				crRun(93, 7, headB),  // its review is in progress
				crRun(100, 7, headA), // this run
			}, ",") + `]}`,
			"GET /actions/runs/90/jobs?per_page=100": `{"jobs":[{"name":"Codex review","status":"completed"}]}`,
			"GET /actions/runs/93/jobs?per_page=100": `{"jobs":[{"name":"Codex review","status":"in_progress"}]}`,
			"POST /actions/runs/90/cancel":           `{}`,
		}
		for _, st := range []string{"queued", "waiting", "pending", "requested"} {
			r[runs+st+"&per_page=100"] = `{"workflow_runs":[]}`
		}
		return r
	}
	for _, tc := range []struct {
		name      string
		responses func() map[string]string
		posts     []string
		output    string
	}{
		{"older head cancelled", func() map[string]string { return base(headA) },
			[]string{"POST /actions/runs/90/cancel"}, "Run 90 is on an older head of PR 7"},
		{"live head moved", func() map[string]string { return base(headC) },
			nil, "nothing to cancel"},
		{"PR read fails", func() map[string]string {
			r := base(headA)
			delete(r, "GET /pulls/7")
			return r
		}, nil, "::warning::Cancel superseded runs:"},
		{"listing fails", func() map[string]string {
			r := base(headA)
			delete(r, runs+"waiting&per_page=100")
			return r
		}, nil, "::warning::Cancel superseded runs:"},
		{"jobs read fails", func() map[string]string {
			r := base(headA)
			delete(r, "GET /actions/runs/90/jobs?per_page=100")
			return r
		}, nil, "::warning::Cancel superseded runs:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runCodeReviewStep(t, script, tc.responses())
			if r.code != 0 {
				t.Errorf("exit %d, want 0\n%s", r.code, r.output)
			}
			if got := r.posts(); !slices.Equal(got, tc.posts) {
				t.Errorf("writes %q, want %q\n%s", got, tc.posts, r.output)
			}
			if !strings.Contains(r.output, tc.output) {
				t.Errorf("output lacks %q:\n%s", tc.output, r.output)
			}
		})
	}
}

// TestCodeReviewHandoffWaitsForNewerRun runs the template's handoff step
// (Codex round 5 P1 on #2323): a newer run on this head that goes from in
// progress to completed with a red gate gets only that gate re-run; one still
// in progress at the bound with a red gate fails the step with ::error; an
// API error is a warning only.
func TestCodeReviewHandoffWaitsForNewerRun(t *testing.T) {
	script := extractCodeReviewStep(t, "Re-run a newer twin's failed gate on this head")
	const (
		title     = "Code Review: PR #7 into main at " + headA
		jobs120   = "GET /actions/runs/120/jobs?per_page=100"
		gateRun   = `{"jobs":[{"id":1201,"name":"Code Review (codex)","status":"in_progress"},{"id":1202,"name":"Codex review","status":"completed","conclusion":"success"}]}`
		gateRed   = `{"jobs":[{"id":1201,"name":"Code Review (codex)","status":"completed","conclusion":"failure"},{"id":1202,"name":"Codex review","status":"completed","conclusion":"success"}]}`
		inFlight  = `{"status":"in_progress"}`
		completed = `{"status":"completed"}`
	)
	base := func() map[string]string {
		return map[string]string{
			"GET /actions/runs/100": `{"workflow_id":5,"check_suite_id":50}`,
			"GET /actions/workflows/5/runs?head_sha=" + headA + "&per_page=100": fmt.Sprintf(`{"workflow_runs":[`+
				`{"id":120,"status":"in_progress","display_title":%q,"check_suite_id":60},`+
				`{"id":95,"status":"completed","display_title":%q,"check_suite_id":40},`+
				`{"id":130,"status":"completed","display_title":"Code Review: PR #8 into main at %s","check_suite_id":70}]}`,
				title, title, headA),
			"GET /actions/runs/95/jobs?per_page=100":  gateRed,
			"GET /actions/runs/130/jobs?per_page=100": gateRed,
			"POST /actions/jobs/1201/rerun":           `{}`,
		}
	}
	for _, tc := range []struct {
		name      string
		responses func() map[string]string
		wait      string
		code      int
		posts     []string
		output    string
	}{
		{"newer run completes red", func() map[string]string {
			r := base()
			r[jobs120+"#1"] = gateRun
			r[jobs120] = gateRed
			r["GET /actions/runs/120#1"] = inFlight
			r["GET /actions/runs/120"] = completed
			return r
		}, "5", 0, []string{"POST /actions/jobs/1201/rerun"}, "its gate (job 1201) ended red: re-run"},
		{"newer run stuck at the bound", func() map[string]string {
			r := base()
			r[jobs120] = gateRed
			r["GET /actions/runs/120"] = inFlight
			return r
		}, "1", 5, nil, "::error::Code Review (codex): run 120 on " + headA + " is still in_progress"},
		{"API error", func() map[string]string {
			r := base()
			delete(r, "GET /actions/runs/100")
			return r
		}, "5", 0, nil, "::warning::Code Review (codex):"},
		{"jobs read fails", func() map[string]string {
			r := base()
			r["GET /actions/runs/120"] = completed
			return r
		}, "5", 0, nil, "::warning::Code Review (codex):"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runCodeReviewStep(t, script, tc.responses(), "HANDOFF_POLL_S=0", "HANDOFF_WAIT_S="+tc.wait)
			if r.code != tc.code {
				t.Errorf("exit %d, want %d\n%s", r.code, tc.code, r.output)
			}
			if got := r.posts(); !slices.Equal(got, tc.posts) {
				t.Errorf("writes %q, want %q\n%s", got, tc.posts, r.output)
			}
			if !strings.Contains(r.output, tc.output) {
				t.Errorf("output lacks %q:\n%s", tc.output, r.output)
			}
			for _, c := range r.calls {
				if strings.Contains(c, "/runs/95") || strings.Contains(c, "/runs/130") {
					t.Errorf("read %s: neither an older run nor another PR's run is a newer twin", c)
				}
			}
		})
	}
}

const (
	headA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	headB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	headC = "cccccccccccccccccccccccccccccccccccccccc"
)
