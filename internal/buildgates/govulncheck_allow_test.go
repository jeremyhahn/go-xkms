package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGovulncheck stands in for govulncheck: it insists on JSON output and
// prints the canned scan the test names, so the gate needs no network.
const fakeGovulncheck = `#!/usr/bin/env bash
case " $* " in *" -format json "*) ;; *) echo "fake govulncheck: want -format json, got: $*" >&2; exit 2;; esac
[ -n "$FAKE_GOVULNCHECK_FAIL" ] && { echo "fake govulncheck: scan failed" >&2; exit 1; }
cat "$FAKE_GOVULNCHECK_JSON"
`

const allow6911 = "GO-2026-6911 2026-12-04 https://github.com/jeremyhahn/go-xkms/issues/2326\n"

// TestGovulncheckAllowScript drives scripts/govulncheck-allow.sh over canned
// govulncheck JSON: an allowlisted reached id passes, and an unlisted reached
// id, an expired entry, a stale (no longer reached) entry or a failed scan
// each fail the gate.
func TestGovulncheckAllowScript(t *testing.T) {
	script, err := filepath.Abs("../../scripts/govulncheck-allow.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := filepath.Abs("testdata/govulncheck")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	fake := filepath.Join(bin, "govulncheck")
	if err := os.WriteFile(fake, []byte(fakeGovulncheck), 0o755); err != nil { // #nosec G306 -- the stub must be executable
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		allow   string
		scan    string
		today   string
		fail    bool
		want    []string
		refusal string
	}{
		{
			name: "an allowlisted reached id passes", allow: allow6911, scan: "reached.json", today: "2026-11-20",
			want: []string{"allowlisted GO-2026-6911 until 2026-12-04", "issues/2326"},
		},
		{
			name: "the expiry day itself still passes", allow: allow6911, scan: "reached.json", today: "2026-12-04",
			want: []string{"allowlisted GO-2026-6911"},
		},
		{
			name: "comments and blank lines are ignored", allow: "# tracked\n\n" + allow6911, scan: "reached.json", today: "2026-11-20",
			want: []string{"allowlisted GO-2026-6911"},
		},
		{
			name: "a reached id not in the allowlist fails", allow: allow6911, scan: "unlisted.json", today: "2026-11-20",
			refusal: "GO-2026-7777 is reached and not allowlisted",
		},
		{
			name: "an expired entry fails", allow: allow6911, scan: "reached.json", today: "2026-12-05",
			refusal: "GO-2026-6911 expired on 2026-12-04",
		},
		{
			name: "a listed id that is not reached fails", allow: allow6911, scan: "clean.json", today: "2026-11-20",
			refusal: "GO-2026-6911 is allowlisted but no longer reached",
		},
		{
			name: "a malformed entry fails", allow: "GO-2026-6911 2026-12-04\n", scan: "reached.json", today: "2026-11-20",
			refusal: "malformed entry",
		},
		{
			name: "a failed scan fails", allow: allow6911, scan: "reached.json", today: "2026-11-20", fail: true,
			refusal: "govulncheck failed",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			allow := filepath.Join(t.TempDir(), "allow")
			if err := os.WriteFile(allow, []byte(c.allow), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script, "-tags=x", "./...") // #nosec G204 -- the repository's own script
			cmd.Env = append(os.Environ(),
				"GOVULNCHECK_BIN="+fake,
				"GOVULNCHECK_ALLOW_FILE="+allow,
				"GOVULNCHECK_TODAY="+c.today,
				"FAKE_GOVULNCHECK_JSON="+filepath.Join(fixtures, c.scan),
			)
			if c.fail {
				cmd.Env = append(cmd.Env, "FAKE_GOVULNCHECK_FAIL=1")
			}
			out, err := cmd.CombinedOutput()
			if c.refusal == "" {
				if err != nil {
					t.Fatalf("the gate refused: %v\n%s", err, out)
				}
				for _, w := range c.want {
					if !strings.Contains(string(out), w) {
						t.Fatalf("the output lacks %q:\n%s", w, out)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("the gate passed; want a refusal containing %q:\n%s", c.refusal, out)
			}
			if !strings.Contains(string(out), c.refusal) {
				t.Fatalf("the refusal lacks %q:\n%s", c.refusal, out)
			}
		})
	}
}

// TestGovulncheckAllowFile pins the checked-in allowlist to ruling 1047 (1):
// exactly one entry, GO-2026-6911 until 2026-12-04, tracked by #2326.
func TestGovulncheckAllowFile(t *testing.T) {
	data, err := os.ReadFile("../../.govulncheck-allow")
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if want := strings.TrimSpace(allow6911); len(entries) != 1 || entries[0] != want {
		t.Fatalf("allowlist entries = %q; want exactly [%q]", entries, want)
	}
}
