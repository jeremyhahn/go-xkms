package buildgates

import (
	"regexp"
	"strings"
	"testing"
)

// makeRecipe returns the recipe lines of target in the Makefile text,
// with backslash continuations joined into one line each.
func targetRecipe(t *testing.T, makefile, target string) string {
	t.Helper()
	lines := strings.Split(makefile, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, target+":") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("Makefile has no %s target", target)
	}
	var b strings.Builder
	for _, l := range lines[start:] {
		if !strings.HasPrefix(l, "\t") {
			break
		}
		l = strings.TrimSpace(l)
		if strings.HasSuffix(l, "\\") {
			b.WriteString(strings.TrimSuffix(l, "\\"))
			b.WriteString(" ")
			continue
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// TestBootstrapRecipePrintsServerLogOnFailure pins the failure path of
// integration-test-bootstrap: when the compose run fails, the recipe prints a
// "--- xkms-server log ---" header and a bounded tail of the xkms-server
// service log, tears the stack down and exits with the original status.
func TestBootstrapRecipePrintsServerLogOnFailure(t *testing.T) {
	recipe := targetRecipe(t, readMakefile(t), "integration-test-bootstrap")

	var runLine string
	for _, l := range strings.Split(recipe, "\n") {
		if strings.Contains(l, "run --build --rm test") {
			runLine = l
			break
		}
	}
	if runLine == "" {
		t.Fatalf("integration-test-bootstrap has no compose run of the test service:\n%s", recipe)
	}

	trap := regexp.MustCompile(`trap '([^']*)' EXIT`).FindStringSubmatch(runLine)
	if trap == nil {
		t.Fatalf("the compose run has no EXIT trap for its failure path:\n%s", runLine)
	}
	body := trap[1]

	if !regexp.MustCompile(`rc=\$\$\?`).MatchString(body) {
		t.Errorf("the trap does not save the run's exit status first: %s", body)
	}
	fail := regexp.MustCompile(`if \[ \$\$rc -ne 0 \]; then (.*?); fi`).FindStringSubmatch(body)
	if fail == nil {
		t.Fatalf("the trap has no branch for a non-zero status: %s", body)
	}
	if !strings.Contains(fail[1], "--- xkms-server log ---") {
		t.Errorf("the failure branch prints no '--- xkms-server log ---' header: %s", fail[1])
	}
	logs := regexp.MustCompile(`logs [^;]*--tail[= ]200[^;]* xkms-server\b`)
	if !logs.MatchString(fail[1]) {
		t.Errorf("the failure branch prints no last-200-lines xkms-server service log: %s", fail[1])
	}
	hdr := strings.Index(fail[1], "--- xkms-server log ---")
	if loc := logs.FindStringIndex(fail[1]); hdr >= 0 && loc != nil && hdr > loc[0] {
		t.Errorf("the header comes after the log: %s", fail[1])
	}

	down := strings.Index(body, "down -v")
	if down < 0 {
		t.Errorf("the trap does not tear the stack down: %s", body)
	}
	exit := strings.LastIndex(body, "exit $$rc")
	if exit < 0 || exit < down {
		t.Errorf("the trap does not exit with the original status after teardown: %s", body)
	}
}
