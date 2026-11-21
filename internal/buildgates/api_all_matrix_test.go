package buildgates

import (
	"regexp"
	"strings"
	"testing"
)

// apiRunFlag finds the -run regex of a go test over ./test/integration/api/...
// in a recipe line.
var apiRunFlag = regexp.MustCompile(`\./test/integration/api/\.\.\.[^"]*?-run '([^']*)'`)

// makeRecipe returns the tab-indented recipe lines of target.
func makeRecipe(makefile, target string) []string {
	lines := strings.Split(makefile, "\n")
	head := regexp.MustCompile(`^` + regexp.QuoteMeta(target) + `[ \t]*:([^=]|$)`)
	var out []string
	for i, line := range lines {
		if !head.MatchString(line) {
			continue
		}
		for _, body := range lines[i+1:] {
			if !strings.HasPrefix(body, "\t") {
				break
			}
			out = append(out, body)
		}
		break
	}
	return out
}

// apiRunRegexes walks target and its prerequisites and returns, per reached
// target, the -run regexes its recipe passes to go test over
// ./test/integration/api/....
func apiRunRegexes(t *testing.T, makefile, target string) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	seen := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		prereqs, ok := makePrerequisites(makefile, name)
		if !ok {
			return
		}
		for _, line := range makeRecipe(makefile, name) {
			for _, m := range apiRunFlag.FindAllStringSubmatch(line, -1) {
				found[name] = append(found[name], m[1])
			}
		}
		for _, p := range prereqs {
			walk(p)
		}
	}
	walk(target)
	return found
}

// TestAPIAllRunsProtocolMatrix pins the row #2321 criterion that the CLI
// protocol matrix (MCP and embedded cells included) runs in
// integration-test-api-all, and runs there exactly once.
func TestAPIAllRunsProtocolMatrix(t *testing.T) {
	makefile := readMakefile(t)
	if _, ok := makePrerequisites(makefile, "integration-test-api-all"); !ok {
		t.Fatal("Makefile has no integration-test-api-all target")
	}
	regexes := apiRunRegexes(t, makefile, "integration-test-api-all")
	for _, name := range []string{
		"TestAllCommandsAllProtocols",
		"TestCLIPlatformMatrix",
		"TestCLISecretsMatrix",
		"TestCLIClusterMatrix",
		"TestCLIBootstrapMatrix",
		"TestCLIEmbeddedProtocol",
	} {
		var hits []string
		for target, list := range regexes {
			for _, expr := range list {
				re, err := regexp.Compile(expr)
				if err != nil {
					t.Fatalf("%s: -run %q: %v", target, expr, err)
				}
				if re.MatchString(name) {
					hits = append(hits, target)
				}
			}
		}
		switch len(hits) {
		case 0:
			t.Errorf("integration-test-api-all reaches no -run regex matching %s (regexes: %v)", name, regexes)
		case 1:
		default:
			t.Errorf("%s runs %d times in integration-test-api-all (targets %v)", name, len(hits), hits)
		}
	}
}
