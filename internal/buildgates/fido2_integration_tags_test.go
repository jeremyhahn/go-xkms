package buildgates

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// goTestTags returns the tag list of the `$(GO) test` command in the recipe
// of target, split on $(comma).
func goTestTags(t *testing.T, makefile, target string) []string {
	t.Helper()
	recipe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(target) + `:[^\n]*\n\t([^\n]*)`)
	m := recipe.FindStringSubmatch(makefile)
	if m == nil {
		t.Fatalf("the Makefile has no recipe for %s", target)
	}
	tags := regexp.MustCompile(`\$\(GO\) test [^']*-tags='\$\(call go_tags,([^']*)\)'`).FindStringSubmatch(m[1])
	if tags == nil {
		t.Fatalf("%s runs no `$(GO) test -tags='$(call go_tags,...)'`: %q", target, m[1])
	}
	return strings.Fields(expandMakeVars(makefile, strings.ReplaceAll(tags[1], "$(comma)", " ")))
}

// The fido2 suite builds its credential stores through
// pkg/testutil/webauthntest, whose DAOs need the JSON codec: without
// codec_json every ceremony test fails at store construction.
func TestFIDO2IntegrationTargetsBuildWithCodecJSON(t *testing.T) {
	makefile := readMakefile(t)
	for _, target := range []string{"integration-test-fido2", "integration-test-fido2-cli"} {
		if tags := goTestTags(t, makefile, target); !slices.Contains(tags, "codec_json") {
			t.Errorf("%s runs go test with tags %v, which lack codec_json", target, tags)
		}
	}
}
