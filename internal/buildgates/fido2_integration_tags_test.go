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
	var buildTags []string
	if bt := regexp.MustCompile(`(?m)^BUILD_TAGS :=([^\n]*)`).FindStringSubmatch(makefile); bt != nil {
		buildTags = strings.Fields(bt[1])
	}
	var out []string
	for _, tag := range strings.Fields(strings.ReplaceAll(tags[1], "$(comma)", " ")) {
		if tag == "$(BUILD_TAGS)" {
			out = append(out, buildTags...)
			continue
		}
		out = append(out, tag)
	}
	return out
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

func TestGoTestTags_ExpandsBuildTagsAndSpaces(t *testing.T) {
	makefile := "BUILD_TAGS := codec_cbor codec_json\n" +
		"x:\n\t$(GO) test -v -tags='$(call go_tags,integration fido2 $(BUILD_TAGS))' ./...\n" +
		"y:\n\t$(GO) test -tags='$(call go_tags,integration$(comma)fido2)' ./...\n"
	if got, want := goTestTags(t, makefile, "x"), []string{"integration", "fido2", "codec_cbor", "codec_json"}; !slices.Equal(got, want) {
		t.Errorf("x tags = %v, want %v", got, want)
	}
	if got, want := goTestTags(t, makefile, "y"), []string{"integration", "fido2"}; !slices.Equal(got, want) {
		t.Errorf("y tags = %v, want %v", got, want)
	}
}
