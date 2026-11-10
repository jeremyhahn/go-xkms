package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// tagsValue matches the value of one -tags flag in a recipe line, in either
// form the Makefile writes: -tags='...' or -tags "...".
var tagsValue = regexp.MustCompile(`-tags[= ]['"]([^'"]*)['"]`)

// recipeOf returns the recipe lines of target in the Makefile text.
func recipeOf(makefile, target string) []string {
	var recipe []string
	in := false
	for _, line := range strings.Split(makefile, "\n") {
		switch {
		case strings.HasPrefix(line, target+":"):
			in = true
		case in && strings.HasPrefix(line, "\t"):
			recipe = append(recipe, line)
		case in:
			return recipe
		}
	}
	return recipe
}

// The stores these suites open are built by the JSON codec, which is compiled
// in only under its build tag: a recipe without the codec tags fails at the
// first store with `codec "json" is not supported in this build`.
func TestIntegrationRecipesBuildWithTheCodecTags(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, target := range []string{"integration-test-sshagent", "integration-test-fido2", "integration-test-fido2-cli"} {
		t.Run(target, func(t *testing.T) {
			values := tagsValue.FindAllStringSubmatch(strings.Join(recipeOf(string(data), target), "\n"), -1)
			if len(values) == 0 {
				t.Fatalf("no -tags value in the recipe of %s", target)
			}
			for _, value := range values {
				for _, codec := range []string{"codec_cbor", "codec_json", "codec_msgpack"} {
					if !strings.Contains(value[1], codec) {
						t.Errorf("-tags value %q lacks %s", value[1], codec)
					}
				}
			}
		})
	}
}
