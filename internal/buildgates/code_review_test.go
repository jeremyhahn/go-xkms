package buildgates

import (
	"os"
	"regexp"
	"testing"
)

// TestCITemplateV151Note pins the ci.yml half of the handbook 86 pair
// (c4de1f7d): ci.yml v1.51 has no job change (its Runner labels step is one
// go-xkms does not take). The code-review.yml half is not part of this file.
func TestCITemplateV151Note(t *testing.T) {
	const ciWorkflow = "../../.github/workflows/ci.yml"
	ci, err := os.ReadFile(ciWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflow, err)
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\A# ci-template: v1\.5[1-9] `),
		regexp.MustCompile(`(?m)^# v1\.51 \(handbook c4de1f7d, #86\): `),
	} {
		if !want.Match(ci) {
			t.Errorf("%s does not match %s", ciWorkflow, want)
		}
	}
}
