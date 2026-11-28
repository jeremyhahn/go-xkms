package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// qrdbVlogWord matches qrdb_vlog as a whole build-tag word in a space- or
// comma-separated tag list.
var qrdbVlogWord = regexp.MustCompile(`(^|[^A-Za-z0-9_])qrdb_vlog([^A-Za-z0-9_]|$)`)

// readRepoLines returns the lines of a file under the repository root.
func readRepoLines(t *testing.T, rel string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.Split(string(data), "\n")
}

// requireVlogOnMatches checks every line of rel matched by sel carries
// qrdb_vlog, and that sel matches at least want lines.
func requireVlogOnMatches(t *testing.T, rel, what string, lines []string, want int, sel func(i int) bool) {
	t.Helper()
	found := 0
	for i, line := range lines {
		if !sel(i) {
			continue
		}
		found++
		if !qrdbVlogWord.MatchString(line) {
			t.Errorf("%s:%d: %s lacks qrdb_vlog (go-qrdb builds its verifiable log only under that tag): %s",
				rel, i+1, what, strings.TrimSpace(line))
		}
	}
	if found < want {
		t.Errorf("%s: found %d %s, want at least %d", rel, found, what, want)
	}
}

// TestQRDBVlogInXkmsdAndTestTagSets: go-qrdb compiles its verifiable-log
// service only with the qrdb_vlog build tag, and xkmsd's embedded node signs
// transparency-log checkpoints through it (row 1601). Every tag set that
// builds xkmsd or runs the unit suite must carry the tag, or the binary
// serves no log and the node log test skips.
func TestQRDBVlogInXkmsdAndTestTagSets(t *testing.T) {
	t.Run("Makefile", func(t *testing.T) {
		const rel = "Makefile"
		lines := readRepoLines(t, rel)
		for _, name := range []string{"TEST_TAGS", "BUILD_TAGS", "SERVER_BUILD_TAGS", "ALL_TAGS"} {
			def := regexp.MustCompile(`^` + name + `\s*:=`)
			seen := false
			requireVlogOnMatches(t, rel, name+" (base := line)", lines, 1, func(i int) bool {
				if seen || !def.MatchString(lines[i]) {
					return false
				}
				seen = true
				return true
			})
		}
	})

	t.Run("ci.yml", func(t *testing.T) {
		const rel = ".github/workflows/ci.yml"
		lines := readRepoLines(t, rel)
		tagsLine := regexp.MustCompile(`^\s*TAGS=`)
		buildsXkmsd := regexp.MustCompile(`go build .*\./cmd/xkmsd`)
		requireVlogOnMatches(t, rel, "TAGS= line before a go build of ./cmd/xkmsd", lines, 2, func(i int) bool {
			if !tagsLine.MatchString(lines[i]) {
				return false
			}
			for j := i + 1; j < len(lines) && j <= i+4; j++ {
				if buildsXkmsd.MatchString(lines[j]) {
					return true
				}
			}
			return false
		})
		fullSuite := regexp.MustCompile(`-tags="[^"$]+"\s+\./\.\.\.`)
		requireVlogOnMatches(t, rel, "full-suite -tags list", lines, 2, func(i int) bool {
			return fullSuite.MatchString(lines[i])
		})
	})

	t.Run("release.yml", func(t *testing.T) {
		const rel = ".github/workflows/release.yml"
		lines := readRepoLines(t, rel)
		buildFlags := regexp.MustCompile(`BUILD_FLAGS="-tags=`)
		requireVlogOnMatches(t, rel, `BUILD_FLAGS="-tags= line`, lines, 2, func(i int) bool {
			return buildFlags.MatchString(lines[i])
		})
		imageBuild := regexp.MustCompile(`^\s*-tags="[^"$]+"\s*\\$`)
		requireVlogOnMatches(t, rel, "-tags list of the xkmsd image build", lines, 1, func(i int) bool {
			if !imageBuild.MatchString(lines[i]) {
				return false
			}
			for j := i + 1; j < len(lines) && j <= i+4; j++ {
				if strings.Contains(lines[j], "./cmd/xkmsd") {
					return true
				}
			}
			return false
		})
	})
}
