package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// inhouseFloors are the lowest in-house module tags any go.mod of this
// repository may require (docs/18 V15, #2312).
var inhouseFloors = map[string]string{
	"github.com/jeremyhahn/go-qrdb":        "v0.58.5-alpha", // docs/18 V15, #2312: GO-2026-6911 unreachable (ruling 1047)
	"github.com/jeremyhahn/go-qrdb/sdk/go": "v0.58.5-alpha", // docs/18 V15, #2312: same tag as go-qrdb
	"github.com/jeremyhahn/go-enclave":     "v0.12.0-alpha", // docs/18 V15, #2312
	"github.com/jeremyhahn/go-codec":       "v1.5.1-alpha",  // docs/18 V15, #2312
	"github.com/jeremyhahn/go-truststrap":  "v0.7.1-alpha",  // docs/18 V15, #2312
}

// inhouseModFiles are the go.mod files of every module in this repository.
var inhouseModFiles = []string{
	"go.mod",
	"sdk/go/go.mod",
	"web/desktop/go.mod",
	"xkey/go.mod",
}

var replaceDate = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)

func parseModFile(t *testing.T, rel string) *modfile.File {
	t.Helper()
	path := filepath.Join(repoRoot, rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return f
}

// TestInhouseDepsAtFloors fails when an in-house module is required below
// its docs/18 V15 floor or at a pseudo-version.
func TestInhouseDepsAtFloors(t *testing.T) {
	for _, rel := range inhouseModFiles {
		f := parseModFile(t, rel)
		for _, r := range f.Require {
			floor, ok := inhouseFloors[r.Mod.Path]
			if !ok {
				continue
			}
			if module.IsPseudoVersion(r.Mod.Version) {
				t.Errorf("%s: %s %s is a pseudo-version; require a tag", rel, r.Mod.Path, r.Mod.Version)
				continue
			}
			if semver.Compare(r.Mod.Version, floor) < 0 {
				t.Errorf("%s: %s %s is below the docs/18 V15 floor %s (#2312)", rel, r.Mod.Path, r.Mod.Version, floor)
			}
		}
	}
}

// TestInhouseReplacesDated fails when a replace of a github.com/jeremyhahn/
// module to a non-local target has no comment carrying a date and a reason.
func TestInhouseReplacesDated(t *testing.T) {
	for _, rel := range inhouseModFiles {
		f := parseModFile(t, rel)
		for _, r := range f.Replace {
			if !strings.HasPrefix(r.Old.Path, "github.com/jeremyhahn/") {
				continue
			}
			if strings.HasPrefix(r.New.Path, "./") || strings.HasPrefix(r.New.Path, "../") {
				continue
			}
			if !hasDatedReason(r.Syntax) {
				t.Errorf("%s: replace %s => %s %s has no comment with a date (YYYY-MM-DD) and a reason",
					rel, r.Old.Path, r.New.Path, r.New.Version)
			}
		}
	}
}

// hasDatedReason reports whether a comment on the replace line, or the
// comment lines directly above it, carries a date and some reason text.
func hasDatedReason(line *modfile.Line) bool {
	if line == nil {
		return false
	}
	var comments []modfile.Comment
	comments = append(comments, line.Before...)
	comments = append(comments, line.Suffix...)
	for _, c := range comments {
		text := strings.TrimSpace(strings.TrimPrefix(c.Token, "//"))
		if !replaceDate.MatchString(text) {
			continue
		}
		if strings.TrimSpace(replaceDate.ReplaceAllString(text, "")) != "" {
			return true
		}
	}
	return false
}
