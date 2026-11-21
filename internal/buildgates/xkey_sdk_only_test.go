package buildgates

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestXkeyProductionImportsOnlySDK is the Preflight architecture gate: xkey
// production code (non-test .go files outside xkey/pkg/) may reach go-xkms
// only through sdk/go, never through github.com/jeremyhahn/go-xkms/pkg/.
func TestXkeyProductionImportsOnlySDK(t *testing.T) {
	root := filepath.Join(repoRoot, "xkey")
	const forbidden = `"github.com/jeremyhahn/go-xkms/pkg/`
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "pkg" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), forbidden) {
			t.Errorf("xkey/%s imports go-xkms/pkg; route it through sdk/go", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk xkey: %v", err)
	}
}
