package buildgates

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSPKIPinningOnlyViaSpkipin enforces docs/00 L1/L2 (docs/18 V41):
// go-truststrap pkg/spkipin owns SPKI-pinned TLS, so go-xkms keeps no copy
// of it. The old pkg/crypto/spki package and the SPKI copy in
// pkg/trust/fetcher must not come back, and no Go file may import the old
// package.
func TestSPKIPinningOnlyViaSpkipin(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot, "pkg", "crypto", "spki")); err == nil {
		t.Errorf("pkg/crypto/spki exists; SPKI pinning belongs to go-truststrap pkg/spkipin")
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "pkg", "trust", "fetcher", "spki.go")); err == nil {
		t.Errorf("pkg/trust/fetcher/spki.go exists; use go-truststrap pkg/spkipin")
	}

	// Built by concatenation so this file does not match itself.
	oldImport := `"github.com/jeremyhahn/go-xkms/pkg/` + `crypto/spki"`
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), oldImport) {
			rel, _ := filepath.Rel(repoRoot, path)
			t.Errorf("%s imports go-xkms/pkg/crypto/spki; use go-truststrap pkg/spkipin", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", repoRoot, err)
	}
}
