package buildgates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// maxInsecureTLSAllowlist is the number of InsecureSkipVerify sites the
// check-insecure-tls gate may allowlist (go-xkms#1284). The list must not
// grow: a moved SPKI-pin site re-homes its entry (#2314).
const maxInsecureTLSAllowlist = 3

// insecureTLSAllowlist returns the entries of the allow_skipverify=( ... )
// array in scripts/check-insecure-tls.sh.
func insecureTLSAllowlist(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "scripts", "check-insecure-tls.sh"))
	if err != nil {
		t.Fatalf("read check-insecure-tls.sh: %v", err)
	}
	_, rest, ok := strings.Cut(string(data), "allow_skipverify=(")
	if !ok {
		t.Fatal("check-insecure-tls.sh: allow_skipverify=( not found")
	}
	body, _, ok := strings.Cut(rest, ")")
	if !ok {
		t.Fatal("check-insecure-tls.sh: allow_skipverify array not closed")
	}
	var entries []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, strings.Trim(line, `'"`))
	}
	return entries
}

// TestInsecureTLSAllowlistNamesExistingFiles fails when the insecure-TLS
// allowlist names a file that is not in the tree (a stale entry keeps the gate
// red on the moved site) or when the list grows past its cap.
func TestInsecureTLSAllowlistNamesExistingFiles(t *testing.T) {
	entries := insecureTLSAllowlist(t)
	if len(entries) == 0 {
		t.Fatal("allow_skipverify is empty; parse failed")
	}
	if len(entries) > maxInsecureTLSAllowlist {
		t.Errorf("allow_skipverify has %d entries, max %d: %v", len(entries), maxInsecureTLSAllowlist, entries)
	}
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(e)))
		if err != nil {
			t.Errorf("allow_skipverify entry %q is not a file in the tree: %v", e, err)
			continue
		}
		if fi.IsDir() {
			t.Errorf("allow_skipverify entry %q is a directory, want a file", e)
		}
	}
}
