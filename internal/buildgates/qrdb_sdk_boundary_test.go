package buildgates

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// qrdbPkgImportPrefix is go-qrdb's internal package tree. go-xkms code,
// tests included, reaches go-qrdb only through its sdk/go boundary
// (docs/18 V40, docs/00 L3).
const qrdbPkgImportPrefix = "github.com/jeremyhahn/go-qrdb/pkg/"

// minQRDBBoundaryTestFiles is a floor on the number of _test.go files the
// walk parses, so a wrong repository root fails rather than passes.
const minQRDBBoundaryTestFiles = 1000

// allowedQRDBPkgTestImports lists test files allowed to import go-qrdb
// pkg/*, keyed by slash path relative to the repository root, with the
// allowed import paths. An entry needs a documented wire-type exception
// (docs/03); there is none today.
var allowedQRDBPkgTestImports = map[string][]string{}

// goXKMSNestedModules are the directories holding their own go.mod that are
// still go-xkms modules and so are walked.
var goXKMSNestedModules = map[string]bool{
	"sdk/go":      true,
	"xkey":        true,
	"web/desktop": true,
}

func TestNoTestImportsQRDBPkg(t *testing.T) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	var problems []string
	parsed := 0
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil && !goXKMSNestedModules[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		parsed++
		allowed := allowedQRDBPkgTestImports[rel]
		for _, spec := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if !strings.HasPrefix(importPath, qrdbPkgImportPrefix) || containsString(allowed, importPath) {
				continue
			}
			problems = append(problems, rel+": "+importPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if parsed < minQRDBBoundaryTestFiles {
		t.Fatalf("parsed %d _test.go files under %s, want at least %d: wrong repository root?", parsed, root, minQRDBBoundaryTestFiles)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("go-xkms tests must import go-qrdb through sdk/go, not pkg/* (docs/18 V40):\n%s", strings.Join(problems, "\n"))
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
