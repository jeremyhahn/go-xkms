// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package usb

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgusb "github.com/jeremyhahn/go-xkms/pkg/api/transport/usb"
)

// implPackageDir is the canonical implementation this package re-exports.
// docs/00 makes every cross-repo edge an sdk/go edge, so anything exported
// there and missing here is unreachable by a consumer.
const implPackageDir = "../../../../pkg/api/transport/usb"

// exportedErrorNames parses dir and returns every exported package-level
// error sentinel it declares.
//
// Every non-test .go file is parsed regardless of build tags, which is the
// point: a consumer of this SDK must be able to reach an error whatever tags
// the implementation file carries, so an error hidden behind a tag still has
// to be re-exported. parser.ParseDir would also ignore tags, but it is
// deprecated for precisely that reason, so the behaviour is spelled out here
// rather than inherited from a call that documents it as a defect.
func exportedErrorNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		fileName := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(fileName, ".go") || strings.HasSuffix(fileName, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, filepath.Join(dir, fileName), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", fileName, err)
		}

		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if strings.HasPrefix(name.Name, "Err") && ast.IsExported(name.Name) {
						names = append(names, name.Name)
					}
				}
			}
		}
	}
	return names
}

// TestEveryImplementationErrorIsReExported derives its expectations from the
// implementation package rather than from a list maintained here.
//
// A hand-written list is checkable but not enforceable: it cannot fail when a
// NEW error is added to pkg/ and nobody re-exports it, which is the only
// failure it was supposed to catch. That is the same shape as the reciprocal
// pin defect — what the repo tests and what a consumer receives are different
// things — so the count has to come from enumerating the tree.
//
// Adding an error to pkg/api/transport/usb and not to this package now fails
// here, without anyone remembering to edit a test.
func TestEveryImplementationErrorIsReExported(t *testing.T) {
	dir, err := filepath.Abs(implPackageDir)
	if err != nil {
		t.Fatalf("resolving %s: %v", implPackageDir, err)
	}

	implNames := exportedErrorNames(t, dir)
	if len(implNames) == 0 {
		t.Fatalf("parsed no exported error sentinels from %s; the derivation "+
			"is broken and this test can no longer fail", dir)
	}

	sdkNames := exportedErrorNames(t, ".")
	present := make(map[string]bool, len(sdkNames))
	for _, n := range sdkNames {
		present[n] = true
	}

	for _, name := range implNames {
		if !present[name] {
			t.Errorf("%s is exported by the implementation but not re-exported "+
				"here; an SDK consumer cannot match on it", name)
		}
	}
}

// TestErrorSentinelsAreIdentities pins that each re-export is the SAME value
// the implementation returns, not a lookalike.
//
// The derivation above proves a name exists; identity is a separate property
// and errors.Is compares values. A re-export that drifted into its own
// errors.New would satisfy the name check, compile, and leave consumers
// matching against something the transport never returns.
func TestErrorSentinelsAreIdentities(t *testing.T) {
	for _, tc := range []struct {
		name string
		sdk  error
		impl error
	}{
		{"ErrNotConnected", ErrNotConnected, pkgusb.ErrNotConnected},
		{"ErrNotSupported", ErrNotSupported, pkgusb.ErrNotSupported},
		{"ErrStreamNotSupported", ErrStreamNotSupported, pkgusb.ErrStreamNotSupported},
		{"ErrNoiseNotConfigured", ErrNoiseNotConfigured, pkgusb.ErrNoiseNotConfigured},
		{"ErrRequestFailed", ErrRequestFailed, pkgusb.ErrRequestFailed},
		{"ErrDirtyState", ErrDirtyState, pkgusb.ErrDirtyState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sdk == nil {
				t.Fatal("the SDK re-export is nil")
			}
			if !errors.Is(tc.sdk, tc.impl) {
				t.Fatalf("the SDK sentinel is not the value the transport returns: %v vs %v",
					tc.sdk, tc.impl)
			}
		})
	}
}
