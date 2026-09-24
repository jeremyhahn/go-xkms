// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package main

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// xkmsctlTestBuildTags is the root package's mandated test build-tag set
// (see cmd/xkmsctl's test targets). collectFlagReads uses it to select the
// same source files the Go toolchain selects when this test binary is
// built, so a file gated behind a tag this build does not carry (frost.go
// behind "frost", for example) is skipped exactly as the compiler skips
// it — matching frost_stub.go's flags, not frost.go's, when built without
// -tags frost. Keep this in lockstep with the tags the project's test
// targets pass for cmd/xkmsctl.
var xkmsctlTestBuildTags = []string{"codec_cbor", "codec_json", "codec_msgpack", "tpm_simulator"}

// flagRead is one `<flagReader var>.<Kind>("<name>")` call site found in
// source.
type flagRead struct {
	file string
	kind string
	name string
}

// flagReaderKinds is the set of flagReader method names TestFlagBindings
// treats as flag reads, mapped to the pflag Value.Type() string each one
// requires the underlying flag to report.
var flagReaderKinds = map[string]string{
	"String":      "string",
	"Bool":        "bool",
	"Int":         "int",
	"Int64":       "int64",
	"Uint":        "uint",
	"Uint32":      "uint32",
	"Duration":    "duration",
	"StringSlice": "stringSlice",
	"IntSlice":    "intSlice",
}

// collectFlagReads statically finds every flagReader-mediated flag read in
// the non-test .go files of the xkmsctl package.
//
// It is a two-pass, name-based heuristic rather than a scope-accurate
// analysis: pass one collects every identifier assigned from
// newFlagReader(...) anywhere in a file; pass two collects every
// "<that identifier>.<Kind>("literal")" call in the same file. It does not
// track block scope, so two unrelated variables that happened to share a
// name and one of which was not a flagReader would be conflated — nothing
// in this package does that (flagReader is the only local type with
// String/Bool/Int/... methods taking a single string argument), and the
// cost of a false positive here is a spurious test failure, not a missed
// bug, so the simplification is deliberate.
func collectFlagReads(t *testing.T) []flagRead {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller: could not resolve this test file's path")
	}
	dir := filepath.Dir(thisFile)

	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}

	ctx := build.Default
	ctx.BuildTags = xkmsctlTestBuildTags

	var reads []flagRead
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		match, err := ctx.MatchFile(dir, filepath.Base(path))
		if err != nil {
			t.Fatalf("MatchFile(%s): %v", path, err)
		}
		if !match {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}

		readerVars := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || fn.Name != "newFlagReader" {
					continue
				}
				if i >= len(assign.Lhs) {
					continue
				}
				lhs, ok := assign.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				readerVars[lhs.Name] = true
			}
			return true
		})

		base := filepath.Base(path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || !readerVars[recv.Name] {
				return true
			}
			kind, ok := flagReaderKinds[sel.Sel.Name]
			if !ok {
				return true
			}
			if len(call.Args) != 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			reads = append(reads, flagRead{file: base, kind: kind, name: name})
			return true
		})
	}
	return reads
}

// collectRegisteredFlagTypes walks the whole live command tree rooted at
// rootCmd and returns, for every flag name registered anywhere in the
// tree, the set of pflag Value.Type() strings it is registered with.
// InheritedFlags merges a command's own persistent flags and every
// ancestor's persistent flags into its local FlagSet as a side effect
// (the same merge cobra performs internally before running a command), so
// the result matches what cmd.Flags().GetX would see at run time.
func collectRegisteredFlagTypes(root *cobra.Command) map[string]map[string]bool {
	types := map[string]map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.InheritedFlags()
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if types[f.Name] == nil {
				types[f.Name] = map[string]bool{}
			}
			types[f.Name][f.Value.Type()] = true
		})
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	return types
}

// TestFlagBindings walks every command in the xkmsctl tree and confirms
// every flag the code reads through a flagReader exists, somewhere in the
// tree, with the type it is read as — so a GetX call on a missing or
// mistyped flag can never again fail silently behind an ignored error.
//
// The check is by flag name across the whole tree, not per command: see
// collectFlagReads for why, and note the same flag name is expected to
// carry the same type everywhere in this codebase (e.g. "output" is
// always a string), so the coarser check still catches the failure modes
// that motivated it — a typo'd flag name, or a Get call whose type does
// not match how the flag was registered.
func TestFlagBindings(t *testing.T) {
	reads := collectFlagReads(t)
	if len(reads) == 0 {
		t.Fatal("collectFlagReads found no flagReader reads; the AST heuristic likely broke")
	}
	registered := collectRegisteredFlagTypes(rootCmd)

	seen := map[flagRead]bool{}
	for _, r := range reads {
		key := flagRead{kind: r.kind, name: r.name}
		if seen[key] {
			continue
		}
		seen[key] = true

		types, ok := registered[r.name]
		if !ok {
			t.Errorf("%s: fr.%s(%q) reads a flag that is not registered on any command in the tree",
				r.file, kindMethodName(r.kind), r.name)
			continue
		}
		if !types[r.kind] {
			t.Errorf("%s: fr.%s(%q) expects pflag type %q, but --%s is registered as %s",
				r.file, kindMethodName(r.kind), r.name, r.kind, r.name, sortedKeys(types))
		}
	}
}

// kindMethodName reverse-maps a pflag type string back to the flagReader
// method name, for error messages.
func kindMethodName(pflagType string) string {
	for method, kind := range flagReaderKinds {
		if kind == pflagType {
			return method
		}
	}
	return pflagType
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
