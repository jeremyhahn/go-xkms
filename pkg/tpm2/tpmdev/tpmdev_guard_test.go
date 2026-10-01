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

package tpmdev

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forbiddenOpeners are the go-tpm entry points that open a TPM device by
// path, by import path and function. Only this package may open a device,
// so every open passes the hardware-in-test refusal.
var forbiddenOpeners = map[string]map[string]bool{
	"github.com/google/go-tpm/tpm2/transport/linuxtpm": {"Open": true},
	"github.com/google/go-tpm/tpm2/transport":          {"OpenTPM": true},
	"github.com/google/go-tpm/legacy/tpm2":             {"OpenTPM": true},
	"github.com/google/go-tpm/tpmutil":                 {"OpenTPM": true},
}

// nonTPMDevices are os.Open arguments that name a device but not a TPM,
// each with the reason it is not one.
var nonTPMDevices = map[string]string{
	"uhid.UHIDDevicePath": "the Linux uhid device the virtual FIDO2 authenticator registers through",
}

// skipDirs are never Go source of this repository.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "testdata": true, "dist": true}

// TestNoTPMDeviceOpensOutsideTpmdev walks every Go file of the repository
// (all modules, test files included) and fails on any TPM device open that
// does not go through this package: a go-tpm path opener, or an os.Open /
// os.OpenFile whose argument names a TPM or a device. That keeps the
// hardware-in-test refusal (Allowed) on every path to the host's TPM.
func TestNoTPMDeviceOpensOutsideTpmdev(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	self, err := filepath.Abs(".")
	require.NoError(t, err)

	var violations []string
	walked := 0
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || path == self {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		walked++
		violations = append(violations, tpmOpensIn(t, root, path)...)
		return nil
	}))

	require.Greater(t, walked, 1000, "the walk must cover the repository, not an empty tree")
	assert.Empty(t, violations, "open TPM devices through pkg/tpm2/tpmdev (Open/Allowed), never directly")
}

// tpmOpensIn returns the direct TPM device opens in one file.
func tpmOpensIn(t *testing.T, root, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		// A file that does not parse (a template, a build-tag fixture) holds
		// no compiled open.
		return nil
	}
	imports := map[string]string{}
	for _, imp := range file.Imports {
		importPath, _ := strconv.Unquote(imp.Path.Value)
		name := importPath[strings.LastIndex(importPath, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = importPath
	}

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath := imports[pkg.Name]
		rel, _ := filepath.Rel(root, path)
		where := rel + ":" + strconv.Itoa(fset.Position(call.Pos()).Line)
		switch {
		case forbiddenOpeners[importPath][sel.Sel.Name]:
			found = append(found, where+": "+pkg.Name+"."+sel.Sel.Name)
		case importPath == "os" && (sel.Sel.Name == "Open" || sel.Sel.Name == "OpenFile") && len(call.Args) > 0:
			if arg := exprText(call.Args[0]); namesATPMDevice(arg) {
				found = append(found, where+": os."+sel.Sel.Name+"("+arg+")")
			}
		}
		return true
	})
	return found
}

// namesATPMDevice reports whether an os.Open argument names a TPM or an
// unlisted device.
func namesATPMDevice(arg string) bool {
	if _, ok := nonTPMDevices[arg]; ok {
		return false
	}
	lower := strings.ToLower(arg)
	return strings.Contains(lower, "tpm") || strings.Contains(lower, "device")
}

// exprText renders an identifier, selector or string literal argument.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.BasicLit:
		return v.Value
	case *ast.CallExpr:
		parts := make([]string, 0, len(v.Args)+1)
		parts = append(parts, exprText(v.Fun))
		for _, a := range v.Args {
			parts = append(parts, exprText(a))
		}
		return strings.Join(parts, " ")
	case *ast.BinaryExpr:
		return exprText(v.X) + " " + exprText(v.Y)
	default:
		return ""
	}
}

// TestNamesATPMDevice pins the os.Open classification.
func TestNamesATPMDevice(t *testing.T) {
	for _, arg := range []string{`"/dev/tpmrm0"`, "params.Config.Device", "device", "tpmPath", "filepath.Join dir tpmName"} {
		assert.True(t, namesATPMDevice(arg), arg)
	}
	for _, arg := range []string{"uhid.UHIDDevicePath", "path", `"/etc/passwd"`, "cfg.StoragePath"} {
		assert.False(t, namesATPMDevice(arg), arg)
	}
}

// TestTpmOpensIn_FindsEachOpener proves the scanner sees every opener form.
func TestTpmOpensIn_FindsEachOpener(t *testing.T) {
	dir := t.TempDir()
	src := `package x

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	legacy "github.com/google/go-tpm/tpmutil"
)

func f(device string) {
	_, _ = linuxtpm.Open("/dev/tpmrm0")
	_, _ = transport.OpenTPM(device)
	_, _ = legacy.OpenTPM(device)
	_, _ = os.OpenFile(device, os.O_RDWR, 0)
	_, _ = os.Open("/etc/hosts")
}
`
	path := filepath.Join(dir, "x.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))
	found := tpmOpensIn(t, dir, path)
	assert.Len(t, found, 4, "%v", found)
}
