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

// Package authzscan reads the authorization gates out of a transport package's
// own source and resolves each one to the wire-level "resource:action" pair it
// asks go-qrdb to decide.
//
// The transports that gate per call site rather than per table — pkg/api/grpc
// and pkg/api/quic — have no in-process table a golden test can compare
// against, the way pkg/api/mcp compares against its methodPermissions map. This
// package builds that table from the source, so those transports can be pinned
// to a checked-in wire contract with the same strength.
//
// Two properties are enforced while scanning:
//
//   - Every resource and action argument must be a pkg/auth constant. A raw
//     string literal is rejected (*RawLiteralError), because a retyped literal is
//     a silent authorization change: the gate simply asks for a permission
//     nobody grants, or a different one that someone does.
//   - Every constant must be one this package knows the value of. An unknown
//     name is rejected (*UnknownConstantError) rather than skipped, so a new
//     constant cannot slip past the golden table unnoticed.
package authzscan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Seam describes one authorize helper: the method name callers invoke, how many
// arguments that call carries, and which of them hold the resource and the
// action. A helper that pins the resource itself reports ResourceArg < 0 and
// names the constant in FixedResource.
type Seam struct {
	Method        string
	Args          int
	ResourceArg   int
	ActionArg     int
	FixedResource string
}

// Site is one authorization gate: the wire pair it requests, keyed by the
// function that holds it.
type Site struct {
	// Key is the enclosing function's name. A function holding more than one
	// gate is disambiguated with a "#N" suffix in call order.
	Key string

	// Resource and Action are the resolved wire values. An argument that is
	// neither a literal nor a pkg/auth constant — a parameter, or the result of
	// a helper such as operationForMethod — is recorded as "<name>", so the
	// indirection is visible in the golden table instead of vanishing from it.
	Resource string
	Action   string

	// Pos is the file:line of the call, for failure messages.
	Pos string
}

// Pair returns the wire-level "resource:action" string the gate requests.
func (s Site) Pair() string { return s.Resource + ":" + s.Action }

// ParseError reports a source file that could not be parsed.
type ParseError struct {
	File string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("authzscan: parse %s: %v", e.File, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// RawLiteralError reports an authorization argument written as a string literal
// instead of a pkg/auth constant.
type RawLiteralError struct {
	Pos     string
	Literal string
}

func (e *RawLiteralError) Error() string {
	return fmt.Sprintf("authzscan: %s: raw authorization literal %s; use the pkg/auth constant", e.Pos, e.Literal)
}

// UnknownConstantError reports a pkg/auth selector whose value this package
// does not know, which means the golden tables cannot vouch for it.
type UnknownConstantError struct {
	Pos  string
	Name string
}

func (e *UnknownConstantError) Error() string {
	return fmt.Sprintf("authzscan: %s: unknown pkg/auth constant %q; add it to authzscan.Constants", e.Pos, e.Name)
}

// Constants is every pkg/auth resource and action constant, by name. The values
// are read from the package itself rather than retyped, so the golden tables
// pin the constant a call site names *and* the string that constant carries.
func Constants() map[string]string {
	return map[string]string{
		"ResourceKeys":          auth.ResourceKeys,
		"ResourceCerts":         auth.ResourceCerts,
		"ResourceBackends":      auth.ResourceBackends,
		"ResourceUsers":         auth.ResourceUsers,
		"ResourceRoles":         auth.ResourceRoles,
		"ResourceTenants":       auth.ResourceTenants,
		"ResourceAudit":         auth.ResourceAudit,
		"ResourceAdmin":         auth.ResourceAdmin,
		"ResourceSeal":          auth.ResourceSeal,
		"ResourceBarrier":       auth.ResourceBarrier,
		"ResourcePIV":           auth.ResourcePIV,
		"ResourceSSH":           auth.ResourceSSH,
		"ResourcePasswords":     auth.ResourcePasswords,
		"ResourcePIN":           auth.ResourcePIN,
		"ResourceTenantBarrier": auth.ResourceTenantBarrier,
		"ResourceCeremony":      auth.ResourceCeremony,
		"ResourceCredentials":   auth.ResourceCredentials,
		"ResourceACMEAccounts":  auth.ResourceACMEAccounts,
		"ResourceACMEOrders":    auth.ResourceACMEOrders,
		"ResourceACMEEAB":       auth.ResourceACMEEAB,
		"ResourceCA":            auth.ResourceCA,
		"ResourceBootstrap":     auth.ResourceBootstrap,
		"ResourcePolicy":        auth.ResourcePolicy,

		"ActionSign":               auth.ActionSign,
		"ActionVerify":             auth.ActionVerify,
		"ActionEncrypt":            auth.ActionEncrypt,
		"ActionDecrypt":            auth.ActionDecrypt,
		"ActionCreate":             auth.ActionCreate,
		"ActionRotate":             auth.ActionRotate,
		"ActionDelete":             auth.ActionDelete,
		"ActionList":               auth.ActionList,
		"ActionGet":                auth.ActionGet,
		"ActionImport":             auth.ActionImport,
		"ActionExport":             auth.ActionExport,
		"ActionRefresh":            auth.ActionRefresh,
		"ActionWrap":               auth.ActionWrap,
		"ActionUnwrap":             auth.ActionUnwrap,
		"ActionDerive":             auth.ActionDerive,
		"ActionGenerate":           auth.ActionGenerate,
		"ActionRevoke":             auth.ActionRevoke,
		"ActionRead":               auth.ActionRead,
		"ActionUpdate":             auth.ActionUpdate,
		"ActionWrite":              auth.ActionWrite,
		"ActionUse":                auth.ActionUse,
		"ActionDisable":            auth.ActionDisable,
		"ActionStatus":             auth.ActionStatus,
		"ActionCapabilities":       auth.ActionCapabilities,
		"ActionBootstrap":          auth.ActionBootstrap,
		"ActionSeal":               auth.ActionSeal,
		"ActionUnseal":             auth.ActionUnseal,
		"ActionRekey":              auth.ActionRekey,
		"ActionRotateRootKey":      auth.ActionRotateRootKey,
		"ActionGenerateRecovery":   auth.ActionGenerateRecovery,
		"ActionRecoverWithKeys":    auth.ActionRecoverWithKeys,
		"ActionInitializeShamir":   auth.ActionInitializeShamir,
		"ActionUnsealShare":        auth.ActionUnsealShare,
		"ActionEnableEncryption":   auth.ActionEnableEncryption,
		"ActionInit":               auth.ActionInit,
		"ActionClaimCert":          auth.ActionClaimCert,
		"ActionClaimShareBegin":    auth.ActionClaimShareBegin,
		"ActionClaimShareComplete": auth.ActionClaimShareComplete,
		"ActionSignCSR":            auth.ActionSignCSR,
		"ActionEnrollCustodian":    auth.ActionEnrollCustodian,
		"ActionRevokeCustodian":    auth.ActionRevokeCustodian,
		"ActionSubmit":             auth.ActionSubmit,
		"ActionStrategy":           auth.ActionStrategy,
		"ActionLock":               auth.ActionLock,
		"ActionUnlock":             auth.ActionUnlock,
	}
}

// Scan reads every non-test Go file in dir and returns the authorization gates
// reached through the given seams, in file-then-line order.
//
// Files are parsed without applying build constraints, so a gate that only
// compiles under a build tag — the FROST handlers, for example — is scanned
// alongside the rest and cannot hide from the golden table.
func Scan(dir string, seams []Seam) ([]Site, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &ParseError{File: dir, Err: err}
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	// The seam definitions themselves take the resource or action as a
	// parameter; only their callers pin a pair.
	helpers := make(map[string]struct{}, len(seams))
	for _, s := range seams {
		helpers[s.Method] = struct{}{}
	}

	constants := Constants()
	fset := token.NewFileSet()

	var sites []Site
	for _, name := range names {
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, &ParseError{File: path, Err: err}
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, isHelper := helpers[fn.Name.Name]; isHelper {
				continue
			}
			found, err := scanFunc(fset, fn, seams, constants)
			if err != nil {
				return nil, err
			}
			sites = append(sites, found...)
		}
	}

	// Disambiguate functions holding more than one gate.
	counts := make(map[string]int, len(sites))
	for _, s := range sites {
		counts[s.Key]++
	}
	seen := make(map[string]int, len(counts))
	for i := range sites {
		key := sites[i].Key
		if counts[key] > 1 {
			sites[i].Key = fmt.Sprintf("%s#%d", key, seen[key])
		}
		seen[key]++
	}
	return sites, nil
}

// scanFunc collects the gates inside a single function declaration.
func scanFunc(fset *token.FileSet, fn *ast.FuncDecl, seams []Seam, constants map[string]string) ([]Site, error) {
	var (
		sites []Site
		fail  error
	)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if fail != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		seam, ok := matchSeam(seams, sel.Sel.Name, len(call.Args))
		if !ok {
			return true
		}
		pos := position(fset, call.Lparen)

		resource := seam.FixedResource
		if seam.ResourceArg >= 0 {
			resource, fail = resolve(fset, call.Args[seam.ResourceArg], constants)
			if fail != nil {
				return false
			}
		} else if value, known := constants[resource]; known {
			resource = value
		} else {
			fail = &UnknownConstantError{Pos: pos, Name: resource}
			return false
		}

		var action string
		action, fail = resolve(fset, call.Args[seam.ActionArg], constants)
		if fail != nil {
			return false
		}

		sites = append(sites, Site{
			Key:      fn.Name.Name,
			Resource: resource,
			Action:   action,
			Pos:      pos,
		})
		return true
	})
	return sites, fail
}

// matchSeam returns the seam a call matches, by method name and arity.
func matchSeam(seams []Seam, method string, args int) (Seam, bool) {
	for _, s := range seams {
		if s.Method == method && s.Args == args {
			return s, true
		}
	}
	return Seam{}, false
}

// resolve turns an authorization argument into its wire value. A pkg/auth
// selector resolves to the constant's string; any other non-literal expression
// becomes a "<name>" marker recording the indirection; a raw literal is an
// error.
func resolve(fset *token.FileSet, arg ast.Expr, constants map[string]string) (string, error) {
	pos := position(fset, arg.Pos())
	switch expr := arg.(type) {
	case *ast.BasicLit:
		return "", &RawLiteralError{Pos: pos, Literal: expr.Value}
	case *ast.SelectorExpr:
		ident, ok := expr.X.(*ast.Ident)
		if !ok || ident.Name != "auth" {
			return "<" + expr.Sel.Name + ">", nil
		}
		value, known := constants[expr.Sel.Name]
		if !known {
			return "", &UnknownConstantError{Pos: pos, Name: expr.Sel.Name}
		}
		return value, nil
	case *ast.Ident:
		return "<" + expr.Name + ">", nil
	case *ast.CallExpr:
		if ident, ok := expr.Fun.(*ast.Ident); ok {
			return "<" + ident.Name + ">", nil
		}
		if sel, ok := expr.Fun.(*ast.SelectorExpr); ok {
			return "<" + sel.Sel.Name + ">", nil
		}
		return "<call>", nil
	default:
		return "<expr>", nil
	}
}

func position(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return fmt.Sprintf("%s:%d", filepath.Base(p.Filename), p.Line)
}
