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
// and pkg/acme/admin — have no in-process table a golden test can compare
// against, the way pkg/api/mcp compares against its rpcMethods table. This
// package builds that table from the source, so those transports can be pinned
// to a checked-in wire contract with the same strength. pkg/api/rest carries
// its own in-process table (routes.go's RouteSpec slice), but its permission
// arguments are scanned the same way, so a raw string literal cannot slip past
// the route table either.
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
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Seam describes one authorize helper: the method name callers invoke, how many
// arguments that call carries, and which of them hold the resource and the
// action. A helper that pins the resource itself reports ResourceArg < 0 and
// names the constant in FixedResource.
//
// By default a seam only matches a method-selector call (x.Method(...)),
// which is how every scanned package so far calls its own authorize helper.
// Bare opts a seam into also matching a plain identifier call (Method(...)),
// which pkg/api/rest's route table needs: its permission-carrying helpers
// (perm, permBulk, permIf, user, ssh) are local closures, not methods.
//
// LabelArgs names the argument indices that build a Site's Key instead of the
// enclosing function's name. Each argument must be a string literal (its
// unquoted text is used) or a selector expression (its selector name is
// used) — the two shapes a call site actually carries for a human-readable
// label: a REST route's literal HTTP method and path, or the handler
// function value an ACME admin route registers. A seam with no LabelArgs
// keeps the original behavior of keying by enclosing function name, which is
// the right label when one function holds exactly one gate.
//
// LabelPrefix is prepended to the last LabelArgs entry only. It exists
// because a REST route helper's literal pattern argument is itself a
// suffix — the helper's caller ("/api/v1", "/api/v1/users", "/xkms/v1/ssh")
// prepends the mount point in the closure body, not at the call site — so
// two helpers can be called with the identical literal pattern ("/keys")
// while registering entirely different routes. LabelPrefix restores that
// mount point to the Key so the two cannot collide.
//
// Permission marks a helper whose ResourceArg carries one whole qrdb
// permission constant (qrdbsdk.Permission*) rather than a resource; the
// constant supplies both halves of the pair and ActionArg is ignored. The
// ACME admin routes gated on three-part cross-scope grants such as
// tenants:list:cross register through such a helper.
type Seam struct {
	Method        string
	Args          int
	ResourceArg   int
	ActionArg     int
	FixedResource string
	Bare          bool
	Permission    bool
	LabelArgs     []int
	LabelPrefix   string
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

// UnknownPermissionError reports a permission-seam argument that is not a
// qrdbsdk permission constant this package knows, which means the golden
// tables cannot vouch for it.
type UnknownPermissionError struct {
	Pos  string
	Name string
}

func (e *UnknownPermissionError) Error() string {
	return fmt.Sprintf("authzscan: %s: unknown qrdbsdk permission %q; add it to authzscan.Permissions", e.Pos, e.Name)
}

// Permissions is every qrdbsdk permission constant a permission seam may
// name, by name. The values come from the SDK itself, so a renamed or
// re-valued grant fails to compile here rather than drifting silently.
func Permissions() map[string]qrdbsdk.Permission {
	return map[string]qrdbsdk.Permission{
		"PermissionTenantsListCross":   qrdbsdk.PermissionTenantsListCross,
		"PermissionTenantsCreateCross": qrdbsdk.PermissionTenantsCreateCross,
		"PermissionTenantsReadCross":   qrdbsdk.PermissionTenantsReadCross,
		"PermissionTenantsUpdateCross": qrdbsdk.PermissionTenantsUpdateCross,
		"PermissionTenantsDeleteCross": qrdbsdk.PermissionTenantsDeleteCross,
	}
}

// Constants is every pkg/auth resource and action constant, by name. The values
// are read from the package itself rather than retyped, so the golden tables
// pin the constant a call site names *and* the string that constant carries.
func Constants() map[string]string {
	return map[string]string{
		"ResourceKeys":            auth.ResourceKeys,
		"ResourceCerts":           auth.ResourceCerts,
		"ResourceBackends":        auth.ResourceBackends,
		"ResourceUsers":           auth.ResourceUsers,
		"ResourceRoles":           auth.ResourceRoles,
		"ResourceTenants":         auth.ResourceTenants,
		"ResourceAudit":           auth.ResourceAudit,
		"ResourceAdmin":           auth.ResourceAdmin,
		"ResourceSeal":            auth.ResourceSeal,
		"ResourceBarrier":         auth.ResourceBarrier,
		"ResourcePIV":             auth.ResourcePIV,
		"ResourceSSH":             auth.ResourceSSH,
		"ResourcePasswords":       auth.ResourcePasswords,
		"ResourcePIN":             auth.ResourcePIN,
		"ResourceTenantBarrier":   auth.ResourceTenantBarrier,
		"ResourceCeremony":        auth.ResourceCeremony,
		"ResourceCredentials":     auth.ResourceCredentials,
		"ResourceACMEAccounts":    auth.ResourceACMEAccounts,
		"ResourceACMEOrders":      auth.ResourceACMEOrders,
		"ResourceACMEEAB":         auth.ResourceACMEEAB,
		"ResourceCA":              auth.ResourceCA,
		"ResourceBootstrap":       auth.ResourceBootstrap,
		"ResourceTPMPolicy":       auth.ResourceTPMPolicy,
		"ResourcePeerAttestation": auth.ResourcePeerAttestation,
		"ResourceOIDCCredentials": auth.ResourceOIDCCredentials,
		"ResourceBackup":          auth.ResourceBackup,
		"ResourceTrustRoots":      auth.ResourceTrustRoots,
		"ResourceVlog":            auth.ResourceVlog,

		"ResourceAttestationEndorsements":    auth.ResourceAttestationEndorsements,
		"ResourceAttestationReferenceValues": auth.ResourceAttestationReferenceValues,
		"ResourceAttestationVerifier":        auth.ResourceAttestationVerifier,
		"ResourceAttestationSigningKeys":     auth.ResourceAttestationSigningKeys,

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
		"ActionWrap":               auth.ActionWrap,
		"ActionUnwrap":             auth.ActionUnwrap,
		"ActionDerive":             auth.ActionDerive,
		"ActionGenerate":           auth.ActionGenerate,
		"ActionIssue":              auth.ActionIssue,
		"ActionEnroll":             auth.ActionEnroll,
		"ActionRevoke":             auth.ActionRevoke,
		"ActionRead":               auth.ActionRead,
		"ActionUpdate":             auth.ActionUpdate,
		"ActionSetEntitlements":    auth.ActionSetEntitlements,
		"ActionSetQuotas":          auth.ActionSetQuotas,
		"ActionSetTPMMode":         auth.ActionSetTPMMode,
		"ActionWrite":              auth.ActionWrite,
		"ActionUse":                auth.ActionUse,
		"ActionDisable":            auth.ActionDisable,
		"ActionEnable":             auth.ActionEnable,
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
		"ActionIssueService":       auth.ActionIssueService,
		"ActionBind":               auth.ActionBind,
		"ActionEnrollCustodian":    auth.ActionEnrollCustodian,
		"ActionRevokeCustodian":    auth.ActionRevokeCustodian,
		"ActionSubmit":             auth.ActionSubmit,
		"ActionStrategy":           auth.ActionStrategy,
		"ActionChallenge":          auth.ActionChallenge,
		"ActionLock":               auth.ActionLock,
		"ActionUnlock":             auth.ActionUnlock,
		"ActionToken":              auth.ActionToken,
		"ActionRestore":            auth.ActionRestore,
		"ActionHead":               auth.ActionHead,
		"ActionProof":              auth.ActionProof,
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

		var (
			methodName string
			bareCall   bool
		)
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			methodName = fun.Sel.Name
		case *ast.Ident:
			methodName = fun.Name
			bareCall = true
		default:
			return true
		}

		seam, ok := matchSeam(seams, methodName, len(call.Args))
		if !ok || (bareCall && !seam.Bare) {
			return true
		}
		pos := position(fset, call.Lparen)

		var resource, action string
		if seam.Permission {
			resource, action, fail = resolvePermission(fset, call.Args[seam.ResourceArg])
		} else {
			resource, action, fail = resolvePair(fset, pos, call.Args, seam, constants)
		}
		if fail != nil {
			return false
		}

		key := fn.Name.Name
		if len(seam.LabelArgs) > 0 {
			key, fail = label(pos, call.Args, seam.LabelArgs, seam.LabelPrefix)
			if fail != nil {
				return false
			}
		}

		sites = append(sites, Site{
			Key:      key,
			Resource: resource,
			Action:   action,
			Pos:      pos,
		})
		return true
	})
	return sites, fail
}

// matchSeam returns the seam a call matches, by method name and arity.
// resolvePair resolves the resource and action a resource/action seam's call
// names, taking the resource from FixedResource when the seam pins it.
func resolvePair(fset *token.FileSet, pos string, args []ast.Expr, seam Seam, constants map[string]string) (string, string, error) {
	resource := seam.FixedResource
	if seam.ResourceArg >= 0 {
		var err error
		resource, err = resolve(fset, args[seam.ResourceArg], constants)
		if err != nil {
			return "", "", err
		}
	} else if value, known := constants[resource]; known {
		resource = value
	} else {
		return "", "", &UnknownConstantError{Pos: pos, Name: resource}
	}

	action, err := resolve(fset, args[seam.ActionArg], constants)
	if err != nil {
		return "", "", err
	}
	return resource, action, nil
}

// resolvePermission resolves a permission seam's argument, which must be a
// qrdbsdk permission constant listed in Permissions, into the resource and
// action qrdb splits it into.
func resolvePermission(fset *token.FileSet, arg ast.Expr) (string, string, error) {
	pos := position(fset, arg.Pos())
	switch expr := arg.(type) {
	case *ast.BasicLit:
		return "", "", &RawLiteralError{Pos: pos, Literal: expr.Value}
	case *ast.SelectorExpr:
		if ident, ok := expr.X.(*ast.Ident); ok && ident.Name == "qrdbsdk" {
			if p, known := Permissions()[expr.Sel.Name]; known {
				return qrdbsdk.PermissionResource(p), qrdbsdk.PermissionAction(p), nil
			}
		}
		return "", "", &UnknownPermissionError{Pos: pos, Name: expr.Sel.Name}
	default:
		return "", "", &UnknownPermissionError{Pos: pos, Name: fmt.Sprintf("%T", arg)}
	}
}

func matchSeam(seams []Seam, method string, args int) (Seam, bool) {
	for _, s := range seams {
		if s.Method == method && s.Args == args {
			return s, true
		}
	}
	return Seam{}, false
}

// LabelArgError reports a Seam.LabelArgs index that a call site cannot
// resolve to a label: either the index is out of range for the call, or the
// argument at that index is not a string literal or a selector expression.
type LabelArgError struct {
	Pos   string
	Index int
}

func (e *LabelArgError) Error() string {
	return fmt.Sprintf("authzscan: %s: label argument index %d cannot be resolved to a label", e.Pos, e.Index)
}

// label builds a Site's Key from the given argument indices of a call,
// joining each argument's resolved text with a space. A string literal
// contributes its unquoted text (a REST route's HTTP method or path); a
// selector expression contributes its selector name (an ACME admin route's
// handler function).
func label(pos string, args []ast.Expr, indices []int, prefix string) (string, error) {
	parts := make([]string, len(indices))
	for i, idx := range indices {
		if idx < 0 || idx >= len(args) {
			return "", &LabelArgError{Pos: pos, Index: idx}
		}
		var part string
		switch arg := args[idx].(type) {
		case *ast.BasicLit:
			s, err := strconv.Unquote(arg.Value)
			if err != nil {
				return "", &LabelArgError{Pos: pos, Index: idx}
			}
			part = s
		case *ast.SelectorExpr:
			part = arg.Sel.Name
		default:
			return "", &LabelArgError{Pos: pos, Index: idx}
		}
		if i == len(indices)-1 {
			part = prefix + part
		}
		parts[i] = part
	}
	return strings.Join(parts, " "), nil
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

// MapSite is one authorization entry pulled from a package-level permission
// map, keyed by the map's own key (a JSON-RPC method name, for MCP). The key
// is a wire-facing identifier the caller already dispatches on, not an
// authorization argument, so it is never scanned for a raw literal the way
// Resource and Action are.
type MapSite struct {
	Key      string
	Resource string
	Action   string
	Pos      string
}

// Pair returns the wire-level "resource:action" string the entry requests.
func (s MapSite) Pair() string { return s.Resource + ":" + s.Action }

// VarNotFoundError reports that ScanMap's target variable does not exist,
// under any name, anywhere in the scanned directory.
type VarNotFoundError struct {
	Dir  string
	Name string
}

func (e *VarNotFoundError) Error() string {
	return fmt.Sprintf("authzscan: %s: variable %q not found", e.Dir, e.Name)
}

// MapEntryError reports a map entry that is not shaped like a registration:
// a non-literal key, a value that is not a call, or a call to the register
// function without its resource and action arguments.
type MapEntryError struct {
	Pos string
	Msg string
}

func (e *MapEntryError) Error() string {
	return fmt.Sprintf("authzscan: %s: %s", e.Pos, e.Msg)
}

// ScanMap reads every non-test Go file in dir, finds the package-level
// variable named varName, and resolves every entry of its
// map[string]T{"key": register(resource, action, ...), ...} literal to the
// wire-level resource:action pair it registers. This is how pkg/api/mcp's
// rpcMethods table declares each JSON-RPC method's permission at its
// registration site, with register = "handle".
//
// An entry whose value calls any other function (pkg/api/mcp's
// handlePublic) registers no permission and yields no site. Every other
// value shape is rejected with *MapEntryError, so an entry cannot slip past
// the golden table by being written some third way. The resource and action
// are resolved exactly as Scan resolves a call argument: a pkg/auth constant
// becomes the constant's value, and a raw string literal is rejected with
// *RawLiteralError. This is the table counterpart of Scan's call-site
// scanning, for the one transport (MCP) that declares its whole permission
// table as data rather than a sequence of gate calls.
func ScanMap(dir, varName, register string) ([]MapSite, error) {
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

	constants := Constants()
	fset := token.NewFileSet()

	var lit *ast.CompositeLit
	for _, name := range names {
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, &ParseError{File: path, Err: err}
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if ident.Name != varName || i >= len(value.Values) {
						continue
					}
					found, ok := value.Values[i].(*ast.CompositeLit)
					if !ok {
						return nil, &MapEntryError{Pos: position(fset, value.Values[i].Pos()), Msg: fmt.Sprintf("variable %q is not a composite literal", varName)}
					}
					lit = found
				}
			}
		}
	}
	if lit == nil {
		return nil, &VarNotFoundError{Dir: dir, Name: varName}
	}

	sites := make([]MapSite, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, &MapEntryError{Pos: position(fset, elt.Pos()), Msg: "map entry is not a key:value pair"}
		}
		keyLit, ok := kv.Key.(*ast.BasicLit)
		if !ok {
			return nil, &MapEntryError{Pos: position(fset, kv.Key.Pos()), Msg: "map key is not a string literal"}
		}
		key, err := strconv.Unquote(keyLit.Value)
		if err != nil {
			return nil, &MapEntryError{Pos: position(fset, kv.Key.Pos()), Msg: "map key is not a valid string literal"}
		}
		call, ok := kv.Value.(*ast.CallExpr)
		if !ok {
			return nil, &MapEntryError{Pos: position(fset, kv.Value.Pos()), Msg: fmt.Sprintf("value for key %q is not a registration call", key)}
		}
		if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != register {
			continue
		}
		if len(call.Args) < 2 {
			return nil, &MapEntryError{Pos: position(fset, kv.Value.Pos()), Msg: fmt.Sprintf("value for key %q does not pass %s a resource and an action", key, register)}
		}
		pos := position(fset, kv.Value.Pos())
		resource, err := resolve(fset, call.Args[0], constants)
		if err != nil {
			return nil, err
		}
		action, err := resolve(fset, call.Args[1], constants)
		if err != nil {
			return nil, err
		}
		sites = append(sites, MapSite{Key: key, Resource: resource, Action: action, Pos: pos})
	}
	return sites, nil
}
