package module

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file guards the PKCS#11 constant tables against two defects that the
// per-constant unit tests cannot see, because both of them leave the module
// perfectly self-consistent while making it non-interoperable.
//
// The first is a collision: two constants in the same namespace holding the
// same value. Cryptoki dispatches on the numeric value, so a duplicate routes
// one mechanism into another mechanism's implementation with no error
// anywhere. The second is drift between the Go constants and the C header in
// cmd/pkcs11-module/include, which is what a C application actually compiles
// against; if the two disagree, every request for the affected mechanism
// arrives at the module carrying a value the module does not recognise.
//
// Both checks read the declarations out of the sources rather than restating
// them, so a constant added later is covered without touching this file.

// cHeaderPath locates the C header that cmd/pkcs11-module exports, relative to
// this package directory.
const cHeaderPath = "../../../cmd/pkcs11-module/include/pkcs11t.h"

// ckNamePattern matches the PKCS#11 constant naming convention: a "CK"
// prefix, an optional namespace letter run such as the "M" of CKM_, and an
// underscore-separated name. It matches both CKM_SHA3_256 and CK_SP800_108_DKM_LENGTH.
var ckNamePattern = regexp.MustCompile(`^CK[A-Z0-9]*_[A-Za-z0-9_]+$`)

// ckConstant is one PKCS#11 constant recovered from the package sources.
type ckConstant struct {
	Name  string
	Type  string
	Value uint64
	Pos   string
}

// unsupportedConstExprError reports a PKCS#11 constant whose declared value
// the scanner could not evaluate. It is always a failure and never a skip: a
// constant the scanner cannot read is a constant the collision check does not
// cover, so silence here would quietly shrink the test's reach.
type unsupportedConstExprError struct {
	Name string
	Pos  string
}

func (e *unsupportedConstExprError) Error() string {
	return "pkcs11: cannot evaluate the value of constant " + e.Name + " declared at " + e.Pos
}

// unsupportedDefineError reports a C preprocessor definition whose value the
// header parser could not evaluate.
type unsupportedDefineError struct {
	Name string
	Expr string
}

func (e *unsupportedDefineError) Error() string {
	return "pkcs11: cannot evaluate the value of #define " + e.Name + " (" + e.Expr + ")"
}

// sharedConstantValues records every value that OASIS deliberately gives to
// more than one name inside a single namespace. Each entry is keyed by
// "<Go type>/<CK prefix>/<value>" and lists the colliding names in sorted
// order, so that a third name joining an existing pair fails the test just as
// a brand new collision does.
//
// Everything listed here is either an OASIS alias (a second spelling of one
// mechanism, usually a deprecated or historical name) or a value belonging to
// a flag or parameter-set namespace that PKCS#11 scopes by context but Go
// happens to give a single named type.
var sharedConstantValues = map[string][]string{
	// CKA_ECDSA_PARAMS is the deprecated spelling of CKA_EC_PARAMS.
	"AttributeType/CKA/0x00000180": {"CKA_EC_PARAMS", "CKA_ECDSA_PARAMS"},

	// CAST128 and CAST5 name the same cipher.
	"KeyType/CKK/0x00000018":       {"CKK_CAST128", "CKK_CAST5"},
	"MechanismType/CKM/0x00000320": {"CKM_CAST128_KEY_GEN", "CKM_CAST5_KEY_GEN"},
	"MechanismType/CKM/0x00000321": {"CKM_CAST128_ECB", "CKM_CAST5_ECB"},
	"MechanismType/CKM/0x00000322": {"CKM_CAST128_CBC", "CKM_CAST5_CBC"},
	"MechanismType/CKM/0x00000323": {"CKM_CAST128_MAC", "CKM_CAST5_MAC"},
	"MechanismType/CKM/0x00000324": {"CKM_CAST128_MAC_GENERAL", "CKM_CAST5_MAC_GENERAL"},
	"MechanismType/CKM/0x00000325": {"CKM_CAST128_CBC_PAD", "CKM_CAST5_CBC_PAD"},
	"MechanismType/CKM/0x000003A4": {"CKM_PBE_MD5_CAST128_CBC", "CKM_PBE_MD5_CAST5_CBC"},
	"MechanismType/CKM/0x000003A5": {"CKM_PBE_SHA1_CAST128_CBC", "CKM_PBE_SHA1_CAST5_CBC"},

	// CKM_ECDSA_KEY_PAIR_GEN is the deprecated spelling of CKM_EC_KEY_PAIR_GEN.
	"MechanismType/CKM/0x00001040": {"CKM_ECDSA_KEY_PAIR_GEN", "CKM_EC_KEY_PAIR_GEN"},

	// CKF_EC_NAMEDCURVE is the name CKF_EC_OID carried before v3.0.
	"MechanismFlag/CKF/0x00800000": {"CKF_EC_NAMEDCURVE", "CKF_EC_OID"},

	// CKF_HW and CKF_END_OF_MESSAGE also share the low bit, but they no longer
	// collide in THIS namespace: CKF_END_OF_MESSAGE is a flag on the
	// message-based operation functions rather than a CK_MECHANISM_INFO flag, so
	// it is typed uint32 and MechanismInfo.HasFlag can no longer be handed it.
	// While it was a MechanismFlag, that call returned true for every hardware
	// mechanism and still compiled.

	// CKF_INTERFACE_FORK_SAFE describes an interface returned by
	// C_GetInterface; CKF_VALIDATION_PROTECTED describes a validation object.
	// Again two unrelated flag words that share the low bit.
	"uint64/CKF/0x00000001": {"CKF_INTERFACE_FORK_SAFE", "CKF_VALIDATION_PROTECTED"},

	// Parameter set values are scoped per key type, so ML-DSA, ML-KEM and
	// SLH-DSA each number their own sets from one. CKA_PARAMETER_SET is only
	// ever read together with CKA_KEY_TYPE, which disambiguates them.
	"ParameterSetType/CKP/0x00000001": {"CKP_ML_DSA_44", "CKP_ML_KEM_512", "CKP_SLH_DSA_SHA2_128S"},
	"ParameterSetType/CKP/0x00000002": {"CKP_ML_DSA_65", "CKP_ML_KEM_768", "CKP_SLH_DSA_SHAKE_128S"},
	"ParameterSetType/CKP/0x00000003": {"CKP_ML_DSA_87", "CKP_ML_KEM_1024", "CKP_SLH_DSA_SHA2_128F"},
}

// evalConstExpr evaluates the limited set of expression forms the PKCS#11
// constant blocks use: integer literals, references to an already-resolved
// constant, parenthesised expressions, type conversions, bitwise complement,
// and the bitwise or, addition and shift operators. Anything else is reported
// rather than guessed at.
func evalConstExpr(expr ast.Expr, resolved map[string]uint64) (uint64, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return 0, false
		}
		v, err := strconv.ParseUint(strings.ReplaceAll(e.Value, "_", ""), 0, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	case *ast.Ident:
		v, ok := resolved[e.Name]
		return v, ok
	case *ast.ParenExpr:
		return evalConstExpr(e.X, resolved)
	case *ast.CallExpr:
		// A type conversion such as uint64(0).
		if len(e.Args) != 1 {
			return 0, false
		}
		return evalConstExpr(e.Args[0], resolved)
	case *ast.UnaryExpr:
		v, ok := evalConstExpr(e.X, resolved)
		if !ok || e.Op != token.XOR {
			return 0, false
		}
		return ^v, true
	case *ast.BinaryExpr:
		left, lok := evalConstExpr(e.X, resolved)
		right, rok := evalConstExpr(e.Y, resolved)
		if !lok || !rok {
			return 0, false
		}
		switch e.Op {
		case token.OR:
			return left | right, true
		case token.ADD:
			return left + right, true
		case token.SHL:
			return left << right, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

// scanPackageConstants recovers every PKCS#11 constant declared in the
// non-test sources of this package, together with its declared Go type.
func scanPackageConstants(t *testing.T) []ckConstant {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	var pending []struct {
		name string
		typ  string
		expr ast.Expr
		pos  string
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			lastType := ""
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if ident, ok := value.Type.(*ast.Ident); ok {
					lastType = ident.Name
				}
				if len(value.Names) != len(value.Values) {
					continue
				}
				for i, ident := range value.Names {
					if !ckNamePattern.MatchString(ident.Name) {
						continue
					}
					pending = append(pending, struct {
						name string
						typ  string
						expr ast.Expr
						pos  string
					}{ident.Name, lastType, value.Values[i], fset.Position(ident.Pos()).String()})
				}
			}
		}
	}

	// Two passes so that a constant declared as an alias of another constant
	// resolves regardless of declaration order.
	resolved := make(map[string]uint64, len(pending))
	for pass := 0; pass < 2; pass++ {
		for _, p := range pending {
			if _, done := resolved[p.name]; done {
				continue
			}
			if v, ok := evalConstExpr(p.expr, resolved); ok {
				resolved[p.name] = v
			}
		}
	}

	constants := make([]ckConstant, 0, len(pending))
	for _, p := range pending {
		v, ok := resolved[p.name]
		if !ok {
			t.Errorf("%v", &unsupportedConstExprError{Name: p.name, Pos: p.pos})
			continue
		}
		constants = append(constants, ckConstant{Name: p.name, Type: p.typ, Value: v, Pos: p.pos})
	}
	return constants
}

// namespaceKey identifies the space a constant's value must be unique within:
// its declared Go type together with its CK prefix.
func namespaceKey(c ckConstant) string {
	prefix := c.Name
	if idx := strings.Index(prefix, "_"); idx >= 0 {
		prefix = prefix[:idx]
	}
	typ := c.Type
	if typ == "" {
		typ = "untyped"
	}
	return typ + "/" + prefix
}

// TestCKConstantValuesAreUniqueWithinNamespace asserts that no two PKCS#11
// constants in the same namespace share a value, except for the aliases and
// context-scoped flag words listed in sharedConstantValues. A collision is the
// dangerous failure mode for a Cryptoki module: dispatch is by value, so a
// duplicate silently sends one operation to another's implementation.
func TestCKConstantValuesAreUniqueWithinNamespace(t *testing.T) {
	constants := scanPackageConstants(t)

	// The scanner reading nothing at all would make this test vacuously
	// green, so require it to have found the bulk of the tables.
	if len(constants) < 700 {
		t.Fatalf("scanned only %d PKCS#11 constants, expected the full tables; the scanner is not reading the sources", len(constants))
	}

	// Spot-check that the families this test exists to protect were scanned,
	// so a change to the naming convention cannot quietly drop one.
	for _, required := range []string{
		"CKM_HKDF_DERIVE", "CKM_SHA3_256", "CKF_HKDF_SALT_KEY",
		"CKP_SLH_DSA_SHAKE_128S", "CKM_AES_XTS", "CKM_XEDDSA",
	} {
		found := false
		for _, c := range constants {
			if c.Name == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("constant %s was not scanned; the collision check does not cover it", required)
		}
	}

	byValue := make(map[string][]string)
	positions := make(map[string]string)
	for _, c := range constants {
		key := fmt.Sprintf("%s/0x%08X", namespaceKey(c), c.Value)
		byValue[key] = append(byValue[key], c.Name)
		positions[c.Name] = c.Pos
	}

	for key, names := range byValue {
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		allowed, ok := sharedConstantValues[key]
		allowed = append([]string(nil), allowed...)
		sort.Strings(allowed)
		if !ok {
			t.Errorf("collision: %v all share the value in %s; distinct constants in one namespace must not share a value (declared at %s)",
				names, key, positions[names[0]])
			continue
		}
		if strings.Join(allowed, ",") != strings.Join(names, ",") {
			t.Errorf("collision set for %s changed: have %v, documented %v", key, names, allowed)
		}
	}

	// Keep the allowlist honest: an entry that no longer describes a real
	// collision would otherwise sit there excusing a future one.
	for key := range sharedConstantValues {
		if len(byValue[key]) < 2 {
			t.Errorf("sharedConstantValues entry %q no longer describes a collision and should be removed", key)
		}
	}
}

// parseCHeaderDefines reads the object-like #define values out of the C header
// that cmd/pkcs11-module exports. It returns the values it could evaluate and,
// separately, the definitions it could not, so that the caller can fail rather
// than silently skip a constant it meant to check.
func parseCHeaderDefines(path string) (values map[string]uint64, unparsed map[string]error, err error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, err
	}

	values = make(map[string]uint64)
	unparsed = make(map[string]error)

	definePattern := regexp.MustCompile(`^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S.*?)\s*$`)
	inBlockComment := false
	var pending [][2]string

	for _, raw := range strings.Split(string(data), "\n") {
		line := raw
		if inBlockComment {
			idx := strings.Index(line, "*/")
			if idx < 0 {
				continue
			}
			line = line[idx+2:]
			inBlockComment = false
		}
		if idx := strings.Index(line, "/*"); idx >= 0 {
			end := strings.Index(line[idx:], "*/")
			if end < 0 {
				line = line[:idx]
				inBlockComment = true
			} else {
				line = line[:idx] + line[idx+end+2:]
			}
		}
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}

		match := definePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name, expr := match[1], strings.TrimSpace(match[2])
		if !ckNamePattern.MatchString(name) {
			continue
		}
		pending = append(pending, [2]string{name, expr})
	}

	// Resolve repeatedly so that a definition referring to one that appears
	// later in the file, such as the CKF_ARRAY_ATTRIBUTE array attributes,
	// still resolves.
	for {
		progress := false
		for _, p := range pending {
			if _, done := values[p[0]]; done {
				continue
			}
			v, evalErr := evalDefineExpr(p[0], p[1], values)
			if evalErr != nil {
				continue
			}
			values[p[0]] = v
			progress = true
		}
		if !progress {
			break
		}
	}
	for _, p := range pending {
		if _, done := values[p[0]]; !done {
			unparsed[p[0]] = &unsupportedDefineError{Name: p[0], Expr: p[1]}
		}
	}
	return values, unparsed, nil
}

// evalDefineExpr evaluates the forms the header uses: a single integer
// literal, a reference to another definition, or those combined with the
// bitwise or operator, optionally parenthesised, complemented with "~" and
// carrying a UL suffix.
func evalDefineExpr(name, expr string, defined map[string]uint64) (uint64, error) {
	expr = strings.TrimSpace(expr)
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}

	var result uint64
	for _, term := range strings.Split(expr, "|") {
		term = strings.Trim(strings.TrimSpace(term), "()")
		term = strings.TrimSpace(term)
		complement := strings.HasPrefix(term, "~")
		term = strings.TrimSpace(strings.TrimPrefix(term, "~"))

		value, ok := uint64(0), false
		if v, err := strconv.ParseUint(strings.TrimRight(term, "ULul"), 0, 64); err == nil {
			value, ok = v, true
		} else if v, found := defined[term]; found {
			value, ok = v, true
		}
		if !ok {
			return 0, &unsupportedDefineError{Name: name, Expr: expr}
		}
		if complement {
			value = ^value
		}
		result |= value
	}
	return result, nil
}

// TestGoConstantsMatchCHeader asserts that every PKCS#11 constant defined both
// in Go and in the exported C header holds the same value. The Go module and
// the header are two halves of one ABI: a C application compiles against the
// header, so a value corrected on one side and not the other leaves the
// module unable to recognise the requests that application sends.
func TestGoConstantsMatchCHeader(t *testing.T) {
	headerValues, unparsed, err := parseCHeaderDefines(cHeaderPath)
	if err != nil {
		t.Fatalf("read C header %s: %v", cHeaderPath, err)
	}
	if len(headerValues) < 500 {
		t.Fatalf("parsed only %d definitions from %s, expected the full header", len(headerValues), cHeaderPath)
	}

	constants := scanPackageConstants(t)
	compared := 0
	comparedNames := make(map[string]bool, len(constants))
	for _, c := range constants {
		if parseErr, bad := unparsed[c.Name]; bad {
			t.Errorf("%s is declared in Go but its header definition could not be checked: %v", c.Name, parseErr)
			continue
		}
		headerValue, ok := headerValues[c.Name]
		if !ok {
			continue
		}
		compared++
		comparedNames[c.Name] = true
		if headerValue != c.Value {
			t.Errorf("%s drifted: Go has 0x%08X (%s) but %s has 0x%08X",
				c.Name, c.Value, c.Pos, cHeaderPath, headerValue)
		}
	}
	if compared < 400 {
		t.Fatalf("only %d constants were shared between Go and the C header; the comparison is not covering the ABI", compared)
	}

	// The comparison above only sees a constant that both sides declare, so a
	// constant dropped from one side passes silently. Name the ones whose
	// value has been argued over, so that losing either declaration fails
	// here rather than in a customer's C application.
	for _, name := range requiredHeaderComparisons {
		if !comparedNames[name] {
			t.Errorf("%s was not compared against %s: it is missing from the Go constants or from the header", name, cHeaderPath)
		}
	}
}

// requiredHeaderComparisons lists constants that must be present on both
// sides of the ABI for the comparison to be meaningful. The two KEM template
// attributes are here because OASIS defines them without the
// CKF_ARRAY_ATTRIBUTE bit that every other *_TEMPLATE attribute carries, and
// this module previously set the bit on both sides at once, which made them
// self-consistent and non-interoperable.
//
// CKR_TOKEN_NOT_INITIALIZED anchors the CKR_ namespace in this check. Both
// sides once gave 0x00000208 to an invented CKR_OPERATION_INCOMPATIBLE, so a
// token reporting the factory state that PKCS#11 v3.2 section 5.1.3 defines
// was rendered under a name that does not exist in the specification.
var requiredHeaderComparisons = []string{
	"CKA_ENCAPSULATE_TEMPLATE",
	"CKA_DECAPSULATE_TEMPLATE",
	"CKR_TOKEN_NOT_INITIALIZED",
}

// repoRootPath locates the repository root relative to this package directory.
const repoRootPath = "../../.."

// canonicalIncludeDir is the one directory in this repository that may hold the
// PKCS#11 C headers. Every cgo package that compiles against Cryptoki types
// must include from here.
const canonicalIncludeDir = "cmd/pkcs11-module/include"

// duplicateHeaderError reports a second copy of a PKCS#11 C header found
// outside the canonical include directory.
type duplicateHeaderError struct {
	Path string
}

func (e *duplicateHeaderError) Error() string {
	return "pkcs11: duplicate C header at " + e.Path + "; the only copy may live in " + canonicalIncludeDir
}

// cgoIncludeDirective matches a cgo CFLAGS line that adds an include directory
// rooted at the package source directory.
var cgoIncludeDirective = regexp.MustCompile(`#cgo CFLAGS:\s*-I\$\{SRCDIR\}/(\S+)`)

// skippedTreeNames are directories that carry third-party or generated content
// and are not part of this repository's own sources.
var skippedTreeNames = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"build":        true,
	"dist":         true,
}

// TestSingleCHeaderCopyInRepository asserts that exactly one copy of each
// PKCS#11 C header exists, in the canonical include directory that
// TestGoConstantsMatchCHeader checks, and that every cgo package includes from
// there.
//
// A second copy of the header is the drift vector the constant guard cannot
// see: it stays whatever version it was branched from while the canonical
// header moves, and the guard, pointed at one path, never reads it. The xkey
// PKCS#11 provider carried such a copy — a v3.0-era pkcs11t.h with 584 defines
// against the canonical header's 709, missing every v3.2 constant — and it was
// unguarded for as long as it existed.
func TestSingleCHeaderCopyInRepository(t *testing.T) {
	root, err := filepath.Abs(repoRootPath)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	canonical := filepath.Join(root, filepath.FromSlash(canonicalIncludeDir))

	headerNames := map[string]bool{"pkcs11.h": true, "pkcs11t.h": true, "pkcs11f.h": true}
	found := make(map[string][]string, len(headerNames))
	var includeDirectives []string

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedTreeNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if headerNames[d.Name()] {
			found[d.Name()] = append(found[d.Name()], path)
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range cgoIncludeDirective.FindAllStringSubmatch(string(source), -1) {
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(m[1])))
			if resolved != canonical {
				continue
			}
			includeDirectives = append(includeDirectives, path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk repository at %s: %v", root, walkErr)
	}

	for name := range headerNames {
		paths := found[name]
		if len(paths) == 0 {
			t.Errorf("%s was not found anywhere under %s; the canonical header set is incomplete", name, root)
			continue
		}
		sort.Strings(paths)
		for _, p := range paths {
			if filepath.Dir(p) != canonical {
				t.Errorf("%v", &duplicateHeaderError{Path: p})
			}
		}
	}

	// The walk finding no cgo package at all would make the include check
	// vacuous, so require the packages that compile against Cryptoki to be
	// present and pointed at the canonical directory.
	if len(includeDirectives) < 2 {
		t.Errorf("only %d cgo source files include from %s; the ABI is no longer compiled against the guarded header",
			len(includeDirectives), canonicalIncludeDir)
	}
}
