// Command secure-analyzer-symbol extracts the stable "symbol" text an
// allowlist entry in scripts/secure-analyzer-allowlist.txt keys on for one
// finding go-qrdb's pkg/secure/analyzer reported, given the file:line:col a
// `go vet -vettool=...` diagnostic carries.
//
// Only two of the three securecheck rules need this tool. Rule 1's forbidden
// import path and rule 3's flagged field name are already inside the
// diagnostic message text, so scripts/secure-analyzer.sh extracts those with
// a regexp and never calls this program for rule 1. Rule 2's message is the
// same fixed string ("call to ssh.ParsePrivateKey is forbidden; ...") for
// every call site, and rule 3's message never names the struct the field is
// declared on -- both need the actual source read back to produce a symbol
// that is not the same for every finding in the file. See go-xkms#607: the
// allowlist used to key on path:line alone, so an unrelated edit above an
// exempted line silently broke the exemption by shifting the line number.
//
// Usage:
//
//	secure-analyzer-symbol [-root <dir>] call <file> <line> <col>
//	secure-analyzer-symbol [-root <dir>] struct <file> <line> <col>
//
// "call" prints the exact source text of the call expression whose Pos()
// (the position go-qrdb's analyzer reports) is line:col in file, collapsed
// to one line. "struct" prints "<Struct>.<Field>" for the struct field
// whose name identifier is at line:col.
//
// line and col are 1-based, matching both go/token.Position and the
// file:line:col: prefix `go vet` prints on every diagnostic -- the two
// values this program's caller already has in hand from that same line, no
// translation either direction.
//
// -root defaults to the current directory (scripts/secure-analyzer.sh
// always passes it explicitly -- the module directory the finding's file
// is under). file is validated against root before anything is opened: it
// must resolve, after joining, to a path root contains, and file itself
// (whether given absolute or relative to root) may not contain a literal
// ".." segment. The file is then read through an *os.Root opened on root,
// which -- unlike Clean, Abs or Join, none of which refuse anything, they
// only compute a name -- refuses at the syscall level to resolve a name
// that would leave root, including through a symlink a string check alone
// cannot see (https://pkg.go.dev/os#OpenRoot).
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// usageError is returned for a malformed invocation, distinct from a
// notFoundError so main can tell "fix the command line" apart from "this
// position does not name what the caller expected" when it chooses an exit
// code.
type usageError struct {
	reason string
}

func (e *usageError) Error() string { return e.reason }

// notFoundError is returned when file parses cleanly but line:col does not
// land on the kind of node the requested mode looks for -- the caller's
// diagnostic and this program's parse of the same file disagree about where
// something is, which is always a bug worth failing loudly on rather than
// printing an empty or partial symbol an allowlist entry could silently key
// on.
type notFoundError struct {
	mode string
	file string
	line int
	col  int
}

func (e *notFoundError) Error() string {
	return fmt.Sprintf("no %s node at %s:%d:%d", e.mode, e.file, e.line, e.col)
}

// pathEscapeError is returned when file would resolve outside root: an
// explicit ".." segment, or (after joining and cleaning) a path Rel reports
// as outside root. file comes from scripts/secure-analyzer.sh, not
// untrusted input in the usual sense, but this program also runs on
// file:line:col text lifted out of `go vet`'s own diagnostic stream, so a
// path that walks out of the module directory it was reported under is a
// bug worth refusing loudly rather than a filesystem read worth having.
type pathEscapeError struct {
	file   string
	root   string
	reason string
}

func (e *pathEscapeError) Error() string {
	return fmt.Sprintf("file %q escapes root %q: %s", e.file, e.root, e.reason)
}

func main() {
	symbol, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "secure-analyzer-symbol: %v\n", err)
		if _, ok := err.(*usageError); ok {
			fmt.Fprintln(os.Stderr, "usage: secure-analyzer-symbol [-root <dir>] <call|struct> <file> <line> <col>")
			os.Exit(2)
		}
		os.Exit(1)
	}
	fmt.Println(symbol)
}

func run(args []string) (string, error) {
	root := ""
	if len(args) >= 2 && args[0] == "-root" {
		root = args[1]
		args = args[2:]
	}
	if len(args) != 4 {
		return "", &usageError{"exactly 4 positional arguments are required: <call|struct> <file> <line> <col>, plus an optional leading -root <dir>"}
	}
	mode, file := args[0], args[1]
	if mode != "call" && mode != "struct" {
		return "", &usageError{fmt.Sprintf("unknown mode %q, want call or struct", mode)}
	}
	line, err := strconv.Atoi(args[2])
	if err != nil {
		return "", &usageError{fmt.Sprintf("line %q is not an integer: %v", args[2], err)}
	}
	col, err := strconv.Atoi(args[3])
	if err != nil {
		return "", &usageError{fmt.Sprintf("col %q is not an integer: %v", args[3], err)}
	}

	if root == "" {
		root, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	root, err = resolveRoot(root)
	if err != nil {
		return "", err
	}

	absFile, relFile, err := resolveFile(root, file)
	if err != nil {
		return "", err
	}

	src, err := readUnderRoot(root, relFile)
	if err != nil {
		return "", err
	}

	fset := token.NewFileSet()
	// absFile, not relFile, so go/token positions and this program's own
	// error messages read as the path the caller passed in.
	astFile, err := parser.ParseFile(fset, absFile, src, 0)
	if err != nil {
		return "", err
	}

	switch mode {
	case "call":
		return callExprAt(fset, astFile, src, absFile, line, col)
	default:
		return structFieldAt(fset, astFile, absFile, line, col)
	}
}

// resolveRoot makes root absolute and clean, once, so resolveFile's
// containment check and readUnderRoot's os.Root are both anchored to the
// same unambiguous directory.
func resolveRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// resolveFile validates file against an already-resolved root
// (resolveRoot) and returns both the absolute path it names and that path
// relative to root, the form readUnderRoot's os.Root needs. Two checks, in
// order: no path segment may be a literal ".." (file may be given absolute
// or relative to root either way); and, via escapesRoot, filepath.Rel(root,
// candidate) must not itself start with ".." -- the check that actually
// PROVES containment, since Clean alone collapses a ".." against an
// earlier segment rather than refusing it, and a value assembled from
// separator-escaped segments could still Join to something Clean resolves
// outside root without ever containing a literal ".." component the
// segment scan above would have caught.
//
// This is the first, string-level layer of defense; readUnderRoot's
// os.Root is the second, syscall-level one, which is what actually stops a
// symlink under root from pointing outside it -- something no amount of
// string validation here can see.
func resolveFile(root, file string) (absPath, relPath string, err error) {
	for _, seg := range strings.Split(filepath.ToSlash(file), "/") {
		if seg == ".." {
			return "", "", &pathEscapeError{file, root, `must not contain a ".." segment`}
		}
	}

	candidate := file
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)

	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", "", &pathEscapeError{file, root, err.Error()}
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", &pathEscapeError{file, root, "resolves outside root"}
	}
	return candidate, filepath.ToSlash(rel), nil
}

// readUnderRoot reads relFile (root-relative, io/fs form) through an
// *os.Root opened on root -- see this package's doc comment for why that,
// rather than os.ReadFile on a Clean/Abs/Join'd name, is the actual
// containment guarantee.
func readUnderRoot(root, relFile string) ([]byte, error) {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(rootHandle.FS(), relFile)
	if cerr := rootHandle.Close(); cerr != nil && err == nil {
		return nil, cerr
	}
	return data, err
}

// callExprAt returns the exact source text of the call expression whose
// Pos() is line:col, collapsed to one line so it is safe as a
// tab-separated allowlist field. It scans for *ast.CallExpr specifically,
// rather than the innermost node at that position, because a CallExpr's
// Pos() is also its Fun's Pos() (and, for `pkg.Name(...)`, that selector's
// X's Pos() too) -- several nodes share the position the analyzer reports,
// and only the CallExpr is the one this program means to describe.
func callExprAt(fset *token.FileSet, f *ast.File, src []byte, file string, line, col int) (string, error) {
	var text string
	ast.Inspect(f, func(n ast.Node) bool {
		if text != "" {
			return false
		}
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pos := fset.Position(ce.Pos())
		if pos.Line != line || pos.Column != col {
			return true
		}
		start := fset.Position(ce.Pos()).Offset
		end := fset.Position(ce.End()).Offset
		text = collapse(string(src[start:end]))
		return false
	})
	if text == "" {
		return "", &notFoundError{mode: "call expression", file: file, line: line, col: col}
	}
	return text, nil
}

// structFieldAt returns "<Struct>.<Field>" for the field whose name
// identifier is at line:col. It only looks at top-level `type X struct {
// ... }` declarations -- every field go-qrdb's rule 3 has ever flagged in
// this repository is declared that way (see the allowlist's own history),
// and a field on an anonymous or locally-scoped struct type has no single
// name to key on regardless.
func structFieldAt(fset *token.FileSet, f *ast.File, file string, line, col int) (string, error) {
	var symbol string
	ast.Inspect(f, func(n ast.Node) bool {
		if symbol != "" {
			return false
		}
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				pos := fset.Position(name.Pos())
				if pos.Line == line && pos.Column == col {
					symbol = ts.Name.Name + "." + name.Name
					return false
				}
			}
		}
		return true
	})
	if symbol == "" {
		return "", &notFoundError{mode: "struct field", file: file, line: line, col: col}
	}
	return symbol, nil
}

// collapse folds s's whitespace (a call expression can span multiple
// source lines) into single spaces, so the result is safe as one field of a
// tab-separated allowlist line.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
