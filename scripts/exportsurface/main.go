// Command exportsurface diffs the exported Go API of a set of modules
// between two revisions materialized as ordinary file trees.
//
// It deliberately does not invoke `go build`, `go list` or anything else
// that resolves a module graph: release-alpha.sh runs it as a precondition,
// before anything is written, and a step that needs `go mod download` to
// succeed is not fast or offline-safe enough for that job. Instead it parses
// only the .go files that make up each candidate package with go/parser and
// reads their top-level declarations directly, the same information `go doc`
// would show a consumer deciding whether a package changed shape.
//
// Usage:
//
//	exportsurface --old DIR --new DIR --module PATH [--module PATH ...]
//
// PATH is a module's directory relative to both --old and --new, e.g. ".",
// "sdk/go", "xkey" -- repeat --module once per published module. Within a
// PATH, every directory that carries its own package -- except one that
// begins another Go module (has its own go.mod), is named "internal" or
// falls under a directory so named, is "testdata" or "vendor", or whose
// package clause is "main" -- contributes its exported declarations to that
// revision's symbol set.
//
// exportsurface prints one line per differing symbol, "+ <module>:<pkg>.<name>"
// for a symbol present only in --new and "- ..." for one present only in
// --old, and exits 0 once the comparison completed. Growth is not a failure
// here: refusing a release over it is release-alpha.sh's policy, not this
// tool's -- this tool only ever reports what changed.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// usageError is returned for a malformed invocation, distinct from a
// moduleError so main can tell "fix the command line" apart from "fix the
// tree being compared" when it chooses an exit code.
type usageError struct {
	reason string
}

func (e *usageError) Error() string { return e.reason }

// pathEscapeError is returned when a --module argument would resolve outside
// the --old/--new tree it is supposed to name a directory under: an absolute
// path, a literal ".." segment, or (after joining and cleaning) a path Rel
// reports as outside root. --old/--new/--module are release-alpha.sh's own
// arguments, not attacker input in the usual sense, but this tool also runs
// against a fetched git ref's tree, and a module path that walks out of the
// two directories it is meant to compare is a bug worth refusing loudly
// rather than a filesystem walk worth having.
type pathEscapeError struct {
	module string
	root   string
	reason string
}

func (e *pathEscapeError) Error() string {
	return fmt.Sprintf("--module %q escapes %q: %s", e.module, e.root, e.reason)
}

// moduleError names the module and revision a failure happened under, so a
// parse error deep in a nested package does not read as "something in this
// program broke" -- it reads as "this file, under this module, in this tree".
type moduleError struct {
	revision string // "old" or "new"
	module   string
	path     string
	cause    error
}

func (e *moduleError) Error() string {
	return fmt.Sprintf("%s revision, module %q, %s: %v", e.revision, e.module, e.path, e.cause)
}

func (e *moduleError) Unwrap() error { return e.cause }

func main() {
	oldDir, newDir, modules, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "exportsurface: %v\n", err)
		fmt.Fprintln(os.Stderr, "usage: exportsurface --old DIR --new DIR --module PATH [--module PATH ...]")
		os.Exit(2)
	}

	added, removed, err := diff(oldDir, newDir, modules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exportsurface: %v\n", err)
		os.Exit(1)
	}

	for _, s := range added {
		fmt.Printf("+ %s\n", s)
	}
	for _, s := range removed {
		fmt.Printf("- %s\n", s)
	}
}

func parseArgs(args []string) (oldDir, newDir string, modules []string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--old":
			if i+1 >= len(args) {
				return "", "", nil, &usageError{"--old needs a value"}
			}
			i++
			oldDir = args[i]
		case "--new":
			if i+1 >= len(args) {
				return "", "", nil, &usageError{"--new needs a value"}
			}
			i++
			newDir = args[i]
		case "--module":
			if i+1 >= len(args) {
				return "", "", nil, &usageError{"--module needs a value"}
			}
			i++
			modules = append(modules, args[i])
		default:
			return "", "", nil, &usageError{fmt.Sprintf("unknown argument %q", args[i])}
		}
	}
	if oldDir == "" {
		return "", "", nil, &usageError{"--old is required"}
	}
	if newDir == "" {
		return "", "", nil, &usageError{"--new is required"}
	}
	if len(modules) == 0 {
		return "", "", nil, &usageError{"at least one --module is required"}
	}
	return oldDir, newDir, modules, nil
}

// diff computes the symbol sets for every module under oldDir and newDir and
// returns what was added and removed, both sorted for a deterministic report.
func diff(oldDir, newDir string, modules []string) (added, removed []string, err error) {
	oldRoot, err := resolveRoot(oldDir)
	if err != nil {
		return nil, nil, fmt.Errorf("--old %q: %w", oldDir, err)
	}
	newRoot, err := resolveRoot(newDir)
	if err != nil {
		return nil, nil, fmt.Errorf("--new %q: %w", newDir, err)
	}

	addedSet := map[string]struct{}{}
	removedSet := map[string]struct{}{}

	for _, m := range modules {
		oldSyms, err := collectModule(oldRoot, m, "old")
		if err != nil {
			return nil, nil, err
		}
		newSyms, err := collectModule(newRoot, m, "new")
		if err != nil {
			return nil, nil, err
		}
		for s := range newSyms {
			if _, ok := oldSyms[s]; !ok {
				addedSet[s] = struct{}{}
			}
		}
		for s := range oldSyms {
			if _, ok := newSyms[s]; !ok {
				removedSet[s] = struct{}{}
			}
		}
	}

	added = setToSortedSlice(addedSet)
	removed = setToSortedSlice(removedSet)
	return added, removed, nil
}

func setToSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// resolveRoot makes a --old/--new argument absolute and clean, once, so every
// module path validated against it (resolveModuleRoot) and every filesystem
// call that follows is anchored to one unambiguous tree rather than
// re-deriving it, differently, at each call site.
func resolveRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// resolveModuleRoot validates module against an already-resolved root (see
// resolveRoot) and returns the directory it names, still under root. Three
// checks, in order: module must be relative (an absolute path ignores root
// entirely); no path segment may be a literal ".."; and, via escapesRoot,
// filepath.Rel(root, joined) must not itself start with ".." -- the check
// that actually PROVES containment, since Clean alone collapses a ".."
// against an earlier segment rather than refusing it, and a module value
// assembled from separator-escaped segments could still Join to something
// Clean resolves outside root without ever containing a literal ".."
// component the segment scan above would have caught.
//
// This is the first, string-level layer of defense; collectModule opens an
// os.Root at root as the second, syscall-level one, which is what actually
// stops a symlink under root from pointing outside it -- something no amount
// of string validation here can see.
func resolveModuleRoot(root, module string) (string, error) {
	if filepath.IsAbs(module) {
		return "", &pathEscapeError{module, root, "must be relative, not absolute"}
	}
	for _, seg := range strings.Split(filepath.ToSlash(module), "/") {
		if seg == ".." {
			return "", &pathEscapeError{module, root, `must not contain a ".." segment`}
		}
	}
	joined := filepath.Clean(filepath.Join(root, module))
	escaped, err := escapesRoot(root, joined)
	if err != nil {
		return "", &pathEscapeError{module, root, err.Error()}
	}
	if escaped {
		return "", &pathEscapeError{module, root, "resolves outside --old/--new"}
	}
	return joined, nil
}

// escapesRoot reports whether joined -- expected to already be root/module,
// Cleaned -- lies outside root, using filepath.Rel as the actual containment
// proof rather than trusting that Clean alone kept it inside. Kept as its own
// function so it is unit tested directly against crafted root/joined pairs,
// not only through cases resolveModuleRoot's earlier, coarser ".." segment
// scan happens to let reach it.
func escapesRoot(root, joined string) (bool, error) {
	rel, err := filepath.Rel(root, joined)
	if err != nil {
		return false, err
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// collectModule walks every package directory under root/module and returns
// the exported symbols they declare, labelled "<module>:<pkg>.<name>". root
// must already be resolved (resolveRoot); module is validated against it
// (resolveModuleRoot) before anything reaches the filesystem -- and, as a
// second, independent layer, every filesystem call below goes through an
// os.Root opened at root, which refuses at the syscall level (not merely a
// string check a symlink could defeat) to resolve any name that would leave
// the directory tree it was opened on
// (https://github.com/securego/gosec/issues/1721; Clean/Abs/Join alone
// evaluate a ".." instead of refusing it, so they cannot make this guarantee
// on their own).
func collectModule(root, module, revision string) (result map[string]struct{}, retErr error) {
	modRoot, err := resolveModuleRoot(root, module)
	if err != nil {
		return nil, &moduleError{revision, module, root, err}
	}
	relModule, err := filepath.Rel(root, modRoot)
	if err != nil {
		return nil, &moduleError{revision, module, root, err}
	}
	relModule = filepath.ToSlash(relModule)

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, &moduleError{revision, module, root, err}
	}
	defer func() {
		if cerr := rootHandle.Close(); cerr != nil && retErr == nil {
			result, retErr = nil, &moduleError{revision, module, root, cerr}
		}
	}()
	rootFS := rootHandle.FS()

	info, err := fs.Stat(rootFS, relModule)
	if err != nil {
		return nil, &moduleError{revision, module, modRoot, err}
	}
	if !info.IsDir() {
		return nil, &moduleError{revision, module, modRoot, fmt.Errorf("not a directory")}
	}

	out := map[string]struct{}{}
	walkErr := fs.WalkDir(rootFS, relModule, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != relModule && skipDir(rootFS, p, d.Name()) {
			return fs.SkipDir
		}
		return collectDir(rootFS, p, relModule, module, out)
	})
	if walkErr != nil {
		return nil, &moduleError{revision, module, modRoot, walkErr}
	}
	return out, nil
}

// skipDir is true for a directory that never contributes to the exported
// surface: hidden directories, fixtures, vendored code, anything named or
// nested under "internal" (go-xkms#419/#421's growth gate is scoped to the
// PUBLISHED surface, and "internal" is the language's own boundary for what
// is not that), and the root of another Go module -- xkey and sdk/go are
// scanned as their own --module entries, so descending into them while
// scanning "." would double count their symbols under the wrong label. p is
// relative to the os.Root fsys was opened on, in io/fs's always-forward-slash
// form, joined with "path" rather than "path/filepath" accordingly.
func skipDir(fsys fs.FS, p, name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "testdata", "vendor", "internal":
		return true
	}
	if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
		return true
	}
	return false
}

// collectDir parses the non-test .go files directly inside dir -- one Go
// package, by construction -- and adds their exported declarations to out.
// A "main" package is skipped: nothing ever imports it, so it has no
// consumer-visible surface for a bump-level check to protect. dir and
// modRootRel are both relative to fsys (an os.Root's FS()), in io/fs form.
func collectDir(fsys fs.FS, dir, modRootRel, module string, out map[string]struct{}) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fp := path.Join(dir, name)
		src, err := fs.ReadFile(fsys, fp)
		if err != nil {
			return fmt.Errorf("read %s: %w", fp, err)
		}
		f, err := parser.ParseFile(fset, fp, src, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", fp, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil
	}
	if files[0].Name.Name == "main" {
		return nil
	}

	relDir, err := filepath.Rel(modRootRel, dir)
	if err != nil {
		return err
	}
	relDir = filepath.ToSlash(relDir)

	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				addFunc(out, module, relDir, d)
			case *ast.GenDecl:
				addGenDecl(out, module, relDir, d)
			}
		}
	}
	return nil
}

func addFunc(out map[string]struct{}, module, relDir string, d *ast.FuncDecl) {
	if !d.Name.IsExported() {
		return
	}
	if d.Recv == nil {
		out[label(module, relDir, d.Name.Name)] = struct{}{}
		return
	}
	recv := receiverTypeName(d.Recv)
	if recv == "" || !ast.IsExported(recv) {
		return
	}
	out[label(module, relDir, recv+"."+d.Name.Name)] = struct{}{}
}

// receiverTypeName returns the bare type name a method is declared on,
// unwrapping a pointer receiver and a generic receiver's type parameters --
// `func (s *Store[K]) Get` and `func (s Store[K]) Get` name the same surface.
func receiverTypeName(fl *ast.FieldList) string {
	if fl == nil || len(fl.List) == 0 {
		return ""
	}
	expr := fl.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func addGenDecl(out map[string]struct{}, module, relDir string, d *ast.GenDecl) {
	switch d.Tok {
	case token.CONST, token.VAR:
		for _, spec := range d.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				if n.IsExported() {
					out[label(module, relDir, n.Name)] = struct{}{}
				}
			}
		}
	case token.TYPE:
		for _, spec := range d.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			out[label(module, relDir, ts.Name.Name)] = struct{}{}
			switch t := ts.Type.(type) {
			case *ast.StructType:
				addFields(out, module, relDir, ts.Name.Name, t.Fields)
			case *ast.InterfaceType:
				addMethods(out, module, relDir, ts.Name.Name, t.Methods)
			}
		}
	}
}

// addFields records a struct's exported fields, including an embedded
// field's promoted name -- `Store` embedding `sync.Mutex` promotes `Lock`
// and `Unlock`, but the embed itself, `Mutex`, is also part of the surface.
func addFields(out map[string]struct{}, module, relDir, typeName string, fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		if len(f.Names) == 0 {
			if name := embeddedName(f.Type); name != "" && ast.IsExported(name) {
				out[label(module, relDir, typeName+"."+name)] = struct{}{}
			}
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				out[label(module, relDir, typeName+"."+n.Name)] = struct{}{}
			}
		}
	}
}

func embeddedName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.StarExpr:
		return embeddedName(t.X)
	}
	return ""
}

// addMethods records an interface's own exported methods. An embedded
// interface has no Names and contributes nothing here -- its methods surface
// through its own type's entry, not duplicated onto the embedder.
func addMethods(out map[string]struct{}, module, relDir, typeName string, fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, f := range fl.List {
		if len(f.Names) == 0 {
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				out[label(module, relDir, typeName+"."+n.Name)] = struct{}{}
			}
		}
	}
}

func label(module, relDir, name string) string {
	if relDir == "." {
		return module + ":" + name
	}
	return module + ":" + relDir + "." + name
}
