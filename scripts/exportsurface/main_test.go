package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveRoot(t *testing.T) {
	t.Run("accepts a relative directory and returns it absolute and clean", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("os.Getwd: %v", err)
		}
		got, err := resolveRoot(".")
		if err != nil {
			t.Fatalf("resolveRoot(\".\"): %v", err)
		}
		want := filepath.Clean(wd)
		if got != want {
			t.Errorf("resolveRoot(\".\") = %q, want %q", got, want)
		}
	})

	t.Run("is idempotent on an already-absolute, already-clean directory", func(t *testing.T) {
		dir := t.TempDir()
		got, err := resolveRoot(dir)
		if err != nil {
			t.Fatalf("resolveRoot(%q): %v", dir, err)
		}
		if got != filepath.Clean(dir) {
			t.Errorf("resolveRoot(%q) = %q, want %q", dir, got, filepath.Clean(dir))
		}
	})
}

func TestResolveModuleRoot_Accepts(t *testing.T) {
	root := t.TempDir()

	cases := []struct {
		name   string
		module string
		want   string
	}{
		{"the root itself", ".", root},
		{"a single-segment subdirectory", "sdk", filepath.Join(root, "sdk")},
		{"a multi-segment subdirectory", "sdk/go", filepath.Join(root, "sdk", "go")},
		{"a trailing slash is cleaned away", "xkey/", filepath.Join(root, "xkey")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveModuleRoot(root, c.module)
			if err != nil {
				t.Fatalf("resolveModuleRoot(%q, %q): %v", root, c.module, err)
			}
			if got != c.want {
				t.Errorf("resolveModuleRoot(%q, %q) = %q, want %q", root, c.module, got, c.want)
			}
		})
	}
}

// TestResolveModuleRoot_RejectsEscapes is the gosec G703 regression: every
// one of these used to reach os.Stat/filepath.WalkDir unvalidated.
func TestResolveModuleRoot_RejectsEscapes(t *testing.T) {
	root := t.TempDir()

	cases := []struct {
		name   string
		module string
	}{
		{"an absolute path ignores root entirely", "/etc/passwd"},
		{"a bare \"..\"", ".."},
		{"a leading \"..\" segment", "../outside"},
		{"a trailing \"..\" segment", "sdk/.."},
		{"a \"..\" segment in the middle", "sdk/../../etc"},
		{"repeated \"..\" segments", "../../../../etc/passwd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveModuleRoot(root, c.module)
			if err == nil {
				t.Fatalf("resolveModuleRoot(%q, %q) = %q, nil -- want a rejection", root, c.module, got)
			}
			var pe *pathEscapeError
			if !errors.As(err, &pe) {
				t.Fatalf("resolveModuleRoot(%q, %q) error is %T (%v), want *pathEscapeError", root, c.module, err, err)
			}
			if pe.module != c.module {
				t.Errorf("pathEscapeError.module = %q, want %q", pe.module, c.module)
			}
			if got != "" {
				t.Errorf("resolveModuleRoot(%q, %q) returned a non-empty path %q on error", root, c.module, got)
			}
		})
	}
}

func TestEscapesRoot(t *testing.T) {
	t.Run("a path under root does not escape", func(t *testing.T) {
		escaped, err := escapesRoot("/a/b", "/a/b/c")
		if err != nil {
			t.Fatalf("escapesRoot: %v", err)
		}
		if escaped {
			t.Errorf("escapesRoot(/a/b, /a/b/c) = true, want false")
		}
	})

	t.Run("root itself does not escape", func(t *testing.T) {
		escaped, err := escapesRoot("/a/b", "/a/b")
		if err != nil {
			t.Fatalf("escapesRoot: %v", err)
		}
		if escaped {
			t.Errorf("escapesRoot(/a/b, /a/b) = true, want false")
		}
	})

	// This is the case resolveModuleRoot's earlier ".." segment scan makes
	// unreachable from a real --module argument today -- exercised directly
	// here so the containment proof itself is verified, not only the coarser
	// check that currently happens to precede every call reaching it.
	t.Run("a sibling directory escapes, with no \"..\" in sight", func(t *testing.T) {
		escaped, err := escapesRoot("/a/b", "/a/c")
		if err != nil {
			t.Fatalf("escapesRoot: %v", err)
		}
		if !escaped {
			t.Errorf("escapesRoot(/a/b, /a/c) = false, want true")
		}
	})

	t.Run("a parent directory escapes", func(t *testing.T) {
		escaped, err := escapesRoot("/a/b", "/a")
		if err != nil {
			t.Fatalf("escapesRoot: %v", err)
		}
		if !escaped {
			t.Errorf("escapesRoot(/a/b, /a) = false, want true")
		}
	})
}

// TestCollectModule_RejectsModuleEscape is the end-to-end case for the
// string-level layer: a module argument that resolveModuleRoot refuses never
// reaches os.OpenRoot at all.
func TestCollectModule_RejectsModuleEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatalf("seed go.mod: %v", err)
	}

	_, err := collectModule(root, "../escape", "old")
	if err == nil {
		t.Fatal("collectModule with an escaping module succeeded, want an error")
	}
	var me *moduleError
	if !errors.As(err, &me) {
		t.Fatalf("collectModule error is %T (%v), want *moduleError", err, err)
	}
	var pe *pathEscapeError
	if !errors.As(err, &pe) {
		t.Fatalf("collectModule error does not wrap *pathEscapeError: %v", err)
	}
}

// TestCollectModule_RejectsSymlinkEscape proves the second, syscall-level
// layer earns its place: a module name with no ".." anywhere in it, naming a
// symlink that itself points outside root, passes every string check in
// resolveModuleRoot and is refused only because collectModule resolves it
// through an os.Root opened at root rather than through a raw os.Stat or
// filepath.WalkDir call.
func TestCollectModule_RejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevated privileges on windows")
	}

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.go"), []byte("package secret\n\nfunc Exfiltrated() {}\n"), 0o600); err != nil {
		t.Fatalf("seed outside package: %v", err)
	}

	link := filepath.Join(root, "escape-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	// The string-level layer alone would accept this: no "..", not absolute,
	// and it resolves (lexically) to a path under root.
	if _, err := resolveModuleRoot(root, "escape-link"); err != nil {
		t.Fatalf("resolveModuleRoot(%q, \"escape-link\") = %v, want nil (this case is exactly what it CANNOT see)", root, err)
	}

	_, err := collectModule(root, "escape-link", "old")
	if err == nil {
		t.Fatal("collectModule followed a symlink out of root and succeeded, want an error")
	}
}

func TestCollectModule_AcceptsAWellFormedModule(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg", "foo")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	src := "package foo\n\n// Exported is a symbol collectModule should find.\nfunc Exported() {}\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "foo.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := collectModule(root, ".", "new")
	if err != nil {
		t.Fatalf("collectModule(%q, \".\", \"new\") = %v", root, err)
	}
	const want = ".:pkg/foo.Exported"
	if _, ok := got[want]; !ok {
		t.Errorf("collectModule result = %v, want it to contain %q", got, want)
	}
}
