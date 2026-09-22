package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture writes src to a temp file named name under t's temp dir and
// returns its path -- callExprAt and structFieldAt both take a real path
// (for their error messages and, in run's caller, for os.ReadFile), so the
// fixtures live on disk rather than as bare strings.
func writeFixture(t *testing.T, name, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func parseFixture(t *testing.T, path string) (*token.FileSet, []byte) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return token.NewFileSet(), src
}

const callFixture = `package keys

import "golang.org/x/crypto/ssh"

func parseA(pemBytes []byte) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	_ = signer
	_ = err
}

func parseB(buf []byte) (int, error) {
	signer, err := ssh.ParsePrivateKey(buf)
	_ = signer
	return 0, err
}
`

func TestCallExprAt(t *testing.T) {
	t.Run("returns the exact call expression text at the reported position", func(t *testing.T) {
		path := writeFixture(t, "parse.go", callFixture)
		fset, src := parseFixture(t, path)
		astFile, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}

		// Line 6 is `signer, err := ssh.ParsePrivateKey(pemBytes)`; the call
		// starts at column 17, right after "signer, err := ".
		got, err := callExprAt(fset, astFile, src, path, 6, 17)
		if err != nil {
			t.Fatalf("callExprAt: %v", err)
		}
		want := "ssh.ParsePrivateKey(pemBytes)"
		if got != want {
			t.Errorf("callExprAt = %q, want %q", got, want)
		}

		// The second call site in the same file, different argument name,
		// must produce a DIFFERENT symbol -- the whole point of keying on
		// the call expression instead of the fixed diagnostic message.
		got2, err := callExprAt(fset, astFile, src, path, 12, 17)
		if err != nil {
			t.Fatalf("callExprAt (second site): %v", err)
		}
		if got2 == got {
			t.Errorf("two call sites with different arguments produced the same symbol %q", got2)
		}
	})

	t.Run("returns a notFoundError when line:col names no call expression", func(t *testing.T) {
		path := writeFixture(t, "parse.go", callFixture)
		fset, src := parseFixture(t, path)
		astFile, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}

		_, err = callExprAt(fset, astFile, src, path, 1, 1)
		if err == nil {
			t.Fatal("callExprAt: expected an error for a position with no call expression, got nil")
		}
		nfe, ok := err.(*notFoundError)
		if !ok {
			t.Fatalf("callExprAt error = %T, want *notFoundError", err)
		}
		if !strings.Contains(nfe.Error(), "call expression") {
			t.Errorf("notFoundError.Error() = %q, want it to mention \"call expression\"", nfe.Error())
		}
	})
}

const structFixture = `package fido2

// WebAuthnAuthenticationOptions carries the PIN for an assertion request.
type WebAuthnAuthenticationOptions struct {
	Origin string
	PIN    string
}

type WebAuthnRegistrationOptions struct {
	Origin string
	PIN    string
}
`

func TestStructFieldAt(t *testing.T) {
	t.Run("returns Struct.Field for the field at the reported position", func(t *testing.T) {
		path := writeFixture(t, "webauthn.go", structFixture)
		fset, src := parseFixture(t, path)
		astFile, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}
		_ = src

		// Line 6 is `	PIN    string` inside WebAuthnAuthenticationOptions;
		// "PIN" starts at column 2.
		got, err := structFieldAt(fset, astFile, path, 6, 2)
		if err != nil {
			t.Fatalf("structFieldAt: %v", err)
		}
		want := "WebAuthnAuthenticationOptions.PIN"
		if got != want {
			t.Errorf("structFieldAt = %q, want %q", got, want)
		}

		// Same field name, different struct: must resolve to a different
		// symbol so the two are independently allowlistable.
		got2, err := structFieldAt(fset, astFile, path, 11, 2)
		if err != nil {
			t.Fatalf("structFieldAt (second struct): %v", err)
		}
		want2 := "WebAuthnRegistrationOptions.PIN"
		if got2 != want2 {
			t.Errorf("structFieldAt = %q, want %q", got2, want2)
		}
	})

	t.Run("returns a notFoundError when line:col names no struct field", func(t *testing.T) {
		path := writeFixture(t, "webauthn.go", structFixture)
		fset, src := parseFixture(t, path)
		astFile, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}

		_, err = structFieldAt(fset, astFile, path, 1, 1)
		if err == nil {
			t.Fatal("structFieldAt: expected an error for a position with no struct field, got nil")
		}
		if _, ok := err.(*notFoundError); !ok {
			t.Fatalf("structFieldAt error = %T, want *notFoundError", err)
		}
	})
}

func TestRun(t *testing.T) {
	t.Run("call mode end-to-end through run, with an explicit -root", func(t *testing.T) {
		path := writeFixture(t, "parse.go", callFixture)
		got, err := run([]string{"-root", filepath.Dir(path), "call", path, "6", "17"})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if got != "ssh.ParsePrivateKey(pemBytes)" {
			t.Errorf("run = %q", got)
		}
	})

	t.Run("struct mode end-to-end through run, with an explicit -root", func(t *testing.T) {
		path := writeFixture(t, "webauthn.go", structFixture)
		got, err := run([]string{"-root", filepath.Dir(path), "struct", path, "6", "2"})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if got != "WebAuthnAuthenticationOptions.PIN" {
			t.Errorf("run = %q", got)
		}
	})

	t.Run("call mode end-to-end through run, root relative to the file's own directory", func(t *testing.T) {
		path := writeFixture(t, "parse.go", callFixture)
		got, err := run([]string{"-root", filepath.Dir(path), "call", "parse.go", "6", "17"})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if got != "ssh.ParsePrivateKey(pemBytes)" {
			t.Errorf("run = %q", got)
		}
	})

	t.Run("rejects an unknown mode", func(t *testing.T) {
		_, err := run([]string{"bogus", "file.go", "1", "1"})
		if err == nil {
			t.Fatal("run: expected an error for an unknown mode, got nil")
		}
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("run error = %T, want *usageError", err)
		}
	})

	t.Run("rejects a non-integer line", func(t *testing.T) {
		_, err := run([]string{"call", "file.go", "x", "1"})
		if err == nil {
			t.Fatal("run: expected an error for a non-integer line, got nil")
		}
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("run error = %T, want *usageError", err)
		}
	})

	t.Run("rejects a missing file", func(t *testing.T) {
		root := t.TempDir()
		_, err := run([]string{"-root", root, "call", filepath.Join(root, "missing.go"), "1", "1"})
		if err == nil {
			t.Fatal("run: expected an error for a missing file, got nil")
		}
	})

	t.Run("rejects the wrong argument count", func(t *testing.T) {
		_, err := run([]string{"call", "file.go", "1"})
		if err == nil {
			t.Fatal("run: expected an error for too few arguments, got nil")
		}
		if _, ok := err.(*usageError); !ok {
			t.Fatalf("run error = %T, want *usageError", err)
		}
	})

	t.Run("rejects a file that escapes -root", func(t *testing.T) {
		root := t.TempDir()
		outside := writeFixture(t, "parse.go", callFixture) // under a DIFFERENT temp dir
		_, err := run([]string{"-root", root, "call", outside, "6", "17"})
		if err == nil {
			t.Fatal("run: expected an error for a file outside -root, got nil")
		}
		if _, ok := err.(*pathEscapeError); !ok {
			t.Fatalf("run error = %T, want *pathEscapeError", err)
		}
	})
}

func TestResolveFile(t *testing.T) {
	t.Run("accepts a path relative to root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "f.go"), []byte("package p\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		abs, rel, err := resolveFile(root, "f.go")
		if err != nil {
			t.Fatalf("resolveFile: %v", err)
		}
		if want := filepath.Join(root, "f.go"); abs != want {
			t.Errorf("abs = %q, want %q", abs, want)
		}
		if rel != "f.go" {
			t.Errorf("rel = %q, want %q", rel, "f.go")
		}
	})

	t.Run("accepts an absolute path already under root", func(t *testing.T) {
		root := t.TempDir()
		sub := filepath.Join(root, "pkg")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		file := filepath.Join(sub, "f.go")
		if err := os.WriteFile(file, []byte("package p\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		abs, rel, err := resolveFile(root, file)
		if err != nil {
			t.Fatalf("resolveFile: %v", err)
		}
		if abs != file {
			t.Errorf("abs = %q, want %q", abs, file)
		}
		if want := filepath.ToSlash(filepath.Join("pkg", "f.go")); rel != want {
			t.Errorf("rel = %q, want %q", rel, want)
		}
	})

	t.Run("rejects a literal .. segment even when the joined path stays inside root", func(t *testing.T) {
		root := t.TempDir()
		if _, _, err := resolveFile(root, "pkg/../pkg/f.go"); err == nil {
			t.Fatal(`resolveFile: expected a pathEscapeError for a ".." segment, got nil`)
		} else if _, ok := err.(*pathEscapeError); !ok {
			t.Fatalf("resolveFile error = %T, want *pathEscapeError", err)
		}
	})

	t.Run("rejects a relative path that walks above root", func(t *testing.T) {
		root := t.TempDir()
		if _, _, err := resolveFile(root, "../outside.go"); err == nil {
			t.Fatal("resolveFile: expected a pathEscapeError, got nil")
		} else if _, ok := err.(*pathEscapeError); !ok {
			t.Fatalf("resolveFile error = %T, want *pathEscapeError", err)
		}
	})

	t.Run("rejects an absolute path outside root", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "f.go") // a sibling temp dir, not under root
		if _, _, err := resolveFile(root, outside); err == nil {
			t.Fatal("resolveFile: expected a pathEscapeError, got nil")
		} else if _, ok := err.(*pathEscapeError); !ok {
			t.Fatalf("resolveFile error = %T, want *pathEscapeError", err)
		}
	})
}

func TestReadUnderRoot(t *testing.T) {
	t.Run("reads a file inside root", func(t *testing.T) {
		root := t.TempDir()
		want := "package p\n"
		if err := os.WriteFile(filepath.Join(root, "f.go"), []byte(want), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readUnderRoot(root, "f.go")
		if err != nil {
			t.Fatalf("readUnderRoot: %v", err)
		}
		if string(got) != want {
			t.Errorf("readUnderRoot = %q, want %q", got, want)
		}
	})

	// The string-level checks in resolveFile cannot see a symlink: this is
	// the syscall-level defense (os.Root) that catches what they can't --
	// a name that resolves to outside root only once the filesystem, not
	// the string, is consulted.
	t.Run("refuses a symlink inside root that points outside it", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		secret := filepath.Join(outside, "secret.go")
		if err := os.WriteFile(secret, []byte("package secret\n"), 0o644); err != nil {
			t.Fatalf("write secret: %v", err)
		}
		link := filepath.Join(root, "escape.go")
		if err := os.Symlink(secret, link); err != nil {
			t.Skipf("symlink not supported on this platform: %v", err)
		}
		if _, err := readUnderRoot(root, "escape.go"); err == nil {
			t.Fatal("readUnderRoot: expected an error reading a symlink that escapes root, got nil")
		}
	})
}
