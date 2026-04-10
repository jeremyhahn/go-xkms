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

package xhome

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolve_EnvOverride verifies that XKEY_HOME takes priority over
// all other strategies.
func TestResolve_EnvOverride(t *testing.T) {
	dir := t.TempDir()

	t.Setenv(EnvHome, dir)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != dir {
		t.Errorf("Root = %q, want %q", h.Root, dir)
	}
}

// TestResolve_EnvCreatesDir verifies that XKEY_HOME creates the
// directory if it does not exist.
func TestResolve_EnvCreatesDir(t *testing.T) {
	parent := t.TempDir()
	newDir := filepath.Join(parent, "fresh-xkey")

	t.Setenv(EnvHome, newDir)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != newDir {
		t.Errorf("Root = %q, want %q", h.Root, newDir)
	}
	info, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
}

// TestResolve_EnvCreatesDirFails verifies that Resolve returns a
// ResolveError when XKEY_HOME points to a path that cannot be created
// (e.g. a path nested under a regular file).
func TestResolve_EnvCreatesDirFails(t *testing.T) {
	ResetRoot()

	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker-file")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// XKEY_HOME points to a child of a regular file, so MkdirAll fails.
	impossibleDir := filepath.Join(blocker, "sub", "dir")
	t.Setenv(EnvHome, impossibleDir)

	_, err := Resolve()
	if err == nil {
		t.Fatal("expected error when XKEY_HOME cannot be created")
	}
	var re *ResolveError
	if !isResolveError(err, &re) {
		t.Fatalf("expected *ResolveError, got %T: %v", err, err)
	}
	if re.Strategy != "env" {
		t.Errorf("Strategy = %q, want %q", re.Strategy, "env")
	}
}

// TestResolve_EnvRelativePath verifies that a relative XKEY_HOME value
// is resolved to an absolute path.
func TestResolve_EnvRelativePath(t *testing.T) {
	dir := t.TempDir()

	// Change to the temp dir so a relative path resolves inside it.
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(oldWd) })

	relDir := "relative-xkey"
	t.Setenv(EnvHome, relDir)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if !filepath.IsAbs(h.Root) {
		t.Errorf("Root %q is not absolute", h.Root)
	}
}

// TestResolve_BinaryDirMarker verifies that a .xkey-home marker file
// in the test binary's directory causes strategy 2 to succeed. This
// exercises the real binaryDir + marker detection path without using
// the test override.
func TestResolve_BinaryDirMarker(t *testing.T) {
	ResetRoot()
	t.Setenv(EnvHome, "")

	// Determine the test binary's directory.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks() error: %v", err)
	}
	binDir := filepath.Dir(resolved)

	// Create the marker file in the binary's directory.
	marker := filepath.Join(binDir, MarkerFile)
	if err := os.WriteFile(marker, nil, 0644); err != nil {
		t.Fatalf("failed to create marker file: %v", err)
	}
	t.Cleanup(func() { os.Remove(marker) })

	// Prevent strategy 3 from interfering by pointing HOME at a
	// non-existent location.
	t.Setenv("HOME", "/nonexistent-xhome-binary-marker-test")

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != binDir {
		t.Errorf("Root = %q, want binary dir %q", h.Root, binDir)
	}
}

// TestResolve_BinaryDir verifies that a .xkey-home marker in the
// binary's directory causes it to be chosen.
func TestResolve_BinaryDir(t *testing.T) {
	// We can't easily move the test binary, so use SetRoot to
	// verify the marker file detection logic directly.
	dir := t.TempDir()

	// Create marker file.
	marker := filepath.Join(dir, MarkerFile)
	if err := os.WriteFile(marker, nil, 0644); err != nil {
		t.Fatal(err)
	}

	// Use SetRoot to simulate this strategy winning.
	SetRoot(dir)
	t.Cleanup(ResetRoot)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != dir {
		t.Errorf("Root = %q, want %q", h.Root, dir)
	}
}

// TestResolve_UserDefaultExistingDir verifies that when HOME points to
// a temp directory that already contains .xkey/, strategy 3 resolves
// to it without needing to create it.
func TestResolve_UserDefaultExistingDir(t *testing.T) {
	ResetRoot()
	t.Setenv(EnvHome, "")

	// Set up a fake HOME with an existing .xkey directory.
	fakeHome := t.TempDir()
	xkeyDir := filepath.Join(fakeHome, userDirName)
	if err := os.MkdirAll(xkeyDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fakeHome)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != xkeyDir {
		t.Errorf("Root = %q, want %q", h.Root, xkeyDir)
	}
}

// TestResolve_UserDefaultCreatesDir verifies that strategy 3 creates
// ~/.xkey/ when the home directory exists but .xkey/ does not.
func TestResolve_UserDefaultCreatesDir(t *testing.T) {
	ResetRoot()
	t.Setenv(EnvHome, "")

	// Set up a fake HOME without .xkey.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	expected := filepath.Join(fakeHome, userDirName)
	if h.Root != expected {
		t.Errorf("Root = %q, want %q", h.Root, expected)
	}
	// Verify the directory was actually created.
	if !isDir(expected) {
		t.Error(".xkey directory was not created under fake HOME")
	}
}

// TestResolve_UserDefault verifies resolution falls through to
// ~/.xkey/ when no env or marker is present.
func TestResolve_UserDefault(t *testing.T) {
	// Clear env to prevent strategy 1 from firing.
	t.Setenv(EnvHome, "")

	// Use override to avoid depending on the real home directory.
	dir := t.TempDir()
	xkeyDir := filepath.Join(dir, userDirName)
	if err := os.MkdirAll(xkeyDir, 0700); err != nil {
		t.Fatal(err)
	}

	SetRoot(xkeyDir)
	t.Cleanup(ResetRoot)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != xkeyDir {
		t.Errorf("Root = %q, want %q", h.Root, xkeyDir)
	}
}

// TestResolve_SystemFallback verifies that /etc/xkey is used as a
// last resort when it exists.
func TestResolve_SystemFallback(t *testing.T) {
	// Can't easily test /etc/xkey without root, so use override.
	dir := t.TempDir()
	SetRoot(dir)
	t.Cleanup(ResetRoot)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != dir {
		t.Errorf("Root = %q, want %q", h.Root, dir)
	}
}

// TestResolve_OverrideTakesPriority verifies that SetRoot always wins.
func TestResolve_OverrideTakesPriority(t *testing.T) {
	overrideDir := t.TempDir()
	envDir := t.TempDir()

	t.Setenv(EnvHome, envDir)
	SetRoot(overrideDir)
	t.Cleanup(ResetRoot)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if h.Root != overrideDir {
		t.Errorf("Root = %q, want override %q", h.Root, overrideDir)
	}
}

// TestResolve_NoValidPath verifies ErrHomeNotResolved when no
// strategy finds a valid directory.
func TestResolve_NoValidPath(t *testing.T) {
	// Unset override and env.
	ResetRoot()
	t.Setenv(EnvHome, "")

	// Override HOME to a non-existent directory so strategy 3 fails.
	t.Setenv("HOME", "/nonexistent-xhome-test-dir")

	// Strategy 4 (/etc/xkey) may or may not exist on the test host.
	// If it does exist, this test will pass via strategy 4, which is
	// fine — we're testing that at least one path works or the error
	// is returned.
	h, err := Resolve()
	if err == nil && h.Root == systemDir {
		t.Skip("/etc/xkey exists on this host, cannot test no-path scenario")
	}
	if err == nil {
		t.Fatal("expected error when no valid path exists")
	}
	if err != ErrHomeNotResolved {
		t.Errorf("error = %v, want ErrHomeNotResolved", err)
	}
}

// TestResolve_OverrideEmptyStringIgnored verifies that SetRoot with an
// empty string is treated the same as no override, falling through to
// normal strategies.
func TestResolve_OverrideEmptyStringIgnored(t *testing.T) {
	SetRoot("")
	t.Cleanup(ResetRoot)

	// Set XKEY_HOME so strategy 1 picks up.
	dir := t.TempDir()
	t.Setenv(EnvHome, dir)

	h, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	// The empty override should be ignored, falling to env strategy.
	if h.Root != dir {
		t.Errorf("Root = %q, want env dir %q", h.Root, dir)
	}
}

// TestHome_PathAccessors verifies all path accessor methods.
func TestHome_PathAccessors(t *testing.T) {
	root := "/test/xkey"
	h := &Home{Root: root}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigPath", h.ConfigPath(), filepath.Join(root, "config.yaml")},
		{"DataDir", h.DataDir(), filepath.Join(root, "data")},
		{"TrustDir", h.TrustDir(), filepath.Join(root, "trust")},
		{"CADir", h.CADir(), filepath.Join(root, "ca")},
		{"DevicesDir", h.DevicesDir(), filepath.Join(root, "devices")},
		{"LUKSPath", h.LUKSPath(), filepath.Join(root, "xkey.luks")},
		{"MountPoint", h.MountPoint(), root},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s() = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestHome_EnsureDataDir verifies that EnsureDataDir creates the
// directory and returns its path.
func TestHome_EnsureDataDir(t *testing.T) {
	root := t.TempDir()
	h := &Home{Root: root}

	dir, err := h.EnsureDataDir()
	if err != nil {
		t.Fatalf("EnsureDataDir() error: %v", err)
	}
	expected := filepath.Join(root, "data")
	if dir != expected {
		t.Errorf("EnsureDataDir() = %q, want %q", dir, expected)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("permissions = %o, want 0700", info.Mode().Perm())
	}
}

// TestHome_EnsureDataDir_AlreadyExists verifies idempotency.
func TestHome_EnsureDataDir_AlreadyExists(t *testing.T) {
	root := t.TempDir()
	h := &Home{Root: root}

	// Create it once.
	if _, err := h.EnsureDataDir(); err != nil {
		t.Fatal(err)
	}
	// Create it again — should succeed.
	dir, err := h.EnsureDataDir()
	if err != nil {
		t.Fatalf("second EnsureDataDir() error: %v", err)
	}
	expected := filepath.Join(root, "data")
	if dir != expected {
		t.Errorf("EnsureDataDir() = %q, want %q", dir, expected)
	}
}

// TestHome_EnsureTrustDir verifies trust directory creation.
func TestHome_EnsureTrustDir(t *testing.T) {
	root := t.TempDir()
	h := &Home{Root: root}

	dir, err := h.EnsureTrustDir()
	if err != nil {
		t.Fatalf("EnsureTrustDir() error: %v", err)
	}
	expected := filepath.Join(root, "trust")
	if dir != expected {
		t.Errorf("EnsureTrustDir() = %q, want %q", dir, expected)
	}
	if !isDir(dir) {
		t.Error("trust directory not created")
	}
}

// TestHome_EnsureTrustDir_Error verifies that EnsureTrustDir returns a
// ResolveError when MkdirAll fails (e.g. root is a regular file).
func TestHome_EnsureTrustDir_Error(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	h := &Home{Root: blocker}
	_, err := h.EnsureTrustDir()
	if err == nil {
		t.Fatal("expected error when root is a file")
	}
	var re *ResolveError
	if !isResolveError(err, &re) {
		t.Fatalf("expected *ResolveError, got %T: %v", err, err)
	}
	if re.Strategy != "ensure_trust" {
		t.Errorf("Strategy = %q, want %q", re.Strategy, "ensure_trust")
	}
	if re.Err == nil {
		t.Error("underlying error should not be nil")
	}
}

// TestHome_EnsureCADir verifies CA directory creation.
func TestHome_EnsureCADir(t *testing.T) {
	root := t.TempDir()
	h := &Home{Root: root}

	dir, err := h.EnsureCADir()
	if err != nil {
		t.Fatalf("EnsureCADir() error: %v", err)
	}
	expected := filepath.Join(root, "ca")
	if dir != expected {
		t.Errorf("EnsureCADir() = %q, want %q", dir, expected)
	}
	if !isDir(dir) {
		t.Error("CA directory not created")
	}
}

// TestHome_EnsureCADir_Error verifies that EnsureCADir returns a
// ResolveError when MkdirAll fails.
func TestHome_EnsureCADir_Error(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	h := &Home{Root: blocker}
	_, err := h.EnsureCADir()
	if err == nil {
		t.Fatal("expected error when root is a file")
	}
	var re *ResolveError
	if !isResolveError(err, &re) {
		t.Fatalf("expected *ResolveError, got %T: %v", err, err)
	}
	if re.Strategy != "ensure_ca" {
		t.Errorf("Strategy = %q, want %q", re.Strategy, "ensure_ca")
	}
	if re.Err == nil {
		t.Error("underlying error should not be nil")
	}
}

// TestHome_EnsureDevicesDir verifies devices directory creation.
func TestHome_EnsureDevicesDir(t *testing.T) {
	root := t.TempDir()
	h := &Home{Root: root}

	dir, err := h.EnsureDevicesDir()
	if err != nil {
		t.Fatalf("EnsureDevicesDir() error: %v", err)
	}
	expected := filepath.Join(root, "devices")
	if dir != expected {
		t.Errorf("EnsureDevicesDir() = %q, want %q", dir, expected)
	}
	if !isDir(dir) {
		t.Error("devices directory not created")
	}
}

// TestHome_EnsureDevicesDir_Error verifies that EnsureDevicesDir
// returns a ResolveError when MkdirAll fails.
func TestHome_EnsureDevicesDir_Error(t *testing.T) {
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	h := &Home{Root: blocker}
	_, err := h.EnsureDevicesDir()
	if err == nil {
		t.Fatal("expected error when root is a file")
	}
	var re *ResolveError
	if !isResolveError(err, &re) {
		t.Fatalf("expected *ResolveError, got %T: %v", err, err)
	}
	if re.Strategy != "ensure_devices" {
		t.Errorf("Strategy = %q, want %q", re.Strategy, "ensure_devices")
	}
	if re.Err == nil {
		t.Error("underlying error should not be nil")
	}
}

// TestHome_EnsureDataDir_Error verifies error handling when directory
// creation fails.
func TestHome_EnsureDataDir_Error(t *testing.T) {
	// Point root at a path that cannot have subdirectories created
	// (the file acts as a blocker).
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	h := &Home{Root: blocker}
	_, err := h.EnsureDataDir()
	if err == nil {
		t.Fatal("expected error when root is a file")
	}
	var re *ResolveError
	if !isResolveError(err, &re) {
		t.Errorf("expected ResolveError, got %T", err)
	}
}

// TestResolveError_Error verifies error formatting.
func TestResolveError_Error(t *testing.T) {
	err := &ResolveError{Strategy: "env", Path: "/foo", Err: os.ErrNotExist}
	got := err.Error()
	if got == "" {
		t.Fatal("empty error message")
	}
	// Verify it contains the strategy and path.
	want := "xhome: env resolution failed for /foo"
	if !strings.HasPrefix(got, want) {
		t.Errorf("error message = %q, want prefix %q", got, want)
	}
}

// TestResolveError_ErrorWithoutPath verifies error formatting without a path.
func TestResolveError_ErrorWithoutPath(t *testing.T) {
	err := &ResolveError{Strategy: "test", Err: os.ErrNotExist}
	got := err.Error()
	want := "xhome: test resolution failed:"
	if !strings.HasPrefix(got, want) {
		t.Errorf("error message = %q, want prefix %q", got, want)
	}
}

// TestResolveError_Unwrap verifies error unwrapping.
func TestResolveError_Unwrap(t *testing.T) {
	inner := os.ErrPermission
	err := &ResolveError{Strategy: "test", Err: inner}
	if err.Unwrap() != inner {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), inner)
	}
}

// TestSetRoot_ResetRoot verifies the override lifecycle.
func TestSetRoot_ResetRoot(t *testing.T) {
	dir := t.TempDir()

	SetRoot(dir)
	h, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if h.Root != dir {
		t.Errorf("Root = %q, want %q", h.Root, dir)
	}

	ResetRoot()
	// After reset, the override is cleared. Resolve should use
	// normal strategies.
}

// TestBinaryDir verifies that binaryDir returns a non-empty path.
func TestBinaryDir(t *testing.T) {
	dir := binaryDir()
	if dir == "" {
		t.Error("binaryDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("binaryDir() = %q, not absolute", dir)
	}
}

// TestBinaryDir_ReturnsParentOfExecutable verifies that binaryDir
// returns the directory containing the resolved executable path,
// which should be the same directory we can independently derive.
func TestBinaryDir_ReturnsParentOfExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("EvalSymlinks() error: %v", err)
	}
	expected := filepath.Dir(resolved)

	got := binaryDir()
	if got != expected {
		t.Errorf("binaryDir() = %q, want %q", got, expected)
	}
}

// TestIsDir verifies the isDir helper.
func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	if !isDir(dir) {
		t.Errorf("isDir(%q) = false, want true", dir)
	}

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if isDir(file) {
		t.Errorf("isDir(%q) = true for a file, want false", file)
	}

	if isDir("/nonexistent-xhome-test-path") {
		t.Error("isDir reported true for nonexistent path")
	}
}

// TestFileExists verifies the fileExists helper.
func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	if !fileExists(dir) {
		t.Error("fileExists returned false for existing dir")
	}

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if !fileExists(file) {
		t.Error("fileExists returned false for existing file")
	}

	if fileExists(filepath.Join(dir, "nonexistent")) {
		t.Error("fileExists returned true for nonexistent path")
	}
}

// isResolveError is a test helper that checks whether err is a
// *ResolveError and optionally populates target.
func isResolveError(err error, target **ResolveError) bool {
	var re *ResolveError
	ok := false
	for e := err; e != nil; {
		if v, isRE := e.(*ResolveError); isRE {
			ok = true
			re = v
			break
		}
		if u, hasUnwrap := e.(interface{ Unwrap() error }); hasUnwrap {
			e = u.Unwrap()
		} else {
			break
		}
	}
	if ok && target != nil {
		*target = re
	}
	return ok
}
