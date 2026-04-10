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

// Package xhome provides unified path resolution for xKey.
//
// Every xKey component (CLI, GUI, LUKS, config) resolves paths through
// a single [Home] value. The resolution order is:
//
//  1. XKEY_HOME environment variable (explicit override)
//  2. Binary's own directory, if it contains a .xkey-home marker file
//  3. ~/.xkey/ (per-user default)
//  4. /etc/xkey/ (system-wide fallback, typically read-only)
//
// The first candidate that exists as a directory (or can be created in
// the case of ~/.xkey/) wins.
package xhome

import (
	"os"
	"path/filepath"
	"sync/atomic"
)

const (
	// EnvHome is the environment variable that overrides all other
	// resolution strategies.
	EnvHome = "XKEY_HOME"

	// MarkerFile is the name of the file whose presence in the
	// binary's directory signals that directory is the xKey home.
	MarkerFile = ".xkey-home"

	// userDirName is the default directory name under $HOME.
	userDirName = ".xkey"

	// systemDir is the system-wide fallback directory.
	systemDir = "/etc/xkey"

	// configFile is the configuration file name.
	configFile = "config.yaml"

	// luksFile is the LUKS container file name.
	luksFile = "xkey.luks"

	// dataDirName is the barrier-encrypted data directory.
	dataDirName = "data"

	// trustDirName is the trust store directory (public CA certs).
	trustDirName = "trust"

	// caDirName is the local User CA directory.
	caDirName = "ca"

	// devicesDirName is the paired device configs directory.
	devicesDirName = "devices"
)

// override allows tests to inject a specific root directory without
// touching the filesystem or environment. When non-nil the pointed-to
// string is returned by Resolve without probing any strategy.
var override atomic.Pointer[string]

// SetRoot overrides the resolved root for testing. Pair with ResetRoot.
func SetRoot(dir string) {
	override.Store(&dir)
}

// ResetRoot clears any override set by SetRoot.
func ResetRoot() {
	override.Store(nil)
}

// Home holds the resolved xKey root directory and provides accessors
// for every well-known path beneath it.
type Home struct {
	// Root is the resolved root directory.
	Root string
}

// Resolve probes the four resolution strategies in order and returns a
// Home pointing at the first valid candidate.
//
// For the user-home strategy (~/.xkey/), the directory is created with
// 0700 permissions if it does not already exist.
func Resolve() (*Home, error) {
	// Check test override first.
	if ptr := override.Load(); ptr != nil && *ptr != "" {
		return &Home{Root: *ptr}, nil
	}

	// Strategy 1: XKEY_HOME environment variable.
	if env := os.Getenv(EnvHome); env != "" {
		abs, err := filepath.Abs(env)
		if err != nil {
			return nil, &ResolveError{Strategy: "env", Path: env, Err: err}
		}
		if isDir(abs) {
			return &Home{Root: abs}, nil
		}
		// If the env var is set, treat it as authoritative even if the
		// directory doesn't exist yet — create it.
		if err := os.MkdirAll(abs, 0700); err != nil {
			return nil, &ResolveError{Strategy: "env", Path: abs, Err: err}
		}
		return &Home{Root: abs}, nil
	}

	// Strategy 2: Binary's own directory (portable/USB mode).
	if binDir := binaryDir(); binDir != "" {
		marker := filepath.Join(binDir, MarkerFile)
		if fileExists(marker) && isDir(binDir) {
			return &Home{Root: binDir}, nil
		}
	}

	// Strategy 3: ~/.xkey/ (per-user default).
	if home, err := os.UserHomeDir(); err == nil {
		userDir := filepath.Join(home, userDirName)
		if isDir(userDir) {
			return &Home{Root: userDir}, nil
		}
		// Create the directory on first use.
		if err := os.MkdirAll(userDir, 0700); err == nil {
			return &Home{Root: userDir}, nil
		}
	}

	// Strategy 4: /etc/xkey/ (system-wide, read-only).
	if isDir(systemDir) {
		return &Home{Root: systemDir}, nil
	}

	return nil, ErrHomeNotResolved
}

// ConfigPath returns the path to the configuration file.
func (h *Home) ConfigPath() string {
	return filepath.Join(h.Root, configFile)
}

// DataDir returns the path to the barrier-encrypted data directory.
func (h *Home) DataDir() string {
	return filepath.Join(h.Root, dataDirName)
}

// TrustDir returns the path to the trust store directory.
func (h *Home) TrustDir() string {
	return filepath.Join(h.Root, trustDirName)
}

// CADir returns the path to the local User CA directory.
func (h *Home) CADir() string {
	return filepath.Join(h.Root, caDirName)
}

// DevicesDir returns the path to the paired device configs directory.
func (h *Home) DevicesDir() string {
	return filepath.Join(h.Root, devicesDirName)
}

// LUKSPath returns the path to the LUKS container file.
func (h *Home) LUKSPath() string {
	return filepath.Join(h.Root, luksFile)
}

// MountPoint returns the root directory itself, which is where a LUKS
// volume is mounted in encrypted mode.
func (h *Home) MountPoint() string {
	return h.Root
}

// EnsureDataDir creates the data directory with 0700 permissions if it
// does not already exist and returns its path.
func (h *Home) EnsureDataDir() (string, error) {
	dir := h.DataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", &ResolveError{Strategy: "ensure_data", Path: dir, Err: err}
	}
	return dir, nil
}

// EnsureTrustDir creates the trust directory with 0700 permissions if
// it does not already exist and returns its path.
func (h *Home) EnsureTrustDir() (string, error) {
	dir := h.TrustDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", &ResolveError{Strategy: "ensure_trust", Path: dir, Err: err}
	}
	return dir, nil
}

// EnsureCADir creates the CA directory with 0700 permissions if it
// does not already exist and returns its path.
func (h *Home) EnsureCADir() (string, error) {
	dir := h.CADir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", &ResolveError{Strategy: "ensure_ca", Path: dir, Err: err}
	}
	return dir, nil
}

// EnsureDevicesDir creates the devices directory with 0700 permissions
// if it does not already exist and returns its path.
func (h *Home) EnsureDevicesDir() (string, error) {
	dir := h.DevicesDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", &ResolveError{Strategy: "ensure_devices", Path: dir, Err: err}
	}
	return dir, nil
}

// binaryDir returns the directory containing the running binary, or
// empty string on any error.
func binaryDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	return filepath.Dir(resolved)
}

// isDir reports whether path exists and is a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExists reports whether path exists (file or directory).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
