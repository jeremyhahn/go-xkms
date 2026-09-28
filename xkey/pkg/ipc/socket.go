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

package ipc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	socketDir      = "xkey"
	socketName     = "xkey.sock"
	instanceSubdir = "run"
)

// EnvSocketPath is the environment variable that explicitly overrides IPC
// socket path resolution. It takes precedence over every other strategy,
// including the XKEY_HOME-derived instance default, so an operator (or a
// generated extension launcher, see pkg/nativemsg) can always pin a
// connection to one exact socket.
const EnvSocketPath = "XKEY_IPC_SOCKET"

// maxUnixSocketPathLen is a conservative ceiling on the paths DefaultSocketPath
// derives from an xKey home directory. AF_UNIX's sun_path buffer is 108 bytes
// on Linux and 104 on macOS, each including a trailing NUL, so a path that is
// safe on both platforms — and that leaves headroom against off-by-one
// mistakes — must stay comfortably under 104. Anything longer falls back to
// runtimeInstanceSocketPath instead of risking a bind(2)/connect(2) failure
// that has nothing to do with xkey's own logic.
const maxUnixSocketPathLen = 90

// DefaultSocketPath returns the IPC socket path to use when none was given
// explicitly. Resolution order:
//
//  1. XKEY_IPC_SOCKET environment variable, when set.
//  2. XKEY_HOME-derived instance socket (<home>/run/xkey.sock), when
//     XKEY_HOME is set and the resulting path fits AF_UNIX's sun_path
//     buffer; otherwise a runtime-dir path keyed by a short hash of the
//     home, so two long or colliding home paths still land on distinct
//     sockets.
//  3. <runtime dir>/xkey/xkey.sock, where the runtime dir is the per-user
//     directory runtimeDirFor chooses.
//
// It returns the empty string when no per-user location can be determined;
// NewServer and the Client refuse an empty path with ErrSocketPathUnresolved.
// There is no shared-directory fallback: a socket under /tmp can be
// pre-empted by another local user (issue #1117).
//
// This is the single place that decides "which xkey instance does an
// unqualified command talk to" — every command and the native messaging
// host route their --socket fallback through it rather than re-implementing
// the chain.
func DefaultSocketPath() string {
	if p := os.Getenv(EnvSocketPath); p != "" {
		return p
	}
	if home := os.Getenv(xhome.EnvHome); home != "" {
		return instanceSocketPath(home)
	}
	base, err := runtimeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, socketDir, socketName)
}

// instanceSocketPath returns the per-instance socket derived from an xkey
// home directory. It prefers the direct <home>/run/xkey.sock path and falls
// back to runtimeInstanceSocketPath when that path would not fit AF_UNIX's
// sun_path buffer.
func instanceSocketPath(home string) string {
	abs, err := filepath.Abs(home)
	if err != nil {
		// filepath.Abs only fails if os.Getwd fails; home is still usable
		// as given, so fall through with it rather than losing the caller's
		// intent.
		abs = home
	}
	direct := filepath.Join(abs, instanceSubdir, socketName)
	if len(direct) <= maxUnixSocketPathLen {
		return direct
	}
	return runtimeInstanceSocketPath(abs)
}

// runtimeInstanceSocketPath returns a short, collision-resistant socket path
// for an xkey home whose direct <home>/run/xkey.sock path is too long for
// AF_UNIX. It keys the path on a short hash of the home's absolute path
// under the runtime directory, so distinct long-path instances still resolve
// to distinct sockets. It returns the empty string when no runtime directory
// can be determined.
func runtimeInstanceSocketPath(absHome string) string {
	base, err := runtimeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, fmt.Sprintf("xkey-%s", shortHash(absHome)), socketName)
}

// runtimeDir returns this process's per-user runtime directory; see
// runtimeDirFor.
func runtimeDir() (string, error) {
	return runtimeDirFor(runtime.GOOS, os.Getenv, effectiveHomeDir)
}

// runtimeDirFor chooses the per-user directory under which xkey places its
// sockets, for the operating system goos:
//
//   - $XDG_RUNTIME_DIR, when set (Linux desktop sessions; the directory is
//     created 0700 for the user by the session manager).
//   - macOS: $TMPDIR, which launchd sets to a per-user 0700 directory under
//     /var/folders; otherwise ~/Library/Caches.
//   - Everywhere else: ~/.xkey/run.
//
// It never returns a shared directory such as /tmp. getenv and home are
// parameters so every branch is testable without touching the environment.
func runtimeDirFor(goos string, getenv func(string) string, home func() (string, error)) (string, error) {
	if dir := getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir, nil
	}
	if goos == "darwin" {
		if dir := getenv("TMPDIR"); dir != "" {
			return filepath.Clean(dir), nil
		}
	}
	homeDir, err := home()
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrSocketPathUnresolved, Cause: err}
	}
	if homeDir == "" {
		return "", ErrSocketPathUnresolved
	}
	if goos == "darwin" {
		return filepath.Join(homeDir, "Library", "Caches"), nil
	}
	return filepath.Join(homeDir, ".xkey", instanceSubdir), nil
}

// effectiveHomeDir returns the home directory of the user the socket belongs
// to. When running as root via sudo that is the invoking user (SUDO_UID), so
// a daemon started with sudo and that user's own client commands resolve the
// same socket; otherwise it is $HOME.
func effectiveHomeDir() (string, error) {
	if uid, _, ok := sudoOwnership(); ok {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return "", err
		}
		return u.HomeDir, nil
	}
	return os.UserHomeDir()
}

// shortHash returns a short hex-encoded SHA-256 digest of s, long enough to
// make accidental collisions between distinct home paths practically
// impossible while keeping the derived socket path well under the AF_UNIX
// length limit.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
