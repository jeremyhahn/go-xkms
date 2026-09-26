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
	"path/filepath"
	"strconv"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// socketBaseDir is the parent of the per-UID socket directory. Named rather
// than inlined so filepath.Join receives no separator-bearing literal.
const socketBaseDir = "/tmp"

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
//  3. $XDG_RUNTIME_DIR/xkey/xkey.sock, when XKEY_HOME is unset.
//  4. /tmp/xkey-$UID/xkey.sock, the last-resort default.
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
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, socketDir, socketName)
	}
	return filepath.Join(socketBaseDir, fmt.Sprintf("xkey-%d", effectiveUID()), socketName)
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
// to distinct sockets.
func runtimeInstanceSocketPath(absHome string) string {
	return filepath.Join(runtimeDir(), fmt.Sprintf("xkey-%s", shortHash(absHome)), socketName)
}

// runtimeDir returns $XDG_RUNTIME_DIR when set, otherwise socketBaseDir.
func runtimeDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return socketBaseDir
}

// shortHash returns a short hex-encoded SHA-256 digest of s, long enough to
// make accidental collisions between distinct home paths practically
// impossible while keeping the derived socket path well under the AF_UNIX
// length limit.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// effectiveUID returns the UID to use for socket path construction. When
// running as root via sudo, it returns the original user's UID from SUDO_UID
// so that the daemon and client commands use the same socket path.
func effectiveUID() int {
	// If running as root via sudo, use the original user's UID
	if os.Getuid() == 0 {
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if uid, err := strconv.Atoi(sudoUID); err == nil {
				return uid
			}
		}
	}
	return os.Getuid()
}
