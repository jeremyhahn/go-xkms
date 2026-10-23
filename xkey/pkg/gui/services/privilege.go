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

package services

import (
	"os"
	"os/exec"
)

// Privilege detection is routed through package-level function variables so
// that tests can drive both the privileged and unprivileged branches on the
// same machine, regardless of the uid the test binary happens to run under.
// This mirrors the getuid seam in pkg/notify.

// geteuid returns the effective user ID of the calling process.
var geteuid = os.Geteuid

// sudoLookPath resolves the sudo binary. Tests replace this to exercise the
// available and unavailable branches without depending on whether sudo is
// installed on the machine running the tests.
var sudoLookPath = exec.LookPath

// sudoCommand builds the command used to re-invoke this binary under sudo.
// Tests replace this so the elevation result handling can be exercised
// without performing a real PAM authentication attempt against the host.
var sudoCommand = exec.Command
