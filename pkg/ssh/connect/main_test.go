// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package connect

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/testsupport"
)

// TestMain runs the package under a short TMPDIR: Start opens an ssh/agent
// session, whose default directory is os.MkdirTemp("", "xkms-ssh-agent-"),
// and under a long runner TMPDIR the agent.sock inside it passes sun_path.
func TestMain(m *testing.M) {
	os.Exit(testsupport.RunWithShortTempDir(m))
}
