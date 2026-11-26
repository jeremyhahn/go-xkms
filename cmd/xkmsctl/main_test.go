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

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun_PrintsCommandError(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs([]string{}) })

	var stderr bytes.Buffer
	code := run([]string{"key", "copy", "src", "dst", "--no-such-flag"}, &stderr)

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "unknown flag: --no-such-flag")
}
