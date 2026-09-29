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

//go:build integration

package acmeadmin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestXkmsctlAdminAccountCLI tests "xkmsctl acme account" commands.
func TestXkmsctlAdminAccountCLI(t *testing.T) {
	cfg := newXkmsctlConfig()
	if err := findXkmsctlBinary(cfg); err != nil {
		t.Fatalf("xkmsctl binary not found: %v", err)
	}

	t.Run("AccountListJSON", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "account", "list", "-o", "json")
		assert.NotEmpty(t, output, "account list should return output")
	})

	t.Run("AccountListWithPagination", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "account", "list", "--page", "1", "--per-page", "5", "-o", "json")
		assert.NotEmpty(t, output, "account list with pagination should return output")
	})

	t.Run("AccountListWithStatus", func(t *testing.T) {
		output := requireSuccess(t, cfg, "acme", "account", "list", "--status", "valid", "-o", "json")
		assert.NotEmpty(t, output, "account list with status filter should return output")
	})

	t.Run("AccountGetInvalidID", func(t *testing.T) {
		xerr := requireFail(t, cfg, "acme", "account", "get", "not-a-number")
		assert.Contains(t, xerr.Stderr+xerr.Stdout, "invalid",
			"should report invalid account ID")
	})

	t.Run("AccountGetNonexistent", func(t *testing.T) {
		xerr := requireFail(t, cfg, "acme", "account", "get", "9999999999")
		assert.True(t, len(xerr.Stderr) > 0 || len(xerr.Stdout) > 0,
			"should have error output for nonexistent account")
	})

	t.Run("AccountDisableInvalidID", func(t *testing.T) {
		xerr := requireFail(t, cfg, "acme", "account", "disable", "not-a-number")
		assert.Contains(t, xerr.Stderr+xerr.Stdout, "invalid",
			"should report invalid account ID")
	})
}
