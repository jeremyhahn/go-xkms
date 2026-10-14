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

//go:build frost

// frost_input_refusals_test.go pins FROST verbs that refuse before any
// ceremony exists: no message to aggregate or verify, a recipient key that
// cannot be provisioned, and a delete of a key the store does not hold.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrostSigningVerbs_RequireMessage(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	cases := []struct {
		cmd   *cobra.Command
		flags []verbFlag
	}{
		{frostAggregateCmd, []verbFlag{{"key-id", "treasury"}, {"commitments", "c.json"}, {"shares", "s.json"}}},
		{frostVerifyCmd, []verbFlag{{"key-id", "treasury"}, {"signature-hex", "00"}}},
	}
	for _, tc := range cases {
		t.Run(tc.cmd.Name(), func(t *testing.T) {
			out, code, stderr := runVerb(t, newFrostTestConfig(t), tc.cmd, nil, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, ErrMessageInputRequired.Error())
			assert.Empty(t, out)
		})
	}
}

func TestFrostRecipientCmd_RefusesUnopenableStore(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)
	notDir := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))
	cfg := NewConfig()
	cfg.OutputFormat = "json"
	cfg.KeyDir = filepath.Join(notDir, "keys")

	out, code, stderr := runVerb(t, cfg, frostRecipientCmd, nil)
	assert.Equal(t, 1, code)
	assert.NotEmpty(t, stderr)
	assert.NotContains(t, out, "recipient_id", "no recipient is reported without a key")
}

func TestFrostDeleteCmd_RefusesUnknownKey(t *testing.T) {
	setFrostPassphraseEnv(t, frostCeremonyPassphrase)

	out, code, stderr := runVerb(t, newFrostTestConfig(t), frostDeleteCmd, []string{"nope"}, verbFlag{"force", "true"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrDeleteKeyFailed.Error())
	assert.NotContains(t, out, "Successfully deleted")
}
