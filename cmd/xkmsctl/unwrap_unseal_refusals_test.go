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

// unwrap_unseal_refusals_test.go pins that key unwrap-by-id and seal unseal
// refuse incomplete input before they reach the server.
package main

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestUnwrapAndUnseal_RefuseIncompleteInput(t *testing.T) {
	cases := []struct {
		name     string
		cmd      *cobra.Command
		args     []string
		flags    []verbFlag
		sentinel error
	}{
		{"unwrap without unwrapping key", keyUnwrapByIDCmd, []string{"imported"},
			[]verbFlag{{"wrapped-file", "wrapped.bin"}}, ErrUnwrappingKeyIDRequired},
		{"unwrap unreadable wrapped file", keyUnwrapByIDCmd, []string{"imported"},
			[]verbFlag{{"wrapped-file", filepath.Join(t.TempDir(), "absent.bin")}, {"unwrapping-key", "kek"}}, ErrReadWrappedKeyFileFailed},
		{"unseal with half a TPM object", unsealDataCmd, []string{"Y2lwaGVy"},
			[]verbFlag{{"key-id", "k"}, {"tpm-public", "cHVi"}}, ErrTPMAreasRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			cfg := &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) {
				reached = true
				return nil, errUserExtBoom
			}}

			out, code, stderr := runVerb(t, cfg, tc.cmd, tc.args, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
			assert.False(t, reached, "no client is created for incomplete input")
		})
	}
}
