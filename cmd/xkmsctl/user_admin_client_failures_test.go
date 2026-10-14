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

// user_admin_client_failures_test.go pins that every user and admin
// lifecycle verb reports a client it cannot create or connect, and stops
// before it prints a result.
package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestUserAdminLifecycleVerbs_ClientFailures(t *testing.T) {
	verbs := []struct {
		cmd  *cobra.Command
		args []string
	}{
		{userListCmd, nil},
		{userGetCmd, []string{"alice"}},
		{userDisableCmd, []string{"alice"}},
		{userEnableCmd, []string{"alice"}},
		{adminDeleteCmd, []string{"root"}},
		{adminDisableCmd, []string{"root"}},
		{adminEnableCmd, []string{"root"}},
		{adminStatusCmd, nil},
	}
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errUserExtBoom }}, ErrCreateClientFailed},
		{"connect", newAdminCRUDConfig("text", &mockAdminCRUDClient{connectErr: errUserExtBoom}), ErrConnectFailed},
	}
	for _, verb := range verbs {
		for _, tc := range cases {
			t.Run(verb.cmd.Parent().Use+" "+verb.cmd.Name()+"/"+tc.name, func(t *testing.T) {
				out, code, stderr := runVerb(t, tc.cfg, verb.cmd, verb.args)
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, tc.sentinel.Error())
				assert.Empty(t, out)
			})
		}
	}
}
