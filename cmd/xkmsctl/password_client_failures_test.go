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

// password_client_failures_test.go pins that every password verb reports a
// client it cannot create or connect, and that update refuses a new
// password it cannot read.
package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestPasswordVerbs_ClientFailures(t *testing.T) {
	verbs := []struct {
		cmd   *cobra.Command
		args  []string
		flags []verbFlag
	}{
		{passwordAddCmd, []string{"github"}, []verbFlag{{"password", "s3cret"}}},
		{passwordGetCmd, []string{"pw-1"}, nil},
		{passwordUpdateCmd, []string{"pw-1"}, []verbFlag{{"name", "gitlab"}}},
		{passwordDeleteCmd, []string{"pw-1"}, nil},
		{passwordLockCmd, nil, nil},
		{passwordStatusCmd, nil, nil},
		{passwordAccessModeCmd, []string{"session_based"}, nil},
		{passwordGenerateCmd, nil, nil},
	}
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errUserExtBoom }}, ErrCreateClientFailed},
		{"connect", newPasswordConfig(&mockPasswordClient{mockBackendsClient: mockBackendsClient{connectErr: errUserExtBoom}}), ErrConnectFailed},
	}
	for _, verb := range verbs {
		for _, tc := range cases {
			t.Run(verb.cmd.Name()+"/"+tc.name, func(t *testing.T) {
				out, code, stderr := runVerb(t, tc.cfg, verb.cmd, verb.args, verb.flags...)
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, tc.sentinel.Error())
				assert.Empty(t, out)
			})
		}
	}
}

func TestPasswordUpdateCmd_RefusesUnreadablePassword(t *testing.T) {
	original := secretStdin
	secretStdin = failingReader{}
	t.Cleanup(func() { secretStdin = original })
	mock := &mockPasswordClient{}

	_, code, stderr := runVerb(t, newPasswordConfig(mock), passwordUpdateCmd, []string{"pw-1"}, verbFlag{"password", "-"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrReadSecretFailed.Error())
	assert.Nil(t, mock.gotUpdateReq, "nothing is updated without the new password")
}
