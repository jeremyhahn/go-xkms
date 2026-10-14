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

// pin_refusals_test.go pins that every pin verb refuses an empty PIN before
// it reaches the server, and reports a client it cannot create or connect.
package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// pinVerb is a pin command with the PIN flags it resolves, in order.
type pinVerb struct {
	cmd  *cobra.Command
	pins []string
}

var pinVerbs = []pinVerb{
	{pinSOSetCmd, []string{"new-pin"}},
	{pinSOChangeCmd, []string{"current-pin", "new-pin"}},
	{pinSOVerifyCmd, []string{"pin"}},
	{pinUserSetCmd, []string{"so-pin", "new-pin"}},
	{pinUserChangeCmd, []string{"current-pin", "new-pin"}},
	{pinUserVerifyCmd, []string{"pin"}},
	{pinLockoutResetCmd, []string{"so-pin"}},
	{pinLockoutCmd, nil},
}

// TestPinVerbs_RefuseEmptyPIN leaves each PIN flag in turn unset, with
// nothing on stdin, and expects the verb to stop before the server.
func TestPinVerbs_RefuseEmptyPIN(t *testing.T) {
	for _, verb := range pinVerbs {
		for missing := range verb.pins {
			t.Run(verb.cmd.Use+"/"+verb.pins[missing], func(t *testing.T) {
				stubPINStdin(t, "")
				var flags []verbFlag
				for _, name := range verb.pins[:missing] {
					flags = append(flags, verbFlag{name, "123456"})
				}
				mock := &mockPINClient{}

				_, code, stderr := runVerb(t, newPINConfig(mock), verb.cmd, nil, flags...)
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, ErrPINEmpty.Error())
				assert.Nil(t, mock.gotSetSOReq)
				assert.Nil(t, mock.gotChangeSOReq)
				assert.Nil(t, mock.gotVerifySOReq)
				assert.Nil(t, mock.gotSetUserReq)
				assert.Nil(t, mock.gotChangeUserReq)
				assert.Nil(t, mock.gotResetReq)
			})
		}
	}
}

func TestPinVerbs_ClientFailures(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errPinRunBoom }}, ErrCreateClientFailed},
		{"connect", newPINConfig(&mockPINClient{mockBackendsClient: mockBackendsClient{connectErr: errPinRunBoom}}), ErrConnectFailed},
	}
	for _, verb := range pinVerbs {
		for _, tc := range cases {
			t.Run(verb.cmd.Use+"/"+tc.name, func(t *testing.T) {
				var flags []verbFlag
				for _, name := range verb.pins {
					flags = append(flags, verbFlag{name, "123456"})
				}
				_, code, stderr := runVerb(t, tc.cfg, verb.cmd, nil, flags...)
				assert.Equal(t, 1, code)
				assert.Contains(t, stderr, tc.sentinel.Error())
			})
		}
	}
}
