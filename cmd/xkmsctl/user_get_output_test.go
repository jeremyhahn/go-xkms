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

// user_get_output_test.go pins how user get renders the last login and the
// credential list.
package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestUserGetCmd_JSONWithLastLoginAndCredentials(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{
		getUserResp: &transport.GetUserResponse{User: transport.UserInfo{Username: "alice", CreatedAt: last, LastLogin: &last}},
		listCredsResp: &transport.ListUserCredentialsResponse{
			Credentials: []transport.CredentialInfo{{ID: "cred-1", DisplayName: "YubiKey"}},
		},
	}

	out, code, stderr := runVerb(t, newUserTestConfig("json", mock), userGetCmd, []string{"alice"})
	require.Equal(t, -1, code, stderr)
	got := lastJSONObject(t, out)
	assert.Equal(t, "2026-01-01T00:00:00Z", got["last_login"])
	assert.Equal(t, []any{map[string]any{"id": "cred-1", "display_name": "YubiKey"}}, got["credentials"])
}

func TestUserGetCmd_TextNamesUnlabelledCredentialByID(t *testing.T) {
	mock := &mockUserClient{
		getUserResp:   &transport.GetUserResponse{User: transport.UserInfo{Username: "alice"}},
		listCredsResp: &transport.ListUserCredentialsResponse{Credentials: []transport.CredentialInfo{{ID: "cred-9"}}},
	}

	out, code, stderr := runVerb(t, newUserTestConfig("text", mock), userGetCmd, []string{"alice"})
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "    1. cred-9\n")
}
