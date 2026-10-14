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

// admin_enroll_fido2_test.go pins the JSON summary of a FIDO2 admin
// enrollment and its refusal when the server will not create the account.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestEnrollFIDO2Admin_JSONSummary(t *testing.T) {
	cfg := &Config{OutputFormat: "json", ClientFactory: func(*Config) (client.Client, error) { return &mockAdminClient{}, nil }}
	cmd := newAdminCreateCmdCopy()
	require.NoError(t, cmd.Flags().Set("display-name", "Root Admin"))
	var out bytes.Buffer

	require.NoError(t, enrollFIDO2Admin(cmd, "root", cfg, NewPrinter("json", &out), ""))

	var summary map[string]interface{}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var obj map[string]interface{}
		require.NoError(t, dec.Decode(&obj))
		if _, ok := obj["pending"]; ok {
			summary = obj
		}
	}
	require.NotNil(t, summary, "the summary object is printed")
	assert.Equal(t, "root", summary["username"])
	assert.Equal(t, "Root Admin", summary["display_name"])
	assert.Equal(t, "admin", summary["role"])
	assert.Equal(t, true, summary["pending"])
}

func TestEnrollFIDO2Admin_CreateUserRefused(t *testing.T) {
	mock := &mockAdminClient{createUserErr: errUserExtBoom}
	cfg := &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}

	err := enrollFIDO2Admin(newAdminCreateCmdCopy(), "root", cfg, NewPrinter("text", io.Discard), "")
	assert.ErrorIs(t, err, ErrCreateUserFailed)
}
