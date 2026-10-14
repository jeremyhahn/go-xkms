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

// status_outputs_test.go pins the PIN lockout report, the algorithm list
// in JSON, and the refusals of the lockout, algorithms and EAB delete verbs.
package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestPinLockout_LockedReport(t *testing.T) {
	mock := &mockPINClient{lockoutResp: &transport.LockoutStatusResponse{
		FailedAttempts: 5, MaxAttempts: 5, IsLocked: true,
		LockoutUntil: "2026-10-14T12:00:00Z", RecoverySeconds: 90,
	}}
	cfg := newPINConfig(mock)
	withGlobalConfig(t, cfg)

	var buf bytes.Buffer
	code, _ := runKeyExt(t, func() { pinLockout(cfg, NewPrinter("text", &buf)) })
	assert.Equal(t, -1, code)
	assert.Contains(t, buf.String(), "  Locked:          true")
	assert.Contains(t, buf.String(), "  Locked Until:    2026-10-14T12:00:00Z")
	assert.Contains(t, buf.String(), "  Recovery In:     90s")

	buf.Reset()
	code, _ = runKeyExt(t, func() { pinLockout(cfg, NewPrinter("json", &buf)) })
	assert.Equal(t, -1, code)
	var got transport.LockoutStatusResponse
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, 90, int(got.RecoverySeconds))
}

func TestPinLockout_UnlockedOmitsRecovery(t *testing.T) {
	cfg := newPINConfig(&mockPINClient{lockoutResp: &transport.LockoutStatusResponse{MaxAttempts: 5}})
	withGlobalConfig(t, cfg)

	var buf bytes.Buffer
	code, _ := runKeyExt(t, func() { pinLockout(cfg, NewPrinter("table", &buf)) })
	assert.Equal(t, -1, code)
	assert.NotContains(t, buf.String(), "Locked Until")
	assert.NotContains(t, buf.String(), "Recovery In")
}

func TestPinLockout_ConnectFailure(t *testing.T) {
	cfg := newPINConfig(&mockPINClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}})
	withGlobalConfig(t, cfg)

	var buf bytes.Buffer
	code, stderr := runKeyExt(t, func() { pinLockout(cfg, NewPrinter("text", &buf)) })
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrConnectFailed.Error())
	assert.Empty(t, buf.String())
}

func TestListAlgorithms_JSON(t *testing.T) {
	cfg := newAlgorithmsConfig(&mockAlgorithmsClient{resp: &transport.AlgorithmsResponse{
		Signing: []transport.AlgorithmInfo{{Algorithm: "Ed25519", Backends: []string{"software"}}},
	}})
	withGlobalConfig(t, cfg)

	var buf bytes.Buffer
	code, _ := runKeyExt(t, func() { listAlgorithms(cfg, NewPrinter("json", &buf)) })
	assert.Equal(t, -1, code)
	var got transport.AlgorithmsResponse
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Len(t, got.Signing, 1)
	assert.Equal(t, "Ed25519", got.Signing[0].Algorithm)
}

func TestListAlgorithms_Failures(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		sentinel error
	}{
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errListBoom }}, ErrCreateClientFailed},
		{"connect", newAlgorithmsConfig(&mockAlgorithmsClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}), ErrConnectFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withGlobalConfig(t, tc.cfg)
			var buf bytes.Buffer
			code, stderr := runKeyExt(t, func() { listAlgorithms(tc.cfg, NewPrinter("text", &buf)) })
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, buf.String())
		})
	}
}

func TestACMEEABDelete_RefusesMissingArguments(t *testing.T) {
	cfg := &Config{OutputFormat: "text"}

	resetACMEEABFlags(t)
	withGlobalConfig(t, cfg)
	code, stderr := runKeyExt(t, func() { acmeEABDelete(cfg, "kid-1") })
	assert.Equal(t, 1, code, "a delete without --tenant is refused")
	assert.NotEmpty(t, stderr)

	acmeEABTenant = "acme-tenant"
	code, stderr = runKeyExt(t, func() { acmeEABDelete(cfg, "") })
	assert.Equal(t, 1, code, "a delete without a KID is refused")
	assert.Contains(t, stderr, ErrACMEEABKIDRequired.Error())
}
