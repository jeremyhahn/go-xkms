// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package keypolicy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// TestCheckStatus proves a disabled or revoked key is refused every
// operation with the typed error naming its status.
func TestCheckStatus(t *testing.T) {
	for _, status := range []Status{StatusDisabled, StatusRevoked} {
		rec := &Record{KeyID: "k", Status: status}
		var unavailable *KeyUnavailableError
		require.ErrorAs(t, rec.Check("alice", OpVerify, 0, now), &unavailable)
		assert.Equal(t, status, unavailable.Status)
		assert.Contains(t, unavailable.Error(), string(status))
	}
	assert.NoError(t, (&Record{KeyID: "k", Status: StatusEnabled}).Check("alice", OpSign, 0, now))
	assert.Equal(t, StatusEnabled, Implicit("k", "software").EffectiveStatus())
}

// TestCheckPolicy proves each policy condition refuses on its own and
// admits what it does not name.
func TestCheckPolicy(t *testing.T) {
	cases := []struct {
		name      string
		policy    Policy
		rotation  *Rotation
		usage     Usage
		principal string
		op        Operation
		refused   bool
	}{
		{name: "empty policy admits", principal: "alice", op: OpSign},
		{name: "expired", policy: Policy{ExpiresAt: now.Unix()}, principal: "alice", op: OpSign, refused: true},
		{name: "not yet expired", policy: Policy{ExpiresAt: now.Unix() + 1}, principal: "alice", op: OpSign},
		{name: "denied principal", policy: Policy{DeniedPrincipals: []string{"alice"}}, principal: "alice", op: OpSign, refused: true},
		{name: "deny wins over allow", policy: Policy{AllowedPrincipals: []string{"alice"}, DeniedPrincipals: []string{"alice"}}, principal: "alice", op: OpSign, refused: true},
		{name: "allowed principal", policy: Policy{AllowedPrincipals: []string{"alice"}}, principal: "alice", op: OpSign},
		{name: "principal not allowed", policy: Policy{AllowedPrincipals: []string{"bob"}}, principal: "alice", op: OpSign, refused: true},
		{name: "operation allowed", policy: Policy{AllowedOperations: []Operation{OpSign}}, principal: "alice", op: OpSign},
		{name: "operation not allowed", policy: Policy{AllowedOperations: []Operation{OpVerify}}, principal: "alice", op: OpSign, refused: true},
		{name: "usage count left", policy: Policy{MaxUsageCount: 2}, usage: Usage{Uses: 1}, principal: "alice", op: OpSign},
		{name: "usage count exhausted", policy: Policy{MaxUsageCount: 2}, usage: Usage{Uses: 2}, principal: "alice", op: OpSign, refused: true},
		{name: "rotation overdue", policy: Policy{RotationRequired: true}, rotation: &Rotation{NextRotation: now.Unix() - 1}, principal: "alice", op: OpSign, refused: true},
		{name: "rotation due later", policy: Policy{RotationRequired: true}, rotation: &Rotation{NextRotation: now.Unix() + 60}, principal: "alice", op: OpSign},
		{name: "rotation required without a schedule", policy: Policy{RotationRequired: true}, principal: "alice", op: OpSign},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := tc.policy
			rec := &Record{KeyID: "k", Policy: &policy, Rotation: tc.rotation, Usage: tc.usage}
			err := rec.Check(tc.principal, tc.op, 0, now)
			if !tc.refused {
				assert.NoError(t, err)
				return
			}
			var denied *PolicyDeniedError
			require.ErrorAs(t, err, &denied)
			assert.Equal(t, tc.op, denied.Operation)
			assert.NotEmpty(t, denied.Reason)
			assert.Contains(t, denied.Error(), denied.Reason)
		})
	}
}

// TestCheckSafety proves the usage limits refuse an authenticated
// encryption past them, never a decryption, and never overflow.
func TestCheckSafety(t *testing.T) {
	rec := &Record{KeyID: "k", Safety: &Safety{MaxOperations: 2, MaxBytes: 100}}
	require.NoError(t, rec.Check("alice", OpEncrypt, 100, now))

	var limit *SafetyLimitError
	require.ErrorAs(t, rec.Check("alice", OpEncrypt, 101, now), &limit)
	assert.Equal(t, "bytes", limit.Limit)

	rec.Use(OpEncrypt, 60, now)
	require.ErrorAs(t, rec.Check("alice", OpWrapKey, 41, now), &limit)
	require.NoError(t, rec.Check("alice", OpEncrypt, 40, now))
	rec.Use(OpEncrypt, 40, now)

	require.ErrorAs(t, rec.Check("alice", OpEncrypt, 0, now), &limit)
	assert.Equal(t, "operations", limit.Limit)
	assert.Contains(t, limit.Error(), "rotate")
	assert.NoError(t, rec.Check("alice", OpDecrypt, 1<<30, now))

	over := &Record{KeyID: "k", Safety: &Safety{MaxBytes: 10}, Usage: Usage{Bytes: 50}}
	require.ErrorAs(t, over.Check("alice", OpEncrypt, 0, now), &limit)
}

// TestUse proves every use is counted and only authenticated encryptions
// count toward the limits.
func TestUse(t *testing.T) {
	rec := &Record{KeyID: "k", Safety: &Safety{MaxOperations: 10}}
	assert.True(t, rec.Tracks())
	rec.Use(OpEncrypt, 5, now)
	rec.Use(OpWrapKey, 7, now)
	rec.Use(OpDecrypt, 9, now)
	assert.Equal(t, Usage{Uses: 3, Operations: 2, Bytes: 12}, rec.Usage)
	assert.Equal(t, now.Unix(), rec.LastUsedAt)

	counted := &Record{Policy: &Policy{MaxUsageCount: 1}}
	assert.True(t, counted.Tracks())
	assert.False(t, (&Record{Policy: &Policy{}}).Tracks())
	assert.False(t, Implicit("k", "software").Tracks())
}

// TestLevel proves the usage percentage takes the tightest limit and maps
// onto the warning, critical and exceeded levels.
func TestLevel(t *testing.T) {
	assert.Zero(t, Implicit("k", "b").UsagePercent())
	assert.Empty(t, Implicit("k", "b").Level())

	cases := []struct {
		safety Safety
		usage  Usage
		want   string
	}{
		{Safety{MaxOperations: 100}, Usage{Operations: 79}, ""},
		{Safety{MaxOperations: 100}, Usage{Operations: 80}, LevelWarning},
		{Safety{MaxOperations: 100, WarningPercent: 50}, Usage{Operations: 50}, LevelWarning},
		{Safety{MaxOperations: 100, MaxBytes: 1000}, Usage{Operations: 10, Bytes: 950}, LevelCritical},
		{Safety{MaxBytes: 1000}, Usage{Bytes: 1000}, LevelExceeded},
	}
	for _, tc := range cases {
		safety := tc.safety
		rec := &Record{Safety: &safety, Usage: tc.usage}
		assert.Equal(t, tc.want, rec.Level(), "%+v %+v", tc.safety, tc.usage)
	}
	rec := &Record{Safety: &Safety{MaxOperations: 4, MaxBytes: 100}, Usage: Usage{Operations: 1, Bytes: 50}}
	assert.InDelta(t, 50.0, rec.UsagePercent(), 0.001)
}

// TestOperationValid proves only the named operations are valid.
func TestOperationValid(t *testing.T) {
	for _, op := range []Operation{OpEncrypt, OpDecrypt, OpSign, OpVerify, OpWrapKey, OpDeriveKey, OpGenerateMAC, OpVerifyMAC} {
		assert.True(t, op.Valid(), op)
	}
	assert.False(t, Operation("").Valid())
	assert.False(t, Operation("admin").Valid())
	assert.False(t, OpUnwrapKey.Valid(), "a policy names unwrapping as wrap_key")
}

func TestCheckUnwrapKey(t *testing.T) {
	wrapOnly := &Record{KeyID: "k", Policy: &Policy{AllowedOperations: []Operation{OpWrapKey}}}
	assert.NoError(t, wrapOnly.Check("", OpUnwrapKey, 0, now), "wrap_key allows unwrapping")

	encryptOnly := &Record{KeyID: "k", Policy: &Policy{AllowedOperations: []Operation{OpEncrypt}}}
	var denied *PolicyDeniedError
	require.ErrorAs(t, encryptOnly.Check("", OpUnwrapKey, 0, now), &denied)
	assert.Equal(t, OpUnwrapKey, denied.Operation)

	exhausted := &Record{KeyID: "k", Safety: &Safety{MaxOperations: 1}, Usage: Usage{Operations: 1}}
	assert.NoError(t, exhausted.Check("", OpUnwrapKey, 0, now), "unwrapping is not bounded by the usage limits")
	exhausted.Use(OpUnwrapKey, 32, now)
	assert.Equal(t, Usage{Uses: 1, Operations: 1}, exhausted.Usage)
}

// TestCheckExportKey proves a key whose policy restricts its operations is
// never exported, whatever it allows, and that exporting is not bounded by
// the safety limits.
func TestCheckExportKey(t *testing.T) {
	assert.False(t, OpExportKey.Valid(), "a policy cannot name exporting")
	unrestricted := &Record{KeyID: "k"}
	assert.NoError(t, unrestricted.Check("", OpExportKey, 0, now))

	restricted := &Record{KeyID: "k", Policy: &Policy{AllowedOperations: []Operation{OpEncrypt, OpDecrypt, OpWrapKey}}}
	var denied *PolicyDeniedError
	require.ErrorAs(t, restricted.Check("", OpExportKey, 0, now), &denied)
	assert.Equal(t, OpExportKey, denied.Operation)

	exhausted := &Record{KeyID: "k", Safety: &Safety{MaxOperations: 1}, Usage: Usage{Operations: 1}}
	assert.NoError(t, exhausted.Check("", OpExportKey, 0, now))
	exhausted.Use(OpExportKey, 0, now)
	assert.Equal(t, Usage{Uses: 1, Operations: 1}, exhausted.Usage)
}

// TestEmpty proves a record holding any state is not empty.
func TestEmpty(t *testing.T) {
	assert.False(t, (&Record{Status: StatusDisabled}).Empty())
	assert.False(t, (&Record{Tags: map[string]string{"a": "b"}}).Empty())
	assert.False(t, (&Record{Rotation: &Rotation{}}).Empty())
	assert.True(t, (&Record{KeyID: "k", Usage: Usage{Uses: 3}}).Empty())
}
