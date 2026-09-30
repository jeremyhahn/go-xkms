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

package keyversion

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestName proves version 1 is the key's own name and every later version
// carries the reserved suffix.
func TestName(t *testing.T) {
	assert.Equal(t, "k", Name("k", 0))
	assert.Equal(t, "k", Name("k", 1))
	assert.Equal(t, "k--v2", Name("k", 2))
	assert.Equal(t, "my-key--v17", Name("my-key", 17))
}

// TestParse proves only the names Name produces for versions after the first
// parse, so a legacy key named like a version is never mistaken for one.
func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		keyID   string
		version uint32
		ok      bool
	}{
		{"k--v2", "k", 2, true},
		{"my--key--v10", "my--key", 10, true},
		{"k", "", 0, false},
		{"k--v1", "", 0, false},
		{"k--v0", "", 0, false},
		{"k--v02", "", 0, false},
		{"k--v", "", 0, false},
		{"k--vx", "", 0, false},
		{"--v2", "", 0, false},
		{"k--v99999999999", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, version, ok := Parse(tt.name)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.keyID, keyID)
			assert.Equal(t, tt.version, version)
		})
	}
	assert.Equal(t, "k", BaseKeyID("k--v3"))
	assert.Equal(t, "k--v1", BaseKeyID("k--v1"))
}

// TestCheckKeyID proves every "--v<digits>" suffix is refused and ordinary
// names containing "--v" elsewhere are not.
func TestCheckKeyID(t *testing.T) {
	for _, reserved := range []string{"k--v1", "k--v2", "k--v01", "a--b--v9"} {
		err := CheckKeyID(reserved)
		var target *ReservedKeyIDError
		require.ErrorAs(t, err, &target, reserved)
		assert.Equal(t, reserved, target.KeyID)
		assert.Contains(t, err.Error(), "reserved")
	}
	for _, allowed := range []string{"k", "k--v", "k--vx", "k--v2-x", "k-v2", "k--version"} {
		assert.NoError(t, CheckKeyID(allowed), allowed)
	}
}

// TestRecordVersion proves lookup by number and its two refusals.
func TestRecordVersion(t *testing.T) {
	rec := Implicit("k", "software")
	v, err := rec.Version(1)
	require.NoError(t, err)
	assert.Equal(t, StateEnabled, v.State)

	_, err = rec.Version(0)
	var invalid *InvalidVersionError
	assert.ErrorAs(t, err, &invalid)

	_, err = rec.Version(2)
	var missing *VersionNotFoundError
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, uint32(2), missing.Version)
}

// TestRecordUsable proves only an enabled version is usable.
func TestRecordUsable(t *testing.T) {
	rec := Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "alice")
	_, err := rec.Usable(1)
	require.NoError(t, err)

	changed, err := rec.SetState(1, StateDisabled)
	require.NoError(t, err)
	assert.True(t, changed)

	_, err = rec.Usable(1)
	var unavailable *VersionUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, StateDisabled, unavailable.State)

	_, err = rec.Usable(3)
	var missing *VersionNotFoundError
	assert.ErrorAs(t, err, &missing)
}

// TestRecordRotationOrder proves new versions become current, Enabled lists
// newest first, and Next never reuses a retired number.
func TestRecordRotationOrder(t *testing.T) {
	rec := Implicit("k", "software")
	assert.Equal(t, uint32(2), rec.Next())
	rec.AddCurrent(2, time.Now(), "")
	rec.AddCurrent(3, time.Now(), "")
	assert.Equal(t, uint32(3), rec.Current)
	assert.Equal(t, []uint32{3, 2, 1}, rec.Enabled())

	require.NoError(t, rec.Retire(1))
	assert.Equal(t, []uint32{3, 2}, rec.Enabled())
	assert.Equal(t, uint32(4), rec.Next())
}

// TestRecordSetState proves the current version cannot be disabled, a
// retired one cannot change, and a no-op change reports false.
func TestRecordSetState(t *testing.T) {
	rec := Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "")

	_, err := rec.SetState(2, StateDisabled)
	var current *CurrentVersionError
	require.ErrorAs(t, err, &current)
	assert.Equal(t, "disable", current.Operation)

	changed, err := rec.SetState(1, StateEnabled)
	require.NoError(t, err)
	assert.False(t, changed)

	require.NoError(t, rec.Retire(1))
	_, err = rec.SetState(1, StateEnabled)
	var retired *RetiredVersionError
	assert.ErrorAs(t, err, &retired)

	_, err = rec.SetState(9, StateEnabled)
	var missing *VersionNotFoundError
	assert.ErrorAs(t, err, &missing)
}

// TestRecordRetire proves the current version cannot be retired and a
// retirement is final.
func TestRecordRetire(t *testing.T) {
	rec := Implicit("k", "software")
	err := rec.Retire(1)
	var current *CurrentVersionError
	require.ErrorAs(t, err, &current)
	assert.Equal(t, "retire", current.Operation)

	rec.AddCurrent(2, time.Now(), "")
	require.NoError(t, rec.Retire(1))
	err = rec.Retire(1)
	var retired *RetiredVersionError
	assert.ErrorAs(t, err, &retired)
	assert.ErrorAs(t, rec.Retire(5), new(*VersionNotFoundError))
}

// TestRecordSetAll proves bulk changes skip the current version when
// disabling and never touch a retired one.
func TestRecordSetAll(t *testing.T) {
	rec := Implicit("k", "software")
	rec.AddCurrent(2, time.Now(), "")
	rec.AddCurrent(3, time.Now(), "")
	rec.AddCurrent(4, time.Now(), "")
	require.NoError(t, rec.Retire(2))

	assert.Equal(t, []uint32{1, 3}, rec.SetAll(StateDisabled))
	assert.Equal(t, []uint32{4}, rec.Enabled())
	assert.Empty(t, rec.SetAll(StateDisabled))

	assert.Equal(t, []uint32{1, 3}, rec.SetAll(StateEnabled))
	assert.Equal(t, []uint32{4, 3, 1}, rec.Enabled())
	v, err := rec.Version(2)
	require.NoError(t, err)
	assert.Equal(t, StateRetired, v.State)
}

// TestErrorMessages proves every error names what it refused, so a caller
// can act on the message alone.
func TestErrorMessages(t *testing.T) {
	cause := errors.New("disk full")
	tests := []struct {
		err  error
		want string
	}{
		{&InvalidVersionError{Version: 0}, "invalid key version 0"},
		{&VersionNotFoundError{KeyID: "k", Version: 3}, `key "k" has no version 3`},
		{&VersionUnavailableError{KeyID: "k", Version: 1, State: StateDisabled}, "version 1 of key \"k\" is disabled"},
		{&CurrentVersionError{KeyID: "k", Version: 2, Operation: "retire"}, "rotate the key first"},
		{&RetiredVersionError{KeyID: "k", Version: 1}, "retired"},
		{&KeyVersionRequiredError{KeyID: "k", Enabled: []uint32{2, 1}}, "key_version is required"},
		{&InvalidRecordKeyError{Field: "backend", Value: "a/b"}, "invalid backend"},
		{&StoreError{Op: "put", Key: "x", Err: cause}, "disk full"},
	}
	for _, tt := range tests {
		assert.Contains(t, tt.err.Error(), tt.want)
	}
	assert.ErrorIs(t, &StoreError{Op: "put", Key: "x", Err: cause}, cause)
}
