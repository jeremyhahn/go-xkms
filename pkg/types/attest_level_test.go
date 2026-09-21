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

package types

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAttestLevel_String(t *testing.T) {
	tests := []struct {
		name string
		l    AttestLevel
		want string
	}{
		{"Unattested", AttestLevelUnattested, "unattested"},
		{"Software", AttestLevelSoftware, "software"},
		{"Hardware", AttestLevelHardware, "hardware"},
		{"ZeroValue", AttestLevel(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.l.String())
		})
	}
}

func TestAttestLevel_IsHardware(t *testing.T) {
	tests := []struct {
		name string
		l    AttestLevel
		want bool
	}{
		{"Hardware", AttestLevelHardware, true},
		{"Software", AttestLevelSoftware, false},
		{"Unattested", AttestLevelUnattested, false},
		{"Unrecognized", AttestLevel("bogus"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.l.IsHardware())
		})
	}
}

// TestParseAttestLevel_RoundTrip proves every exported constant parses back
// to itself, so String() and ParseAttestLevel agree in both directions.
func TestParseAttestLevel_RoundTrip(t *testing.T) {
	tests := []AttestLevel{
		AttestLevelUnattested,
		AttestLevelSoftware,
		AttestLevelHardware,
	}

	for _, want := range tests {
		t.Run(want.String(), func(t *testing.T) {
			got, err := ParseAttestLevel(want.String())
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

// TestParseAttestLevel_UnknownIsTypedError proves an unrecognized string
// fails closed with ErrUnknownAttestLevel, rather than silently resolving
// to the zero value — a caller must not be able to smuggle a level this
// build does not understand past ParseAttestLevel by spelling it any way it
// likes.
func TestParseAttestLevel_UnknownIsTypedError(t *testing.T) {
	tests := []string{"", "HARDWARE", "hw", "bogus", " hardware"}

	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			got, err := ParseAttestLevel(s)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrUnknownAttestLevel))
			assert.Equal(t, AttestLevel(""), got)
		})
	}
}

// TestAttestLevel_JSONRoundTrip proves a KeyAttributes.AttestLevel field
// round-trips through JSON, and that the zero value is omitted rather than
// serialized as an empty string — the same convention KeyOrigin already
// follows.
func TestAttestLevel_JSONRoundTrip(t *testing.T) {
	type holder struct {
		Level AttestLevel `json:"attest_level,omitempty"`
	}

	for _, level := range []AttestLevel{AttestLevelHardware, AttestLevelSoftware, AttestLevelUnattested} {
		t.Run(level.String(), func(t *testing.T) {
			data, err := json.Marshal(holder{Level: level})
			require.NoError(t, err)

			var got holder
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, level, got.Level)
		})
	}

	data, err := json.Marshal(holder{})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(data), "zero value must be omitted, not serialized as an empty string")
}

// TestAttestLevel_YAMLRoundTrip mirrors TestAttestLevel_JSONRoundTrip for
// YAML, since types.KeyAttributes carries yaml tags alongside json ones for
// config-file-driven callers.
func TestAttestLevel_YAMLRoundTrip(t *testing.T) {
	type holder struct {
		Level AttestLevel `yaml:"attest_level,omitempty"`
	}

	for _, level := range []AttestLevel{AttestLevelHardware, AttestLevelSoftware, AttestLevelUnattested} {
		t.Run(level.String(), func(t *testing.T) {
			data, err := yaml.Marshal(holder{Level: level})
			require.NoError(t, err)

			var got holder
			require.NoError(t, yaml.Unmarshal(data, &got))
			assert.Equal(t, level, got.Level)
		})
	}
}
