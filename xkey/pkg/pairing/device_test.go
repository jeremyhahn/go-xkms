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

package pairing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestDuration_MarshalYAML verifies a Duration renders as a Go duration
// string ("1h30m0s"), not as raw nanoseconds, so the persisted devices.yaml
// stays human-editable.
func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration(90 * time.Minute)

	out, err := yaml.Marshal(d)
	require.NoError(t, err)
	assert.Equal(t, "1h30m0s\n", string(out))
}

// TestDuration_UnmarshalYAML verifies a duration string round-trips back
// into the same value MarshalYAML produced.
func TestDuration_UnmarshalYAML(t *testing.T) {
	var d Duration
	require.NoError(t, yaml.Unmarshal([]byte("1h30m0s\n"), &d))
	assert.Equal(t, Duration(90*time.Minute), d)
}

// TestDuration_UnmarshalYAML_InvalidDuration verifies a malformed duration
// string is reported as an error rather than silently defaulting to zero.
func TestDuration_UnmarshalYAML_InvalidDuration(t *testing.T) {
	var d Duration
	err := yaml.Unmarshal([]byte("not-a-duration\n"), &d)
	assert.Error(t, err)
}

// TestDuration_UnmarshalYAML_WrongNodeKind verifies a non-scalar YAML node
// (a mapping, where a string is expected) is reported as a decode error.
func TestDuration_UnmarshalYAML_WrongNodeKind(t *testing.T) {
	var d Duration
	err := yaml.Unmarshal([]byte("foo: bar\n"), &d)
	assert.Error(t, err)
}

// TestDuration_YAMLRoundTrip exercises Marshal and Unmarshal together as a
// struct field, matching how Duration is actually used in the config.
func TestDuration_YAMLRoundTrip(t *testing.T) {
	type wrapper struct {
		Timeout Duration `yaml:"timeout"`
	}

	original := wrapper{Timeout: Duration(45 * time.Second)}
	out, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded wrapper
	require.NoError(t, yaml.Unmarshal(out, &decoded))
	assert.Equal(t, original.Timeout, decoded.Timeout)
}
