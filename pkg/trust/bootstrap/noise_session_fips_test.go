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

package bootstrap

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const noiseSessionFIPSSubprocessEnv = "XKMS_NOISE_SESSION_FIPS_SUBPROCESS"

// TestNoiseSession_RefusesTypedUnderFIPSOnly proves that a process running
// GODEBUG=fips140=only learns the Noise_XX suite is unavailable, not that a
// handshake broke or a key is malformed: NewNoiseSession and
// LoadNoiseStaticKey return ErrNoiseFIPSUnsupported, and mapNoiseError keeps
// it. crypto/fips140 fixes its mode when the process starts, so the
// assertions run in a child re-executed under fips140=only, whatever mode the
// parent runs in.
func TestNoiseSession_RefusesTypedUnderFIPSOnly(t *testing.T) {
	if os.Getenv(noiseSessionFIPSSubprocessEnv) == "1" {
		_, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
		require.ErrorIs(t, err, ErrNoiseFIPSUnsupported, "NewNoiseSession")

		// The refusal also wraps ErrHandshakeFailed; mapping it must pick
		// the refusal every time, not whichever sentinel the map yields
		// first.
		for range 32 {
			require.Equal(t, ErrNoiseFIPSUnsupported, mapNoiseError(err), "mapNoiseError")
		}

		_, err = LoadNoiseStaticKey(make([]byte, NoiseKeySize))
		require.ErrorIs(t, err, ErrNoiseFIPSUnsupported, "LoadNoiseStaticKey")
		assert.NotErrorIs(t, err, ErrNoiseInvalidMessage)
		return
	}

	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GODEBUG=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNoiseSession_RefusesTypedUnderFIPSOnly$", "-test.v")
	cmd.Env = append(env, noiseSessionFIPSSubprocessEnv+"=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "fips140=only subprocess failed:\n%s", out)
	assert.Contains(t, string(out), "PASS", "fips140=only subprocess did not pass:\n%s", out)
}

// TestLoadNoiseStaticKey_MalformedKeyStaysInvalidMessage pins the other side
// of the refusal: a key of the wrong size is still reported as
// ErrNoiseInvalidMessage, never as a FIPS refusal.
func TestLoadNoiseStaticKey_MalformedKeyStaysInvalidMessage(t *testing.T) {
	_, err := LoadNoiseStaticKey([]byte{1, 2, 3})
	require.ErrorIs(t, err, ErrNoiseInvalidMessage)
	assert.NotErrorIs(t, err, ErrNoiseFIPSUnsupported)
}
