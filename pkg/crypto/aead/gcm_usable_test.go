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

package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestArbitraryIVGCMUsable_AgreesWithConstruction pins the probe's one
// invariant: it answers for the process it runs in, so the cached answer must
// agree with performing the construction afresh, in every mode the suite is
// run under. The uncached probe is the oracle; cipher.NewGCM is checked
// alongside it so the test cannot pass on two probes that agree with each
// other but not with the runtime.
func TestArbitraryIVGCMUsable_AgreesWithConstruction(t *testing.T) {
	want := probeArbitraryIVGCM()
	require.Equal(t, want, ArbitraryIVGCMUsable(),
		"ArbitraryIVGCMUsable must agree with performing an arbitrary-IV GCM seal in this process")

	block, err := aes.NewCipher(make([]byte, 16))
	require.NoError(t, err, "AES itself is approved and must construct in every mode")
	_, gcmErr := cipher.NewGCM(block)
	require.Equal(t, want, gcmErr == nil,
		"the probe must agree with cipher.NewGCM in this process")
}

// TestArbitraryIVGCMUsable_IsStable pins the cache: the FIPS posture is fixed
// at process start, so the answer must never change within a process.
func TestArbitraryIVGCMUsable_IsStable(t *testing.T) {
	first := ArbitraryIVGCMUsable()
	for i := 0; i < 100; i++ {
		require.Equal(t, first, ArbitraryIVGCMUsable(),
			"ArbitraryIVGCMUsable changed its answer within one process")
	}
}

// TestArbitraryIVGCMUsable_UnderFIPSModes re-execs the test binary under each
// GODEBUG fips140 setting, because the FIPS posture is fixed when the process
// starts and cannot be toggled in-process.
//
//   - fips140=on must report true: arbitrary-IV GCM works there, and gating on
//     fips140.Enabled() — true under both on and only — would have withdrawn a
//     working construction (#292).
//   - fips140=only must report false, the child must exit 0 (capability
//     refused, process alive), and NewGCM must fail in agreement with the
//     report.
func TestArbitraryIVGCMUsable_UnderFIPSModes(t *testing.T) {
	if mode := os.Getenv("XKMS_FIPS_GCM_SUBPROCESS"); mode != "" {
		usable := ArbitraryIVGCMUsable()

		block, err := aes.NewCipher(make([]byte, 16))
		require.NoError(t, err, "AES itself is approved and must construct in every mode")
		_, gcmErr := cipher.NewGCM(block)

		switch mode {
		case "on":
			require.True(t, usable,
				"arbitrary-IV GCM works under fips140=on; reporting it unusable withdraws a working construction")
			require.NoError(t, gcmErr)
		case "only":
			require.False(t, usable,
				"fips140=only refuses arbitrary-IV GCM; reporting it usable lets callers walk into the runtime refusal")
			require.Error(t, gcmErr)
		default:
			t.Fatalf("unknown subprocess mode %q", mode)
		}
		return
	}

	for _, mode := range []string{"on", "only"} {
		t.Run("fips140="+mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestArbitraryIVGCMUsable_UnderFIPSModes$", "-test.v")
			cmd.Env = append(os.Environ(),
				"XKMS_FIPS_GCM_SUBPROCESS="+mode, "GODEBUG=fips140="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("fips140=%s subprocess failed: %v\n%s", mode, err, out)
			}
			require.Contains(t, string(out), "PASS",
				"fips140=%s subprocess did not pass:\n%s", mode, out)
			require.NotContains(t, string(out), "panic:",
				"fips140=%s subprocess panicked:\n%s", mode, out)
		})
	}
}
