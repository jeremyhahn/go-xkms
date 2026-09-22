// Copyright (C) 2025 go-xkms authors
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published
//    by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

package module

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFIPSMode drives fipsModeEnabled from both sides for a test. GODEBUG=
// fips140 can only be set before the process starts, so this is the seam a
// test overrides instead of re-execing a subprocess for every FIPS-mode
// behaviour case (go-xkms #21). Production code never assigns to
// fipsModeEnabled; only tests do, always restoring it via t.Cleanup.
func withFIPSMode(t *testing.T, on bool) {
	t.Helper()
	original := fipsModeEnabled
	fipsModeEnabled = func() bool { return on }
	t.Cleanup(func() { fipsModeEnabled = original })
}

const (
	fipsLibraryDescription  = "go-xkms PKCS#11 FIPS 140-3"
	plainLibraryDescription = "go-xkms PKCS#11"
	fipsTokenModel          = "FIPS 140-3 Token"
	plainTokenModel         = "Virtual Token"

	// fipsLabelSubprocessEnv marks the re-executed child of
	// TestModuleLabels_IgnoreRuntimeModuleState.
	fipsLabelSubprocessEnv = "XKMS_FIPS_LABEL_SUBPROCESS"
	// fipsLabelParentBuiltEnv carries the parent's fips.Built() verdict to
	// the child, so the child can assert provenance is unchanged by GODEBUG.
	fipsLabelParentBuiltEnv = "XKMS_FIPS_LABEL_PARENT_BUILT"
)

// wantLabels returns the labels the artifact this test binary belongs to must
// carry. The verdict is the build metadata's, not the environment's, which is
// what lets the same assertions hold in a non-FIPS unit-test binary and in a
// GOFIPS140-built one.
func wantLabels(t *testing.T) (description, model string) {
	t.Helper()
	if fips.Built() {
		return fipsLibraryDescription, fipsTokenModel
	}
	return plainLibraryDescription, plainTokenModel
}

// F4/F5: the module labels itself so a user can tell a FIPS build from a
// non-FIPS one. The label is the build-time truth — the GOFIPS140 setting the
// toolchain recorded in this binary (fips.Built) — not the process's FIPS-mode
// filter state, so the labels must not be swayed by fipsModeEnabled.
func TestModuleLabels_FollowTheBuildNotTheEnvironment(t *testing.T) {
	withFIPSMode(t, false)
	require.Equal(t, fips.Built(), fipsBuild(),
		"fipsBuild must report exactly the recorded build setting")

	description, model := wantLabels(t)
	assert.Equal(t, description, moduleLibraryDescription(),
		"CK_INFO.libraryDescription must describe the artifact that was built")
	assert.Equal(t, model, tokenModel(),
		"CK_TOKEN_INFO.model must describe the artifact that was built")

	// The build-time truth ignores the FIPS-mode filter: a non-FIPS binary a
	// test drives to filter like FIPS (fipsModeEnabled) must not relabel itself.
	withFIPSMode(t, true)
	require.True(t, fipsModeEnabled(), "the seam must still drive the filter")
	assert.Equal(t, fips.Built(), fipsBuild(),
		"fipsBuild is the compiled state; the FIPS-mode filter must not flip it")
	assert.Equal(t, description, moduleLibraryDescription(),
		"the library description must not move with the filter")
	assert.Equal(t, model, tokenModel(),
		"the token model must not move with the filter")
}

// The labels must also ignore the MODULE state, which is the signal they used
// to rest on. GODEBUG=fips140 selects crypto/fips140.Enabled() either way and
// is fixed at process start, so each posture is asserted in a re-executed
// child: under fips140=on a non-FIPS build must still not claim to be a FIPS
// module, and under fips140=off a FIPS build must still claim to be one. Both
// children assert the label against the parent's build verdict, which GODEBUG
// cannot change — the defect this pins is a label that moved with the module
// state instead (#219).
func TestModuleLabels_IgnoreRuntimeModuleState(t *testing.T) {
	if os.Getenv(fipsLabelSubprocessEnv) == "1" {
		parentBuilt := os.Getenv(fipsLabelParentBuiltEnv) == "true"
		require.Equal(t, parentBuilt, fips.Built(),
			"build provenance changed between parent and child; GODEBUG must not touch it")
		require.Equal(t, parentBuilt, fipsBuild(),
			"fipsBuild must follow the build metadata, not the module state")

		description, model := wantLabels(t)
		assert.Equal(t, description, moduleLibraryDescription())
		assert.Equal(t, model, tokenModel())
		// fipsModeEnabled defaults to crypto/fips140.Enabled and the child
		// never overrides it, so in the child it must agree with the real
		// stdlib verdict as GODEBUG selected it.
		assert.Equal(t, fips140.Enabled(), fipsModeEnabled(),
			"the filter, unlike the label, follows the module state")
		return
	}

	for _, state := range []string{"on", "off"} {
		t.Run("fips140="+state, func(t *testing.T) {
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestModuleLabels_IgnoreRuntimeModuleState$", "-test.v")
			cmd.Env = append(os.Environ(),
				fipsLabelSubprocessEnv+"=1",
				fipsLabelParentBuiltEnv+"="+boolString(fips.Built()),
				"GODEBUG=fips140="+state)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "child under GODEBUG=fips140=%s failed:\n%s", state, out)
			require.True(t, strings.Contains(string(out), "PASS"),
				"child under GODEBUG=fips140=%s did not pass:\n%s", state, out)
		})
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// The FIPS-mode filter defaults to crypto/fips140.Enabled but is overridable
// through withFIPSMode, so a non-FIPS binary can still exercise the
// approved-mechanism filter in tests without a live GODEBUG=fips140 subprocess
// for every case (go-xkms #21).
func TestFIPSModeEnabled_HonoursTheInjectedSeam(t *testing.T) {
	withFIPSMode(t, false)
	assert.False(t, fipsModeEnabled(), "withFIPSMode(false) must be honoured")

	withFIPSMode(t, true)
	assert.True(t, fipsModeEnabled(),
		"a test must be able to drive the FIPS filter without a FIPS build")
}

// The library-description tag fits CK_INFO.libraryDescription (32 bytes) and the
// model tag fits CK_TOKEN_INFO.model (16 bytes), so neither is silently
// truncated when the FIPS build sets it.
func TestFIPSLabels_FitTheirFixedFields(t *testing.T) {
	assert.LessOrEqual(t, len(fipsLibraryDescription), 32,
		"CK_INFO.libraryDescription is a 32-byte field")
	assert.LessOrEqual(t, len(fipsTokenModel), 16,
		"CK_TOKEN_INFO.model is a 16-byte field")
}
