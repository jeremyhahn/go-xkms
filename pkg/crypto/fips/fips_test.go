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

package fips

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildInfo assembles synthetic build metadata from key/value pairs so the
// GOFIPS140 lookup can be driven through values this test binary was not built
// with — every selector, an explicit "off", and the absent case — without
// rebuilding it under each one. It panics on an odd argument count, which is a
// mistake in the test rather than a condition under test.
func buildInfo(pairs ...string) *debug.BuildInfo {
	if len(pairs)%2 != 0 {
		panic("buildInfo: odd number of key/value arguments")
	}
	info := &debug.BuildInfo{}
	for i := 0; i < len(pairs); i += 2 {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: pairs[i], Value: pairs[i+1]})
	}
	return info
}

func TestEnabled_ReturnsFalseWhenUnset(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.False(t, Enabled(), "Enabled must return false when GOFIPS140 is empty")
}

func TestEnabled_ReturnsTrueWhenSet(t *testing.T) {
	values := []string{"v1.0.0", "1", "true", "on", "yes"}
	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			t.Setenv(EnvGOFIPS140, v)
			require.True(t, Enabled(), "Enabled must return true when GOFIPS140=%q", v)
		})
	}
}

func TestDefaultKDF_ReturnsArgon2idWhenFIPSDisabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.Equal(t, KDFArgon2id, DefaultKDF(), "DefaultKDF must return argon2id in standard mode")
}

func TestDefaultKDF_ReturnsPBKDF2WhenFIPSEnabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "v1.0.0")
	assert.Equal(t, KDFPBKDF2, DefaultKDF(), "DefaultKDF must return pbkdf2 in FIPS mode")
}

func TestDefaultLUKSKDF_ReturnsArgon2idWhenFIPSDisabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "")
	assert.Equal(t, KDFArgon2id, DefaultLUKSKDF(), "DefaultLUKSKDF must return argon2id in standard mode")
}

func TestDefaultLUKSKDF_ReturnsPBKDF2WhenFIPSEnabled(t *testing.T) {
	t.Setenv(EnvGOFIPS140, "1")
	assert.Equal(t, KDFPBKDF2, DefaultLUKSKDF(), "DefaultLUKSKDF must return pbkdf2 in FIPS mode")
}

// buildSettingFrom must find the recorded GOFIPS140 value among the other
// settings cmd/go stamps in, whichever selector the build ran with.
func TestBuildSettingFrom_ReturnsRecordedSelector(t *testing.T) {
	for _, selector := range []string{"latest", "inprocess", "certified", "v1.0.0"} {
		t.Run(selector, func(t *testing.T) {
			info := buildInfo(
				"-buildmode", "exe",
				"GOARCH", "amd64",
				buildSettingKey, selector,
				"GOOS", "linux")
			assert.Equal(t, selector, buildSettingFrom(info),
				"the recorded GOFIPS140 selector must be returned verbatim")
		})
	}
}

// The absent cases, which are the common ones: a non-FIPS build records no
// GOFIPS140 setting at all, and ReadBuildInfo can report no metadata whatever.
func TestBuildSettingFrom_ReturnsEmptyWhenAbsent(t *testing.T) {
	assert.Equal(t, "", buildSettingFrom(nil),
		"nil metadata (ReadBuildInfo reported none) must not be dereferenced")
	assert.Equal(t, "", buildSettingFrom(&debug.BuildInfo{}),
		"metadata carrying no settings at all records no FIPS build")
	assert.Equal(t, "", buildSettingFrom(buildInfo("-buildmode", "exe", "GOARCH", "amd64")),
		"a normal build's settings carry no GOFIPS140")
	// DefaultGODEBUG=fips140=on really is recorded beside GOFIPS140 in a FIPS
	// build, so a lookup matching on substring rather than key would read the
	// wrong entry — and would then report a FIPS build for any binary whose
	// GODEBUG default merely mentions fips140.
	assert.Equal(t, "", buildSettingFrom(buildInfo("DefaultGODEBUG", "fips140=on")),
		"only the GOFIPS140 key counts; a neighbouring setting must not be mistaken for it")
}

// Absent and off are different facts and the reader must keep them apart: that
// distinction is the whole reason provenance is read from build metadata rather
// than inferred from module state (#219). Both are non-builds, but only
// BuildSetting can say which one the toolchain recorded.
func TestBuildSettingFrom_DistinguishesAbsentFromOff(t *testing.T) {
	absent := buildSettingFrom(buildInfo("GOARCH", "amd64"))
	off := buildSettingFrom(buildInfo(buildSettingKey, "off"))

	require.Equal(t, "", absent, "an unrecorded setting reads back empty")
	require.Equal(t, "off", off, "a recorded off must be reported as off, not flattened to empty")
	assert.NotEqual(t, absent, off,
		"a caller must be able to tell an unrecorded setting from one recorded as off")

	assert.False(t, builtFrom(absent), "no recorded setting is not a FIPS build")
	assert.False(t, builtFrom(off), "an explicit off is not a FIPS build either")
}

func TestBuiltFrom_TrueForEnablingSelectors(t *testing.T) {
	for _, selector := range []string{"latest", "inprocess", "certified", "v1.0.0", "v1.2.3"} {
		t.Run(selector, func(t *testing.T) {
			assert.True(t, builtFrom(selector),
				"GOFIPS140=%q enables the module, so the artifact is a FIPS build", selector)
		})
	}
}

func TestBuiltFrom_FalseForAbsentOrOff(t *testing.T) {
	assert.False(t, builtFrom(""),
		"no recorded GOFIPS140 means the binary was not built as a FIPS module")
	// The toolchain does not record "off" today; the spelling is refused anyway
	// so the answer cannot flip if a future toolchain starts recording it.
	assert.False(t, builtFrom("off"),
		"GOFIPS140=off does not enable the module and must never read as a FIPS build")
}

// BuildSetting must report exactly what the lookup finds in this binary's own
// metadata. The require on ok is deliberate: a test binary does carry build
// metadata (measured), and if that ever stopped holding this test would be
// asserting nothing and should say so loudly rather than pass empty-handed.
func TestBuildSetting_ReadsThisBinarysMetadata(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	require.True(t, ok, "a Go test binary carries build metadata; without it this test proves nothing")

	assert.Equal(t, buildSettingFrom(info), BuildSetting(),
		"BuildSetting must be the lookup applied to this binary's own metadata")

	if got := BuildSetting(); got != "" {
		assert.NotEqual(t, "off", got,
			"the toolchain records GOFIPS140 only when it enables the module, never as off")
	}
}

// Provenance must not move with the environment. This is the entire distinction
// from Enabled, and the direction of the #219 defect: GOFIPS140 in the
// environment selects module state for the process, never what was compiled.
func TestBuildSetting_IgnoresTheEnvironment(t *testing.T) {
	recorded := BuildSetting()

	t.Setenv(EnvGOFIPS140, "latest")
	require.True(t, Enabled(), "the environment signal must be live or this test asserts nothing")
	assert.Equal(t, recorded, BuildSetting(),
		"setting GOFIPS140 in the environment must not alter the recorded build setting")

	t.Setenv(EnvGOFIPS140, "off")
	assert.Equal(t, recorded, BuildSetting(),
		"clearing GOFIPS140 in the environment must not alter the recorded build setting")
}

func TestBuilt_MatchesTheRecordedSetting(t *testing.T) {
	assert.Equal(t, builtFrom(BuildSetting()), Built(),
		"Built must be builtFrom applied to the recorded setting and nothing else")
}

func TestBuilt_IgnoresTheEnvironment(t *testing.T) {
	built := Built()

	t.Setenv(EnvGOFIPS140, "latest")
	require.True(t, Enabled(), "the environment signal must be live or this test asserts nothing")
	assert.Equal(t, built, Built(),
		"a non-FIPS build run under GOFIPS140 filters like FIPS but is still not a FIPS build")

	t.Setenv(EnvGOFIPS140, "off")
	assert.Equal(t, built, Built(),
		"build provenance is fixed at link time and the environment cannot revoke it")
}
