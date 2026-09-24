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
	"crypto/fips140"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
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

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// runOutsideFIPS reports whether the caller is already running with no
// GODEBUG selector, in which case it returns true so the caller performs
// its real assertion. Otherwise it re-execs the current test binary with
// GODEBUG stripped from the environment, asserts the child exits zero and
// prints PASS, and returns false so the caller performs no assertion of its
// own -- the parent's own environment may still have a FIPS selector (as
// go-xkms#23 requires when running this whole suite under
// GODEBUG=fips140=only), and crypto/fips140.Enabled is fixed for the life
// of the process, so only the child's answer is meaningful for a test whose
// premise is "outside FIPS mode".
func runOutsideFIPS(t *testing.T, testName string) bool {
	t.Helper()
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		return true
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GODEBUG=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(env, "XKMS_FIPS_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("no-GODEBUG subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("no-GODEBUG subprocess did not pass:\n%s", out)
	}
	return false
}

func TestDefaultKDF_ReturnsArgon2idOutsideFIPS(t *testing.T) {
	if !runOutsideFIPS(t, "TestDefaultKDF_ReturnsArgon2idOutsideFIPS") {
		return
	}
	assert.Equal(t, KDFArgon2id, DefaultKDF(), "DefaultKDF must return argon2id outside FIPS mode")
}

func TestDefaultLUKSKDF_ReturnsArgon2idOutsideFIPS(t *testing.T) {
	if !runOutsideFIPS(t, "TestDefaultLUKSKDF_ReturnsArgon2idOutsideFIPS") {
		return
	}
	assert.Equal(t, KDFArgon2id, DefaultLUKSKDF(), "DefaultLUKSKDF must return argon2id outside FIPS mode")
}

// TestDefaultKDFs_ReturnPBKDF2UnderFIPS140On is the compliance assertion for
// go-xkms #21: DefaultKDF/DefaultLUKSKDF select pbkdf2 because
// crypto/fips140.Enabled is true, not because of a GOFIPS140 environment
// variable this package used to read itself. crypto/fips140.Enabled is fixed
// when the process starts, so this re-execs under GODEBUG=fips140=on,
// mirroring pkg/quantum/mlkem512.TestNewAndCreate_RefuseUnderFIPS.
func TestDefaultKDFs_ReturnPBKDF2UnderFIPS140On(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		if !fips140.Enabled() {
			t.Fatal("child process is not FIPS-active; GODEBUG=fips140=on was not honored")
		}
		if got := DefaultKDF(); got != KDFPBKDF2 {
			t.Fatalf("DefaultKDF() = %q, want %q under GODEBUG=fips140=on", got, KDFPBKDF2)
		}
		if got := DefaultLUKSKDF(); got != KDFPBKDF2 {
			t.Fatalf("DefaultLUKSKDF() = %q, want %q under GODEBUG=fips140=on", got, KDFPBKDF2)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDefaultKDFs_ReturnPBKDF2UnderFIPS140On", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
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

// TestBuildSettingAndBuilt_IgnoreGODEBUG is the direction #219 fixed:
// GODEBUG=fips140 selects crypto/fips140.Enabled's module state for the
// process, and must not move BuildSetting/Built, which read only this
// binary's build metadata. crypto/fips140.Enabled is fixed when the process
// starts, so this re-execs, comparing the child's BuildSetting()/Built()
// against the parent's — the parent's own values, not a hard-coded
// expectation, because whether this test binary itself is a FIPS build
// depends on how `go test` was invoked.
func TestBuildSettingAndBuilt_IgnoreGODEBUG(t *testing.T) {
	recordedSetting := BuildSetting()
	recordedBuilt := Built()

	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		if !fips140.Enabled() {
			t.Fatal("child process is not FIPS-active; GODEBUG=fips140=on was not honored")
		}
		wantSetting := os.Getenv("XKMS_FIPS_PARENT_SETTING")
		wantBuilt := os.Getenv("XKMS_FIPS_PARENT_BUILT") == "true"
		if got := BuildSetting(); got != wantSetting {
			t.Fatalf("BuildSetting() = %q under GODEBUG=fips140=on, want %q (the parent's "+
				"build setting, unmoved by GODEBUG)", got, wantSetting)
		}
		if got := Built(); got != wantBuilt {
			t.Fatalf("Built() = %v under GODEBUG=fips140=on, want %v (the parent's build "+
				"verdict, unmoved by GODEBUG)", got, wantBuilt)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBuildSettingAndBuilt_IgnoreGODEBUG", "-test.v")
	cmd.Env = append(os.Environ(),
		"XKMS_FIPS_SUBPROCESS=1",
		"GODEBUG=fips140=on",
		"XKMS_FIPS_PARENT_SETTING="+recordedSetting,
		"XKMS_FIPS_PARENT_BUILT="+boolString(recordedBuilt))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
}
