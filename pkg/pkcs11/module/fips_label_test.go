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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// F4/F5: the module labels itself so a user can tell a FIPS build from a
// non-FIPS one. The label is the build-time truth (fipsBuild → crypto/fips140),
// not the runtime GOFIPS140 environment, so a non-FIPS test binary — which is
// what runs here — must report the non-FIPS labels and must not be swayed by an
// environment variable a caller sets. The FIPS-labelled branch is asserted by
// the FIPS enforcement suite, which runs under a FIPS-compiled binary.
func TestModuleLabels_NonFIPSBuild(t *testing.T) {
	require.False(t, fipsBuild(),
		"the unit test binary is not FIPS-compiled; if this fails the label helpers cannot be trusted here")

	assert.Equal(t, "go-xkms PKCS#11", moduleLibraryDescription(),
		"a non-FIPS build must not claim to be a FIPS module in CK_INFO")
	assert.Equal(t, "Virtual Token", tokenModel(),
		"a non-FIPS build must not claim to be a FIPS token in CK_TOKEN_INFO")

	// The build-time truth ignores the runtime GOFIPS140 signal: a non-FIPS
	// binary a test runs under GOFIPS140 filters like FIPS (fipsModeEnabled)
	// but must not mislabel itself as a FIPS artifact.
	t.Setenv(fipsEnvForTest, "latest")
	assert.False(t, fipsBuild(),
		"fipsBuild is the compiled state; the runtime GOFIPS140 env must not flip it")
	assert.Equal(t, "Virtual Token", tokenModel(),
		"the label must stay non-FIPS even when the env forces FIPS filtering")
}

// The FIPS-mode filter, unlike the label, does honour the runtime env so a
// non-FIPS binary can still exercise the approved-mechanism filter in tests.
func TestFIPSModeEnabled_HonoursRuntimeEnv(t *testing.T) {
	t.Setenv(fipsEnvForTest, "off")
	require.False(t, fipsModeEnabled())

	t.Setenv(fipsEnvForTest, "latest")
	assert.True(t, fipsModeEnabled(),
		"a test must be able to drive the FIPS filter through the env without a FIPS build")
}

// The library-description tag fits CK_INFO.libraryDescription (32 bytes) and the
// model tag fits CK_TOKEN_INFO.model (16 bytes), so neither is silently
// truncated when the FIPS build sets it.
func TestFIPSLabels_FitTheirFixedFields(t *testing.T) {
	assert.LessOrEqual(t, len("go-xkms PKCS#11 FIPS 140-3"), 32,
		"CK_INFO.libraryDescription is a 32-byte field")
	assert.LessOrEqual(t, len("FIPS 140-3 Token"), 16,
		"CK_TOKEN_INFO.model is a 16-byte field")
}
