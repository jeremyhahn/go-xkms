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

package services

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// PKCS11Service.ensureSoftHSM2Config: env-var early return (0% -> partial)
// ---------------------------------------------------------------------------

func TestFinal90Push_EnsureSoftHSM2Config_EnvVarEarlyReturn(t *testing.T) {
	// Save and restore the original SOFTHSM2_CONF value.
	orig := os.Getenv("SOFTHSM2_CONF")
	t.Cleanup(func() {
		if orig == "" {
			os.Unsetenv("SOFTHSM2_CONF")
		} else {
			os.Setenv("SOFTHSM2_CONF", orig)
		}
	})

	os.Setenv("SOFTHSM2_CONF", "/tmp/fake-softhsm2.conf")

	svc := &PKCS11Service{
		log: testLogger(),
	}
	err := svc.ensureSoftHSM2Config()
	assert.NoError(t, err)
}

func TestFinal90Push_EnsureSoftHSM2Config_EnvVarEmpty_FallsThrough(t *testing.T) {
	// When SOFTHSM2_CONF is empty, the function falls through to system
	// path checks and eventually creates a config. We verify it does not
	// return an error (it either finds a system config or creates one).
	//
	// The created config goes under $HOME/.config/softhsm2, and the function
	// exports SOFTHSM2_CONF as a side effect, so this needs its own home:
	// without one it wrote the developer's real directory and left the
	// variable pointing there for every test that ran afterwards.
	// isolateHome claims both, and t.Setenv restores the variable whatever
	// production did to it.
	isolateHome(t)

	svc := &PKCS11Service{
		log: testLogger(),
	}
	// This will either find a system config or create a user config.
	// Either way it should not return an error on a normal system.
	err := svc.ensureSoftHSM2Config()
	assert.NoError(t, err)
}
