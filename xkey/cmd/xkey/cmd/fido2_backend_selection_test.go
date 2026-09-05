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

package cmd

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The set of backend names FIDO2Config.Validate accepts. createFIDO2KeyBackend
// must have a case for each and must refuse everything else: the two switches
// live in different functions over the same enum, and a name added to one but
// not the other used to mean "software keys" rather than "unknown backend"
// (#313).
var fido2ValidBackends = []string{"software", "tpm2", "phone"}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCreateFIDO2KeyBackend_RefusesUnknownBackend(t *testing.T) {
	// The regression guard. The default branch previously returned software
	// keys, silently downgrading key custody for any unrecognised name.
	for _, name := range []string{"bogus", "", "SOFTWARE", "yubikey", "tpm"} {
		t.Run(name, func(t *testing.T) {
			backend, err := createFIDO2KeyBackend(&FIDO2Config{Backend: name}, discardLogger())

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrFIDO2InvalidBackend)
			assert.Nil(t, backend, "no backend may be handed back with an error")
		})
	}
}

func TestFIDO2ConfigValidate_RejectsExactlyWhatTheBackendFactoryRejects(t *testing.T) {
	// Pins the two switches together. If someone teaches Validate a new backend
	// name without teaching createFIDO2KeyBackend the same name, this fails.
	for _, name := range fido2ValidBackends {
		cfg := &FIDO2Config{
			StorageType:       FIDO2StorageTypeMemory,
			Backend:           name,
			AttestationFormat: "none",
		}
		if name == "tpm2" {
			cfg.AttestationFormat = "none"
		}
		require.NoError(t, cfg.Validate(), "Validate must accept %q", name)

		// The factory must not answer a Validate-accepted name with
		// ErrFIDO2InvalidBackend. Construction may still fail for a host
		// reason (no TPM, no paired phone); only the classification matters.
		_, err := createFIDO2KeyBackend(cfg, discardLogger())
		assert.NotErrorIs(t, err, ErrFIDO2InvalidBackend,
			"createFIDO2KeyBackend has no case for the Validate-accepted name %q", name)
	}

	for _, name := range []string{"bogus", "", "yubikey"} {
		cfg := &FIDO2Config{
			StorageType:       FIDO2StorageTypeMemory,
			Backend:           name,
			AttestationFormat: "none",
		}
		assert.ErrorIs(t, cfg.Validate(), ErrFIDO2InvalidBackend,
			"Validate must reject %q", name)
	}
}

func TestCreateFIDO2KeyBackend_AcceptsSoftware(t *testing.T) {
	// The positive control: without it the refusal test above would still pass
	// if the factory refused every name.
	backend, err := createFIDO2KeyBackend(&FIDO2Config{
		StorageType: FIDO2StorageTypeMemory,
		Backend:     "software",
	}, discardLogger())

	require.NoError(t, err)
	assert.NotNil(t, backend)
}
