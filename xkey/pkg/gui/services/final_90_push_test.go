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
	"encoding/base64"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	pkcs11svc "github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
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
	orig := os.Getenv("SOFTHSM2_CONF")
	t.Cleanup(func() {
		if orig == "" {
			os.Unsetenv("SOFTHSM2_CONF")
		} else {
			os.Setenv("SOFTHSM2_CONF", orig)
		}
	})

	os.Unsetenv("SOFTHSM2_CONF")

	svc := &PKCS11Service{
		log: testLogger(),
	}
	// This will either find a system config or create a user config.
	// Either way it should not return an error on a normal system.
	err := svc.ensureSoftHSM2Config()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// PKCS11IPCHandler: Sign with invalid base64 (transport non-nil)
// ---------------------------------------------------------------------------

func TestFinal90Push_HandlePKCS11Sign_InvalidBase64(t *testing.T) {
	// Create handler with a non-nil transport so we pass the nil-transport
	// guard and reach the base64 decode path.
	transport := &pkcs11svc.EmbeddedTransport{}
	handler := NewPKCS11IPCHandler(transport, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11Sign(&ipc.SignParams{
		Backend: "software",
		KeyID:   "test-key",
		Data:    "!!!not-valid-base64!!!",
	})

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
	assert.Contains(t, err.Error(), "failed to decode sign data")
}

func TestFinal90Push_HandlePKCS11Sign_ValidBase64_TransportFails(t *testing.T) {
	// Valid base64 but the EmbeddedTransport.Sign will fail because
	// xkms is not initialized in unit tests. This covers lines 69-78.
	transport := &pkcs11svc.EmbeddedTransport{}
	handler := NewPKCS11IPCHandler(transport, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11Sign(&ipc.SignParams{
		Backend: "software",
		KeyID:   "test-key",
		Data:    base64.StdEncoding.EncodeToString([]byte("hello")),
		Hash:    "SHA-256",
	})

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
}

// ---------------------------------------------------------------------------
// PKCS11IPCHandler: GetPIVCertificate with non-nil transport
// ---------------------------------------------------------------------------

func TestFinal90Push_HandlePKCS11GetPIVCertificate_EmptyFormat_Defaults(t *testing.T) {
	// Exercises the format-defaulting branch (line 96-98) and then the
	// transport call which fails because xkms is not initialized.
	transport := &pkcs11svc.EmbeddedTransport{}
	handler := NewPKCS11IPCHandler(transport, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11GetPIVCertificate(&ipc.PIVCertParams{
		Backend: "software",
		Slot:    "9a",
		Format:  "", // should default to "pem"
	})

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
}

func TestFinal90Push_HandlePKCS11GetPIVCertificate_ExplicitFormat(t *testing.T) {
	// Exercises the path where format is already set (skips default).
	transport := &pkcs11svc.EmbeddedTransport{}
	handler := NewPKCS11IPCHandler(transport, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11GetPIVCertificate(&ipc.PIVCertParams{
		Backend: "software",
		Slot:    "9c",
		Format:  "der",
	})

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
}

// ---------------------------------------------------------------------------
// PKCS11IPCHandler: ListPIVSlots with non-nil transport
// ---------------------------------------------------------------------------

func TestFinal90Push_HandlePKCS11ListPIVSlots_TransportFails(t *testing.T) {
	// Exercises the transport.ListPIVSlots call path which fails because
	// xkms is not initialized. Covers lines 125-131.
	transport := &pkcs11svc.EmbeddedTransport{}
	handler := NewPKCS11IPCHandler(transport, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11ListPIVSlots(&ipc.PIVSlotsParams{
		Backend: "software",
	})

	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
}
