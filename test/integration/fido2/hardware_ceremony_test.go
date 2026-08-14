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

//go:build integration && fido2 && yubikey_hardware

// The ceremonies in this file require a REAL, physically attached CTAP2
// authenticator (a YubiKey or equivalent) and a human present to touch it.
// There is no honest software substitute: the point of the test is that the
// attestation and assertion signatures come from real secure-element hardware.
//
// The yubikey_hardware build tag EXCLUDES the file from every other build,
// matching pkg/backend/pkcs11/yubikey_integration_test.go. That is deliberate:
// a runtime skip would have let an unattended run print "ok" for hardware
// coverage that never happened. Without the tag these tests do not exist; with
// the tag they run and a missing authenticator is a failure.

package fido2

import (
	"testing"
)

// TestFIDO2Registration_HardwareYubiKey_EndToEnd runs the identical end-to-end
// ceremony against a REAL hardware authenticator (e.g. a YubiKey). The
// yubikey_hardware build tag keeps it out of every run that has no physical key
// attached, so an unattended run never reports hardware coverage it did not
// obtain.
//
// Run manually, with a key plugged in, ready to touch it:
//
//	make integration-test-fido2-hardware
func TestFIDO2Registration_HardwareYubiKey_EndToEnd(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	handler := cfg.CreateHandler(t)

	surface := newCeremonySurface(t)
	username := GenerateUniqueUsername("fido2-reg-hw")

	t.Log("Hardware authenticator registration: please touch your security key when prompted")
	runRegistrationCeremony(t, surface, handler, username)
}

// TestFIDO2Authentication_HardwareYubiKey_EndToEnd runs the identical end-to-end
// register-then-authenticate ceremony against a REAL hardware authenticator
// (e.g. a YubiKey). The yubikey_hardware build tag keeps it out of every run
// that has no physical key attached, so an unattended run never reports hardware
// coverage it did not obtain.
//
// Run manually, with a key plugged in, ready to touch it:
//
//	make integration-test-fido2-hardware
func TestFIDO2Authentication_HardwareYubiKey_EndToEnd(t *testing.T) {
	cfg := LoadFIDO2TestConfig()
	handler := cfg.CreateHandler(t)
	defer CleanupCredential(t, handler)

	surface := newCeremonySurface(t)
	username := GenerateUniqueUsername("fido2-auth-hw")

	t.Log("Hardware authenticator register+authenticate: please touch your security key when prompted")
	runRegistrationCeremony(t, surface, handler, username)
	runAuthenticationCeremony(t, surface, handler, username)
}
