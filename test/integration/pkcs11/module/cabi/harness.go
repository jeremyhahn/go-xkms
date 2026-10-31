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

//go:build integration && pkcs11_cabi

package cabi

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"testing"
)

// modulePathEnv names the environment variable holding the shared object to
// load. The Makefile target sets it to the freshly built
// build/lib/libxkms_pkcs11.so.
const modulePathEnv = "PKCS11_MODULE"

// userPINEnv names the environment variable holding the user PIN.
const userPINEnv = "XKMS_PKCS11_USER_PIN"

// defaultUserPIN matches the PIN the Makefile provisions the test token with.
const defaultUserPIN = "87654321"

// soPINEnv names the environment variable holding the Security Officer PIN.
const soPINEnv = "XKMS_PKCS11_SO_PIN"

// defaultSOPIN matches the SO PIN the Makefile provisions the test token with.
const defaultSOPIN = "12345678"

var (
	// sharedOnce guards the one-time dlopen and C_Initialize. A PKCS#11 module
	// may be initialized once per process (v3.2 section 5.6), and the shared
	// object holds a second Go runtime, so loading it repeatedly is neither
	// permitted nor cheap.
	sharedOnce sync.Once
	// sharedModule is the loaded module, valid after sharedOnce has run.
	sharedModule *Module
	// sharedSlot is the first slot with a token present.
	sharedSlot uint
	// sharedErr records why loading failed, if it did.
	sharedErr error
)

// LoadShared returns the process-wide module, loading and initializing it on
// first use, together with the slot the tests operate on.
func LoadShared() (*Module, uint, error) {
	sharedOnce.Do(func() {
		path := os.Getenv(modulePathEnv)
		if path == "" {
			sharedErr = &ConfigError{
				Variable: modulePathEnv,
				Reason:   "not set; point it at the built libxkms_pkcs11.so",
			}
			return
		}
		if _, err := os.Stat(path); err != nil {
			sharedErr = &ConfigError{Variable: modulePathEnv, Reason: err.Error()}
			return
		}

		mod, err := Open(path)
		if err != nil {
			sharedErr = err
			return
		}

		// An already-initialized module is not an error for this suite: the
		// point is to reach a usable token, not to own the initialization.
		if err := mod.Initialize(); err != nil && RV(err) != CKR_CRYPTOKI_ALREADY_INITIALIZED {
			sharedErr = err
			return
		}

		slots, err := mod.SlotList()
		if err != nil {
			sharedErr = err
			return
		}
		if len(slots) == 0 {
			sharedErr = &LoadError{Path: path, Reason: "C_GetSlotList reported no slot with a token present"}
			return
		}

		sharedModule = mod
		sharedSlot = slots[0]
	})

	return sharedModule, sharedSlot, sharedErr
}

// Fixture is a logged-in read-write session with automatic cleanup of every
// object the test created.
type Fixture struct {
	// Module is the loaded shared object.
	Module *Module
	// Slot is the slot the session was opened on.
	Slot uint
	// Session is the logged-in read-write session.
	Session *Session

	t       *testing.T
	objects []uint
}

// NewFixture opens a logged-in read-write session for t and registers the
// teardown. A failure to reach the token fails the test rather than skipping
// it: this suite exists to exercise a real module against a real daemon, and a
// missing one is a broken environment, not a reason to report success.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()

	mod, slot, err := LoadShared()
	if err != nil {
		t.Fatalf("loading PKCS#11 module: %v", err)
	}

	session, err := mod.OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession on slot %d: %v", slot, err)
	}

	pin := os.Getenv(userPINEnv)
	if pin == "" {
		pin = defaultUserPIN
	}
	if err := session.Login(CKU_USER, pin); err != nil {
		if cerr := session.Close(); cerr != nil {
			t.Errorf("C_CloseSession after failed login: %v", cerr)
		}
		t.Fatalf("C_Login as CKU_USER: %v", err)
	}

	f := &Fixture{Module: mod, Slot: slot, Session: session, t: t}
	t.Cleanup(f.teardown)
	return f
}

// UserPIN returns the CKU_USER PIN the suite authenticates with, so a test that
// logs out to exercise a login gate can log back in before its teardown runs.
func UserPIN() string {
	if pin := os.Getenv(userPINEnv); pin != "" {
		return pin
	}
	return defaultUserPIN
}

// SOPIN returns the CKU_SO PIN, for a test that must set an attribute only the
// Security Officer may set, such as CKA_TRUSTED (v3.2 Table 13 footnote 10).
func SOPIN() string {
	if pin := os.Getenv(soPINEnv); pin != "" {
		return pin
	}
	return defaultSOPIN
}

// Track registers obj for destruction when the test finishes.
func (f *Fixture) Track(obj uint) uint {
	f.objects = append(f.objects, obj)
	return obj
}

// teardown destroys tracked objects and closes the session. Failures are
// reported rather than ignored, because a token that will not release its
// objects leaks state into the next test.
func (f *Fixture) teardown() {
	for i := len(f.objects) - 1; i >= 0; i-- {
		if err := f.Session.DestroyObject(f.objects[i]); err != nil {
			f.t.Errorf("C_DestroyObject(%d): %v", f.objects[i], err)
		}
	}
	if err := f.Session.Logout(); err != nil {
		f.t.Errorf("C_Logout: %v", err)
	}
	if err := f.Session.Close(); err != nil {
		f.t.Errorf("C_CloseSession: %v", err)
	}
}

// SupportsMechanism reports whether the slot advertises mechType in
// C_GetMechanismList.
func (f *Fixture) SupportsMechanism(mechType uint) bool {
	f.t.Helper()

	list, err := f.Module.MechanismList(f.Slot)
	if err != nil {
		f.t.Fatalf("C_GetMechanismList: %v", err)
	}
	for _, m := range list {
		if m == mechType {
			return true
		}
	}
	return false
}

// UniqueLabel returns a label unlikely to collide with objects left by other
// tests or earlier runs against the same persistent token.
func UniqueLabel(t *testing.T, prefix string) string {
	t.Helper()

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("generating a unique label: %v", err)
	}
	return fmt.Sprintf("%s-%x", prefix, suffix)
}
