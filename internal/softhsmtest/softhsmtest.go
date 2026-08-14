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

//go:build pkcs11

// Package softhsmtest provisions a private, fully initialized SoftHSM2 token
// for tests that need a real PKCS#11 device.
//
// Every token lives inside t.TempDir() and SOFTHSM2_CONF is redirected there
// for the duration of the test, so the host's own SoftHSM token store is never
// read, written, or otherwise disturbed. Nothing here shells out: the token is
// initialized through the PKCS#11 API itself, so no softhsm2-util binary is
// required.
//
// Tests use this instead of guarding on a pre-provisioned host token. The
// pkcs11 build tag is only used in environments where SoftHSM2 is a declared
// dependency (the devcontainer and CI), so a missing library is a hard failure
// rather than a reason to skip.
package softhsmtest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/pkcs11"
)

// Standard credentials for provisioned test tokens. They are fixed so that a
// test can hand them to a backend configuration without threading them
// through every helper.
const (
	// SOPIN is the security officer PIN of every provisioned token.
	SOPIN = "87654321"

	// UserPIN is the normal user PIN of every provisioned token.
	UserPIN = "1234"
)

// libraryCandidates lists the paths SoftHSM2 is installed to across the
// distributions this project builds on.
var libraryCandidates = []string{
	"/usr/lib/softhsm/libsofthsm2.so",
	"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	"/usr/lib64/softhsm/libsofthsm2.so",
	"/usr/local/lib/softhsm/libsofthsm2.so",
	"/opt/homebrew/lib/softhsm/libsofthsm2.so",
}

// Token describes a provisioned SoftHSM2 token.
type Token struct {
	// Library is the absolute path of libsofthsm2.so.
	Library string

	// Label is the token label, unique per test.
	Label string

	// SOPIN and UserPIN are the token's credentials.
	SOPIN   string
	UserPIN string
}

// Library returns the path of libsofthsm2.so, failing the test when SoftHSM2
// is not installed.
func Library(t *testing.T) string {
	t.Helper()

	if env := os.Getenv("SOFTHSM2_LIB"); env != "" {
		if isFile(env) {
			return env
		}
		t.Fatalf("softhsmtest: SOFTHSM2_LIB=%s does not point at a file", env)
	}

	for _, candidate := range libraryCandidates {
		if isFile(candidate) {
			return candidate
		}
	}

	t.Fatalf("softhsmtest: libsofthsm2.so not found in %v; install softhsm2 or set SOFTHSM2_LIB", libraryCandidates)
	return ""
}

// Provision creates an isolated SoftHSM2 token store under t.TempDir(),
// redirects SOFTHSM2_CONF at it, and initializes a token with the given label
// so it is immediately usable for key generation.
//
// Because it calls t.Setenv, a test using this helper cannot call t.Parallel.
func Provision(t *testing.T, label string) Token {
	t.Helper()

	lib := Library(t)

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	if err := os.Mkdir(tokenDir, 0o750); err != nil {
		t.Fatalf("softhsmtest: creating token directory: %v", err)
	}

	conf := filepath.Join(root, "softhsm2.conf")
	contents := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
		tokenDir)
	if err := os.WriteFile(conf, []byte(contents), 0o600); err != nil {
		t.Fatalf("softhsmtest: writing softhsm2.conf: %v", err)
	}

	// t.Setenv restores the previous value when the test ends, so the host
	// configuration is left exactly as it was found.
	t.Setenv("SOFTHSM2_CONF", conf)

	initializeToken(t, lib, label)

	return Token{
		Library: lib,
		Label:   label,
		SOPIN:   SOPIN,
		UserPIN: UserPIN,
	}
}

// Slot resolves the slot the token currently occupies in the given context.
//
// SoftHSM2 assigns a fresh, randomized slot ID to an initialized token, and
// that ID is only observable after the context that will use it has run
// C_Initialize. Callers must therefore resolve the slot through their own
// context rather than caching an ID from provisioning time.
func (tok Token) Slot(t *testing.T, ctx *pkcs11.Ctx) uint {
	t.Helper()
	return findSlotByLabel(t, ctx, tok.Label)
}

// initializeToken runs C_InitToken and C_InitPIN against the first free slot.
func initializeToken(t *testing.T, lib, label string) {
	t.Helper()

	ctx := pkcs11.New(lib)
	if ctx == nil {
		t.Fatalf("softhsmtest: pkcs11.New(%q) returned nil", lib)
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		t.Fatalf("softhsmtest: C_Initialize: %v", err)
	}
	defer func() {
		if err := ctx.Finalize(); err != nil {
			t.Errorf("softhsmtest: C_Finalize: %v", err)
		}
	}()

	slots, err := ctx.GetSlotList(false)
	if err != nil {
		t.Fatalf("softhsmtest: C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("softhsmtest: SoftHSM2 reported no slots")
	}

	// SoftHSM always exposes one uninitialized slot at the end of the list.
	// Initializing it moves the token into a fresh slot ID.
	free := slots[len(slots)-1]
	if err := ctx.InitToken(free, SOPIN, label); err != nil {
		t.Fatalf("softhsmtest: C_InitToken: %v", err)
	}

	slot := findSlotByLabel(t, ctx, label)

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("softhsmtest: C_OpenSession: %v", err)
	}
	defer func() {
		if err := ctx.CloseSession(session); err != nil {
			t.Errorf("softhsmtest: C_CloseSession: %v", err)
		}
	}()

	if err := ctx.Login(session, pkcs11.CKU_SO, SOPIN); err != nil {
		t.Fatalf("softhsmtest: C_Login(SO): %v", err)
	}
	if err := ctx.InitPIN(session, UserPIN); err != nil {
		t.Fatalf("softhsmtest: C_InitPIN: %v", err)
	}
	if err := ctx.Logout(session); err != nil {
		t.Fatalf("softhsmtest: C_Logout: %v", err)
	}
}

// findSlotByLabel locates the slot holding the token with the given label.
func findSlotByLabel(t *testing.T, ctx *pkcs11.Ctx, label string) uint {
	t.Helper()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf("softhsmtest: C_GetSlotList(tokenPresent): %v", err)
	}

	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if trimLabel(info.Label) == label {
			return slot
		}
	}

	t.Fatalf("softhsmtest: no slot holds token %q after C_InitToken", label)
	return 0
}

// trimLabel strips the space padding PKCS#11 applies to fixed-width labels.
func trimLabel(label string) string {
	for len(label) > 0 && label[len(label)-1] == ' ' {
		label = label[:len(label)-1]
	}
	return label
}

// isFile reports whether path exists and is a regular file.
func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
