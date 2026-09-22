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

//go:build integration && fips

// Package fips drives the built PKCS#11 shared library through
// github.com/miekg/pkcs11 to prove that FIPS mode is enforced the way it is
// advertised.
//
// The pre-existing FIPS coverage only proved the negative half of the claim --
// that a non-approved mechanism is withheld. The dangerous half is the other
// one: a FIPS build in which the approved mechanisms also stop working, or in
// which the advertised surface and the enforced surface drift apart. Every test
// here targets one of those two failures.
//
// The suite deliberately loads the .so rather than calling the Go API, because
// the drift these tests hunt for lives between the cgo entry points and the Go
// registry: a C application asking C_GetMechanismList sees whatever the slot
// manager holds, which is not necessarily what GetMechanismDescriptor will
// later agree to perform.
//
// # FIPS regime
//
// The module's policy switch is crypto/fips140.Enabled (go-xkms #21): true
// under GODEBUG=fips140=on|only at runtime, or in a binary built with an
// enabling GOFIPS140 build variable (which the toolchain restricts to
// {off, latest, inprocess, certified, v1.Y.Z}, and which has no effect set as
// a plain runtime environment variable -- only GODEBUG selects module state
// at runtime). This harness therefore drives the module through
// GODEBUG=fips140=on rather than GOFIPS140, which is the same signal every
// GODEBUG=fips140=on subprocess test elsewhere in this repository uses
// (pkg/crypto/aead, pkg/crypto/kdf, pkg/quantum/mlkem512, ...).
//
// TestMain re-executes the suite under GODEBUG=fips140=on rather than
// trusting the caller, so the suite cannot silently assert FIPS behaviour of
// a non-FIPS process. It never skips: a misinvocation is corrected, not
// excused.
package fips

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// envFIPS is the environment variable that selects FIPS mode: GODEBUG, read
// by crypto/fips140.Enabled. It is spelled out here rather than imported so
// that the test observes the module through the same signal a deployment
// uses.
const envFIPS = "GODEBUG"

// fipsRuntimeValue is the value TestMain sets when the caller did not select a
// regime: GODEBUG=fips140=on activates the Go Cryptographic Module for this
// process (and for the c-shared library it dlopen()s, whose own Go runtime
// reads the same environment at its own initialization) without requiring a
// GOFIPS140 build.
const fipsRuntimeValue = "fips140=on"

// envHelper marks a re-executed child process and names the job it should do.
// Its presence also suppresses the TestMain re-execution, so a child can never
// recurse.
const envHelper = "XKMS_FIPS_HELPER"

// helperDumpMechanisms is the envHelper value that asks a child to print the
// mechanism list it observes and exit.
const helperDumpMechanisms = "dump-mechanisms"

// dumpMarker prefixes the single line of JSON a helper child writes, so the
// parent can find it in among the testing package's own output.
const dumpMarker = "XKMS_FIPS_MECHANISM_DUMP "

// errNoDump reports that a helper child produced no dump line. It is a distinct
// type because "the child ran and said nothing" and "the child failed" call for
// different diagnosis, and collapsing them into one string loses that.
type errNoDump struct {
	output string
}

func (e *errNoDump) Error() string {
	return fmt.Sprintf("helper child produced no %q line; output was:\n%s", dumpMarker, e.output)
}

// errHelperFailed reports that a helper child exited non-zero.
type errHelperFailed struct {
	cause  error
	output string
}

func (e *errHelperFailed) Error() string {
	return fmt.Sprintf("helper child failed: %v; output was:\n%s", e.cause, e.output)
}

func (e *errHelperFailed) Unwrap() error { return e.cause }

// errModuleLoad reports that the shared library could not be loaded.
type errModuleLoad struct {
	path string
}

func (e *errModuleLoad) Error() string {
	return fmt.Sprintf("pkcs11.New(%q) returned nil: the shared library is missing or not loadable", e.path)
}

// mechanismRecord is one mechanism as a C application sees it: the type, and
// whatever C_GetMechanismInfo says about it. InfoError is non-empty when
// C_GetMechanismInfo refused a mechanism that C_GetMechanismList had just
// offered, which is itself a defect worth carrying across the process boundary.
type mechanismRecord struct {
	Mechanism  uint   `json:"mechanism"`
	MinKeySize uint   `json:"min_key_size"`
	MaxKeySize uint   `json:"max_key_size"`
	Flags      uint   `json:"flags"`
	InfoError  string `json:"info_error,omitempty"`
}

// mechanismDump is the whole observation a helper child reports back.
type mechanismDump struct {
	FIPSEnv    string            `json:"fips_env"`
	Mechanisms []mechanismRecord `json:"mechanisms"`
}

// types returns the mechanism types in the dump, in list order.
func (d *mechanismDump) types() []uint {
	out := make([]uint, 0, len(d.Mechanisms))
	for _, m := range d.Mechanisms {
		out = append(out, m.Mechanism)
	}
	return out
}

// set returns the dump's mechanism types as a set for membership tests.
func (d *mechanismDump) set() map[uint]mechanismRecord {
	out := make(map[uint]mechanismRecord, len(d.Mechanisms))
	for _, m := range d.Mechanisms {
		out[m.Mechanism] = m
	}
	return out
}

// TestMain guarantees the suite's own process is in FIPS mode before any test
// runs.
//
// Without this, running the suite without GODEBUG=fips140 set would exercise
// the non-FIPS module while every assertion claimed to be about FIPS, and the
// whole suite would pass green while proving nothing. Re-executing is not a
// skip: the tests still run, in the regime they describe.
//
// The check is for "fips140" specifically, not merely a non-empty GODEBUG:
// GODEBUG carries unrelated debug settings too (comma-separated), and a
// caller's GODEBUG set for some other reason must not be read as "a FIPS
// regime was explicitly selected".
func TestMain(m *testing.M) {
	if os.Getenv(envHelper) != "" || strings.Contains(os.Getenv(envFIPS), "fips140") {
		os.Exit(m.Run())
	}

	fmt.Printf("re-executing under %s=%s: the suite must not assert FIPS behaviour of a non-FIPS process\n",
		envFIPS, fipsRuntimeValue)

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), envFIPS+"="+fipsRuntimeValue)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "re-execution failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// modulePath returns the shared library under test.
func modulePath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("PKCS11_MODULE")
	if path == "" {
		t.Fatal("PKCS11_MODULE is unset: this suite tests the built .so as a C application sees it, " +
			"so there is nothing to test without it")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("PKCS11_MODULE=%q is not readable: %v", path, err)
	}
	return path
}

// userPIN returns the token's user PIN.
func userPIN(t *testing.T) string {
	t.Helper()
	pin := os.Getenv("XKMS_PKCS11_USER_PIN")
	if pin == "" {
		pin = os.Getenv("PKCS11_PIN")
	}
	if pin == "" {
		t.Fatal("no user PIN in XKMS_PKCS11_USER_PIN or PKCS11_PIN: every crypto operation " +
			"here runs on a login-required token, so an unauthenticated fixture would " +
			"prove nothing about the mechanisms")
	}
	return pin
}

// token is a loaded module with one logged-in read/write session.
type token struct {
	ctx     *pkcs11.Ctx
	slot    uint
	session pkcs11.SessionHandle
}

// openToken loads the shared library, opens a read/write session on the first
// slot with a token, and logs in as CKU_USER.
func openToken(t *testing.T) *token {
	t.Helper()

	path := modulePath(t)
	ctx := pkcs11.New(path)
	if ctx == nil {
		t.Fatal((&errModuleLoad{path: path}).Error())
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		t.Fatalf("C_Initialize: %v", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf("C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("C_GetSlotList returned no slot with a token present")
	}

	session, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("C_OpenSession: %v", err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, userPIN(t)); err != nil {
		t.Fatalf("C_Login(CKU_USER): %v", err)
	}

	tok := &token{ctx: ctx, slot: slots[0], session: session}
	t.Cleanup(tok.close)
	return tok
}

// close tears the session and the module down in PKCS#11 order.
func (tok *token) close() {
	if err := tok.ctx.Logout(tok.session); err != nil {
		fmt.Fprintf(os.Stderr, "C_Logout: %v\n", err)
	}
	if err := tok.ctx.CloseSession(tok.session); err != nil {
		fmt.Fprintf(os.Stderr, "C_CloseSession: %v\n", err)
	}
	if err := tok.ctx.Finalize(); err != nil {
		fmt.Fprintf(os.Stderr, "C_Finalize: %v\n", err)
	}
	tok.ctx.Destroy()
}

// collectMechanisms enumerates C_GetMechanismList and asks C_GetMechanismInfo
// about every entry, recording a refusal rather than failing on it so callers
// can assert on the contradiction directly.
func collectMechanisms(ctx *pkcs11.Ctx, slot uint) (*mechanismDump, error) {
	mechs, err := ctx.GetMechanismList(slot)
	if err != nil {
		return nil, fmt.Errorf("C_GetMechanismList: %w", err)
	}

	dump := &mechanismDump{
		FIPSEnv:    os.Getenv(envFIPS),
		Mechanisms: make([]mechanismRecord, 0, len(mechs)),
	}
	for _, m := range mechs {
		rec := mechanismRecord{Mechanism: m.Mechanism}
		info, infoErr := ctx.GetMechanismInfo(slot, []*pkcs11.Mechanism{m})
		if infoErr != nil {
			rec.InfoError = infoErr.Error()
		} else {
			rec.MinKeySize = info.MinKeySize
			rec.MaxKeySize = info.MaxKeySize
			rec.Flags = info.Flags
		}
		dump.Mechanisms = append(dump.Mechanisms, rec)
	}
	return dump, nil
}

// TestFIPSHelper_DumpMechanisms is the child half of the two-regime comparison.
//
// It is a test rather than a separate binary because the mechanism list must be
// observed by exactly the same code in both regimes; a hand-written second
// program would be free to drift. It runs its body only when the parent asked
// for it, so a normal run of the suite costs nothing.
func TestFIPSHelper_DumpMechanisms(t *testing.T) {
	if os.Getenv(envHelper) != helperDumpMechanisms {
		return
	}

	path := os.Getenv("PKCS11_MODULE")
	ctx := pkcs11.New(path)
	if ctx == nil {
		t.Fatal((&errModuleLoad{path: path}).Error())
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("C_Initialize: %v", err)
	}
	defer func() {
		if err := ctx.Finalize(); err != nil {
			t.Errorf("C_Finalize: %v", err)
		}
		ctx.Destroy()
	}()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatalf("C_GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("C_GetSlotList returned no slot with a token present")
	}

	dump, err := collectMechanisms(ctx, slots[0])
	if err != nil {
		t.Fatalf("collecting mechanisms: %v", err)
	}
	encoded, err := json.Marshal(dump)
	if err != nil {
		t.Fatalf("encoding dump: %v", err)
	}
	fmt.Println(dumpMarker + string(encoded))
}

// mechanismsInRegime re-executes this binary with the given GODEBUG value and
// returns the mechanism list that child observed.
//
// A child process is the only honest way to observe the other regime. The
// module reads crypto/fips140.Enabled, whose module state a c-shared library's
// own Go runtime resolves once, at the moment the dynamic loader initialises
// it, from the process environment at that instant -- so setting the variable
// in this process and re-opening the library does not change what the library
// sees, and a second dlopen of the same path returns the library that is
// already loaded in whatever mode it started in. A test that toggled the
// variable in-process would therefore report the current regime twice and
// call the filter proven.
func mechanismsInRegime(t *testing.T, fipsValue string) *mechanismDump {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSHelper_DumpMechanisms$", "-test.v")
	env := make([]string, 0, len(os.Environ())+3)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, envFIPS+"=") || strings.HasPrefix(kv, "XKMS_PKCS11_STORAGE_PATH=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, envHelper+"="+helperDumpMechanisms)
	env = append(env, "XKMS_PKCS11_STORAGE_PATH="+t.TempDir())
	if fipsValue != "" {
		env = append(env, envFIPS+"="+fipsValue)
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal((&errHelperFailed{cause: err, output: string(out)}).Error())
	}

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, dumpMarker) {
			continue
		}
		var dump mechanismDump
		if jsonErr := json.Unmarshal([]byte(strings.TrimPrefix(trimmed, dumpMarker)), &dump); jsonErr != nil {
			t.Fatalf("decoding helper dump: %v; line was %q", jsonErr, trimmed)
		}
		return &dump
	}
	t.Fatal((&errNoDump{output: string(out)}).Error())
	return nil
}

// ckrOf extracts the CKR_ value from a PKCS#11 error, reporting whether the
// error was a PKCS#11 error at all. Asserting on the CK_RV rather than on the
// error string is what makes "refused for the right reason" checkable.
func ckrOf(err error) (pkcs11.Error, bool) {
	var ckr pkcs11.Error
	if errors.As(err, &ckr) {
		return ckr, true
	}
	return 0, false
}

// isMechanismInvalid reports whether err is exactly CKR_MECHANISM_INVALID.
func isMechanismInvalid(err error) bool {
	ckr, ok := ckrOf(err)
	return ok && ckr == pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)
}
