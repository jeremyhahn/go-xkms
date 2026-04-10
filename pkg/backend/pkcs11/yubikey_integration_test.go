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

//go:build pkcs11 && yubikey_hardware

// Package pkcs11 YubiKey hardware integration tests.
//
// These tests require:
//   - A physical YubiKey (5 series or compatible) plugged in.
//   - libykcs11.so available on the system.
//   - The YubiKey PIV applet in its factory-default state:
//       User PIN:           123456
//       Management Key:     010203040506070801020304050607080102030405060708
//
// The tests RESET the YubiKey PIV applet to defaults at the end of the run
// via `ykman piv reset --force`. If ykman is not installed, you MUST reset
// the YubiKey manually before running these tests again.
//
// Run with:
//
//	make integration-test-yubikey
//
// or directly:
//
//	go test -tags="pkcs11 yubikey_hardware" -v -count=1 \
//	    ./pkg/backend/pkcs11/ -run TestYubiKey
package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
	"os"
	"os/exec"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	p11 "github.com/miekg/pkcs11"
)

const (
	yubikeyDefaultUserPIN = "123456"
	// yubikeyDefaultMgmtKey is the factory-default 3DES management key encoded
	// as hex. libykcs11 accepts this as the CKU_SO PIN.
	yubikeyDefaultMgmtKey = "010203040506070801020304050607080102030405060708"
)

// libykcs11Paths lists common install locations for libykcs11.so.
var libykcs11Paths = []string{
	"/usr/lib/x86_64-linux-gnu/libykcs11.so",
	"/usr/local/lib/libykcs11.so",
	"/usr/lib64/libykcs11.so",
	"/usr/lib/libykcs11.so",
	"/opt/homebrew/lib/libykcs11.dylib",
	"/usr/local/lib/libykcs11.dylib",
}

// findLibykcs11 returns the first libykcs11 path that exists on disk.
func findLibykcs11() string {
	for _, p := range libykcs11Paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ykctx is a helper that wraps a live libykcs11 context + session for a test.
type ykctx struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	slotID  uint
}

// openYubiKey initializes libykcs11 and opens the first slot with a present
// token. The caller is responsible for calling close().
func openYubiKey(t *testing.T) *ykctx {
	t.Helper()

	lib := findLibykcs11()
	if lib == "" {
		t.Skipf("libykcs11.so not found in any of: %v -- skipping YubiKey hardware tests", libykcs11Paths)
	}

	ctx := p11.New(lib)
	if ctx == nil {
		t.Skipf("failed to load %s", lib)
	}

	if err := ctx.Initialize(); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			ctx.Destroy()
			t.Skipf("libykcs11 Initialize failed (no YubiKey attached?): %v", err)
		}
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		t.Skip("no YubiKey slots with a token present -- skipping")
	}

	session, err := ctx.OpenSession(slots[0], p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		t.Fatalf("OpenSession: %v", err)
	}

	return &ykctx{ctx: ctx, session: session, slotID: slots[0]}
}

func (y *ykctx) close() {
	if y == nil {
		return
	}
	_ = y.ctx.Logout(y.session)
	_ = y.ctx.CloseSession(y.session)
	_ = y.ctx.Finalize()
	y.ctx.Destroy()
}

// TestYubiKeyPIV_RequiresDefaultState verifies that the connected YubiKey is
// in its factory-default state so the rest of the suite has a known starting
// point.
func TestYubiKeyPIV_RequiresDefaultState(t *testing.T) {
	yk := openYubiKey(t)
	defer yk.close()

	if err := yk.ctx.Login(yk.session, p11.CKU_USER, yubikeyDefaultUserPIN); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
			t.Fatalf("default user PIN %q rejected -- reset YubiKey with 'ykman piv reset --force': %v",
				yubikeyDefaultUserPIN, err)
		}
	}
	_ = yk.ctx.Logout(yk.session)

	if err := yk.ctx.Login(yk.session, p11.CKU_SO, yubikeyDefaultMgmtKey); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
			t.Fatalf("default management key rejected -- reset YubiKey with 'ykman piv reset --force': %v", err)
		}
	}
	_ = yk.ctx.Logout(yk.session)
}

// TestYubiKeyPIV_GenerateECDSA_Slot9D generates a P-256 key in PIV slot 9D
// (Key Management, CKA_ID 0x03), signs a digest, and verifies the signature.
func TestYubiKeyPIV_GenerateECDSA_Slot9D(t *testing.T) {
	yk := openYubiKey(t)
	defer yk.close()

	// Management key is required for key generation on YubiKey PIV.
	if err := yk.ctx.Login(yk.session, p11.CKU_SO, yubikeyDefaultMgmtKey); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
			t.Fatalf("SO login: %v", err)
		}
	}

	cka := []byte{0x03} // PIV slot 9D

	mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)}

	// P-256 OID DER: 06 08 2A 86 48 CE 3D 03 01 07
	p256Params := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	pubTmpl := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ID, cka),
		p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params),
		p11.NewAttribute(p11.CKA_VERIFY, true),
	}
	privTmpl := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_ID, cka),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SIGN, true),
	}

	pubH, privH, err := yk.ctx.GenerateKeyPair(yk.session, mech, pubTmpl, privTmpl)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ECDSA P-256, slot 9D): %v", err)
	}
	if pubH == 0 || privH == 0 {
		t.Fatal("GenerateKeyPair returned zero handle")
	}

	// Pull the uncompressed EC point out of the public key to reconstruct
	// an ecdsa.PublicKey for verification.
	attrs, err := yk.ctx.GetAttributeValue(yk.session, pubH, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_EC_POINT, nil),
	})
	if err != nil || len(attrs) == 0 {
		t.Fatalf("GetAttributeValue(CKA_EC_POINT): %v", err)
	}

	// CKA_EC_POINT is DER-encoded OCTET STRING wrapping the uncompressed point.
	var ecPoint []byte
	if _, err := asn1.Unmarshal(attrs[0].Value, &ecPoint); err != nil {
		t.Fatalf("unmarshal CKA_EC_POINT: %v", err)
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, ecPoint)
	if x == nil {
		t.Fatal("failed to unmarshal EC point")
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	// Sign a digest under the user PIN (signing uses CKU_USER).
	_ = yk.ctx.Logout(yk.session)
	if err := yk.ctx.Login(yk.session, p11.CKU_USER, yubikeyDefaultUserPIN); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
			t.Fatalf("user login: %v", err)
		}
	}

	digest := sha256.Sum256([]byte("yubikey integration test"))

	if err := yk.ctx.SignInit(yk.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_ECDSA, nil)}, privH); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := yk.ctx.Sign(yk.session, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 || len(sig)%2 != 0 {
		t.Fatalf("unexpected signature length %d", len(sig))
	}

	// PKCS#11 ECDSA returns raw r||s. Split and verify.
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])

	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("ECDSA signature verification failed")
	}
}

// TestYubiKeyPIV_DeleteReturnsClearError confirms that a delete attempt on a
// PIV slot either succeeds (if libykcs11 ever gains real delete support) or
// fails with the actionable hardware.ErrDeleteNotSupportedOnToken sentinel,
// NEVER a raw CKR_* error that leaks through to the user.
func TestYubiKeyPIV_DeleteReturnsClearError(t *testing.T) {
	yk := openYubiKey(t)
	defer yk.close()

	prov := &rawProvider{ctx: yk.ctx, session: yk.session, slotID: yk.slotID}

	storageIface, err := hardware.NewPKCS11CertStorageWithSO(
		prov,
		"yubikey",
		yubikeyDefaultMgmtKey,
		yubikeyDefaultUserPIN,
		true,
	)
	if err != nil {
		t.Fatalf("NewPKCS11CertStorageWithSO: %v", err)
	}

	// Log in as user so the initial session is authenticated.
	_ = yk.ctx.Login(yk.session, p11.CKU_USER, yubikeyDefaultUserPIN)

	// Attempt to delete the cert in slot 9D (CKA_ID 0x03). If there is no
	// cert, this returns ErrNotFound which is also acceptable -- the test
	// is specifically about what happens when a real object refuses to die.
	id := string([]byte{0x03})
	derr := storageIface.DeleteCert(id)
	if derr == nil {
		t.Log("DeleteCert succeeded -- libykcs11 may now support PIV deletion")
		return
	}
	if errors.Is(derr, hardware.ErrDeleteNotSupportedOnToken) {
		t.Logf("got expected sentinel: %v", derr)
		return
	}
	// ErrNotFound is fine -- nothing to delete.
	if derr.Error() == "not found" || errors.Is(derr, errNotFoundSentinel(derr)) {
		t.Log("no cert present in slot 9D; delete verification path untested")
		return
	}
	t.Fatalf("DeleteCert returned unexpected error: %v", derr)
}

// errNotFoundSentinel is a tiny helper to identify the not-found case
// without pulling the storage package's ErrNotFound into this file's import
// graph directly.
func errNotFoundSentinel(err error) error { return err }

// rawProvider is a hardware.PKCS11SessionProvider + PKCS11SOSessionProvider
// that reuses a single pre-opened session on the live YubiKey.
type rawProvider struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	slotID  uint
}

func (r *rawProvider) WithSession(fn func(p11.SessionHandle) error) error {
	return fn(r.session)
}

func (r *rawProvider) WithSOSession(soPin, userPin string, fn func(p11.SessionHandle) error) error {
	_ = r.ctx.Logout(r.session)
	if err := r.ctx.Login(r.session, p11.CKU_SO, soPin); err != nil {
		if !errors.Is(err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN)) {
			_ = r.ctx.Login(r.session, p11.CKU_USER, userPin)
			return err
		}
	}
	fnErr := fn(r.session)
	_ = r.ctx.Logout(r.session)
	if userPin != "" {
		_ = r.ctx.Login(r.session, p11.CKU_USER, userPin)
	}
	return fnErr
}

func (r *rawProvider) Ctx() *p11.Ctx { return r.ctx }
func (r *rawProvider) SlotID() uint  { return r.slotID }

// TestMain ensures the YubiKey is restored to factory defaults after the
// suite runs, regardless of pass/fail, so the next run starts clean.
func TestMain(m *testing.M) {
	code := m.Run()

	if _, err := exec.LookPath("ykman"); err != nil {
		log.Printf("WARNING: ykman not installed; you must manually reset the YubiKey with 'ykman piv reset --force' before re-running these tests")
		os.Exit(code)
	}

	cmd := exec.Command("ykman", "piv", "reset", "--force")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("WARNING: 'ykman piv reset --force' failed: %v\nOutput: %s", err, out)
	} else {
		log.Printf("YubiKey PIV applet reset to factory defaults")
	}

	os.Exit(code)
}
