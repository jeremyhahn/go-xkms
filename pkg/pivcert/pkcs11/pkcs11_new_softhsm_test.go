// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	p11 "github.com/miekg/pkcs11"
)

// newTestCertificate builds a minimal self-signed certificate for Store/
// Retrieve round-trip tests; its content is not under test here, only that
// it survives the PKCS#11 round trip byte-for-byte.
func newTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert
}

// newTestPIN wraps a plaintext PIN in a *secure.Secret the way production
// configuration does, for PKCS11StorageConfig.PIN/SOPIN.
func newTestPIN(t *testing.T, pin string) *secure.Secret {
	t.Helper()
	sec, err := secure.NewSecret([]byte(pin))
	if err != nil {
		t.Fatalf("secure.NewSecret() error = %v", err)
	}
	return sec
}

// TestNew_SoftHSMRoundTrip drives New (and therefore acquireModule,
// resolveSlot, newSessionPool and Close/releaseModule, none of which any
// other test in this package reaches: they all go through NewFromSession or
// a mock hardware.HardwareCertStorage) against a real, test-isolated
// SoftHSM2 token, proving the full production construction path works and
// that a certificate genuinely round-trips through it.
func TestNew_SoftHSMRoundTrip(t *testing.T) {
	tok := softhsmtest.Provision(t, "new-roundtrip-token")

	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SlotID:      -1,
	}

	s, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if s.Type() != pivcert.StorageTypePKCS11 {
		t.Errorf("Type() = %v, want %v", s.Type(), pivcert.StorageTypePKCS11)
	}

	cert := newTestCertificate(t, "New() SoftHSM round trip")
	if err := s.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	got, err := s.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !got.Equal(cert) {
		t.Error("Retrieve() returned a certificate that does not match what Store() saved")
	}

	if err := s.Delete(pivcert.PIVSlotAuthentication); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := s.Retrieve(pivcert.PIVSlotAuthentication); err == nil {
		t.Error("Retrieve() after Delete() expected an error, got nil")
	}
}

// TestNew_ModuleRefCounting proves acquireModule/releaseModule's reference
// counting: two storages opened against the same library path share one
// C_Initialize, and closing one must not invalidate sessions held by the
// other -- only the last Close finalizes the library.
func TestNew_ModuleRefCounting(t *testing.T) {
	tok := softhsmtest.Provision(t, "refcount-token")

	newStorage := func() *PKCS11CertStorage {
		t.Helper()
		s, err := New(&pivcert.PKCS11StorageConfig{
			LibraryPath: tok.Library,
			TokenLabel:  tok.Label,
			PIN:         newTestPIN(t, tok.UserPIN),
			SlotID:      -1,
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		return s
	}

	first := newStorage()
	second := newStorage()

	// Closing the first storage must not break the second's session pool,
	// since the library is still referenced by the second.
	if err := first.Close(); err != nil {
		t.Fatalf("first.Close() error = %v", err)
	}

	cert := newTestCertificate(t, "still alive after first Close")
	if err := second.Store(pivcert.PIVSlotDigitalSignature, cert); err != nil {
		t.Fatalf("second.Store() after first.Close() error = %v", err)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("second.Close() error = %v", err)
	}
}

// TestNew_RequireSO proves New's RequireSO branch (SO PIN plumbed through to
// hardware.NewPKCS11CertStorageWithSO for tokens whose certificate deletes
// require CKU_SO elevation) against a real SO-provisioned SoftHSM token.
func TestNew_RequireSO(t *testing.T) {
	tok := softhsmtest.Provision(t, "require-so-token")

	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SOPIN:       newTestPIN(t, tok.SOPIN),
		RequireSO:   true,
		SlotID:      -1,
	}

	s, err := New(config)
	if err != nil {
		t.Fatalf("New() with RequireSO error = %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	cert := newTestCertificate(t, "RequireSO round trip")
	if err := s.Store(pivcert.PIVSlotKeyManagement, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if _, err := s.Retrieve(pivcert.PIVSlotKeyManagement); err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
}

// TestNew_WrongLibraryPath proves New's acquireModule failure path (a
// library path that does not resolve to a loadable PKCS#11 module) surfaces
// a typed error instead of panicking.
func TestNew_WrongLibraryPath(t *testing.T) {
	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: "/nonexistent/libsofthsm2.so",
		TokenLabel:  "does-not-matter",
	}
	if _, err := New(config); err == nil {
		t.Error("New() expected error for a library path that cannot be loaded, got nil")
	}
}

// TestNew_UnknownTokenLabel proves New's resolveSlot failure path (a token
// label that does not exist on the module) releases the module reference
// and surfaces a typed error rather than leaking the reference.
func TestNew_UnknownTokenLabel(t *testing.T) {
	tok := softhsmtest.Provision(t, "unknown-label-token")

	config := &pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  "this-token-label-does-not-exist",
		PIN:         newTestPIN(t, tok.UserPIN),
		SlotID:      -1,
	}
	if _, err := New(config); err == nil {
		t.Error("New() expected error for an unknown token label, got nil")
	}

	// The failed New() above must have released its module reference; a
	// fresh New() against the real label must still succeed.
	s, err := New(&pivcert.PKCS11StorageConfig{
		LibraryPath: tok.Library,
		TokenLabel:  tok.Label,
		PIN:         newTestPIN(t, tok.UserPIN),
		SlotID:      -1,
	})
	if err != nil {
		t.Fatalf("New() after a failed New() on the same library error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// newTestSession provisions a fresh SoftHSM2 token, initializes and logs
// into a context/session pair the caller owns, and registers cleanup to log
// out, close the session and finalize the context -- the raw ctx+session
// lifecycle NewFromSession/NewFromSessionWithSO are for, as opposed to New's
// self-managed acquireModule/session-pool lifecycle.
func newTestSession(t *testing.T, label string) (tok softhsmtest.Token, ctx *p11.Ctx, session p11.SessionHandle, slotID uint) {
	t.Helper()

	tok = softhsmtest.Provision(t, label)

	ctx = p11.New(tok.Library)
	if ctx == nil {
		t.Fatalf("p11.New(%q) returned nil", tok.Library)
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("ctx.Initialize() error = %v", err)
	}
	t.Cleanup(func() {
		_ = ctx.Finalize()
		ctx.Destroy()
	})

	slotID = tok.Slot(t, ctx)

	sess, err := ctx.OpenSession(slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("ctx.OpenSession() error = %v", err)
	}
	t.Cleanup(func() { _ = ctx.CloseSession(sess) })

	if err := ctx.Login(sess, p11.CKU_USER, tok.UserPIN); err != nil {
		t.Fatalf("ctx.Login() error = %v", err)
	}
	t.Cleanup(func() { _ = ctx.Logout(sess) })

	return tok, ctx, sess, slotID
}

// TestNewFromSession_SoftHSMRoundTrip drives NewFromSession, and therefore
// singleSessionProvider's WithSession/Ctx/SlotID, against a real session on
// a test-isolated SoftHSM2 token -- the raw ctx+session reuse path callers
// take when a module/session is already managed elsewhere (e.g. the backend
// or module manager), which no other test in this package reaches.
func TestNewFromSession_SoftHSMRoundTrip(t *testing.T) {
	_, ctx, session, slotID := newTestSession(t, "newfromsession-token")

	s, err := NewFromSession(ctx, session, slotID)
	if err != nil {
		t.Fatalf("NewFromSession() error = %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	cert := newTestCertificate(t, "NewFromSession round trip")
	if err := s.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	got, err := s.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !got.Equal(cert) {
		t.Error("Retrieve() returned a certificate that does not match what Store() saved")
	}
}

// TestNewFromSessionWithSO_SoftHSMRoundTrip drives NewFromSessionWithSO, and
// therefore singleSessionProvider's WithSOSession, against a real session:
// Delete under RequireSO elevates to CKU_SO for the destroy and restores
// CKU_USER afterward, which TestNewFromSession_SoftHSMRoundTrip's plain
// CKU_USER session never exercises.
func TestNewFromSessionWithSO_SoftHSMRoundTrip(t *testing.T) {
	tok, ctx, session, slotID := newTestSession(t, "newfromsessionwithso-token")

	s, err := NewFromSessionWithSO(ctx, session, slotID, tok.SOPIN, tok.UserPIN)
	if err != nil {
		t.Fatalf("NewFromSessionWithSO() error = %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	cert := newTestCertificate(t, "NewFromSessionWithSO round trip")
	if err := s.Store(pivcert.PIVSlotDigitalSignature, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if err := s.Delete(pivcert.PIVSlotDigitalSignature); err != nil {
		t.Fatalf("Delete() (requires SO elevation) error = %v", err)
	}
	if _, err := s.Retrieve(pivcert.PIVSlotDigitalSignature); err == nil {
		t.Error("Retrieve() after SO-elevated Delete() expected an error, got nil")
	}
}

// TestSingleSessionProvider_Accessors proves singleSessionProvider's Ctx and
// SlotID getters return exactly the values it was constructed with -- the
// contract hardware.PKCS11SessionProvider callers rely on to resolve which
// context and slot a session belongs to.
func TestSingleSessionProvider_Accessors(t *testing.T) {
	_, ctx, session, slotID := newTestSession(t, "single-provider-accessors")

	p := &singleSessionProvider{ctx: ctx, session: session, slotID: slotID}

	if p.Ctx() != ctx {
		t.Error("Ctx() did not return the exact ctx the provider was constructed with")
	}
	if p.SlotID() != slotID {
		t.Errorf("SlotID() = %d, want %d", p.SlotID(), slotID)
	}
}

// TestStandalonePool_SlotID proves standalonePool.SlotID returns the slot ID
// the pool was created against.
func TestStandalonePool_SlotID(t *testing.T) {
	_, ctx, _, slotID := newTestSession(t, "standalone-pool-slotid")

	pool, err := newSessionPool(ctx, slotID, nil, 1)
	if err != nil {
		t.Fatalf("newSessionPool() error = %v", err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Errorf("pool.Close() error = %v", err)
		}
	}()

	if pool.SlotID() != slotID {
		t.Errorf("SlotID() = %d, want %d", pool.SlotID(), slotID)
	}
}

// TestNewFromPool_SoftHSMRoundTrip drives NewFromPool against a real
// session pool, the path callers take when a pool is already managed
// elsewhere (e.g. an HSM backend sharing one pool across several storage
// wrappers), which no other test in this package reaches.
func TestNewFromPool_SoftHSMRoundTrip(t *testing.T) {
	_, ctx, _, slotID := newTestSession(t, "newfrompool-token")

	pool, err := newSessionPool(ctx, slotID, nil, 2)
	if err != nil {
		t.Fatalf("newSessionPool() error = %v", err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Errorf("pool.Close() error = %v", err)
		}
	}()

	s, err := NewFromPool(pool, "")
	if err != nil {
		t.Fatalf("NewFromPool() error = %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	cert := newTestCertificate(t, "NewFromPool round trip")
	if err := s.Store(pivcert.PIVSlotCardAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	got, err := s.Retrieve(pivcert.PIVSlotCardAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !got.Equal(cert) {
		t.Error("Retrieve() returned a certificate that does not match what Store() saved")
	}
}

// TestResolveSlot_EmptyTokenLabelUsesFirstSlot proves resolveSlot falls
// back to the first available slot when TokenLabel is empty (SlotID
// unset via -1), rather than erroring or requiring a label.
func TestResolveSlot_EmptyTokenLabelUsesFirstSlot(t *testing.T) {
	tok := softhsmtest.Provision(t, "empty-label-token")

	ctx := p11.New(tok.Library)
	if ctx == nil {
		t.Fatalf("p11.New(%q) returned nil", tok.Library)
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("ctx.Initialize() error = %v", err)
	}
	defer func() {
		_ = ctx.Finalize()
		ctx.Destroy()
	}()

	slot, err := resolveSlot(ctx, &pivcert.PKCS11StorageConfig{SlotID: -1})
	if err != nil {
		t.Fatalf("resolveSlot() error = %v", err)
	}

	want := tok.Slot(t, ctx)
	if slot != want {
		t.Errorf("resolveSlot() = %d, want %d (the provisioned token's slot)", slot, want)
	}
}
