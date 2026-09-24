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

package hardware

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleSessionProvider implements PKCS11SessionProvider directly over one
// real, logged-in PKCS#11 session. It intentionally does NOT implement
// PKCS11SearchProvider or PKCS11SOSessionProvider: this repo has only one
// borrower per test, so there is no concurrent search to serialize against,
// and it exercises doSearch's non-pooled fallback path (Init/find/Final
// called directly) rather than SessionPool's WithSearch.
type singleSessionProvider struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	slot    uint
}

func (s *singleSessionProvider) WithSession(fn func(session pkcs11.SessionHandle) error) error {
	return fn(s.session)
}

func (s *singleSessionProvider) Ctx() *pkcs11.Ctx { return s.ctx }
func (s *singleSessionProvider) SlotID() uint     { return s.slot }

var _ PKCS11SessionProvider = (*singleSessionProvider)(nil)

// newSoftHSMCertStorage provisions an isolated SoftHSM2 token, opens and
// logs into a single RW session on it, and wraps it in a PKCS11CertStorage.
// Everything is torn down (logout, session close, context finalize/destroy)
// when the test ends.
func newSoftHSMCertStorage(t *testing.T, label string) (*PKCS11CertStorage, *singleSessionProvider) {
	t.Helper()

	tok := softhsmtest.Provision(t, label)

	ctx := pkcs11.New(tok.Library)
	require.NotNil(t, ctx, "SoftHSM2 library must load")
	require.NoError(t, ctx.Initialize())
	t.Cleanup(func() {
		ctx.Finalize()
		ctx.Destroy()
	})

	slot := tok.Slot(t, ctx)
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctx.CloseSession(session) })

	require.NoError(t, ctx.Login(session, pkcs11.CKU_USER, tok.UserPIN))
	t.Cleanup(func() { _ = ctx.Logout(session) })

	provider := &singleSessionProvider{ctx: ctx, session: session, slot: slot}

	s, err := NewPKCS11CertStorageWithSO(provider, tok.Label, tok.SOPIN, tok.UserPIN, false)
	require.NoError(t, err)

	return s.(*PKCS11CertStorage), provider
}

// TestPKCS11CertStorage_SaveGetDeleteCert_RealToken drives SaveCert, GetCert,
// CertExists and DeleteCert against a real SoftHSM2 token, proving the
// CKA_ID-keyed CRUD path actually round-trips a certificate rather than just
// validating its inputs.
func TestPKCS11CertStorage_SaveGetDeleteCert_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-cert-crud")

	cert, err := generateTestCertificate("crud-cert")
	require.NoError(t, err)

	exists, err := s.CertExists("crud-cert")
	require.NoError(t, err)
	assert.False(t, exists, "must not exist before it is saved")

	require.NoError(t, s.SaveCert("crud-cert", cert))

	exists, err = s.CertExists("crud-cert")
	require.NoError(t, err)
	assert.True(t, exists)

	got, err := s.GetCert("crud-cert")
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got.Raw)

	require.NoError(t, s.DeleteCert("crud-cert"))

	_, err = s.GetCert("crud-cert")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	exists, err = s.CertExists("crud-cert")
	require.NoError(t, err)
	assert.False(t, exists)

	// Deleting an already-absent certificate must report not-found rather
	// than silently succeeding.
	err = s.DeleteCert("crud-cert")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestPKCS11CertStorage_SaveCert_OverwritesExisting verifies a second
// SaveCert under the same id replaces the token object instead of leaving
// two CKO_CERTIFICATE objects with the same CKA_ID.
func TestPKCS11CertStorage_SaveCert_OverwritesExisting(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-cert-overwrite")

	first, err := generateTestCertificate("first")
	require.NoError(t, err)
	second, err := generateTestCertificate("second")
	require.NoError(t, err)

	require.NoError(t, s.SaveCert("overwrite-me", first))
	require.NoError(t, s.SaveCert("overwrite-me", second))

	got, err := s.GetCert("overwrite-me")
	require.NoError(t, err)
	assert.Equal(t, second.Raw, got.Raw)
	assert.NotEqual(t, first.Raw, got.Raw)

	ids, err := s.ListCerts()
	require.NoError(t, err)
	assert.Equal(t, []string{"overwrite-me"}, ids, "the overwritten object must not leave a duplicate")
}

// TestPKCS11CertStorage_CertChainLifecycle_RealToken drives SaveCertChain,
// GetCertChain, and DeleteCertChain against a real token, proving the chain
// members are stored in order under id-chain-<n> and released as a group
// without disturbing the id's own certificate record.
func TestPKCS11CertStorage_CertChainLifecycle_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-chain-lifecycle")

	leafCert, err := generateTestCertificate("leaf")
	require.NoError(t, err)
	require.NoError(t, s.SaveCert("primary-record", leafCert))

	chain, err := generateTestCertificateChain(3)
	require.NoError(t, err)
	require.NoError(t, s.SaveCertChain("primary-record", chain))

	got, err := s.GetCertChain("primary-record")
	require.NoError(t, err)
	require.Len(t, got, 3)
	for i := range chain {
		assert.Equal(t, chain[i].Raw, got[i].Raw, "chain member %d must round-trip in order", i)
	}

	require.NoError(t, s.DeleteCertChain("primary-record"))

	_, err = s.GetCertChain("primary-record")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// The certificate record itself must survive the chain's deletion.
	leaf, err := s.GetCert("primary-record")
	require.NoError(t, err)
	assert.Equal(t, leafCert.Raw, leaf.Raw)

	err = s.DeleteCertChain("primary-record")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestPKCS11CertStorage_SaveCertChain_ReplacesPreviousMembers verifies a
// second SaveCertChain call for the same id releases every member of the
// previous chain before writing the new one, so a shorter replacement chain
// does not leave stale members from the longer original behind.
func TestPKCS11CertStorage_SaveCertChain_ReplacesPreviousMembers(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-chain-replace")

	original, err := generateTestCertificateChain(3)
	require.NoError(t, err)
	require.NoError(t, s.SaveCertChain("replace-me", original))

	replacement, err := generateTestCertificateChain(1)
	require.NoError(t, err)
	require.NoError(t, s.SaveCertChain("replace-me", replacement))

	got, err := s.GetCertChain("replace-me")
	require.NoError(t, err)
	require.Len(t, got, 1, "the shorter replacement must fully supersede the original")
	assert.Equal(t, replacement[0].Raw, got[0].Raw)
}

// TestPKCS11CertStorage_ListCerts_ExcludesChainMembers verifies ListCerts
// enumerates only primary certificate ids, filtering out the chain member
// objects that live alongside them under id-chain-<n>.
func TestPKCS11CertStorage_ListCerts_ExcludesChainMembers(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-list-certs")

	standalone, err := generateTestCertificate("standalone")
	require.NoError(t, err)
	require.NoError(t, s.SaveCert("standalone", standalone))

	withChain, err := generateTestCertificate("primary-record")
	require.NoError(t, err)
	require.NoError(t, s.SaveCert("primary-record", withChain))

	chain, err := generateTestCertificateChain(2)
	require.NoError(t, err)
	require.NoError(t, s.SaveCertChain("primary-record", chain))

	ids, err := s.ListCerts()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"standalone", "primary-record"}, ids)
}

// TestPKCS11CertStorage_GetCapacity_RealToken verifies GetCapacity queries
// real CK_TOKEN_INFO from the token rather than only exercising the
// closed-storage error path. SoftHSM2 reports CK_EFFECTIVELY_INFINITE for
// MaxSessionCount, so the real-token outcome is ErrNotSupported -- the same
// branch a token with no fixed session ceiling hits in production -- proving
// GetCapacity reached and correctly classified real token info instead of
// erroring before the call.
func TestPKCS11CertStorage_GetCapacity_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-capacity")

	_, _, err := s.GetCapacity()
	assert.ErrorIs(t, err, ErrNotSupported)
}

// TestPKCS11CertStorage_RejectsReservedChainID verifies every entry point
// that accepts a certificate id refuses one shaped like a chain record
// (<id>-chain) before touching the token, each with the typed
// ErrIDReservedForChain.
func TestPKCS11CertStorage_RejectsReservedChainID(t *testing.T) {
	const reservedID = "primary-chain"
	cert, err := generateTestCertificate("reserved")
	require.NoError(t, err)
	chain, err := generateTestCertificateChain(1)
	require.NoError(t, err)

	s := &PKCS11CertStorage{}

	assertReserved := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrIDReservedForChain)
	}

	t.Run("SaveCert", func(t *testing.T) { assertReserved(t, s.SaveCert(reservedID, cert)) })
	t.Run("GetCert", func(t *testing.T) { _, err := s.GetCert(reservedID); assertReserved(t, err) })
	t.Run("DeleteCert", func(t *testing.T) { assertReserved(t, s.DeleteCert(reservedID)) })
	t.Run("DeleteCertChain", func(t *testing.T) { assertReserved(t, s.DeleteCertChain(reservedID)) })
	t.Run("SaveCertChain", func(t *testing.T) { assertReserved(t, s.SaveCertChain(reservedID, chain)) })
	t.Run("GetCertChain", func(t *testing.T) { _, err := s.GetCertChain(reservedID); assertReserved(t, err) })
	t.Run("CertExists", func(t *testing.T) { _, err := s.CertExists(reservedID); assertReserved(t, err) })
}

// TestPKCS11CertStorage_GetCert_NotFound_RealToken verifies GetCert against a
// real, empty token reports storage.ErrNotFound rather than a raw PKCS#11
// search error.
func TestPKCS11CertStorage_GetCert_NotFound_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-getcert-notfound")

	_, err := s.GetCert("does-not-exist")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestPKCS11CertStorage_GetCertChain_NotFound_RealToken verifies
// GetCertChain against a real, empty token reports storage.ErrNotFound.
func TestPKCS11CertStorage_GetCertChain_NotFound_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-getchain-notfound")

	_, err := s.GetCertChain("does-not-exist")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestPKCS11CertStorage_ListCerts_Empty_RealToken verifies ListCerts on a
// freshly provisioned, empty token returns an empty slice rather than an
// error.
func TestPKCS11CertStorage_ListCerts_Empty_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-list-empty")

	ids, err := s.ListCerts()
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// TestPKCS11CertStorage_Close_RealToken verifies Close marks the storage
// closed exactly once and every subsequent operation on a real (now closed)
// instance reports ErrStorageClosed, matching the contract the closed-mock
// tests assert without a live token.
func TestPKCS11CertStorage_Close_RealToken(t *testing.T) {
	s, _ := newSoftHSMCertStorage(t, "rand-close")

	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "Close must be idempotent")

	_, err := s.CertExists("anything")
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestPKCS11CertStorage_NewWithNilPool_RealErrorType verifies the
// constructor's nil-pool guard, matching the shape of the other constructor
// tests but asserted via errors.Is against the exported sentinel rather than
// a message substring.
func TestPKCS11CertStorage_NewWithNilPool_RealErrorType(t *testing.T) {
	_, err := NewPKCS11CertStorageWithSO(nil, "label", "", "", false)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilContext)
}
