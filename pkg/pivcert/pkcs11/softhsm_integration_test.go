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

//go:build pkcs11 && integration

package pkcs11

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	softHSMLibrary  = "/usr/lib/softhsm/libsofthsm2.so"
	softHSMToken    = "e2e-piv-test"
	softHSMPIN      = "123456"
	softHSMAutoSlot = -1
)

// skipIfNoSoftHSM skips the test if SoftHSM is not installed.
func skipIfNoSoftHSM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(softHSMLibrary); err != nil {
		t.Skip("SoftHSM not available")
	}
}

// softhsmConfig returns a PKCS#11 storage config pointing at the SoftHSM test token.
func softhsmConfig() *pivcert.PKCS11StorageConfig {
	return &pivcert.PKCS11StorageConfig{
		LibraryPath: softHSMLibrary,
		TokenLabel:  softHSMToken,
		PIN:         softHSMPIN,
		SlotID:      softHSMAutoSlot,
	}
}

// generateSoftHSMTestCert creates a self-signed ECDSA P-256 certificate for
// integration test use. Named differently from generateTestCert in the unit
// test file to avoid redeclaration when both build tag sets are active.
func generateSoftHSMTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate ECDSA key")

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "generate serial number")

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Integration Test Certificate",
			Organization: []string{"go-xkms Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "create self-signed certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "parse generated certificate")

	return cert
}

// TestSoftHSMListAllPIVSlots verifies that List() returns all 4 pre-provisioned
// PIV certificates with correct metadata.
func TestSoftHSMListAllPIVSlots(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	slots, err := store.List()
	require.NoError(t, err, "list PIV slots")
	require.Len(t, slots, 4, "expected exactly 4 PIV slot entries")

	// Build a map for easier lookup by slot.
	slotMap := make(map[pivcert.PIVSlot]pivcert.PIVSlotInfo, len(slots))
	for _, info := range slots {
		slotMap[info.Slot] = info
	}

	// 9a - PIV Authentication (RSA 2048)
	info, ok := slotMap[pivcert.PIVSlotAuthentication]
	require.True(t, ok, "slot 9a must be present")
	assert.Contains(t, info.Subject, "PIV Authentication Test", "9a subject mismatch")
	assert.Equal(t, "RSA", info.Algorithm, "9a algorithm")
	assert.Equal(t, 2048, info.KeySize, "9a key size")
	assert.NotEmpty(t, info.Fingerprint, "9a fingerprint must not be empty")
	assert.NotEmpty(t, info.NotBefore, "9a NotBefore must not be empty")
	assert.NotEmpty(t, info.NotAfter, "9a NotAfter must not be empty")
	assert.NotEmpty(t, info.Issuer, "9a Issuer must not be empty")

	// 9c - Digital Signature (RSA 2048)
	info, ok = slotMap[pivcert.PIVSlotDigitalSignature]
	require.True(t, ok, "slot 9c must be present")
	assert.Contains(t, info.Subject, "Digital Signature Test", "9c subject mismatch")
	assert.Equal(t, "RSA", info.Algorithm, "9c algorithm")
	assert.Equal(t, 2048, info.KeySize, "9c key size")
	assert.NotEmpty(t, info.Fingerprint, "9c fingerprint must not be empty")
	assert.NotEmpty(t, info.NotBefore, "9c NotBefore must not be empty")
	assert.NotEmpty(t, info.NotAfter, "9c NotAfter must not be empty")
	assert.NotEmpty(t, info.Issuer, "9c Issuer must not be empty")

	// 9d - Key Management (RSA 2048)
	info, ok = slotMap[pivcert.PIVSlotKeyManagement]
	require.True(t, ok, "slot 9d must be present")
	assert.Contains(t, info.Subject, "Key Management Test", "9d subject mismatch")
	assert.Equal(t, "RSA", info.Algorithm, "9d algorithm")
	assert.Equal(t, 2048, info.KeySize, "9d key size")
	assert.NotEmpty(t, info.Fingerprint, "9d fingerprint must not be empty")
	assert.NotEmpty(t, info.NotBefore, "9d NotBefore must not be empty")
	assert.NotEmpty(t, info.NotAfter, "9d NotAfter must not be empty")
	assert.NotEmpty(t, info.Issuer, "9d Issuer must not be empty")

	// 9e - Card Authentication (ECDSA P-256)
	info, ok = slotMap[pivcert.PIVSlotCardAuthentication]
	require.True(t, ok, "slot 9e must be present")
	assert.Contains(t, info.Subject, "Card Authentication Test", "9e subject mismatch")
	assert.Equal(t, "ECDSA", info.Algorithm, "9e algorithm")
	assert.Equal(t, 256, info.KeySize, "9e key size")
	assert.NotEmpty(t, info.Fingerprint, "9e fingerprint must not be empty")
	assert.NotEmpty(t, info.NotBefore, "9e NotBefore must not be empty")
	assert.NotEmpty(t, info.NotAfter, "9e NotAfter must not be empty")
	assert.NotEmpty(t, info.Issuer, "9e Issuer must not be empty")
}

// TestSoftHSMRetrieveBySlot verifies that each pre-provisioned certificate
// can be retrieved individually and contains correct key material.
func TestSoftHSMRetrieveBySlot(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	tests := []struct {
		slot      pivcert.PIVSlot
		expectCN  string
		expectAlg string // "RSA" or "ECDSA"
	}{
		{pivcert.PIVSlotAuthentication, "PIV Authentication Test", "RSA"},
		{pivcert.PIVSlotDigitalSignature, "Digital Signature Test", "RSA"},
		{pivcert.PIVSlotKeyManagement, "Key Management Test", "RSA"},
		{pivcert.PIVSlotCardAuthentication, "Card Authentication Test", "ECDSA"},
	}

	for _, tc := range tests {
		t.Run(string(tc.slot), func(t *testing.T) {
			cert, err := store.Retrieve(tc.slot)
			require.NoError(t, err, "retrieve slot %s", tc.slot)
			require.NotNil(t, cert, "certificate must not be nil for slot %s", tc.slot)

			assert.Equal(t, tc.expectCN, cert.Subject.CommonName,
				"slot %s: CN mismatch", tc.slot)

			switch tc.expectAlg {
			case "RSA":
				rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
				require.True(t, ok, "slot %s: expected RSA public key", tc.slot)
				assert.Equal(t, 2048, rsaKey.N.BitLen(),
					"slot %s: RSA key size mismatch", tc.slot)
			case "ECDSA":
				ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
				require.True(t, ok, "slot %s: expected ECDSA public key", tc.slot)
				assert.Equal(t, 256, ecKey.Curve.Params().BitSize,
					"slot %s: ECDSA curve size mismatch", tc.slot)
			}

			now := time.Now()
			assert.True(t, cert.NotBefore.Before(now),
				"slot %s: NotBefore (%v) should be in the past", tc.slot, cert.NotBefore)
			assert.True(t, cert.NotAfter.After(now),
				"slot %s: NotAfter (%v) should be in the future", tc.slot, cert.NotAfter)
		})
	}
}

// TestSoftHSMRetrieveEmptySlot verifies that retrieving a certificate from
// an unpopulated slot (f9 attestation) returns an error.
func TestSoftHSMRetrieveEmptySlot(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	cert, err := store.Retrieve(pivcert.PIVSlotAttestation)
	require.Error(t, err, "retrieve from empty slot f9 must fail")
	assert.Nil(t, cert, "certificate from empty slot must be nil")
	assert.ErrorIs(t, err, pivcert.ErrCertificateNotFound,
		"error must wrap ErrCertificateNotFound")
}

// TestSoftHSMStoreAndDelete verifies the full store/retrieve/delete lifecycle
// using a retired slot so we do not disturb the pre-provisioned test data.
func TestSoftHSMStoreAndDelete(t *testing.T) {
	skipIfNoSoftHSM(t)
	// NOT parallel: mutates token state

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	testCert := generateSoftHSMTestCert(t)
	targetSlot := pivcert.PIVSlotRetired1

	// Store
	err = store.Store(targetSlot, testCert)
	require.NoError(t, err, "store certificate in retired1 slot")

	// Retrieve and verify
	retrieved, err := store.Retrieve(targetSlot)
	require.NoError(t, err, "retrieve stored certificate")
	require.NotNil(t, retrieved, "retrieved certificate must not be nil")
	assert.Equal(t, testCert.Subject.CommonName, retrieved.Subject.CommonName,
		"retrieved CN must match stored CN")
	assert.Equal(t, 0, testCert.SerialNumber.Cmp(retrieved.SerialNumber),
		"serial numbers must match")
	assert.True(t, bytes.Equal(testCert.Raw, retrieved.Raw),
		"raw certificate bytes must match")

	// Delete
	err = store.Delete(targetSlot)
	require.NoError(t, err, "delete certificate from retired1 slot")

	// Verify deletion
	cert, err := store.Retrieve(targetSlot)
	require.Error(t, err, "retrieve after delete must fail")
	assert.Nil(t, cert, "certificate after delete must be nil")
	assert.ErrorIs(t, err, pivcert.ErrCertificateNotFound,
		"error after delete must wrap ErrCertificateNotFound")
}

// TestSoftHSMImportExport verifies PEM and DER import/export round-trip
// integrity using a retired slot.
func TestSoftHSMImportExport(t *testing.T) {
	skipIfNoSoftHSM(t)
	// NOT parallel: mutates token state

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	testCert := generateSoftHSMTestCert(t)
	targetSlot := pivcert.PIVSlotRetired2

	// Clean up after test in case of leftover state.
	defer func() {
		_ = store.Delete(targetSlot)
	}()

	// Import as PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testCert.Raw,
	})
	require.NotNil(t, pemData, "PEM encoding must succeed")

	err = store.Import(targetSlot, pemData, pivcert.FormatPEM)
	require.NoError(t, err, "import PEM certificate")

	// Export as PEM and verify round-trip
	exportedPEM, err := store.Export(targetSlot, pivcert.FormatPEM)
	require.NoError(t, err, "export as PEM")
	require.NotEmpty(t, exportedPEM, "exported PEM must not be empty")

	block, rest := pem.Decode(exportedPEM)
	require.NotNil(t, block, "exported PEM must be decodable")
	assert.Empty(t, rest, "no trailing data after PEM block")
	assert.Equal(t, "CERTIFICATE", block.Type, "PEM block type")
	assert.True(t, bytes.Equal(testCert.Raw, block.Bytes),
		"PEM round-trip: raw bytes must match original")

	// Export as DER and verify
	exportedDER, err := store.Export(targetSlot, pivcert.FormatDER)
	require.NoError(t, err, "export as DER")
	require.NotEmpty(t, exportedDER, "exported DER must not be empty")
	assert.True(t, bytes.Equal(testCert.Raw, exportedDER),
		"DER export: raw bytes must match original")

	// Parse the DER to confirm it is a valid certificate
	parsedCert, err := x509.ParseCertificate(exportedDER)
	require.NoError(t, err, "parse exported DER")
	assert.Equal(t, testCert.Subject.CommonName, parsedCert.Subject.CommonName,
		"parsed DER CN must match")

	// Clean up
	err = store.Delete(targetSlot)
	require.NoError(t, err, "delete imported certificate")
}

// TestSoftHSMCKAIDMapping verifies the PIV slot to CKA_ID byte mapping,
// including the f9 -> 0x19 fix (previously the bug mapped f9 -> 0xf9).
func TestSoftHSMCKAIDMapping(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	tests := []struct {
		slot     pivcert.PIVSlot
		expected byte
	}{
		{pivcert.PIVSlotAuthentication, 0x01},
		{pivcert.PIVSlotDigitalSignature, 0x02},
		{pivcert.PIVSlotKeyManagement, 0x03},
		{pivcert.PIVSlotCardAuthentication, 0x04},
		{pivcert.PIVSlotAttestation, 0x19}, // NOT 0xf9 - this was the regression bug
	}

	for _, tc := range tests {
		t.Run(string(tc.slot), func(t *testing.T) {
			id, err := pivID(tc.slot)
			require.NoError(t, err, "pivID(%s) must not error", tc.slot)
			require.Len(t, id, 1, "pivID must return exactly 1 byte")
			assert.Equal(t, tc.expected, id[0],
				"slot %s: CKA_ID byte mismatch (got 0x%02x, want 0x%02x)",
				tc.slot, id[0], tc.expected)
		})
	}

	// Verify f9 is explicitly NOT 0xf9
	id, err := pivID(pivcert.PIVSlotAttestation)
	require.NoError(t, err)
	assert.NotEqual(t, byte(0xf9), id[0],
		"REGRESSION: f9 slot must NOT map to 0xf9 (got 0x%02x)", id[0])
}

// TestSoftHSMNewFromSession verifies the NewFromSession code path, which is
// the exact path the GUI uses when it already holds a PKCS#11 context and
// session from the module manager.
func TestSoftHSMNewFromSession(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	// Manually initialize PKCS#11 context (simulating what the GUI does).
	ctx := p11.New(softHSMLibrary)
	require.NotNil(t, ctx, "p11.New must return non-nil context")

	err := ctx.Initialize()
	if err != nil {
		// CKR_CRYPTOKI_ALREADY_INITIALIZED is expected when other tests
		// (or the session pool) already initialized the library.
		require.ErrorIs(t, err, p11.Error(p11.CKR_CRYPTOKI_ALREADY_INITIALIZED),
			"Initialize should succeed or return CKR_CRYPTOKI_ALREADY_INITIALIZED")
	}
	defer ctx.Finalize()
	defer ctx.Destroy()

	// Resolve slot by token label (same as resolveSlot does internally).
	slots, err := ctx.GetSlotList(true)
	require.NoError(t, err, "GetSlotList")
	require.NotEmpty(t, slots, "at least one slot must exist")

	var slotID uint
	found := false
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if strings.TrimRight(info.Label, " ") == softHSMToken {
			slotID = s
			found = true
			break
		}
	}
	require.True(t, found, "token %q must be found", softHSMToken)

	// Open session and login.
	session, err := ctx.OpenSession(slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	require.NoError(t, err, "OpenSession")
	defer ctx.CloseSession(session)

	err = ctx.Login(session, p11.CKU_USER, softHSMPIN)
	if err != nil {
		require.ErrorIs(t, err, p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN),
			"Login should succeed or return CKR_USER_ALREADY_LOGGED_IN")
	}
	defer ctx.Logout(session)

	// Create storage via NewFromSession (the GUI path).
	store, err := NewFromSession(ctx, session, slotID)
	require.NoError(t, err, "NewFromSession")
	defer store.Close()

	// Verify we see the same 4 certificates.
	slotInfos, err := store.List()
	require.NoError(t, err, "List via NewFromSession")
	require.Len(t, slotInfos, 4, "NewFromSession must see all 4 PIV certs")

	// Build set of slot IDs for verification.
	foundSlots := make(map[pivcert.PIVSlot]bool, len(slotInfos))
	for _, info := range slotInfos {
		foundSlots[info.Slot] = true
	}

	assert.True(t, foundSlots[pivcert.PIVSlotAuthentication], "9a must be present")
	assert.True(t, foundSlots[pivcert.PIVSlotDigitalSignature], "9c must be present")
	assert.True(t, foundSlots[pivcert.PIVSlotKeyManagement], "9d must be present")
	assert.True(t, foundSlots[pivcert.PIVSlotCardAuthentication], "9e must be present")

	// Verify individual cert retrieval works through the session path.
	cert, err := store.Retrieve(pivcert.PIVSlotAuthentication)
	require.NoError(t, err, "Retrieve 9a via NewFromSession")
	require.NotNil(t, cert, "9a certificate must not be nil")
	assert.Equal(t, "PIV Authentication Test", cert.Subject.CommonName,
		"9a CN via NewFromSession")
}

// TestSoftHSMConcurrentList verifies that concurrent List() calls through the
// session-pool-backed New() constructor do not race or deadlock.
func TestSoftHSMConcurrentList(t *testing.T) {
	skipIfNoSoftHSM(t)
	t.Parallel()

	store, err := New(softhsmConfig())
	require.NoError(t, err, "create PKCS#11 storage")
	defer store.Close()

	const goroutines = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)
	results := make([][]pivcert.PIVSlotInfo, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			slots, err := store.List()
			errs[idx] = err
			results[idx] = slots
		}(i)
	}

	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d: List() must not error", i)
		require.Len(t, results[i], 4,
			"goroutine %d: must return exactly 4 slots", i)

		for _, info := range results[i] {
			assert.NotEmpty(t, info.Subject,
				"goroutine %d: slot %s subject must not be empty", i, info.Slot)
			assert.NotEmpty(t, info.Fingerprint,
				"goroutine %d: slot %s fingerprint must not be empty", i, info.Slot)
			assert.NotEmpty(t, info.Algorithm,
				"goroutine %d: slot %s algorithm must not be empty", i, info.Slot)
			assert.Greater(t, info.KeySize, 0,
				"goroutine %d: slot %s key size must be positive", i, info.Slot)
		}
	}
}
