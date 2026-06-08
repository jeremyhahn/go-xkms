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

//go:build integration && pkcs11

package piv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	p11 "github.com/miekg/pkcs11"
)

const (
	testPIN   = "1234"
	testSOPIN = "12345678"
)

// softhsmLibPath returns the SoftHSM2 library path.
func softhsmLibPath() string {
	paths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// initSoftHSMToken creates a temporary SoftHSM2 token for testing.
// Returns the token label, slot ID, and cleanup function.
func initSoftHSMToken(t *testing.T) (tokenLabel string, slotID int, cleanup func()) {
	t.Helper()

	tmpDir := t.TempDir()
	confFile := filepath.Join(tmpDir, "softhsm2.conf")
	tokenDir := filepath.Join(tmpDir, "tokens")
	err := os.MkdirAll(tokenDir, 0700)
	require.NoError(t, err, "failed to create token directory")

	confContent := fmt.Sprintf("directories.tokendir = %s\n", tokenDir)
	err = os.WriteFile(confFile, []byte(confContent), 0644)
	require.NoError(t, err, "failed to write softhsm2 config")

	t.Setenv("SOFTHSM2_CONF", confFile)

	// SoftHSM2 enforces a max label length of 32 characters.
	// Truncate the test name to fit within the limit.
	name := t.Name()
	const maxLabel = 32
	const prefix = "piv-"
	if len(prefix)+len(name) > maxLabel {
		name = name[len(name)-(maxLabel-len(prefix)):]
	}
	label := prefix + name
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--pin", testPIN, "--so-pin", testSOPIN)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confFile)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "softhsm2-util init failed: %s", string(output))

	// Parse slot ID from output like:
	// "The token has been initialized and is reassigned to slot 123456789"
	re := regexp.MustCompile(`reassigned to slot (\d+)`)
	matches := re.FindStringSubmatch(string(output))
	require.NotEmpty(t, matches, "failed to parse slot ID from output: %s", string(output))

	parsedSlotID, err := strconv.Atoi(matches[1])
	require.NoError(t, err, "failed to parse slot ID integer from: %s", matches[1])

	return label, parsedSlotID, func() {
		// SOFTHSM2_CONF is cleaned up by t.Setenv automatically
	}
}

// generateTestCertWithSubject creates a self-signed ECDSA P-256 test certificate.
func generateTestCertWithSubject(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert
}

// newPKCS11Storage creates a PKCS11CertStorage connected to the test SoftHSM2 token.
func newPKCS11Storage(t *testing.T, libPath string, slotID int) *xkms.PIVPKCS11Backend {
	t.Helper()

	storage, err := xkms.NewPIVPKCS11Backend(&xkms.PIVPKCS11StorageConfig{
		LibraryPath: libPath,
		SlotID:      slotID,
		PIN:         testPIN,
	})
	require.NoError(t, err, "failed to create PKCS11CertStorage")

	t.Cleanup(func() {
		storage.Close()
	})

	return storage
}

// newSOSessionStorage opens a raw PKCS#11 context and session, logs in as
// CKU_USER, then creates a PKCS11CertStorage via NewFromSessionWithSO.
// Returns the storage. Cleanup closes the session and finalizes the context.
func newSOSessionStorage(t *testing.T, libPath string, slotID int) *xkms.PIVPKCS11Backend {
	t.Helper()

	ctx := p11.New(libPath)
	require.NotNil(t, ctx, "failed to load PKCS#11 library")

	if err := ctx.Initialize(); err != nil {
		// Tolerate CKR_CRYPTOKI_ALREADY_INITIALIZED when SoftHSM is
		// shared across tests in the same process.
		if p11Err, ok := err.(p11.Error); !ok || uint(p11Err) != p11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			require.NoError(t, err, "PKCS#11 Initialize failed")
		}
	}

	session, err := ctx.OpenSession(uint(slotID), p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	require.NoError(t, err, "OpenSession failed")

	if err := ctx.Login(session, p11.CKU_USER, testPIN); err != nil {
		// Tolerate CKR_USER_ALREADY_LOGGED_IN when token login is shared.
		if p11Err, ok := err.(p11.Error); !ok || uint(p11Err) != p11.CKR_USER_ALREADY_LOGGED_IN {
			require.NoError(t, err, "CKU_USER Login failed")
		}
	}

	storage, err := xkms.NewPIVPKCS11BackendFromSessionWithSO(ctx, session, uint(slotID), testSOPIN, testPIN)
	require.NoError(t, err, "NewFromSessionWithSO failed")

	t.Cleanup(func() {
		storage.Close()
		ctx.Logout(session)
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
	})

	return storage
}

// TestPKCS11CertStorage_FullLifecycle tests the complete lifecycle of certificate
// storage operations on a real SoftHSM2 token: store, retrieve, list, delete, close.
func TestPKCS11CertStorage_FullLifecycle(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	cert := generateTestCertWithSubject(t, "test-full-lifecycle")

	// Step 1: Store certificate in slot 9a
	err := storage.Store(xkms.PIVSlotAuthentication, cert)
	require.NoError(t, err, "Store should succeed")

	// Step 2: Retrieve and verify cert matches
	retrieved, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Retrieve should succeed")
	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName,
		"retrieved certificate subject should match stored certificate")
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber,
		"retrieved certificate serial number should match")

	// Step 3: List -- verify slot 9a appears
	slots, err := storage.List()
	require.NoError(t, err, "List should succeed")

	found := false
	for _, info := range slots {
		if info.Slot == xkms.PIVSlotAuthentication {
			found = true
			assert.Contains(t, info.Subject, "test-full-lifecycle",
				"listed slot info should contain the certificate subject")
			break
		}
	}
	assert.True(t, found, "slot 9a should appear in List result")

	// Step 4: Delete slot 9a
	err = storage.Delete(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Delete should succeed")

	// Step 5: List -- verify slot 9a is gone
	slots, err = storage.List()
	require.NoError(t, err, "List after delete should succeed")
	for _, info := range slots {
		assert.NotEqual(t, xkms.PIVSlotAuthentication, info.Slot,
			"slot 9a should not appear after deletion")
	}

	// Step 6: Close storage
	err = storage.Close()
	require.NoError(t, err, "Close should succeed")
}

// TestPKCS11CertStorage_StoreRetrieveRoundtrip verifies that DER bytes are
// preserved exactly through a store/retrieve cycle.
func TestPKCS11CertStorage_StoreRetrieveRoundtrip(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	cert := generateTestCertWithSubject(t, "test-roundtrip")

	err := storage.Store(xkms.PIVSlotAuthentication, cert)
	require.NoError(t, err)

	retrieved, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)

	assert.Equal(t, cert.Raw, retrieved.Raw,
		"retrieved certificate DER bytes must be identical to stored certificate")
}

// TestPKCS11CertStorage_Overwrite verifies that storing to an occupied slot
// replaces the existing certificate.
func TestPKCS11CertStorage_Overwrite(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	cert1 := generateTestCertWithSubject(t, "cert-overwrite-original")
	cert2 := generateTestCertWithSubject(t, "cert-overwrite-replacement")

	// Store cert1 in slot 9a
	err := storage.Store(xkms.PIVSlotAuthentication, cert1)
	require.NoError(t, err, "first Store should succeed")

	// Overwrite with cert2 in same slot
	err = storage.Store(xkms.PIVSlotAuthentication, cert2)
	require.NoError(t, err, "overwrite Store should succeed")

	// Retrieve -- should get cert2
	retrieved, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)

	assert.Equal(t, "cert-overwrite-replacement", retrieved.Subject.CommonName,
		"retrieved certificate should be the replacement, not the original")
	assert.NotEqual(t, cert1.Raw, retrieved.Raw,
		"retrieved certificate should not match the original")
	assert.Equal(t, cert2.Raw, retrieved.Raw,
		"retrieved certificate DER bytes should match the replacement")

	// Verify only one cert in list for this slot
	slots, err := storage.List()
	require.NoError(t, err)
	count := 0
	for _, info := range slots {
		if info.Slot == xkms.PIVSlotAuthentication {
			count++
		}
	}
	assert.Equal(t, 1, count, "should have exactly one certificate in slot 9a after overwrite")
}

// TestPKCS11CertStorage_MultiSlot tests storing different certificates in
// multiple PIV slots simultaneously.
func TestPKCS11CertStorage_MultiSlot(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	type slotCert struct {
		slot xkms.PIVSlot
		cn   string
	}

	entries := []slotCert{
		{xkms.PIVSlotAuthentication, "multi-9a"},
		{xkms.PIVSlotDigitalSignature, "multi-9c"},
		{xkms.PIVSlotKeyManagement, "multi-9d"},
		{xkms.PIVSlotCardAuthentication, "multi-9e"},
	}

	certs := make(map[xkms.PIVSlot]*x509.Certificate, len(entries))

	// Store different certs in each slot
	for _, e := range entries {
		cert := generateTestCertWithSubject(t, e.cn)
		certs[e.slot] = cert

		err := storage.Store(e.slot, cert)
		require.NoError(t, err, "Store to slot %s should succeed", e.slot)
	}

	// List -- verify 4 slots
	slots, err := storage.List()
	require.NoError(t, err)
	assert.Len(t, slots, 4, "List should return 4 populated slots")

	// Retrieve each -- verify correct cert per slot
	for _, e := range entries {
		retrieved, err := storage.Retrieve(e.slot)
		require.NoError(t, err, "Retrieve from slot %s should succeed", e.slot)
		assert.Equal(t, e.cn, retrieved.Subject.CommonName,
			"cert in slot %s should have correct subject", e.slot)
		assert.Equal(t, certs[e.slot].Raw, retrieved.Raw,
			"cert in slot %s should have identical DER bytes", e.slot)
	}
}

// TestPKCS11CertStorage_ImportExportDER tests the DER import/export roundtrip.
func TestPKCS11CertStorage_ImportExportDER(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	cert := generateTestCertWithSubject(t, "test-der-import-export")
	originalDER := cert.Raw

	// Import as DER
	err := storage.Import(xkms.PIVSlotAuthentication, originalDER, xkms.PIVFormatDER)
	require.NoError(t, err, "Import DER should succeed")

	// Export as DER
	exportedDER, err := storage.Export(xkms.PIVSlotAuthentication, xkms.PIVFormatDER)
	require.NoError(t, err, "Export DER should succeed")

	assert.Equal(t, originalDER, exportedDER,
		"exported DER bytes must match original DER bytes")
}

// TestPKCS11CertStorage_ImportExportPEM tests the PEM import/export roundtrip.
func TestPKCS11CertStorage_ImportExportPEM(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	cert := generateTestCertWithSubject(t, "test-pem-import-export")

	// Encode cert as PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	require.NotNil(t, pemData, "PEM encoding should not be nil")

	// Import as PEM
	err := storage.Import(xkms.PIVSlotAuthentication, pemData, xkms.PIVFormatPEM)
	require.NoError(t, err, "Import PEM should succeed")

	// Export as PEM
	exportedPEM, err := storage.Export(xkms.PIVSlotAuthentication, xkms.PIVFormatPEM)
	require.NoError(t, err, "Export PEM should succeed")

	// Decode exported PEM and verify the certificate matches
	block, _ := pem.Decode(exportedPEM)
	require.NotNil(t, block, "exported PEM should be decodable")
	assert.Equal(t, "CERTIFICATE", block.Type, "PEM block type should be CERTIFICATE")

	exportedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "exported PEM should contain a valid certificate")

	assert.Equal(t, cert.Subject.CommonName, exportedCert.Subject.CommonName,
		"exported certificate subject should match imported certificate")
	assert.Equal(t, cert.Raw, exportedCert.Raw,
		"exported certificate DER bytes should match imported certificate")
}

// TestPKCS11CertStorage_DeleteNotFound verifies that deleting from an empty slot
// returns ErrCertificateNotFound.
func TestPKCS11CertStorage_DeleteNotFound(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	err := storage.Delete(xkms.PIVSlotAuthentication)
	require.Error(t, err, "Delete from empty slot should return an error")
	assert.True(t, errors.Is(err, xkms.ErrPIVCertificateNotFound),
		"error should be ErrCertificateNotFound, got: %v", err)
}

// TestPKCS11CertStorage_RetrieveNotFound verifies that retrieving from an empty slot
// returns ErrCertificateNotFound.
func TestPKCS11CertStorage_RetrieveNotFound(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	_, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.Error(t, err, "Retrieve from empty slot should return an error")
	assert.True(t, errors.Is(err, xkms.ErrPIVCertificateNotFound),
		"error should be ErrCertificateNotFound, got: %v", err)
}

// TestPKCS11CertStorage_CKAIDMapping verifies the CKA_ID mapping matches the
// expected YubiKey PIV slot mapping. It stores certs in all 4 primary slots,
// then uses raw PKCS#11 operations via the Export/Retrieve API to verify that
// the correct CKA_ID values (0x01, 0x02, 0x03, 0x04) are assigned.
func TestPKCS11CertStorage_CKAIDMapping(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newPKCS11Storage(t, libPath, slotID)

	// Expected CKA_ID mapping from the implementation:
	//   9a -> 0x01, 9c -> 0x02, 9d -> 0x03, 9e -> 0x04
	expectedCKAIDs := map[xkms.PIVSlot]byte{
		xkms.PIVSlotAuthentication:     0x01,
		xkms.PIVSlotDigitalSignature:   0x02,
		xkms.PIVSlotKeyManagement:      0x03,
		xkms.PIVSlotCardAuthentication: 0x04,
	}

	// Store certs in all 4 primary slots
	for slot := range expectedCKAIDs {
		cert := generateTestCertWithSubject(t, "ckaid-test-"+string(slot))
		err := storage.Store(slot, cert)
		require.NoError(t, err, "Store to slot %s should succeed", slot)
	}

	// Verify each slot can be retrieved (proving the CKA_ID mapping is correct
	// since findCertObject uses CKA_ID for lookup)
	for slot := range expectedCKAIDs {
		retrieved, err := storage.Retrieve(slot)
		require.NoError(t, err, "Retrieve from slot %s should succeed", slot)
		assert.Equal(t, "ckaid-test-"+string(slot), retrieved.Subject.CommonName,
			"slot %s should contain the correct certificate", slot)
	}

	// Verify all 4 appear in List
	slots, err := storage.List()
	require.NoError(t, err)
	assert.Len(t, slots, 4, "List should return exactly 4 slots")

	// Verify each listed slot has the expected slot identifier
	listedSlots := make(map[xkms.PIVSlot]bool)
	for _, info := range slots {
		listedSlots[info.Slot] = true
	}

	for slot := range expectedCKAIDs {
		assert.True(t, listedSlots[slot],
			"slot %s should appear in List (confirming CKA_ID reverse mapping)", slot)
	}

	// Cross-verify: store and retrieve in one slot does not affect another
	// (i.e., CKA_IDs are distinct and correctly mapped)
	cert9a, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)
	cert9c, err := storage.Retrieve(xkms.PIVSlotDigitalSignature)
	require.NoError(t, err)

	assert.NotEqual(t, cert9a.Raw, cert9c.Raw,
		"certificates in different slots must be distinct (CKA_ID isolation)")
}

// TestPKCS11CertStorage_NewFromSessionWithSO verifies that a PKCS11CertStorage
// created via NewFromSessionWithSO can perform the full Store/Retrieve/Delete
// lifecycle, proving SO session elevation works for write operations.
func TestPKCS11CertStorage_NewFromSessionWithSO(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newSOSessionStorage(t, libPath, slotID)

	cert := generateTestCertWithSubject(t, "so-session-lifecycle")

	// Store via SO-elevated session
	err := storage.Store(xkms.PIVSlotAuthentication, cert)
	require.NoError(t, err, "Store via SO session should succeed")

	// Retrieve and verify
	retrieved, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Retrieve after SO Store should succeed")
	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName,
		"retrieved certificate subject should match stored certificate")
	assert.Equal(t, cert.Raw, retrieved.Raw,
		"retrieved certificate DER bytes should match stored certificate")

	// List should show the slot
	slots, err := storage.List()
	require.NoError(t, err, "List should succeed")
	found := false
	for _, info := range slots {
		if info.Slot == xkms.PIVSlotAuthentication {
			found = true
			assert.Contains(t, info.Subject, "so-session-lifecycle")
			break
		}
	}
	assert.True(t, found, "slot 9a should appear in List after SO Store")

	// Delete via SO-elevated session
	err = storage.Delete(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Delete via SO session should succeed")

	// Confirm deletion
	_, err = storage.Retrieve(xkms.PIVSlotAuthentication)
	require.Error(t, err, "Retrieve after Delete should fail")
}

// TestPKCS11CertStorage_SOSessionOverwrite verifies that overwriting a
// certificate in the same slot works via SO session elevation. This is the
// exact scenario that was broken (CKR_USER_TYPE_INVALID) before the SO
// session support was added: the delete-then-create pattern during overwrite
// requires SO login on YubiKey PIV tokens.
func TestPKCS11CertStorage_SOSessionOverwrite(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	storage := newSOSessionStorage(t, libPath, slotID)

	cert1 := generateTestCertWithSubject(t, "so-overwrite-original")
	cert2 := generateTestCertWithSubject(t, "so-overwrite-replacement")

	// Store first cert
	err := storage.Store(xkms.PIVSlotAuthentication, cert1)
	require.NoError(t, err, "first Store via SO session should succeed")

	// Verify first cert
	retrieved, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, "so-overwrite-original", retrieved.Subject.CommonName)

	// Overwrite with second cert (this is the operation that previously failed
	// with CKR_USER_TYPE_INVALID because the delete phase needed SO login)
	err = storage.Store(xkms.PIVSlotAuthentication, cert2)
	require.NoError(t, err, "overwrite Store via SO session should succeed")

	// Verify the replacement cert is stored
	retrieved, err = storage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Retrieve after overwrite should succeed")
	assert.Equal(t, "so-overwrite-replacement", retrieved.Subject.CommonName,
		"retrieved certificate should be the replacement, not the original")
	assert.Equal(t, cert2.Raw, retrieved.Raw,
		"retrieved certificate DER bytes should match the replacement")
	assert.NotEqual(t, cert1.Raw, retrieved.Raw,
		"retrieved certificate should not match the original")

	// Verify only one cert in the slot
	slots, err := storage.List()
	require.NoError(t, err)
	count := 0
	for _, info := range slots {
		if info.Slot == xkms.PIVSlotAuthentication {
			count++
		}
	}
	assert.Equal(t, 1, count, "should have exactly one certificate in slot 9a after overwrite")
}

// TestPKCS11CertStorage_NewFromSessionWithSO_InvalidConfig verifies that
// NewFromSessionWithSO returns an error when called with a nil context.
func TestPKCS11CertStorage_NewFromSessionWithSO_InvalidConfig(t *testing.T) {
	_, err := xkms.NewPIVPKCS11BackendFromSessionWithSO(nil, 0, 0, testSOPIN, testPIN)
	require.Error(t, err, "NewFromSessionWithSO with nil ctx should return an error")
	assert.Contains(t, err.Error(), "NewFromSessionWithSO",
		"error should identify the constructor")
}

// TestPKCS11CertStorage_SOSessionStore_ThenRegularRetrieve stores a certificate
// via an SO-elevated session, then retrieves it via a regular (non-SO) session
// to verify data integrity across session types. This proves that the cert
// object written by the SO session is accessible to normal CKU_USER sessions.
func TestPKCS11CertStorage_SOSessionStore_ThenRegularRetrieve(t *testing.T) {
	libPath := softhsmLibPath()
	if libPath == "" {
		t.Skip("SoftHSM2 not available")
	}

	_, slotID, cleanup := initSoftHSMToken(t)
	defer cleanup()

	cert := generateTestCertWithSubject(t, "so-store-regular-retrieve")

	// Store via SO-elevated session
	soStorage := newSOSessionStorage(t, libPath, slotID)
	err := soStorage.Store(xkms.PIVSlotAuthentication, cert)
	require.NoError(t, err, "Store via SO session should succeed")

	// Retrieve via a separate regular (non-SO) session
	regularStorage := newPKCS11Storage(t, libPath, slotID)
	retrieved, err := regularStorage.Retrieve(xkms.PIVSlotAuthentication)
	require.NoError(t, err, "Retrieve via regular session should succeed")

	assert.Equal(t, cert.Subject.CommonName, retrieved.Subject.CommonName,
		"certificate subject should match across session types")
	assert.Equal(t, cert.SerialNumber, retrieved.SerialNumber,
		"certificate serial number should match across session types")
	assert.Equal(t, cert.Raw, retrieved.Raw,
		"certificate DER bytes should be identical across session types")
}
