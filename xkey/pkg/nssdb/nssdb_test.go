// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

package nssdb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"  //nolint:gosec
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCA generates a self-signed CA certificate for testing.
func testCA(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// testCAWithSerial generates a self-signed CA with a specific serial number.
func testCAWithSerial(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: "Test CA Serial " + big.NewInt(serial).String(),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{byte(serial & 0xFF), 0x01, 0x02, 0x03},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// --- NewWriter tests ---

func TestNewWriter(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(dir)
	require.NoError(t, err)
	require.NotNil(t, w)
	defer w.Close()

	// Verify database files were created.
	_, err = os.Stat(filepath.Join(dir, cert9DBFile))
	assert.NoError(t, err, "cert9.db should exist")

	_, err = os.Stat(filepath.Join(dir, key4DBFile))
	assert.NoError(t, err, "key4.db should exist")

	// Verify the password entry exists in key4.db.
	var item1 []byte
	err = w.keyDB.QueryRow("SELECT item1 FROM metaData WHERE id = 'password'").Scan(&item1)
	assert.NoError(t, err)
	assert.Len(t, item1, 20, "global salt should be 20 bytes")

	// Verify intermediate key was derived.
	assert.NotNil(t, w.intermediateKey)
	assert.Len(t, w.intermediateKey, 20, "SHA1 output should be 20 bytes")
}

func TestNewWriterNonExistentDir(t *testing.T) {
	_, err := NewWriter("/nonexistent/path/that/does/not/exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDirNotExist)
}

func TestNewWriterNotADirectory(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir")
	require.NoError(t, os.WriteFile(filePath, []byte("x"), filePerm))

	_, err := NewWriter(filePath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDirNotExist)
}

func TestNewWriterReopenExistingDB(t *testing.T) {
	dir := t.TempDir()

	// First open: creates the DB and password entry.
	w1, err := NewWriter(dir)
	require.NoError(t, err)

	var salt1 []byte
	require.NoError(t, w1.keyDB.QueryRow("SELECT item1 FROM metaData WHERE id = 'password'").Scan(&salt1))
	require.NoError(t, w1.Close())

	// Second open: re-derives the intermediate key from the existing salt.
	w2, err := NewWriter(dir)
	require.NoError(t, err)
	defer w2.Close()

	var salt2 []byte
	require.NoError(t, w2.keyDB.QueryRow("SELECT item1 FROM metaData WHERE id = 'password'").Scan(&salt2))

	// Salt should be unchanged.
	assert.Equal(t, salt1, salt2, "global salt should persist across opens")

	// Intermediate keys should match since they derive from the same salt.
	assert.Equal(t, w1.intermediateKey, w2.intermediateKey)
}

// --- AddTrustedCA tests ---

func TestAddTrustedCA(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	err = w.AddTrustedCA(cert, "xkey-test-ca")
	require.NoError(t, err)

	// Verify certificate object in cert9.db.
	var certClass, certType []byte
	var certValue, issuer, subject, label []byte
	err = w.certDB.QueryRow(
		"SELECT a0, a80, a11, a81, a101, a3 FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate),
	).Scan(&certClass, &certType, &certValue, &issuer, &subject, &label)
	require.NoError(t, err)

	assert.Equal(t, encodeUint32(ckoCertificate), certClass)
	assert.Equal(t, encodeUint32(0), certType, "CKC_X_509 = 0")
	assert.Equal(t, cert.Raw, certValue)
	assert.Equal(t, cert.RawIssuer, issuer)
	assert.Equal(t, cert.RawSubject, subject)
	assert.Equal(t, []byte("xkey-test-ca"), label)

	// Verify trust object in cert9.db.
	var trustClass []byte
	var trustServerAuth, trustClientAuth, trustCodeSigning, trustEmail []byte
	err = w.certDB.QueryRow(
		"SELECT a0, ace536358, ace536359, ace53635a, ace53635b FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoNSSTrust),
	).Scan(&trustClass, &trustServerAuth, &trustClientAuth, &trustCodeSigning, &trustEmail)
	require.NoError(t, err)

	assert.Equal(t, encodeUint32(ckoNSSTrust), trustClass)
	trustedDelegator := encodeUint32(cktNSSTrustedDelegator)
	assert.Equal(t, trustedDelegator, trustServerAuth)
	assert.Equal(t, trustedDelegator, trustClientAuth)
	assert.Equal(t, trustedDelegator, trustCodeSigning)
	assert.Equal(t, trustedDelegator, trustEmail)

	// Verify trust hashes.
	var sha1Hash, md5Hash []byte
	err = w.certDB.QueryRow(
		"SELECT ace5363b4, ace5363b5 FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoNSSTrust),
	).Scan(&sha1Hash, &md5Hash)
	require.NoError(t, err)

	expectedSHA1 := sha1.Sum(cert.Raw) //nolint:gosec
	expectedMD5 := md5.Sum(cert.Raw)   //nolint:gosec
	assert.Equal(t, expectedSHA1[:], sha1Hash)
	assert.Equal(t, expectedMD5[:], md5Hash)

	// Verify trust signatures exist in key4.db metaData.
	var sigCount int
	err = w.keyDB.QueryRow("SELECT COUNT(*) FROM metaData WHERE id LIKE 'sig_cert_%'").Scan(&sigCount)
	require.NoError(t, err)
	assert.Greater(t, sigCount, 0, "trust signatures should exist in key4.db")
}

func TestAddTrustedCANilCertificate(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	err = w.AddTrustedCA(nil, "some-label")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilCertificate)
}

func TestAddTrustedCAEmptyLabel(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	err = w.AddTrustedCA(cert, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyLabel)
}

func TestAddTrustedCAWriterClosed(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	cert := testCA(t)
	err = w.AddTrustedCA(cert, "label")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWriterClosed)
}

func TestAddTrustedCAMultipleCerts(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert1 := testCAWithSerial(t, 100)
	cert2 := testCAWithSerial(t, 200)

	// Add a small delay to ensure different object IDs.
	require.NoError(t, w.AddTrustedCA(cert1, "xkey-ca-1"))
	time.Sleep(2 * time.Second) // Ensure different time-based ID.
	require.NoError(t, w.AddTrustedCA(cert2, "xkey-ca-2"))

	// Both should be in the database. Count certificate objects (a0 = ckoCertificate).
	var certCount int
	err = w.certDB.QueryRow(
		"SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate),
	).Scan(&certCount)
	require.NoError(t, err)
	assert.Equal(t, 2, certCount)

	// Count trust objects.
	var trustCount int
	err = w.certDB.QueryRow(
		"SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoNSSTrust),
	).Scan(&trustCount)
	require.NoError(t, err)
	assert.Equal(t, 2, trustCount)
}

// --- RemoveByPrefix tests ---

func TestRemoveByPrefix(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	require.NoError(t, w.AddTrustedCA(cert, "xkey-remove-test"))

	// Verify it exists.
	var count int
	err = w.certDB.QueryRow("SELECT COUNT(*) FROM nssPublic").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should have cert + trust objects")

	// Remove by prefix.
	err = w.RemoveByPrefix("xkey-remove")
	require.NoError(t, err)

	// The certificate object has a matching label, so it should be removed.
	// The trust object has explicit-null as label, so it won't match the prefix.
	err = w.certDB.QueryRow("SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate)).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "certificate objects should be removed")
}

func TestRemoveByPrefixEmptyPrefix(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	err = w.RemoveByPrefix("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyPrefix)
}

func TestRemoveByPrefixWriterClosed(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	err = w.RemoveByPrefix("xkey")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWriterClosed)
}

func TestRemoveByPrefixNoMatch(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	require.NoError(t, w.AddTrustedCA(cert, "xkey-keep-this"))

	// Remove with non-matching prefix.
	err = w.RemoveByPrefix("nonexistent-prefix")
	require.NoError(t, err)

	// The certificate should still be there.
	var count int
	err = w.certDB.QueryRow("SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate)).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "certificate should not be removed")
}

// --- Close tests ---

func TestClose(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)

	err = w.Close()
	require.NoError(t, err)

	// Second close should be a no-op.
	err = w.Close()
	require.NoError(t, err)
}

func TestCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)

	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
}

// --- InitDir tests ---

func TestInitDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "newdir")

	err := InitDir(dir)
	require.NoError(t, err)

	// Verify all files exist.
	_, err = os.Stat(filepath.Join(dir, cert9DBFile))
	assert.NoError(t, err, "cert9.db should exist")

	_, err = os.Stat(filepath.Join(dir, key4DBFile))
	assert.NoError(t, err, "key4.db should exist")

	p11Content, err := os.ReadFile(filepath.Join(dir, pkcs11TxtFile))
	require.NoError(t, err)
	assert.Contains(t, string(p11Content), "NSS Internal PKCS #11 Module")

	// Verify the password entry was initialized.
	db, err := sql.Open("sqlite", filepath.Join(dir, key4DBFile))
	require.NoError(t, err)
	defer db.Close()

	var item1, item2 []byte
	err = db.QueryRow("SELECT item1, item2 FROM metaData WHERE id = 'password'").Scan(&item1, &item2)
	require.NoError(t, err)
	assert.Len(t, item1, 20)
	assert.Greater(t, len(item2), 0)
}

func TestInitDirExistingDir(t *testing.T) {
	dir := t.TempDir()

	// Initialize twice should not fail.
	require.NoError(t, InitDir(dir))
	require.NoError(t, InitDir(dir))

	// Verify files still exist.
	_, err := os.Stat(filepath.Join(dir, cert9DBFile))
	assert.NoError(t, err)
}

// --- Helper function tests ---

func TestExplicitNull(t *testing.T) {
	n := explicitNull()
	assert.Equal(t, []byte{0xA5, 0x00, 0x5A}, n)
}

func TestEncodeUint32(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00}},
		{"one", 1, []byte{0x00, 0x00, 0x00, 0x01}},
		{"ckoCertificate", ckoCertificate, []byte{0x00, 0x00, 0x00, 0x01}},
		{"ckoNSSTrust", ckoNSSTrust, []byte{0xCE, 0x53, 0x43, 0x53}},
		{"cktNSSTrustedDelegator", cktNSSTrustedDelegator, []byte{0xCE, 0x53, 0x43, 0x52}},
		{"maxUint32", 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeUint32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncodeBool(t *testing.T) {
	assert.Equal(t, []byte{0x01}, encodeBool(true))
	assert.Equal(t, []byte{0x00}, encodeBool(false))
}

func TestMarshalSerial(t *testing.T) {
	serial := big.NewInt(42)
	der, err := marshalSerial(serial)
	require.NoError(t, err)

	// Verify it's a valid ASN.1 INTEGER.
	var parsed *big.Int
	rest, err := asn1.Unmarshal(der, &parsed)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, 0, serial.Cmp(parsed))
}

func TestMarshalSerialLargeNumber(t *testing.T) {
	serial := new(big.Int)
	serial.SetString("123456789012345678901234567890", 10)
	der, err := marshalSerial(serial)
	require.NoError(t, err)

	var parsed *big.Int
	_, err = asn1.Unmarshal(der, &parsed)
	require.NoError(t, err)
	assert.Equal(t, 0, serial.Cmp(parsed))
}

func TestParseAttrHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint32
		wantErr  bool
	}{
		{"single_digit", "a0", 0x0, false},
		{"single_digit_nonzero", "a1", 0x1, false},
		{"two_digit", "a81", 0x81, false},
		{"three_digit", "a101", 0x101, false},
		{"three_digit_2", "a170", 0x170, false},
		{"eight_digit", "ace536358", 0xCE536358, false},
		{"eight_digit_2", "ace5363b4", 0xCE5363B4, false},
		{"no_a_prefix", "x81", 0, true},
		{"invalid_hex", "aggg", 0, true},
		{"too_short", "a", 0, true},
		{"single_char", "b", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseAttrHex(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestPkcs7Pad(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		padLen    int
	}{
		{"14_bytes_to_16", make([]byte, 14), 16, 16},
		{"16_bytes_to_32", make([]byte, 16), 16, 32},
		{"1_byte_to_16", make([]byte, 1), 16, 16},
		{"15_bytes_to_16", make([]byte, 15), 16, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.input, tt.blockSize)
			assert.Len(t, padded, tt.padLen)
			// Verify the padding byte value.
			padByte := padded[len(padded)-1]
			for i := len(padded) - int(padByte); i < len(padded); i++ {
				assert.Equal(t, padByte, padded[i])
			}
		})
	}
}

func TestEncodeSignatureData(t *testing.T) {
	attrType := uint32(0x81)
	attrValue := []byte("test-value")

	data := encodeSignatureData(attrType, attrValue)

	// Parse the encoded data:
	// 4-byte len + 4-byte zero ULONG + 4-byte len + 4-byte type ULONG + attrValue
	offset := 0

	// First piece: encode(0 as ULONG)
	pieceLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	assert.Equal(t, uint32(4), pieceLen)
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[offset:offset+4]))
	offset += 4

	// Second piece: encode(attrType as ULONG)
	pieceLen = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	assert.Equal(t, uint32(4), pieceLen)
	assert.Equal(t, attrType, binary.BigEndian.Uint32(data[offset:offset+4]))
	offset += 4

	// Remaining: raw attrValue
	assert.Equal(t, attrValue, data[offset:])
}

func TestAppendEncoded(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	result := appendEncoded(nil, data)

	assert.Len(t, result, 6)
	assert.Equal(t, uint32(2), binary.BigEndian.Uint32(result[0:4]))
	assert.Equal(t, data, result[4:6])
}

func TestAppendEncodedEmpty(t *testing.T) {
	result := appendEncoded(nil, nil)
	assert.Len(t, result, 4)
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(result[0:4]))
}

// --- ASN.1 structure tests ---

func TestMarshalPBES2Roundtrip(t *testing.T) {
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	ciphertext := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	_, err = rand.Read(ciphertext)
	require.NoError(t, err)

	blob, err := marshalPBES2(salt, iv, ciphertext)
	require.NoError(t, err)
	assert.Greater(t, len(blob), 0)

	// Verify it's valid ASN.1 by unmarshaling the outer SEQUENCE.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(blob, &outer)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, asn1.TagSequence, outer.Tag)
}

func TestMarshalPBMAC1Roundtrip(t *testing.T) {
	salt := make([]byte, 32)
	hmacVal := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	_, err = rand.Read(hmacVal)
	require.NoError(t, err)

	blob, err := marshalPBMAC1(salt, hmacVal)
	require.NoError(t, err)
	assert.Greater(t, len(blob), 0)

	// Verify it's valid ASN.1.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(blob, &outer)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, asn1.TagSequence, outer.Tag)
}

// --- Integration-style tests ---

func TestFullWorkflow(t *testing.T) {
	dir := t.TempDir()

	// Initialize the directory.
	require.NoError(t, InitDir(dir))

	// Open a writer and add two CAs.
	w, err := NewWriter(dir)
	require.NoError(t, err)

	cert1 := testCAWithSerial(t, 1001)
	cert2 := testCAWithSerial(t, 1002)

	require.NoError(t, w.AddTrustedCA(cert1, "xkey-ca-alpha"))
	time.Sleep(2 * time.Second) // Ensure different time-based IDs.
	require.NoError(t, w.AddTrustedCA(cert2, "xkey-ca-beta"))

	// Verify both are stored.
	var totalCount int
	err = w.certDB.QueryRow("SELECT COUNT(*) FROM nssPublic").Scan(&totalCount)
	require.NoError(t, err)
	assert.Equal(t, 4, totalCount, "2 certs + 2 trust objects = 4 rows")

	// Remove one by prefix.
	require.NoError(t, w.RemoveByPrefix("xkey-ca-alpha"))

	// Verify removal.
	var remaining int
	err = w.certDB.QueryRow(
		"SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate),
	).Scan(&remaining)
	require.NoError(t, err)
	assert.Equal(t, 1, remaining, "only xkey-ca-beta cert should remain")

	require.NoError(t, w.Close())

	// Reopen and verify persistence.
	w2, err := NewWriter(dir)
	require.NoError(t, err)
	defer w2.Close()

	err = w2.certDB.QueryRow(
		"SELECT COUNT(*) FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate),
	).Scan(&remaining)
	require.NoError(t, err)
	assert.Equal(t, 1, remaining, "data should persist after reopen")
}

func TestCertObjectAttributes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	require.NoError(t, w.AddTrustedCA(cert, "xkey-attr-test"))

	// Verify all certificate attributes.
	var (
		aClass   []byte // a0
		aToken   []byte // a1
		aPrivate []byte // a2
		aLabel   []byte // a3
		aValue   []byte // a11
		aCertTyp []byte // a80
		aIssuer  []byte // a81
		aSerial  []byte // a82
		aSubject []byte // a101
		aID      []byte // a102
		aOverExt []byte // a170
	)
	err = w.certDB.QueryRow(
		"SELECT a0, a1, a2, a3, a11, a80, a81, a82, a101, a102, a170 FROM nssPublic WHERE a0 = ?",
		encodeUint32(ckoCertificate),
	).Scan(&aClass, &aToken, &aPrivate, &aLabel, &aValue, &aCertTyp, &aIssuer, &aSerial, &aSubject, &aID, &aOverExt)
	require.NoError(t, err)

	assert.Equal(t, encodeUint32(ckoCertificate), aClass, "CKA_CLASS")
	assert.Equal(t, encodeBool(true), aToken, "CKA_TOKEN")
	assert.Equal(t, encodeBool(false), aPrivate, "CKA_PRIVATE")
	assert.Equal(t, []byte("xkey-attr-test"), aLabel, "CKA_LABEL")
	assert.Equal(t, cert.Raw, aValue, "CKA_VALUE")
	assert.Equal(t, encodeUint32(0), aCertTyp, "CKA_CERTIFICATE_TYPE")
	assert.Equal(t, cert.RawIssuer, aIssuer, "CKA_ISSUER")
	assert.Equal(t, cert.RawSubject, aSubject, "CKA_SUBJECT")
	assert.Equal(t, cert.SubjectKeyId, aID, "CKA_ID")
	assert.Equal(t, encodeBool(true), aOverExt, "CKA_NSS_OVERRIDE_EXTENSIONS")

	// Verify serial is valid ASN.1 INTEGER TLV.
	var parsedSerial *big.Int
	_, err = asn1.Unmarshal(aSerial, &parsedSerial)
	require.NoError(t, err)
	assert.Equal(t, 0, cert.SerialNumber.Cmp(parsedSerial))
}

func TestTrustObjectAttributes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	require.NoError(t, w.AddTrustedCA(cert, "xkey-trust-test"))

	// Verify all trust attributes.
	var (
		aClass      []byte
		aToken      []byte
		aPrivate    []byte
		aLabel      []byte
		aIssuer     []byte
		aSerial     []byte
		aOverExt    []byte
		aServerAuth []byte
		aClientAuth []byte
		aCodeSign   []byte
		aEmail      []byte
		aStepUp     []byte
		aSHA1       []byte
		aMD5        []byte
	)
	err = w.certDB.QueryRow(
		`SELECT a0, a1, a2, a3, a81, a82, a170,
		        ace536358, ace536359, ace53635a, ace53635b, ace536360,
		        ace5363b4, ace5363b5
		 FROM nssPublic WHERE a0 = ?`,
		encodeUint32(ckoNSSTrust),
	).Scan(&aClass, &aToken, &aPrivate, &aLabel, &aIssuer, &aSerial, &aOverExt,
		&aServerAuth, &aClientAuth, &aCodeSign, &aEmail, &aStepUp,
		&aSHA1, &aMD5)
	require.NoError(t, err)

	assert.Equal(t, encodeUint32(ckoNSSTrust), aClass, "CKA_CLASS")
	assert.Equal(t, encodeBool(true), aToken, "CKA_TOKEN")
	assert.Equal(t, encodeBool(false), aPrivate, "CKA_PRIVATE")
	assert.Equal(t, explicitNull(), aLabel, "CKA_LABEL should be explicit null")
	assert.Equal(t, cert.RawIssuer, aIssuer, "CKA_ISSUER")
	assert.Equal(t, encodeBool(true), aOverExt, "CKA_NSS_OVERRIDE_EXTENSIONS")

	trustedDelegator := encodeUint32(cktNSSTrustedDelegator)
	assert.Equal(t, trustedDelegator, aServerAuth, "TRUST_SERVER_AUTH")
	assert.Equal(t, trustedDelegator, aClientAuth, "TRUST_CLIENT_AUTH")
	assert.Equal(t, trustedDelegator, aCodeSign, "TRUST_CODE_SIGNING")
	assert.Equal(t, trustedDelegator, aEmail, "TRUST_EMAIL_PROTECTION")
	assert.Equal(t, encodeBool(false), aStepUp, "TRUST_STEP_UP_APPROVED")

	expectedSHA1 := sha1.Sum(cert.Raw) //nolint:gosec
	expectedMD5 := md5.Sum(cert.Raw)   //nolint:gosec
	assert.Equal(t, expectedSHA1[:], aSHA1, "CERT_SHA1_HASH")
	assert.Equal(t, expectedMD5[:], aMD5, "CERT_MD5_HASH")
}

func TestTrustSignaturesInKey4DB(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	cert := testCA(t)
	require.NoError(t, w.AddTrustedCA(cert, "xkey-sig-test"))

	// Count trust signatures (excludes the "password" entry).
	var sigCount int
	err = w.keyDB.QueryRow(
		"SELECT COUNT(*) FROM metaData WHERE id LIKE 'sig_cert_%'",
	).Scan(&sigCount)
	require.NoError(t, err)

	// Trust object has 14 attributes, each should have a PBMAC1 signature.
	assert.Equal(t, 14, sigCount, "each trust attribute should have a PBMAC1 signature")

	// Verify each signature is valid ASN.1.
	rows, err := w.keyDB.Query("SELECT item1 FROM metaData WHERE id LIKE 'sig_cert_%'")
	require.NoError(t, err)
	defer rows.Close()

	for rows.Next() {
		var item1 []byte
		require.NoError(t, rows.Scan(&item1))
		assert.Greater(t, len(item1), 0, "signature blob should not be empty")

		// Verify it's valid ASN.1.
		var outer asn1.RawValue
		rest, err := asn1.Unmarshal(item1, &outer)
		assert.NoError(t, err, "signature should be valid ASN.1")
		assert.Empty(t, rest)
	}
	require.NoError(t, rows.Err())
}

func TestGenerateObjectID(t *testing.T) {
	id := generateObjectID()
	assert.Greater(t, id, int64(0))
	assert.LessOrEqual(t, id, int64(0x3FFFFFFF), "should be masked to 30 bits")
}

func TestDeriveIntermediateKey(t *testing.T) {
	salt := make([]byte, 20)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	key := deriveIntermediateKey(salt)
	assert.Len(t, key, 20, "SHA1 output is 20 bytes")

	// Same salt should produce same key (deterministic).
	key2 := deriveIntermediateKey(salt)
	assert.Equal(t, key, key2)

	// Different salt should produce different key.
	salt2 := make([]byte, 20)
	_, err = rand.Read(salt2)
	require.NoError(t, err)
	key3 := deriveIntermediateKey(salt2)
	assert.NotEqual(t, key, key3)
}

func TestBuildPBES2PasswordEntry(t *testing.T) {
	intermediateKey := deriveIntermediateKey(make([]byte, 20))

	blob, err := buildPBES2PasswordEntry(intermediateKey)
	require.NoError(t, err)
	assert.Greater(t, len(blob), 0)

	// Verify it's valid ASN.1.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(blob, &outer)
	require.NoError(t, err)
	assert.Empty(t, rest)
}

func TestBuildPBES2PasswordEntryDifferentEachTime(t *testing.T) {
	intermediateKey := deriveIntermediateKey(make([]byte, 20))

	blob1, err := buildPBES2PasswordEntry(intermediateKey)
	require.NoError(t, err)

	blob2, err := buildPBES2PasswordEntry(intermediateKey)
	require.NoError(t, err)

	// Should be different due to random salt and IV.
	assert.NotEqual(t, blob1, blob2)
}
