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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // NSS requires MD5 hash for cert fingerprint
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // NSS requires SHA1 hash for cert fingerprint
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
	"golang.org/x/crypto/pbkdf2"
)

const (
	// PKCS#11 object classes.
	ckoCertificate uint32 = 0x00000001
	ckoNSSTrust    uint32 = 0xCE534353

	// Trust values.
	cktNSSTrustedDelegator uint32 = 0xCE534352

	// NSS explicit-null sentinel (distinct from SQL NULL).
	// Used for attributes that must be present but have no meaningful value.
	explicitNullByte0 byte = 0xA5
	explicitNullByte1 byte = 0x00
	explicitNullByte2 byte = 0x5A

	// Database file names.
	cert9DBFile  = "cert9.db"
	key4DBFile   = "key4.db"
	pkcs11TxtFile = "pkcs11.txt"

	// File permissions.
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

// Well-known ASN.1 OIDs used in PBES2/PBMAC1 structures.
var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBMAC1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// pkcs11TxtContent is the standard NSS internal module configuration.
const pkcs11TxtContent = `library=
name=NSS Internal PKCS #11 Module
parameters=configdir='sql:.' certPrefix='' keyPrefix='' secmod='secmod.db' flags= updatedir='' updateCertPrefix='' updateKeyPrefix='' updateid='' updateTokenDescription=''
NSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={slotFlags=[ECC,RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] askpw=any timeout=30})
`

// cert9.db schema with all known NSS attribute columns.
const cert9Schema = `CREATE TABLE IF NOT EXISTS nssPublic (
  id PRIMARY KEY UNIQUE ON CONFLICT ABORT,
  a0, a1, a2, a3, a10, a11, a12,
  a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b,
  a90,
  a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c,
  a110, a111,
  a120, a121, a122, a123, a124, a125, a126, a127, a128, a129,
  a130, a131, a132, a133, a134,
  a160, a161, a162, a163, a164, a165, a166,
  a170,
  a180, a181,
  a200, a201, a202,
  a210,
  a300, a301, a302,
  a400, a401, a402, a403, a404, a405, a406,
  a480, a481, a482,
  a500, a501, a502, a503,
  a40000211, a40000212,
  a80000001,
  ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358,
  ace534364, ace534365, ace534366, ace534367, ace534368, ace534369,
  ace534373, ace534374,
  ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357,
  ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360,
  ace5363b4, ace5363b5,
  ad5a0db00);
CREATE INDEX IF NOT EXISTS issuer ON nssPublic (a81);
CREATE INDEX IF NOT EXISTS subject ON nssPublic (a101);
CREATE INDEX IF NOT EXISTS label ON nssPublic (a3);
CREATE INDEX IF NOT EXISTS ckaid ON nssPublic (a102);`

// key4.db schema.
const key4Schema = `CREATE TABLE IF NOT EXISTS nssPrivate (
  id PRIMARY KEY UNIQUE ON CONFLICT ABORT,
  a0, a1, a2, a3, a10, a11, a12,
  a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b,
  a90,
  a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c,
  a110, a111,
  a120, a121, a122, a123, a124, a125, a126, a127, a128, a129,
  a130, a131, a132, a133, a134,
  a160, a161, a162, a163, a164, a165, a166,
  a170,
  a180, a181,
  a200, a201, a202,
  a210,
  a300, a301, a302,
  a400, a401, a402, a403, a404, a405, a406,
  a480, a481, a482,
  a500, a501, a502, a503,
  a40000211, a40000212,
  a80000001,
  ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358,
  ace534364, ace534365, ace534366, ace534367, ace534368, ace534369,
  ace534373, ace534374,
  ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357,
  ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360,
  ace5363b4, ace5363b5,
  ad5a0db00);
CREATE INDEX IF NOT EXISTS issuer ON nssPrivate (a81);
CREATE INDEX IF NOT EXISTS subject ON nssPrivate (a101);
CREATE INDEX IF NOT EXISTS label ON nssPrivate (a3);
CREATE INDEX IF NOT EXISTS ckaid ON nssPrivate (a102);
CREATE TABLE IF NOT EXISTS metaData (
  id PRIMARY KEY UNIQUE ON CONFLICT REPLACE,
  item1,
  item2);`

// Writer writes trusted CA certificates into NSS cert9.db and key4.db databases.
type Writer struct {
	certDB          *sql.DB
	keyDB           *sql.DB
	dir             string
	intermediateKey []byte
	closed          bool
}

// NewWriter opens (or creates) the cert9.db and key4.db databases in the
// given directory. The directory must already exist. Call Close when finished.
func NewWriter(nssdbDir string) (*Writer, error) {
	info, err := os.Stat(nssdbDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDirNotExist, nssdbDir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrDirNotExist, nssdbDir)
	}

	certDBPath := filepath.Join(nssdbDir, cert9DBFile)
	keyDBPath := filepath.Join(nssdbDir, key4DBFile)

	certDB, err := sql.Open("sqlite", certDBPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cert9.db: %s", ErrOpenDatabase, err)
	}

	keyDB, err := sql.Open("sqlite", keyDBPath)
	if err != nil {
		certDB.Close()
		return nil, fmt.Errorf("%w: key4.db: %s", ErrOpenDatabase, err)
	}

	// Enable WAL mode for better concurrent read performance.
	for _, db := range []*sql.DB{certDB, keyDB} {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			certDB.Close()
			keyDB.Close()
			return nil, fmt.Errorf("%w: %s", ErrCreateSchema, err)
		}
	}

	if _, err := certDB.Exec(cert9Schema); err != nil {
		certDB.Close()
		keyDB.Close()
		return nil, fmt.Errorf("%w: cert9.db: %s", ErrCreateSchema, err)
	}

	if _, err := keyDB.Exec(key4Schema); err != nil {
		certDB.Close()
		keyDB.Close()
		return nil, fmt.Errorf("%w: key4.db: %s", ErrCreateSchema, err)
	}

	w := &Writer{
		certDB: certDB,
		keyDB:  keyDB,
		dir:    nssdbDir,
	}

	// Initialize the password entry if not already present, and derive the
	// intermediate key used for trust object signatures.
	if err := w.ensurePassword(); err != nil {
		certDB.Close()
		keyDB.Close()
		return nil, err
	}

	return w, nil
}

// AddTrustedCA inserts a certificate object and a corresponding trust object
// into cert9.db, then writes PBMAC1 signatures for the trust attributes
// into key4.db metaData.
func (w *Writer) AddTrustedCA(cert *x509.Certificate, label string) error {
	if w.closed {
		return ErrWriterClosed
	}
	if cert == nil {
		return ErrNilCertificate
	}
	if label == "" {
		return ErrEmptyLabel
	}

	serialDER, err := marshalSerial(cert.SerialNumber)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSerialEncode, err)
	}

	baseID := generateObjectID()
	certID := baseID
	trustID := baseID + 1

	// Build attribute maps.
	certAttrs := w.buildCertAttrs(cert, label, serialDER)
	trustAttrs := w.buildTrustAttrs(cert, serialDER)

	// Insert certificate object into cert9.db.
	if err := w.insertObject(w.certDB, "nssPublic", certID, certAttrs); err != nil {
		return fmt.Errorf("%w: %s", ErrInsertCertificate, err)
	}

	// Insert trust object into cert9.db.
	if err := w.insertObject(w.certDB, "nssPublic", trustID, trustAttrs); err != nil {
		return fmt.Errorf("%w: %s", ErrInsertTrust, err)
	}

	// Write PBMAC1 signatures for trust object attributes into key4.db.
	if err := w.writeTrustSignatures(trustID, trustAttrs); err != nil {
		return fmt.Errorf("%w: %s", ErrSignatureInsert, err)
	}

	return nil
}

// RemoveByPrefix removes all certificate and trust objects from cert9.db whose
// label (column a3) starts with the given prefix. It also removes associated
// trust signatures from key4.db metaData.
func (w *Writer) RemoveByPrefix(prefix string) error {
	if w.closed {
		return ErrWriterClosed
	}
	if prefix == "" {
		return ErrEmptyPrefix
	}

	// Find object IDs to remove so we can clean up key4.db signatures too.
	rows, err := w.certDB.Query(
		"SELECT id FROM nssPublic WHERE typeof(a3) = 'blob' AND CAST(a3 AS TEXT) LIKE ?",
		prefix+"%",
	)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrRemoveCertificate, err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("%w: %s", ErrRemoveCertificate, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: %s", ErrRemoveCertificate, err)
	}

	if len(ids) == 0 {
		return nil
	}

	// Delete from cert9.db.
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "DELETE FROM nssPublic WHERE id IN (" + strings.Join(placeholders, ",") + ")"
	if _, err := w.certDB.Exec(query, args...); err != nil {
		return fmt.Errorf("%w: %s", ErrRemoveCertificate, err)
	}

	// Delete trust signatures from key4.db metaData.
	for _, id := range ids {
		sigPrefix := fmt.Sprintf("sig_cert_%x_%%", id)
		if _, err := w.keyDB.Exec("DELETE FROM metaData WHERE id LIKE ?", sigPrefix); err != nil {
			return fmt.Errorf("%w: %s", ErrRemoveTrust, err)
		}
	}

	return nil
}

// Close closes both the cert9.db and key4.db database connections.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	var errs []string
	if err := w.certDB.Close(); err != nil {
		errs = append(errs, "cert9.db: "+err.Error())
	}
	if err := w.keyDB.Close(); err != nil {
		errs = append(errs, "key4.db: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrCloseDatabase, strings.Join(errs, "; "))
	}
	return nil
}

// InitDir creates the NSS database directory (if needed) and initializes
// cert9.db, key4.db, and pkcs11.txt. It is safe to call on an existing
// directory; the schema uses IF NOT EXISTS.
func InitDir(nssdbDir string) error {
	if err := os.MkdirAll(nssdbDir, dirPerm); err != nil {
		return fmt.Errorf("%w: %s", ErrInitDir, err)
	}

	// Write pkcs11.txt.
	p11Path := filepath.Join(nssdbDir, pkcs11TxtFile)
	if err := os.WriteFile(p11Path, []byte(pkcs11TxtContent), filePerm); err != nil {
		return fmt.Errorf("%w: %s", ErrWritePKCS11Txt, err)
	}

	// Open and close a Writer to create the schema and password entry.
	w, err := NewWriter(nssdbDir)
	if err != nil {
		return err
	}
	return w.Close()
}

// ---- internal helpers ----

// explicitNull returns the 3-byte NSS explicit-null sentinel.
func explicitNull() []byte {
	return []byte{explicitNullByte0, explicitNullByte1, explicitNullByte2}
}

// encodeUint32 encodes a uint32 as 4 bytes big-endian.
func encodeUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// encodeBool encodes a boolean as a single byte.
func encodeBool(v bool) []byte {
	if v {
		return []byte{0x01}
	}
	return []byte{0x00}
}

// generateObjectID returns a time-based object ID masked to 30 bits.
func generateObjectID() int64 {
	return time.Now().Unix() & 0x3FFFFFFF
}

// marshalSerial encodes a certificate serial number as a full ASN.1 INTEGER TLV.
func marshalSerial(serial *big.Int) ([]byte, error) {
	return asn1.Marshal(serial)
}

// buildCertAttrs returns the attribute map for a certificate object.
func (w *Writer) buildCertAttrs(cert *x509.Certificate, label string, serialDER []byte) map[string][]byte {
	return map[string][]byte{
		"a0":   encodeUint32(ckoCertificate),   // CKA_CLASS
		"a1":   encodeBool(true),               // CKA_TOKEN
		"a2":   encodeBool(false),              // CKA_PRIVATE
		"a3":   []byte(label),                  // CKA_LABEL
		"a11":  cert.Raw,                       // CKA_VALUE
		"a80":  encodeUint32(0),                // CKA_CERTIFICATE_TYPE = CKC_X_509
		"a81":  cert.RawIssuer,                 // CKA_ISSUER
		"a82":  serialDER,                      // CKA_SERIAL_NUMBER
		"a101": cert.RawSubject,                // CKA_SUBJECT
		"a102": cert.SubjectKeyId,              // CKA_ID
		"a170": encodeBool(true),               // CKA_NSS_OVERRIDE_EXTENSIONS
	}
}

// buildTrustAttrs returns the attribute map for a trust object.
func (w *Writer) buildTrustAttrs(cert *x509.Certificate, serialDER []byte) map[string][]byte {
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec
	md5Sum := md5.Sum(cert.Raw)   //nolint:gosec

	return map[string][]byte{
		"a0":        encodeUint32(ckoNSSTrust),             // CKA_CLASS
		"a1":        encodeBool(true),                      // CKA_TOKEN
		"a2":        encodeBool(false),                     // CKA_PRIVATE
		"a3":        explicitNull(),                        // CKA_LABEL (explicit null)
		"a81":       cert.RawIssuer,                        // CKA_ISSUER
		"a82":       serialDER,                             // CKA_SERIAL_NUMBER
		"a170":      encodeBool(true),                      // CKA_NSS_OVERRIDE_EXTENSIONS
		"ace536358": encodeUint32(cktNSSTrustedDelegator),  // TRUST_SERVER_AUTH
		"ace536359": encodeUint32(cktNSSTrustedDelegator),  // TRUST_CLIENT_AUTH
		"ace53635a": encodeUint32(cktNSSTrustedDelegator),  // TRUST_CODE_SIGNING
		"ace53635b": encodeUint32(cktNSSTrustedDelegator),  // TRUST_EMAIL_PROTECTION
		"ace536360": encodeBool(false),                     // TRUST_STEP_UP_APPROVED
		"ace5363b4": sha1Sum[:],                            // CERT_SHA1_HASH
		"ace5363b5": md5Sum[:],                             // CERT_MD5_HASH
	}
}

// insertObject inserts a row into the specified table with the given ID and
// attribute column values.
func (w *Writer) insertObject(db *sql.DB, table string, id int64, attrs map[string][]byte) error {
	cols := []string{"id"}
	placeholders := []string{"?"}
	values := []any{id}

	for col, val := range attrs {
		cols = append(cols, col)
		placeholders = append(placeholders, "?")
		values = append(values, val)
	}

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)",
		table,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	_, err := db.Exec(query, values...)
	return err
}

// ---- password and signature management ----

// ensurePassword checks whether the key4.db metaData already has a "password"
// entry. If not, it creates one for an empty password and derives the
// intermediate key. If the entry exists, it re-derives the intermediate key
// from the stored global salt.
func (w *Writer) ensurePassword() error {
	var item1 []byte
	err := w.keyDB.QueryRow("SELECT item1 FROM metaData WHERE id = 'password'").Scan(&item1)
	if err == nil && len(item1) > 0 {
		// Password entry exists; derive intermediate key from stored global salt.
		w.intermediateKey = deriveIntermediateKey(item1)
		return nil
	}

	// Generate a new password entry for empty password.
	globalSalt := make([]byte, 20)
	if _, err := rand.Read(globalSalt); err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordInit, err)
	}

	w.intermediateKey = deriveIntermediateKey(globalSalt)

	item2, err := buildPBES2PasswordEntry(w.intermediateKey)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordInit, err)
	}

	_, err = w.keyDB.Exec(
		"INSERT OR REPLACE INTO metaData (id, item1, item2) VALUES (?, ?, ?)",
		"password", globalSalt, item2,
	)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordInit, err)
	}

	return nil
}

// deriveIntermediateKey computes SHA1(globalSalt + "") for an empty password.
func deriveIntermediateKey(globalSalt []byte) []byte {
	h := sha1.New() //nolint:gosec
	h.Write(globalSalt)
	// Empty password: no additional bytes written.
	return h.Sum(nil)
}

// buildPBES2PasswordEntry creates the ASN.1 PBES2 blob that encrypts
// "password-check" using AES-256-CBC with a key derived from the
// intermediate key via PBKDF2.
func buildPBES2PasswordEntry(intermediateKey []byte) ([]byte, error) {
	perKeySalt := make([]byte, 32)
	if _, err := rand.Read(perKeySalt); err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	derivedKey := pbkdf2.Key(intermediateKey, perKeySalt, 1, 32, sha256.New)

	// Encrypt "password-check" with AES-256-CBC and PKCS#7 padding.
	plaintext := pkcs7Pad([]byte("password-check"), aes.BlockSize)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	return marshalPBES2(perKeySalt, iv, ciphertext)
}

// writeTrustSignatures writes a PBMAC1 signature into key4.db metaData for
// each non-null attribute on the trust object.
func (w *Writer) writeTrustSignatures(trustID int64, attrs map[string][]byte) error {
	for attrName, attrValue := range attrs {
		attrType, err := parseAttrHex(attrName)
		if err != nil {
			continue // skip attributes that don't parse as hex (shouldn't happen)
		}

		sigBlob, err := w.buildPBMAC1Signature(attrType, attrValue)
		if err != nil {
			return err
		}

		sigID := fmt.Sprintf("sig_cert_%x_%s", trustID, attrName)
		_, err = w.keyDB.Exec(
			"INSERT OR REPLACE INTO metaData (id, item1, item2) VALUES (?, ?, NULL)",
			sigID, sigBlob,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// buildPBMAC1Signature creates the ASN.1 PBMAC1 blob for a single attribute.
func (w *Writer) buildPBMAC1Signature(attrType uint32, attrValue []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	sigKey := pbkdf2.Key(w.intermediateKey, salt, 1, 32, sha256.New)

	// Build the data to sign:
	// encode(0_as_ulong) + encode(attrType_as_ulong) + attrValue
	// where encode(x) = len(x) as 4-byte BE + x
	data := encodeSignatureData(attrType, attrValue)

	mac := hmac.New(sha256.New, sigKey)
	mac.Write(data)
	hmacValue := mac.Sum(nil)

	return marshalPBMAC1(salt, hmacValue)
}

// encodeSignatureData builds the HMAC input for a trust attribute signature.
// Format: encode(0_as_ulong_4bytes) + encode(attrType_as_ulong_4bytes) + attrValue
// where encode(piece) = len(piece) as 4-byte big-endian + piece.
func encodeSignatureData(attrType uint32, attrValue []byte) []byte {
	zeroULONG := encodeUint32(0)
	typeULONG := encodeUint32(attrType)

	// encode(zeroULONG): 4-byte length + 4-byte value
	// encode(typeULONG): 4-byte length + 4-byte value
	// attrValue: raw bytes
	totalLen := 4 + len(zeroULONG) + 4 + len(typeULONG) + len(attrValue)
	buf := make([]byte, 0, totalLen)

	buf = appendEncoded(buf, zeroULONG)
	buf = appendEncoded(buf, typeULONG)
	buf = append(buf, attrValue...)

	return buf
}

// appendEncoded appends len(data) as 4-byte big-endian followed by data.
func appendEncoded(buf, data []byte) []byte {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	buf = append(buf, lenBuf...)
	buf = append(buf, data...)
	return buf
}

// parseAttrHex parses an attribute column name like "a81" or "ace536358"
// into its PKCS#11 attribute type integer. The name must start with "a"
// followed by a hex-encoded integer (e.g., "a0" = 0x0, "a81" = 0x81,
// "ace536358" = 0xCE536358).
func parseAttrHex(name string) (uint32, error) {
	if len(name) < 2 || name[0] != 'a' {
		return 0, fmt.Errorf("invalid attribute name: %s", name)
	}
	hexStr := name[1:]
	val, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid hex in attribute name %s: %w", name, err)
	}
	return uint32(val), nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS#7.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// ---- ASN.1 structures ----

// pbes2Params represents the full PBES2 ASN.1 wrapper.
type pbes2Params struct {
	AlgorithmID pbes2AlgorithmID
	Encrypted   []byte
}

type pbes2AlgorithmID struct {
	OID    asn1.ObjectIdentifier
	Params pbes2InnerParams
}

type pbes2InnerParams struct {
	KDF        pbkdf2Params
	Encryption encryptionParams
}

type pbkdf2Params struct {
	OID    asn1.ObjectIdentifier
	Params pbkdf2InnerParams
}

type pbkdf2InnerParams struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        algorithmOID
}

type algorithmOID struct {
	OID asn1.ObjectIdentifier
}

type encryptionParams struct {
	OID asn1.ObjectIdentifier
	IV  []byte
}

// marshalPBES2 creates the ASN.1 PBES2 structure for the password entry.
func marshalPBES2(salt, iv, ciphertext []byte) ([]byte, error) {
	p := pbes2Params{
		AlgorithmID: pbes2AlgorithmID{
			OID: oidPBES2,
			Params: pbes2InnerParams{
				KDF: pbkdf2Params{
					OID: oidPBKDF2,
					Params: pbkdf2InnerParams{
						Salt:       salt,
						Iterations: 1,
						KeyLength:  32,
						PRF: algorithmOID{
							OID: oidHMACWithSHA256,
						},
					},
				},
				Encryption: encryptionParams{
					OID: oidAES256CBC,
					IV:  iv,
				},
			},
		},
		Encrypted: ciphertext,
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("%w: PBES2: %s", ErrASN1Marshal, err)
	}
	return b, nil
}

// pbmac1Params represents the full PBMAC1 ASN.1 wrapper.
type pbmac1Params struct {
	AlgorithmID pbmac1AlgorithmID
	HMAC        []byte
}

type pbmac1AlgorithmID struct {
	OID    asn1.ObjectIdentifier
	Params pbmac1InnerParams
}

type pbmac1InnerParams struct {
	KDF pbkdf2Params
	MAC algorithmOID
}

// marshalPBMAC1 creates the ASN.1 PBMAC1 structure for a trust signature.
func marshalPBMAC1(salt, hmacValue []byte) ([]byte, error) {
	p := pbmac1Params{
		AlgorithmID: pbmac1AlgorithmID{
			OID: oidPBMAC1,
			Params: pbmac1InnerParams{
				KDF: pbkdf2Params{
					OID: oidPBKDF2,
					Params: pbkdf2InnerParams{
						Salt:       salt,
						Iterations: 1,
						KeyLength:  32,
						PRF: algorithmOID{
							OID: oidHMACWithSHA256,
						},
					},
				},
				MAC: algorithmOID{
					OID: oidHMACWithSHA256,
				},
			},
		},
		HMAC: hmacValue,
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("%w: PBMAC1: %s", ErrASN1Marshal, err)
	}
	return b, nil
}
