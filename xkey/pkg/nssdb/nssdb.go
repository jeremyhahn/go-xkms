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
	"crypto/md5" //nolint:gosec // NSS requires MD5 hash for cert fingerprint
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
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite" // pure-Go SQLite driver
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
	cert9DBFile   = "cert9.db"
	key4DBFile    = "key4.db"
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
		return nil, &DetailError{Err: ErrDirNotExist, Detail: fmt.Sprintf(": %s", nssdbDir)}
	}
	if !info.IsDir() {
		return nil, &DetailError{Err: ErrDirNotExist, Detail: fmt.Sprintf(": %s is not a directory", nssdbDir)}
	}

	certDBPath := filepath.Join(nssdbDir, cert9DBFile)
	keyDBPath := filepath.Join(nssdbDir, key4DBFile)

	certDB, err := sql.Open("sqlite", certDBPath)
	if err != nil {
		return nil, &DetailError{Err: ErrOpenDatabase, Detail: fmt.Sprintf(": cert9.db: %s", err)}
	}

	keyDB, err := sql.Open("sqlite", keyDBPath)
	if err != nil {
		_ = certDB.Close()
		return nil, &DetailError{Err: ErrOpenDatabase, Detail: fmt.Sprintf(": key4.db: %s", err)}
	}

	// Enable WAL mode for better concurrent read performance.
	for _, db := range []*sql.DB{certDB, keyDB} {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			_ = certDB.Close()
			_ = keyDB.Close()
			return nil, &DetailError{Err: ErrCreateSchema, Detail: fmt.Sprintf(": %s", err)}
		}
	}

	if _, err := certDB.Exec(cert9Schema); err != nil {
		_ = certDB.Close()
		_ = keyDB.Close()
		return nil, &DetailError{Err: ErrCreateSchema, Detail: fmt.Sprintf(": cert9.db: %s", err)}
	}

	if _, err := keyDB.Exec(key4Schema); err != nil {
		_ = certDB.Close()
		_ = keyDB.Close()
		return nil, &DetailError{Err: ErrCreateSchema, Detail: fmt.Sprintf(": key4.db: %s", err)}
	}

	w := &Writer{
		certDB: certDB,
		keyDB:  keyDB,
		dir:    nssdbDir,
	}

	// Initialize the password entry if not already present, and derive the
	// intermediate key used for trust object signatures.
	if err := w.ensurePassword(); err != nil {
		_ = certDB.Close()
		_ = keyDB.Close()
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
		return &DetailError{Err: ErrSerialEncode, Detail: fmt.Sprintf(": %s", err)}
	}

	baseID := generateObjectID()
	certID := baseID
	trustID := baseID + 1

	// Build attribute maps.
	certAttrs := w.buildCertAttrs(cert, label, serialDER)
	trustAttrs := w.buildTrustAttrs(cert, serialDER)

	// Insert certificate object into cert9.db.
	if err := w.insertObject(w.certDB, "nssPublic", certID, certAttrs); err != nil {
		return &DetailError{Err: ErrInsertCertificate, Detail: fmt.Sprintf(": %s", err)}
	}

	// Insert trust object into cert9.db.
	if err := w.insertObject(w.certDB, "nssPublic", trustID, trustAttrs); err != nil {
		return &DetailError{Err: ErrInsertTrust, Detail: fmt.Sprintf(": %s", err)}
	}

	// Write PBMAC1 signatures for trust object attributes into key4.db.
	if err := w.writeTrustSignatures(trustID, trustAttrs); err != nil {
		return &DetailError{Err: ErrSignatureInsert, Detail: fmt.Sprintf(": %s", err)}
	}

	return nil
}

// RemoveByPrefix removes certificate objects whose label (column a3) starts
// with the given prefix AND every trust object whose CKA_ISSUER +
// CKA_SERIAL_NUMBER pair matches one of those certificates.
//
// Trust objects carry no label (CKA_LABEL is explicit-null per the NSS
// on-disk format), so a label-prefix match alone leaves the trust objects
// behind. NSS later picks one of the stale trust objects when looking up
// trust for a re-added certificate, and the corresponding HMAC signatures
// from the previous run no longer validate — the cert then shows ",,"
// trust flags despite a fresh, valid trust object also existing in the
// database. Re-syncing the same certificate set repeatedly compounds the
// problem: every sync layered another stale trust object on top.
//
// Associated key4.db HMAC signatures are removed for every deleted object,
// both certificate IDs and trust IDs.
func (w *Writer) RemoveByPrefix(prefix string) error {
	if w.closed {
		return ErrWriterClosed
	}
	if prefix == "" {
		return ErrEmptyPrefix
	}

	// Capture (id, issuer, serial) for every certificate matching the label
	// prefix. The issuer+serial pairs are what links a trust object to its
	// certificate in NSS.
	rows, err := w.certDB.Query(
		"SELECT id, a81, a82 FROM nssPublic WHERE typeof(a3) = 'blob' AND CAST(a3 AS TEXT) LIKE ?",
		prefix+"%",
	)
	if err != nil {
		return &DetailError{Err: ErrRemoveCertificate, Detail: fmt.Sprintf(": %s", err)}
	}
	defer func() { _ = rows.Close() }()

	type certRef struct {
		id     int64
		issuer []byte
		serial []byte
	}
	var certs []certRef
	for rows.Next() {
		var c certRef
		if err := rows.Scan(&c.id, &c.issuer, &c.serial); err != nil {
			return &DetailError{Err: ErrRemoveCertificate, Detail: fmt.Sprintf(": %s", err)}
		}
		certs = append(certs, c)
	}
	if err := rows.Err(); err != nil {
		return &DetailError{Err: ErrRemoveCertificate, Detail: fmt.Sprintf(": %s", err)}
	}

	if len(certs) == 0 {
		return nil
	}

	// Find every trust object whose issuer+serial match any of the certs we
	// are about to remove. There may be more than one per cert if previous
	// syncs left stale entries behind.
	var trustIDs []int64
	for _, c := range certs {
		tRows, err := w.certDB.Query(
			"SELECT id FROM nssPublic WHERE hex(a0) = ? AND a81 = ? AND a82 = ?",
			"CE534353", c.issuer, c.serial,
		)
		if err != nil {
			return &DetailError{Err: ErrRemoveTrust, Detail: fmt.Sprintf(": %s", err)}
		}
		for tRows.Next() {
			var id int64
			if err := tRows.Scan(&id); err != nil {
				_ = tRows.Close()
				return &DetailError{Err: ErrRemoveTrust, Detail: fmt.Sprintf(": %s", err)}
			}
			trustIDs = append(trustIDs, id)
		}
		if err := tRows.Err(); err != nil {
			_ = tRows.Close()
			return &DetailError{Err: ErrRemoveTrust, Detail: fmt.Sprintf(": %s", err)}
		}
		_ = tRows.Close()
	}

	// Gather all IDs to delete (certs + trust objects) and run a single
	// DELETE.
	allIDs := make([]int64, 0, len(certs)+len(trustIDs))
	for _, c := range certs {
		allIDs = append(allIDs, c.id)
	}
	allIDs = append(allIDs, trustIDs...)

	placeholders := make([]string, len(allIDs))
	args := make([]any, len(allIDs))
	for i, id := range allIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := "DELETE FROM nssPublic WHERE id IN (" + strings.Join(placeholders, ",") + ")"
	if _, err := w.certDB.Exec(query, args...); err != nil {
		return &DetailError{Err: ErrRemoveCertificate, Detail: fmt.Sprintf(": %s", err)}
	}

	// Drop HMAC signatures for every removed object.
	for _, id := range allIDs {
		sigPrefix := fmt.Sprintf("sig_cert_%x_%%", id)
		if _, err := w.keyDB.Exec("DELETE FROM metaData WHERE id LIKE ?", sigPrefix); err != nil {
			return &DetailError{Err: ErrRemoveTrust, Detail: fmt.Sprintf(": %s", err)}
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
		return &DetailError{Err: ErrCloseDatabase, Detail: fmt.Sprintf(": %s", strings.Join(errs, "; "))}
	}
	return nil
}

// InitDir creates the NSS database directory (if needed) and initializes
// cert9.db, key4.db, and pkcs11.txt. It is safe to call on an existing
// directory; the schema uses IF NOT EXISTS.
func InitDir(nssdbDir string) error {
	if err := os.MkdirAll(nssdbDir, dirPerm); err != nil {
		return &DetailError{Err: ErrInitDir, Detail: fmt.Sprintf(": %s", err)}
	}

	// Write pkcs11.txt.
	p11Path := filepath.Join(nssdbDir, pkcs11TxtFile)
	if err := os.WriteFile(p11Path, []byte(pkcs11TxtContent), filePerm); err != nil {
		return &DetailError{Err: ErrWritePKCS11Txt, Detail: fmt.Sprintf(": %s", err)}
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

// objectIDCounter provides unique object IDs by combining a time-based
// seed with an atomic counter to avoid collisions when adding multiple
// certificates in rapid succession.
var objectIDCounter atomic.Int64

// generateObjectID returns a unique object ID. The first call in a given
// second uses the time-based value; subsequent calls within the same
// second increment from there.
func generateObjectID() int64 {
	timeBase := time.Now().Unix() & 0x3FFFFFFF
	for {
		current := objectIDCounter.Load()
		next := current + 2 // reserve 2 IDs (cert + trust)
		if next < timeBase {
			next = timeBase
		}
		if objectIDCounter.CompareAndSwap(current, next) {
			return next
		}
	}
}

// marshalSerial encodes a certificate serial number as a full ASN.1 INTEGER TLV.
func marshalSerial(serial *big.Int) ([]byte, error) {
	return asn1.Marshal(serial)
}

// buildCertAttrs returns the attribute map for a certificate object.
func (w *Writer) buildCertAttrs(cert *x509.Certificate, label string, serialDER []byte) map[string][]byte {
	return map[string][]byte{
		"a0":   encodeUint32(ckoCertificate), // CKA_CLASS
		"a1":   encodeBool(true),             // CKA_TOKEN
		"a2":   encodeBool(false),            // CKA_PRIVATE
		"a3":   []byte(label),                // CKA_LABEL
		"a11":  cert.Raw,                     // CKA_VALUE
		"a80":  encodeUint32(0),              // CKA_CERTIFICATE_TYPE = CKC_X_509
		"a81":  cert.RawIssuer,               // CKA_ISSUER
		"a82":  serialDER,                    // CKA_SERIAL_NUMBER
		"a101": cert.RawSubject,              // CKA_SUBJECT
		"a102": cert.SubjectKeyId,            // CKA_ID
		"a170": encodeBool(true),             // CKA_NSS_OVERRIDE_EXTENSIONS
	}
}

// buildTrustAttrs returns the attribute map for a trust object.
func (w *Writer) buildTrustAttrs(cert *x509.Certificate, serialDER []byte) map[string][]byte {
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec
	md5Sum := md5.Sum(cert.Raw)   //nolint:gosec

	return map[string][]byte{
		"a0":        encodeUint32(ckoNSSTrust),            // CKA_CLASS
		"a1":        encodeBool(true),                     // CKA_TOKEN
		"a2":        encodeBool(false),                    // CKA_PRIVATE
		"a3":        explicitNull(),                       // CKA_LABEL (explicit null)
		"a81":       cert.RawIssuer,                       // CKA_ISSUER
		"a82":       serialDER,                            // CKA_SERIAL_NUMBER
		"a170":      encodeBool(true),                     // CKA_NSS_OVERRIDE_EXTENSIONS
		"ace536358": encodeUint32(cktNSSTrustedDelegator), // TRUST_SERVER_AUTH
		"ace536359": encodeUint32(cktNSSTrustedDelegator), // TRUST_CLIENT_AUTH
		"ace53635a": encodeUint32(cktNSSTrustedDelegator), // TRUST_CODE_SIGNING
		"ace53635b": encodeUint32(cktNSSTrustedDelegator), // TRUST_EMAIL_PROTECTION
		"ace536360": encodeBool(false),                    // TRUST_STEP_UP_APPROVED
		"ace5363b4": sha1Sum[:],                           // CERT_SHA1_HASH
		"ace5363b5": md5Sum[:],                            // CERT_MD5_HASH
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
		return &DetailError{Err: ErrPasswordInit, Detail: fmt.Sprintf(": %s", err)}
	}

	w.intermediateKey = deriveIntermediateKey(globalSalt)

	item2, err := buildPBES2PasswordEntry(w.intermediateKey)
	if err != nil {
		return &DetailError{Err: ErrPasswordInit, Detail: fmt.Sprintf(": %s", err)}
	}

	_, err = w.keyDB.Exec(
		"INSERT OR REPLACE INTO metaData (id, item1, item2) VALUES (?, ?, ?)",
		"password", globalSalt, item2,
	)
	if err != nil {
		return &DetailError{Err: ErrPasswordInit, Detail: fmt.Sprintf(": %s", err)}
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
// the trust attributes NSS verifies on a trust object. NSS only checks the
// CKA_TRUST_* and CKA_CERT_*_HASH attribute signatures; signing the
// structural attributes (CLASS/TOKEN/PRIVATE/LABEL/ISSUER/SERIAL/OVERRIDE)
// just adds noise to metaData. We match what certutil writes.
func (w *Writer) writeTrustSignatures(trustID int64, attrs map[string][]byte) error {
	for attrName, attrValue := range attrs {
		attrType, err := parseAttrHex(attrName)
		if err != nil {
			continue
		}
		if !nssSignsAttribute(attrType) {
			continue
		}

		sigBlob, err := w.buildPBMAC1Signature(uint32(trustID), attrType, attrValue)
		if err != nil {
			return err
		}

		// NSS expects sig IDs of the form sig_cert_<trustID-hex>_<attrType-hex>.
		// The attribute portion must be the bare PKCS#11 attribute ID — no
		// "a" SQLite column-name prefix. If the prefix is present NSS
		// silently ignores the signature, treats the trust attribute as
		// untrusted, and certutil -L shows the cert with ",," trust flags.
		sigID := fmt.Sprintf("sig_cert_%x_%x", trustID, attrType)
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

// nssSignsAttribute reports whether NSS expects a HMAC signature for the
// given PKCS#11 attribute type on a trust object. NSS validates only the
// trust-bearing attributes; structural attributes are not signed.
func nssSignsAttribute(attrType uint32) bool {
	switch attrType {
	case 0xCE536358, // CKA_TRUST_SERVER_AUTH
		0xCE536359, // CKA_TRUST_CLIENT_AUTH
		0xCE53635A, // CKA_TRUST_CODE_SIGNING
		0xCE53635B, // CKA_TRUST_EMAIL_PROTECTION
		0xCE536360, // CKA_TRUST_STEP_UP_APPROVED
		0xCE5363B4, // CKA_CERT_SHA1_HASH
		0xCE5363B5: // CKA_CERT_MD5_HASH
		return true
	}
	return false
}

// buildPBMAC1Signature creates the ASN.1 PBMAC1 blob for one attribute on
// the trust object identified by objectID.
func (w *Writer) buildPBMAC1Signature(objectID, attrType uint32, attrValue []byte) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	sigKey := pbkdf2.Key(w.intermediateKey, salt, 1, 32, sha256.New)

	data := encodeSignatureData(objectID, attrType, attrValue)

	mac := hmac.New(sha256.New, sigKey)
	mac.Write(data)
	hmacValue := mac.Sum(nil)

	return marshalPBMAC1(salt, hmacValue)
}

// encodeSignatureData builds the HMAC input for a trust attribute signature.
// NSS (lib/softoken/sftkdb.c sftkdb_HMACSDB) concatenates raw big-endian
// values with no length prefixes:
//
//	objectID  (CK_OBJECT_HANDLE, uint32 BE) ||
//	attrType  (CK_ATTRIBUTE_TYPE, uint32 BE) ||
//	attrValue (raw bytes)
//
// The earlier xkey writer substituted 0 for objectID and wrapped each
// ulong in a 4-byte length prefix; the resulting HMAC didn't validate so
// NSS treated every trust attribute as untrusted.
func encodeSignatureData(objectID, attrType uint32, attrValue []byte) []byte {
	buf := make([]byte, 0, 8+len(attrValue))
	objBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(objBuf, objectID)
	typeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(typeBuf, attrType)
	buf = append(buf, objBuf...)
	buf = append(buf, typeBuf...)
	buf = append(buf, attrValue...)
	return buf
}

// parseAttrHex parses an attribute column name like "a81" or "ace536358"
// into its PKCS#11 attribute type integer. The name must start with "a"
// followed by a hex-encoded integer (e.g., "a0" = 0x0, "a81" = 0x81,
// "ace536358" = 0xCE536358).
func parseAttrHex(name string) (uint32, error) {
	if len(name) < 2 || name[0] != 'a' {
		return 0, &MessageError{Msg: fmt.Sprintf("invalid attribute name: %s", name)}
	}
	hexStr := name[1:]
	val, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return 0, &WrappedError{Msg: fmt.Sprintf("invalid hex in attribute name %s", name), Err: err}
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
		return nil, &DetailError{Err: ErrASN1Marshal, Detail: fmt.Sprintf(": PBES2: %s", err)}
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
		return nil, &DetailError{Err: ErrASN1Marshal, Detail: fmt.Sprintf(": PBMAC1: %s", err)}
	}
	return b, nil
}
