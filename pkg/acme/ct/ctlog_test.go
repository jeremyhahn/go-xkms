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

package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testTimestamp is the SCT timestamp, in milliseconds, the test log issues.
const testTimestamp uint64 = 1_760_000_000_000

// The test fixtures spell the RFC 6962 §3.1 OIDs out rather than reuse the
// package's, so the tests check the code against the RFC, not itself.
var (
	testPoisonOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	testPrecertEKUOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
)

// testPrecert is a precertificate submission and the precert_entry
// (RFC 6962 §3.2) a log signs for it.
type testPrecert struct {
	der           []byte
	chain         [][]byte
	issuerKeyHash [32]byte
	tbs           []byte
}

// testCTLog is an RFC 6962 log served by httptest. Its add-pre-chain
// endpoint (§4.2) answers with an SCT signed over a fixed precert_entry.
type testCTLog struct {
	key        crypto.Signer
	entry      testPrecert
	extensions []byte

	// edit, when set, changes the response before it is sent.
	edit func(*addPrecertChainResponse)

	requests atomic.Int32
	server   *httptest.Server
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-256 key: %v", err)
	}
	return key
}

func newP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-384 key: %v", err)
	}
	return key
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating RSA-%d key: %v", bits, err)
	}
	return key
}

func createCert(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", template.Subject.CommonName, err)
	}
	return cert
}

func caTemplate(serial int64, name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Unix(1_700_000_000, 0),
		NotAfter:              time.Unix(1_900_000_000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

// newTestCA returns a self-signed CA certificate and its key.
func newTestCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newP256Key(t)
	template := caTemplate(1, name)
	return createCert(t, template, template, key.Public(), key), key
}

// newPrecertSigningCert returns a Precertificate Signing Certificate
// (RFC 6962 §3.1) issued by ca.
func newPrecertSigningCert(t *testing.T, ca *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newP256Key(t)
	template := caTemplate(2, "Precertificate Signing")
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{testPrecertEKUOID}
	return createCert(t, template, ca, key.Public(), caKey), key
}

// newTestPrecert issues a precertificate for ca, signed by psc when one is
// given. RFC 6962 §3.2 signs the TBSCertificate of the final certificate,
// so the entry's tbs comes from the certificate ca issues from the same
// template without the poison extension.
func newTestPrecert(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, psc *x509.Certificate, pscKey crypto.Signer) testPrecert {
	t.Helper()
	leafKey := newP256Key(t)
	template := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: "leaf.example.com"},
			DNSNames:     []string{"leaf.example.com"},
			NotBefore:    time.Unix(1_760_000_000, 0),
			NotAfter:     time.Unix(1_767_776_000, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}
	final := createCert(t, template(), ca, leafKey.Public(), caKey)

	precertTemplate := template()
	precertTemplate.ExtraExtensions = []pkix.Extension{{
		Id:       testPoisonOID,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	}}
	signer, signerKey, chain := ca, caKey, [][]byte{ca.Raw}
	if psc != nil {
		signer, signerKey, chain = psc, pscKey, [][]byte{psc.Raw, ca.Raw}
	}
	precert := createCert(t, precertTemplate, signer, leafKey.Public(), signerKey)

	return testPrecert{
		der:           precert.Raw,
		chain:         chain,
		issuerKeyHash: sha256.Sum256(ca.RawSubjectPublicKeyInfo),
		tbs:           final.RawTBSCertificate,
	}
}

// precertSignedData is the RFC 6962 §3.2 digitally-signed struct for a
// precert_entry, encoded as RFC 5246 §4 specifies.
func precertSignedData(timestamp uint64, entry testPrecert, extensions []byte) []byte {
	data := []byte{0, 0} // sct_version v1, signature_type certificate_timestamp
	data = binary.BigEndian.AppendUint64(data, timestamp)
	data = binary.BigEndian.AppendUint16(data, 1) // entry_type precert_entry
	data = append(data, entry.issuerKeyHash[:]...)
	n := len(entry.tbs)
	data = append(data, byte(n>>16), byte(n>>8), byte(n))
	data = append(data, entry.tbs...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(extensions)))
	return append(data, extensions...)
}

// signSCT returns the SCT a log holding key issues for entry.
func signSCT(key crypto.Signer, entry testPrecert, extensions []byte) (*SignedCertificateTimestamp, error) {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(precertSignedData(testTimestamp, entry, extensions))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	sigAlg := SignatureAlgorithmECDSA
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		sigAlg = SignatureAlgorithmRSA
	}
	return &SignedCertificateTimestamp{
		Version:    V1,
		LogID:      sha256.Sum256(spki),
		Timestamp:  testTimestamp,
		Extensions: extensions,
		Signature: DigitallySigned{
			HashAlgorithm: HashAlgorithmSHA256,
			SigAlgorithm:  sigAlg,
			Signature:     signature,
		},
	}, nil
}

// newTestCTLog starts a log holding key that signs entry.
func newTestCTLog(t *testing.T, key crypto.Signer, entry testPrecert) *testCTLog {
	t.Helper()
	l := &testCTLog{key: key, entry: entry}
	l.server = httptest.NewServer(http.HandlerFunc(l.addPreChain))
	t.Cleanup(l.server.Close)
	return l
}

// group returns the enabled configuration of the log.
func (l *testCTLog) group() LogGroup {
	return LogGroup{
		Name:      "Test Log",
		Operator:  "Test Operator",
		URL:       l.server.URL,
		PublicKey: l.key.Public(),
		Enabled:   true,
	}
}

// addPreChain serves RFC 6962 §4.2 add-pre-chain.
func (l *testCTLog) addPreChain(w http.ResponseWriter, r *http.Request) {
	l.requests.Add(1)
	if r.Method != http.MethodPost || r.URL.Path != "/ct/v1/add-pre-chain" {
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}
	var req addPrecertChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if len(req.Chain) != len(l.entry.chain)+1 || req.Chain[0] != base64.StdEncoding.EncodeToString(l.entry.der) {
		http.Error(w, "unexpected chain", http.StatusBadRequest)
		return
	}

	sct, err := signSCT(l.key, l.entry, l.extensions)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	resp := sctResponse(sct)
	if l.edit != nil {
		l.edit(&resp)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encoding failed", http.StatusInternalServerError)
	}
}

// sctResponse encodes sct as an RFC 6962 §4.2 add-pre-chain response.
func sctResponse(sct *SignedCertificateTimestamp) addPrecertChainResponse {
	sig := sct.Signature.Signature
	signature := []byte{
		byte(sct.Signature.HashAlgorithm),
		byte(sct.Signature.SigAlgorithm),
		byte(len(sig) >> 8),
		byte(len(sig)),
	}
	return addPrecertChainResponse{
		SCTVersion: sct.Version,
		ID:         base64.StdEncoding.EncodeToString(sct.LogID[:]),
		Timestamp:  sct.Timestamp,
		Extensions: base64.StdEncoding.EncodeToString(sct.Extensions),
		Signature:  base64.StdEncoding.EncodeToString(append(signature, sig...)),
	}
}
