// Package cttest provides an in-process Certificate Transparency log for
// tests: an RFC 6962 §4.2 add-pre-chain endpoint that answers with a real
// SCT, signed under the log's own key, or fails in a chosen way.
package cttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
)

// Mode selects how a Log answers a submission.
type Mode int

const (
	// Issues returns a valid SCT.
	Issues Mode = iota
	// Refuses answers with an HTTP error.
	Refuses
	// BadSignature returns an SCT signed over other data.
	BadSignature
	// Hangs answers only once the request is abandoned.
	Hangs
)

// Log is an RFC 6962 log served over HTTP for the lifetime of a test.
type Log struct {
	key    *ecdsa.PrivateKey
	mode   Mode
	server *httptest.Server

	// logID is the SHA-256 hash of the log's SubjectPublicKeyInfo (RFC
	// 6962 §3.2).
	logID [32]byte

	mu     sync.Mutex
	chains [][][]byte
}

// NewLog starts a log answering in mode; the test's cleanup stops it.
func NewLog(t testing.TB, mode Mode) *Log {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cttest: generate log key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("cttest: marshal log key: %v", err)
	}
	log := &Log{key: key, mode: mode, logID: sha256.Sum256(spki)}
	log.server = httptest.NewServer(http.HandlerFunc(log.addPreChain))
	t.Cleanup(log.server.Close)
	return log
}

// Group is the enabled log configuration naming this log.
func (l *Log) Group(name, operator string) ct.LogGroup {
	return ct.LogGroup{
		Name:      name,
		Operator:  operator,
		URL:       l.server.URL,
		PublicKey: &l.key.PublicKey,
		Enabled:   true,
	}
}

// Submitted returns every chain submitted to the log, in order.
func (l *Log) Submitted() [][][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.chains
}

// ID is the log's ID, the SHA-256 hash of its SubjectPublicKeyInfo (RFC
// 6962 §3.2).
func (l *Log) ID() [32]byte {
	return l.logID
}

// PublicKey is the key the log signs its SCTs with.
func (l *Log) PublicKey() *ecdsa.PublicKey {
	return &l.key.PublicKey
}

// addPreChain serves RFC 6962 §4.2 add-pre-chain.
func (l *Log) addPreChain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain []string `json:"chain"`
	}
	if r.URL.Path != "/ct/v1/add-pre-chain" || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Chain) < 2 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	chain := make([][]byte, len(req.Chain))
	for i, encoded := range req.Chain {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "bad chain", http.StatusBadRequest)
			return
		}
		chain[i] = der
	}
	l.mu.Lock()
	l.chains = append(l.chains, chain)
	l.mu.Unlock()

	switch l.mode {
	case Refuses:
		http.Error(w, "precertificate refused", http.StatusBadRequest)
		return
	case Hangs:
		<-r.Context().Done()
		return
	}

	precert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		http.Error(w, "bad precertificate", http.StatusBadRequest)
		return
	}
	issuer, err := x509.ParseCertificate(chain[1])
	if err != nil {
		http.Error(w, "bad issuer", http.StatusBadRequest)
		return
	}
	tbs, err := WithoutExtension(precert.RawTBSCertificate, ct.OIDPrecertPoison)
	if err != nil {
		http.Error(w, "bad tbsCertificate", http.StatusBadRequest)
		return
	}
	if l.mode == BadSignature {
		tbs = append(tbs, 0x00)
	}
	timestamp := uint64(time.Now().UnixMilli())
	digest := sha256.Sum256(SignedEntry(timestamp, sha256.Sum256(issuer.RawSubjectPublicKeyInfo), tbs))
	signature, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	logID := l.logID

	// RFC 5246 §4.7 digitally-signed: SHA-256 (4), ECDSA (3), then the
	// 2-byte length of the signature.
	digitallySigned := binary.BigEndian.AppendUint16([]byte{4, 3}, uint16(len(signature)))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"sct_version": 0,
		"id":          base64.StdEncoding.EncodeToString(logID[:]),
		"timestamp":   timestamp,
		"extensions":  "",
		"signature":   base64.StdEncoding.EncodeToString(append(digitallySigned, signature...)),
	}); err != nil {
		http.Error(w, "encoding failed", http.StatusInternalServerError)
	}
}

// SignedEntry is the data an SCT for a precertificate signs (RFC 6962
// §3.2): a v1 certificate_timestamp over a precert_entry.
func SignedEntry(timestamp uint64, issuerKeyHash [32]byte, tbs []byte) []byte {
	data := []byte{0, 0} // sct_version v1, signature_type certificate_timestamp
	data = binary.BigEndian.AppendUint64(data, timestamp)
	data = binary.BigEndian.AppendUint16(data, 1) // entry_type precert_entry
	data = append(data, issuerKeyHash[:]...)
	data = append(data, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
	data = append(data, tbs...)
	return binary.BigEndian.AppendUint16(data, 0) // no extensions
}

// tbsFields is an RFC 5280 §4.1 TBSCertificate with its fields left
// encoded, so one extension can be removed and the rest re-encoded as is.
type tbsFields struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

// WithoutExtension re-encodes tbsDER without the extension id: the
// precertificate's TBSCertificate a log signs drops the poison, and the
// final certificate's drops the SCT list (RFC 6962 §3.2).
func WithoutExtension(tbsDER []byte, id asn1.ObjectIdentifier) ([]byte, error) {
	var tbs tbsFields
	if _, err := asn1.Unmarshal(tbsDER, &tbs); err != nil {
		return nil, err
	}
	kept := tbs.Extensions[:0]
	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(id) {
			kept = append(kept, ext)
		}
	}
	tbs.Extensions = kept
	return asn1.Marshal(tbs)
}
