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

package hardware

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
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	storagepkg "github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTPM2Store creates a TPM2 certificate storage over the given simulator.
func newTPM2Store(t *testing.T, tpm transport.TPMCloser) *TPM2CertStorage {
	t.Helper()

	store, err := NewTPM2CertStorage(tpm, DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}

	tpmStore, ok := store.(*TPM2CertStorage)
	if !ok {
		t.Fatal("NewTPM2CertStorage did not return *TPM2CertStorage")
	}

	return tpmStore
}

// generateNamedCert creates a small ECDSA test certificate with the given
// common name. ECDSA keeps the PEM well inside the 2KB NV record budget so
// several certificates fit in the simulator's NV RAM.
func generateNamedCert(t *testing.T, commonName string, serial int64) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// TestTPM2CertStorage_ListThenGetRoundTrip is the round trip that the
// hash-only index scheme could not satisfy: every ID reported by ListCerts
// must resolve through GetCert to the certificate that was stored under it.
// This is exactly how HardwareBackendAdapter.Scan walks the store.
func TestTPM2CertStorage_ListThenGetRoundTrip(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	saved := map[string]string{
		"root-ca":         "Round Trip Root",
		"intermediate-ca": "Round Trip Intermediate",
		"leaf":            "Round Trip Leaf",
	}

	serial := int64(1)
	for id, commonName := range saved {
		if err := store.SaveCert(id, generateNamedCert(t, commonName, serial)); err != nil {
			t.Fatalf("SaveCert(%q) error = %v", id, err)
		}
		serial++
	}

	ids, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}

	if len(ids) != len(saved) {
		t.Fatalf("ListCerts() returned %d ids (%v), want %d", len(ids), ids, len(saved))
	}

	sort.Strings(ids)
	want := make([]string, 0, len(saved))
	for id := range saved {
		want = append(want, id)
	}
	sort.Strings(want)

	for i, id := range ids {
		if id != want[i] {
			t.Errorf("ListCerts()[%d] = %q, want %q", i, id, want[i])
		}
	}

	// The listed IDs must be directly usable with GetCert.
	for _, id := range ids {
		cert, err := store.GetCert(id)
		if err != nil {
			t.Fatalf("GetCert(%q) after ListCerts() error = %v", id, err)
		}

		if cert.Subject.CommonName != saved[id] {
			t.Errorf("GetCert(%q).CommonName = %q, want %q", id, cert.Subject.CommonName, saved[id])
		}
	}
}

// TestTPM2CertStorage_ListThenGetChainRoundTrip covers the chain variant of
// the list -> get round trip.
func TestTPM2CertStorage_ListThenGetChainRoundTrip(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	chain := []*x509.Certificate{generateNamedCert(t, "Chain Leaf", 10)}
	if err := store.SaveCertChain("chain-id", chain); err != nil {
		t.Fatalf("SaveCertChain() error = %v", err)
	}

	// A chain record is not a certificate: ListCerts names certificate
	// records only, so the chain is absent from it and is read back under
	// the id it was stored under.
	ids, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ListCerts() = %v, want no certificate records for a chain-only store", ids)
	}

	got, err := store.GetCertChain("chain-id")
	if err != nil {
		t.Fatalf("GetCertChain(%q) error = %v", "chain-id", err)
	}

	if len(got) != 1 || got[0].Subject.CommonName != "Chain Leaf" {
		t.Fatalf("GetCertChain() returned %d certs, want the stored chain", len(got))
	}
}

// TestTPM2CertStorage_RoundTripSurvivesRestart proves the ID -> handle binding
// lives in the TPM rather than in process memory: a brand new storage instance
// over the same device still lists and resolves the original IDs.
func TestTPM2CertStorage_RoundTripSurvivesRestart(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	first := newTPM2Store(t, tpm)
	if err := first.SaveCert("persisted-cert", generateNamedCert(t, "Persisted", 42)); err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// A new storage instance holds no state from the first one.
	second := newTPM2Store(t, tpm)
	defer func() { _ = second.Close() }()

	ids, err := second.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() after restart error = %v", err)
	}

	if len(ids) != 1 || ids[0] != "persisted-cert" {
		t.Fatalf("ListCerts() after restart = %v, want [persisted-cert]", ids)
	}

	cert, err := second.GetCert(ids[0])
	if err != nil {
		t.Fatalf("GetCert(%q) after restart error = %v", ids[0], err)
	}

	if cert.Subject.CommonName != "Persisted" {
		t.Errorf("CommonName = %q, want Persisted", cert.Subject.CommonName)
	}
}

// TestTPM2CertStorage_LookupMissingID verifies missing IDs report ErrNotFound
// through every read path.
func TestTPM2CertStorage_LookupMissingID(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	if _, err := store.GetCert("missing"); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("GetCert(missing) error = %v, want ErrNotFound", err)
	}

	if _, err := store.GetCertChain("missing"); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("GetCertChain(missing) error = %v, want ErrNotFound", err)
	}

	exists, err := store.CertExists("missing")
	if err != nil {
		t.Errorf("CertExists(missing) error = %v, want nil", err)
	}
	if exists {
		t.Error("CertExists(missing) = true, want false")
	}

	if err := store.DeleteCert("missing"); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("DeleteCert(missing) error = %v, want ErrNotFound", err)
	}
}

// TestTPM2CertStorage_MalformedID verifies malformed identifiers are rejected
// rather than resolved to an arbitrary NV index.
func TestTPM2CertStorage_MalformedID(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	if _, err := store.GetCert(""); !errors.Is(err, storagepkg.ErrInvalidID) {
		t.Errorf("GetCert(\"\") error = %v, want ErrInvalidID", err)
	}

	malformed := []string{
		"0xZZZZZZZZ",       // not hex
		"0x00000001",       // hex, but far below the certificate range
		"0x02000000",       // hex, but above the certificate range
		"0x018000000000",   // too wide for a handle
		"not-a-handle-0x1", // prefix in the wrong place
	}

	for _, id := range malformed {
		if _, err := store.GetCert(id); !errors.Is(err, storagepkg.ErrNotFound) {
			t.Errorf("GetCert(%q) error = %v, want ErrNotFound", id, err)
		}
	}

	if err := store.SaveCert("", generateNamedCert(t, "No ID", 7)); !errors.Is(err, storagepkg.ErrInvalidID) {
		t.Errorf("SaveCert(\"\") error = %v, want ErrInvalidID", err)
	}
}

// TestTPM2CertStorage_HeaderlessBlobIsRefused covers the removed pre-header
// record shape: an NV blob with no magic header is not listed and not
// resolved by GetCert -- it is skipped by ListCerts (indistinguishable from
// another subsystem's use of the same NV index range) and refused with
// ErrCertRecordMissingHeader when addressed directly by the ID that hashes
// to its index. There is no dual reader and no NV-handle addressing form
// left to fall back to.
func TestTPM2CertStorage_HeaderlessBlobIsRefused(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	cert := generateNamedCert(t, "Headerless Cert", 99)
	headerlessPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	index := store.certIndexFromID("headerless-id")
	if err := store.writeNVIndex(index, headerlessPEM); err != nil {
		t.Fatalf("writeNVIndex() error = %v", err)
	}

	ids, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ListCerts() = %v, want none: a headerless record is not this storage's", ids)
	}

	if _, err := store.GetCert("headerless-id"); !errors.Is(err, ErrCertRecordMissingHeader) {
		t.Fatalf("GetCert(headerless-id) error = %v, want ErrCertRecordMissingHeader", err)
	}
}

// findCollidingIDs searches for two distinct certificate IDs that hash to the
// same NV index. The index space is 2^22 wide, so a birthday search finds a
// pair in a few thousand iterations.
func findCollidingIDs(t *testing.T, store *TPM2CertStorage) (string, string) {
	t.Helper()

	seen := make(map[uint32]string)
	for i := 0; i < 1<<24; i++ {
		id := "collide-" + strconv.Itoa(i)
		index := store.certIndexFromID(id)

		if previous, ok := seen[index]; ok {
			return previous, id
		}
		seen[index] = id
	}

	t.Fatal("no colliding certificate IDs found")
	return "", ""
}

// TestTPM2CertStorage_HashCollisionIsolation verifies that a certificate whose
// ID hashes onto an index already owned by a different ID is neither stored
// over it, returned from it, nor able to delete it. Two IDs sharing an NV
// index is the failure mode the ID header in each record exists to detect.
func TestTPM2CertStorage_HashCollisionIsolation(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	occupantID, collidingID := findCollidingIDs(t, store)
	if store.certIndexFromID(occupantID) != store.certIndexFromID(collidingID) {
		t.Fatalf("findCollidingIDs returned non-colliding IDs %q and %q", occupantID, collidingID)
	}

	if err := store.SaveCert(occupantID, generateNamedCert(t, "Occupant", 1)); err != nil {
		t.Fatalf("SaveCert(%q) error = %v", occupantID, err)
	}

	// Writing the colliding ID must be refused rather than clobber the occupant.
	err := store.SaveCert(collidingID, generateNamedCert(t, "Colliding", 2))
	if !errors.Is(err, ErrNVIndexUnavailable) {
		t.Fatalf("SaveCert(%q) error = %v, want ErrNVIndexUnavailable", collidingID, err)
	}

	// Reads for the colliding ID must not return the occupant's certificate.
	if _, err := store.GetCert(collidingID); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("GetCert(%q) error = %v, want ErrNotFound", collidingID, err)
	}

	exists, err := store.CertExists(collidingID)
	if err != nil {
		t.Fatalf("CertExists(%q) error = %v", collidingID, err)
	}
	if exists {
		t.Errorf("CertExists(%q) = true, want false", collidingID)
	}

	// Deleting the colliding ID must leave the occupant intact.
	if err := store.DeleteCert(collidingID); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Fatalf("DeleteCert(%q) error = %v, want ErrNotFound: the colliding index belongs to another id", collidingID, err)
	}

	ids, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(ids) != 1 || ids[0] != occupantID {
		t.Fatalf("ListCerts() = %v, want [%s] to survive the colliding delete", ids, occupantID)
	}

	surviving, err := store.GetCert(occupantID)
	if err != nil {
		t.Fatalf("GetCert(%q) error = %v", occupantID, err)
	}
	if surviving.Subject.CommonName != "Occupant" {
		t.Errorf("occupant CommonName = %q, want Occupant", surviving.Subject.CommonName)
	}
}

// TestCertRecordCodec covers the NV record encoding in isolation.
func TestCertRecordCodec(t *testing.T) {
	payload := []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")

	record, err := encodeCertRecord("cert-id", payload)
	if err != nil {
		t.Fatalf("encodeCertRecord() error = %v", err)
	}

	id, got, ok := decodeCertRecord(record)
	if !ok {
		t.Fatal("decodeCertRecord() reported no ID header for an encoded record")
	}
	if id != "cert-id" {
		t.Errorf("decoded id = %q, want cert-id", id)
	}
	if string(got) != string(payload) {
		t.Errorf("decoded payload = %q, want %q", got, payload)
	}
}

// TestCertRecordCodec_Invalid covers blobs that carry no usable ID header.
func TestCertRecordCodec_Invalid(t *testing.T) {
	truncated, err := encodeCertRecord("cert-id", []byte("payload"))
	if err != nil {
		t.Fatalf("encodeCertRecord() error = %v", err)
	}

	emptyID, err := encodeCertRecord("", []byte("payload"))
	if err != nil {
		t.Fatalf("encodeCertRecord(\"\") error = %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"shorter than header", []byte("XKC")},
		{"legacy pem", []byte("-----BEGIN CERTIFICATE-----\n")},
		{"wrong magic", append([]byte("XKC0\x00\x02id"), []byte("payload")...)},
		{"truncated id", truncated[:certRecordHeaderSize+2]},
		{"empty id", emptyID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, payload, ok := decodeCertRecord(tt.data)
			if ok {
				t.Fatalf("decodeCertRecord(%q) reported an ID header, want none", tt.data)
			}
			if id != "" {
				t.Errorf("id = %q, want empty", id)
			}
			if string(payload) != string(tt.data) {
				t.Errorf("payload = %q, want the input returned untouched", payload)
			}
		})
	}
}

// TestEncodeCertRecord_IDTooLong verifies IDs beyond the header's capacity are
// rejected instead of silently truncated.
func TestEncodeCertRecord_IDTooLong(t *testing.T) {
	oversized := make([]byte, maxCertIDLength+1)
	for i := range oversized {
		oversized[i] = 'a'
	}

	if _, err := encodeCertRecord(string(oversized), []byte("payload")); !errors.Is(err, storagepkg.ErrInvalidID) {
		t.Fatalf("encodeCertRecord(oversized) error = %v, want ErrInvalidID", err)
	}
}

// TestTPM2CertStorage_SaveCertTooLargeWithHeader verifies the record header is
// counted against the NV size budget: a certificate that fits with one byte to
// spare on its own no longer fits once the ID header is prepended.
func TestTPM2CertStorage_SaveCertTooLargeWithHeader(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	cert := generateTestCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	const id = "header-budget"

	config := DefaultTPM2CertStorageConfig()
	config.MaxCertSize = len(pemData) + certRecordHeaderSize + len(id) - 1

	store, err := NewTPM2CertStorage(tpm, config)
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SaveCert(id, cert); !errors.Is(err, ErrCertificateTooLarge) {
		t.Fatalf("SaveCert() error = %v, want ErrCertificateTooLarge", err)
	}

	// One more byte of budget and the same certificate stores cleanly.
	config.MaxCertSize++
	roomy, err := NewTPM2CertStorage(tpm, config)
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	defer func() { _ = roomy.Close() }()

	if err := roomy.SaveCert(id, cert); err != nil {
		t.Fatalf("SaveCert() with exact budget error = %v", err)
	}
}

// defineForeignNVIndex creates an NV index in the certificate range that the
// owner hierarchy cannot read, standing in for an index another subsystem
// defined inside the same range.
func defineForeignNVIndex(t *testing.T, store *TPM2CertStorage, index uint32) {
	t.Helper()

	nvPublic := tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			AuthWrite: true,
			AuthRead:  true,
			NoDA:      true,
		},
		DataSize: 8,
	}

	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(nvPublic),
	}).Execute(store.tpm); err != nil {
		t.Fatalf("failed to define foreign NV index: %v", err)
	}
}

// TestTPM2CertStorage_ForeignNVIndex verifies an unreadable index inside the
// certificate range is skipped by ListCerts and reported as a read failure,
// never as a missing or empty certificate.
func TestTPM2CertStorage_ForeignNVIndex(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	const foreignID = "foreign-id"
	defineForeignNVIndex(t, store, store.certIndexFromID(foreignID))

	// A cert this storage does own must still list cleanly.
	if err := store.SaveCert("owned", generateNamedCert(t, "Owned", 5)); err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	ids, err := store.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts() error = %v", err)
	}
	if len(ids) != 1 || ids[0] != "owned" {
		t.Fatalf("ListCerts() = %v, want [owned]", ids)
	}

	// Reads against the foreign index surface the hardware failure rather than
	// reporting the certificate as absent.
	if _, err := store.GetCert(foreignID); err == nil || errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("GetCert(%q) error = %v, want a read failure", foreignID, err)
	}

	if _, err := store.GetCertChain(foreignID); err == nil || errors.Is(err, storagepkg.ErrNotFound) {
		t.Errorf("GetCertChain(%q) error = %v, want a read failure", foreignID, err)
	}

	if _, err := store.CertExists(foreignID); err == nil {
		t.Errorf("CertExists(%q) error = nil, want a read failure", foreignID)
	}

	if err := store.DeleteCert(foreignID); err == nil {
		t.Errorf("DeleteCert(%q) error = nil, want a read failure", foreignID)
	}

	if err := store.SaveCert(foreignID, generateNamedCert(t, "Foreign", 6)); err == nil {
		t.Errorf("SaveCert(%q) error = nil, want a read failure", foreignID)
	}
}

// TestTPM2CertStorage_ClosedStorage verifies every operation refuses to run
// against closed storage.
func TestTPM2CertStorage_ClosedStorage(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	cert := generateNamedCert(t, "Closed", 8)

	tests := []struct {
		name string
		call func() error
	}{
		{"SaveCert", func() error { return store.SaveCert("id", cert) }},
		{"GetCert", func() error { _, err := store.GetCert("id"); return err }},
		{"DeleteCert", func() error { return store.DeleteCert("id") }},
		{"SaveCertChain", func() error { return store.SaveCertChain("id", []*x509.Certificate{cert}) }},
		{"GetCertChain", func() error { _, err := store.GetCertChain("id"); return err }},
		{"ListCerts", func() error { _, err := store.ListCerts(); return err }},
		{"CertExists", func() error { _, err := store.CertExists("id"); return err }},
		{"GetCapacity", func() error { _, _, err := store.GetCapacity(); return err }},
		{"Close", func() error { return store.Close() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrStorageClosed) {
				t.Errorf("%s error = %v, want ErrStorageClosed", tt.name, err)
			}
		})
	}
}

// TestTPM2CertStorage_NVHandleAddressingIsRemoved proves the removed
// NV-handle addressing form ("0x01800000") is no longer a special ID shape:
// a record is only reachable by the ID it was saved under. A handle string
// is now just an ordinary (and, absent a coincidental match, unresolvable)
// ID like any other.
func TestTPM2CertStorage_NVHandleAddressingIsRemoved(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	if err := store.SaveCert("handle-cert", generateNamedCert(t, "By Handle", 11)); err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	handle := fmt.Sprintf("0x%08x", store.certIndexFromID("handle-cert"))

	if _, err := store.GetCert(handle); !errors.Is(err, storagepkg.ErrNotFound) {
		t.Fatalf("GetCert(%q) error = %v, want ErrNotFound: NV-handle addressing must not resolve the record", handle, err)
	}

	// The ID it was actually saved under still works.
	cert, err := store.GetCert("handle-cert")
	if err != nil {
		t.Fatalf("GetCert(handle-cert) error = %v", err)
	}
	if cert.Subject.CommonName != "By Handle" {
		t.Errorf("CommonName = %q, want By Handle", cert.Subject.CommonName)
	}
}

// TestTPM2CertStorage_GetCapacityCountsRecords verifies capacity accounting
// tracks stored certificates.
func TestTPM2CertStorage_GetCapacityCountsRecords(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()

	store := newTPM2Store(t, tpm)
	defer func() { _ = store.Close() }()

	total, before, err := store.GetCapacity()
	if err != nil {
		t.Fatalf("GetCapacity() error = %v", err)
	}

	if err := store.SaveCert("capacity-cert", generateNamedCert(t, "Capacity", 12)); err != nil {
		t.Fatalf("SaveCert() error = %v", err)
	}

	totalAfter, after, err := store.GetCapacity()
	if err != nil {
		t.Fatalf("GetCapacity() error = %v", err)
	}

	if totalAfter != total {
		t.Errorf("total capacity changed from %d to %d", total, totalAfter)
	}
	if after != before-1 {
		t.Errorf("available capacity = %d, want %d", after, before-1)
	}
}
