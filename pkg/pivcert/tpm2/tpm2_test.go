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

//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// simulatorTPM wraps the embedded TPM simulator so it satisfies
// transport.TPMCloser. Tests never touch a host TPM device.
type simulatorTPM struct {
	sim       *simulator.Simulator
	transport transport.TPM
}

// Send forwards a command to the simulator.
func (s *simulatorTPM) Send(input []byte) ([]byte, error) {
	return s.transport.Send(input)
}

// Close shuts the simulator down, releasing the process-wide simulator lock.
func (s *simulatorTPM) Close() error {
	return s.sim.Close()
}

// newSimulator starts an embedded TPM simulator for the test and closes it on
// cleanup. The go-tpm-tools simulator is process-wide, so tests must not run in
// parallel and must always release it.
func newSimulator(t *testing.T) *simulatorTPM {
	t.Helper()

	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		t.Fatalf("failed to start TPM simulator: %v", err)
	}

	tpm := &simulatorTPM{sim: sim, transport: transport.FromReadWriter(sim)}
	t.Cleanup(func() { _ = tpm.Close() })

	return tpm
}

// newStore creates PIV certificate storage over the simulator and closes it on
// cleanup.
func newStore(t *testing.T, tpm transport.TPM) *TPM2CertStorage {
	t.Helper()

	store, err := New(&Config{TPM: tpm})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	return store
}

// generateCert creates a small ECDSA certificate. ECDSA keeps the PEM record
// well inside the NV budget so several certificates fit in the simulator.
func generateCert(t *testing.T, commonName string, serial int64) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
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

// nvHandlesInRange returns the NV indices defined inside the certificate range
// starting at DefaultBaseIndex. It reads TPM state directly so tests can see
// where the slot mapping actually lands.
func nvHandlesInRange(t *testing.T, tpm transport.TPM) []uint32 {
	t.Helper()

	resp, err := gotpm2.GetCapability{
		Capability:    gotpm2.TPMCapHandles,
		Property:      DefaultBaseIndex,
		PropertyCount: 256,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("GetCapability(handles) error = %v", err)
	}

	handles, err := resp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatalf("Handles() error = %v", err)
	}

	const span = 0x00400000
	indices := make([]uint32, 0, len(handles.Handle))
	for _, handle := range handles.Handle {
		index := uint32(handle)
		if index < DefaultBaseIndex || index >= DefaultBaseIndex+span {
			continue
		}
		indices = append(indices, index)
	}

	return indices
}

// TestStoreRetrieve_RoundTrip verifies certificates come back byte-identical
// from every kind of PIV slot.
func TestStoreRetrieve_RoundTrip(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
		pivcert.PIVSlotAttestation,
		pivcert.PIVSlotRetired1,
		pivcert.PIVSlotRetired20,
	}

	stored := make(map[pivcert.PIVSlot]*x509.Certificate, len(slots))
	for i, slot := range slots {
		cert := generateCert(t, "Slot "+string(slot), int64(i+1))
		if err := store.Store(slot, cert); err != nil {
			t.Fatalf("Store(%q) error = %v", slot, err)
		}
		stored[slot] = cert
	}

	// Every slot must return its own certificate, not a neighbour's.
	for _, slot := range slots {
		got, err := store.Retrieve(slot)
		if err != nil {
			t.Fatalf("Retrieve(%q) error = %v", slot, err)
		}
		if !bytes.Equal(got.Raw, stored[slot].Raw) {
			t.Errorf("Retrieve(%q) returned different DER bytes", slot)
		}
		if got.Subject.CommonName != stored[slot].Subject.CommonName {
			t.Errorf("Retrieve(%q).CommonName = %q, want %q",
				slot, got.Subject.CommonName, stored[slot].Subject.CommonName)
		}
	}
}

// TestStoreRetrieve_PersistsAcrossReopen is the test that proves the slot to NV
// index mapping is stable: a brand new storage instance, holding no state from
// the first, recomputes the same NV index and reads back the same bytes.
func TestStoreRetrieve_PersistsAcrossReopen(t *testing.T) {
	tpm := newSimulator(t)

	first, err := New(&Config{TPM: tpm})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	written := map[pivcert.PIVSlot]*x509.Certificate{
		pivcert.PIVSlotAuthentication:   generateCert(t, "Persisted Auth", 1),
		pivcert.PIVSlotDigitalSignature: generateCert(t, "Persisted Signature", 2),
		pivcert.PIVSlotRetired7:         generateCert(t, "Persisted Retired", 3),
	}
	for slot, cert := range written {
		if err := first.Store(slot, cert); err != nil {
			t.Fatalf("Store(%q) error = %v", slot, err)
		}
	}

	handlesBefore := nvHandlesInRange(t, tpm)
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// A second instance shares nothing with the first except the TPM.
	second := newStore(t, tpm)

	for slot, cert := range written {
		got, err := second.Retrieve(slot)
		if err != nil {
			t.Fatalf("Retrieve(%q) after reopen error = %v", slot, err)
		}
		if !bytes.Equal(got.Raw, cert.Raw) {
			t.Errorf("Retrieve(%q) after reopen returned different DER bytes", slot)
		}
	}

	// Reading through a new instance must not have moved or duplicated NV state.
	handlesAfter := nvHandlesInRange(t, tpm)
	if len(handlesBefore) != len(handlesAfter) {
		t.Errorf("NV indices changed across reopen: %d before, %d after", len(handlesBefore), len(handlesAfter))
	}

	listed, err := second.List()
	if err != nil {
		t.Fatalf("List() after reopen error = %v", err)
	}
	if len(listed) != len(written) {
		t.Errorf("List() after reopen returned %d slots, want %d", len(listed), len(written))
	}
}

// TestPIVSlotCertIDs_MapToDistinctNVIndices verifies every slot in the registry
// lands on its own NV index inside the configured range. Each certificate is
// removed before the next is stored, so the NV budget never limits the sweep.
func TestPIVSlotCertIDs_MapToDistinctNVIndices(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	const span = 0x00400000
	indices := make(map[uint32]pivcert.PIVSlot, len(pivcert.AllSlots()))

	for i, slot := range pivcert.AllSlots() {
		if err := store.Store(slot, generateCert(t, "Index "+string(slot), int64(i+1))); err != nil {
			t.Fatalf("Store(%q) error = %v", slot, err)
		}

		handles := nvHandlesInRange(t, tpm)
		if len(handles) != 1 {
			t.Fatalf("slot %q defined %d NV indices, want exactly 1", slot, len(handles))
		}

		index := handles[0]
		if index < DefaultBaseIndex || index >= DefaultBaseIndex+span {
			t.Errorf("slot %q landed on %#x, outside [%#x, %#x)",
				slot, index, DefaultBaseIndex, DefaultBaseIndex+span)
		}
		if previous, dup := indices[index]; dup {
			t.Errorf("slots %q and %q collide on NV index %#x", previous, slot, index)
		}
		indices[index] = slot

		if err := store.Delete(slot); err != nil {
			t.Fatalf("Delete(%q) error = %v", slot, err)
		}
		if remaining := nvHandlesInRange(t, tpm); len(remaining) != 0 {
			t.Fatalf("Delete(%q) left %d NV indices behind", slot, len(remaining))
		}
	}

	if len(indices) != len(pivcert.AllSlots()) {
		t.Errorf("mapped %d distinct NV indices, want %d", len(indices), len(pivcert.AllSlots()))
	}
}

// TestStore_InvalidInput covers the rejections Store owes its callers.
func TestStore_InvalidInput(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	cert := generateCert(t, "Invalid Input", 1)

	tests := []struct {
		name    string
		slot    pivcert.PIVSlot
		cert    *x509.Certificate
		wantErr error
	}{
		{"unknown slot", "zz", cert, pivcert.ErrInvalidSlot},
		{"empty slot", "", cert, pivcert.ErrInvalidSlot},
		{"nil certificate", pivcert.PIVSlotAuthentication, nil, pivcert.ErrInvalidCertificate},
		{
			"oversized certificate",
			pivcert.PIVSlotAuthentication,
			&x509.Certificate{Raw: make([]byte, pivcert.MaxCertSizeTPM2+1)},
			pivcert.ErrCertificateTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Store(tt.slot, tt.cert); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Store() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestStore_CertificateExceedsNVRecordBudget verifies a certificate that fits
// the PIV limit but not the configured NV record size is refused, rather than
// silently truncated in NV RAM.
func TestStore_CertificateExceedsNVRecordBudget(t *testing.T) {
	tpm := newSimulator(t)

	store, err := New(&Config{TPM: tpm, MaxCertSize: 512})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	// An RSA-4096 certificate PEM is far larger than a 512-byte NV record.
	big := generateRSACert(t, "Too Large For NV", 1)
	if err := store.Store(pivcert.PIVSlotAuthentication, big); !errors.Is(err, pivcert.ErrCertificateTooLarge) {
		t.Fatalf("Store(oversized) error = %v, want ErrCertificateTooLarge", err)
	}

	// The slot must be left empty rather than half written.
	if _, err := store.Retrieve(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Fatalf("Retrieve() after refused store error = %v, want ErrCertificateNotFound", err)
	}
}

// TestStore_ReplacesExistingCertificate verifies re-issuing into a populated
// slot replaces the certificate instead of failing or duplicating NV records.
func TestStore_ReplacesExistingCertificate(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	original := generateCert(t, "Original", 1)
	replacement := generateCert(t, "Replacement", 2)

	if err := store.Store(pivcert.PIVSlotKeyManagement, original); err != nil {
		t.Fatalf("Store(original) error = %v", err)
	}
	if err := store.Store(pivcert.PIVSlotKeyManagement, replacement); err != nil {
		t.Fatalf("Store(replacement) error = %v", err)
	}

	got, err := store.Retrieve(pivcert.PIVSlotKeyManagement)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !bytes.Equal(got.Raw, replacement.Raw) {
		t.Error("Retrieve() returned the original certificate after replacement")
	}
	if handles := nvHandlesInRange(t, tpm); len(handles) != 1 {
		t.Errorf("replacement left %d NV indices, want 1", len(handles))
	}
}

// TestRetrieve_MissingAndInvalid covers reads that cannot be satisfied.
func TestRetrieve_MissingAndInvalid(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	if _, err := store.Retrieve(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Retrieve(empty slot) error = %v, want ErrCertificateNotFound", err)
	}

	if _, err := store.Retrieve("zz"); !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Retrieve(invalid slot) error = %v, want ErrInvalidSlot", err)
	}

	// A populated slot must not make a different empty slot look populated.
	if err := store.Store(pivcert.PIVSlotAuthentication, generateCert(t, "Only Slot", 1)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if _, err := store.Retrieve(pivcert.PIVSlotDigitalSignature); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Retrieve(other slot) error = %v, want ErrCertificateNotFound", err)
	}
}

// TestDelete_RemovesCertificate covers deletion and its error cases.
func TestDelete_RemovesCertificate(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	if err := store.Store(pivcert.PIVSlotDigitalSignature, generateCert(t, "Deletable", 1)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	if err := store.Delete(pivcert.PIVSlotDigitalSignature); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := store.Retrieve(pivcert.PIVSlotDigitalSignature); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Retrieve() after Delete error = %v, want ErrCertificateNotFound", err)
	}

	// Deleting an empty slot reports the empty slot rather than succeeding.
	if err := store.Delete(pivcert.PIVSlotDigitalSignature); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Delete(empty slot) error = %v, want ErrCertificateNotFound", err)
	}

	if err := store.Delete("zz"); !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Delete(invalid slot) error = %v, want ErrInvalidSlot", err)
	}
}

// TestDelete_LeavesOtherSlotsIntact verifies deletion is scoped to one slot.
func TestDelete_LeavesOtherSlotsIntact(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	kept := generateCert(t, "Kept", 1)
	if err := store.Store(pivcert.PIVSlotAuthentication, kept); err != nil {
		t.Fatalf("Store(kept) error = %v", err)
	}
	if err := store.Store(pivcert.PIVSlotKeyManagement, generateCert(t, "Removed", 2)); err != nil {
		t.Fatalf("Store(removed) error = %v", err)
	}

	if err := store.Delete(pivcert.PIVSlotKeyManagement); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	got, err := store.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve(kept) error = %v", err)
	}
	if !bytes.Equal(got.Raw, kept.Raw) {
		t.Error("deleting one slot changed another slot's certificate")
	}
}

// TestList_ReportsPopulatedSlots verifies List describes exactly the slots that
// hold certificates.
func TestList_ReportsPopulatedSlots(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	empty, err := store.List()
	if err != nil {
		t.Fatalf("List() on empty storage error = %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("List() on empty storage returned %d slots", len(empty))
	}

	cert := generateCert(t, "Listed", 7)
	if err := store.Store(pivcert.PIVSlotCardAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	listed, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("List() returned %d slots, want 1", len(listed))
	}

	info := listed[0]
	if info.Slot != pivcert.PIVSlotCardAuthentication {
		t.Errorf("Slot = %q, want %q", info.Slot, pivcert.PIVSlotCardAuthentication)
	}
	if info.Subject != cert.Subject.String() {
		t.Errorf("Subject = %q, want %q", info.Subject, cert.Subject.String())
	}
	if info.SerialNumber != cert.SerialNumber.Text(16) {
		t.Errorf("SerialNumber = %q, want %q", info.SerialNumber, cert.SerialNumber.Text(16))
	}
	if info.Algorithm != "ECDSA" {
		t.Errorf("Algorithm = %q, want ECDSA", info.Algorithm)
	}
	if info.KeySize != 256 {
		t.Errorf("KeySize = %d, want 256", info.KeySize)
	}
	if info.Fingerprint != pivcert.ThumbprintSHA256(cert) {
		t.Errorf("Fingerprint = %q, want %q", info.Fingerprint, pivcert.ThumbprintSHA256(cert))
	}
	if info.StoredAt.IsZero() {
		t.Error("StoredAt is zero")
	}
}

// TestList_IgnoresForeignRecords verifies certificates another subsystem stored
// in the same NV index range are not reported as PIV slots.
func TestList_IgnoresForeignRecords(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	foreign, err := hardware.NewTPM2CertStorage(&retainedTPM{tpm: tpm}, hardware.DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	if err := foreign.SaveCert("platform-root-ca", generateCert(t, "Platform Root", 1)); err != nil {
		t.Fatalf("SaveCert(foreign) error = %v", err)
	}

	if err := store.Store(pivcert.PIVSlotAuthentication, generateCert(t, "PIV Auth", 2)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	listed, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 1 || listed[0].Slot != pivcert.PIVSlotAuthentication {
		t.Fatalf("List() = %+v, want only the PIV authentication slot", listed)
	}

	// The foreign record must survive the PIV store's view of NV RAM.
	if _, err := foreign.GetCert("platform-root-ca"); err != nil {
		t.Errorf("foreign certificate lost: %v", err)
	}
}

// TestImportExport_RoundTrip verifies both encodings survive a round trip.
func TestImportExport_RoundTrip(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	cert := generateCert(t, "Import Export", 3)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tests := []struct {
		name   string
		slot   pivcert.PIVSlot
		data   []byte
		format pivcert.CertFormat
	}{
		{"DER", pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER},
		{"PEM", pivcert.PIVSlotKeyManagement, pemData, pivcert.FormatPEM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Import(tt.slot, tt.data, tt.format); err != nil {
				t.Fatalf("Import() error = %v", err)
			}

			exportedDER, err := store.Export(tt.slot, pivcert.FormatDER)
			if err != nil {
				t.Fatalf("Export(DER) error = %v", err)
			}
			if !bytes.Equal(exportedDER, cert.Raw) {
				t.Error("Export(DER) returned different bytes")
			}

			exportedPEM, err := store.Export(tt.slot, pivcert.FormatPEM)
			if err != nil {
				t.Fatalf("Export(PEM) error = %v", err)
			}
			if !bytes.Equal(exportedPEM, pemData) {
				t.Error("Export(PEM) returned different bytes")
			}
		})
	}
}

// TestImport_InvalidInput covers import data that cannot produce a certificate.
func TestImport_InvalidInput(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	cert := generateCert(t, "Valid", 1)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})

	tests := []struct {
		name    string
		slot    pivcert.PIVSlot
		data    []byte
		format  pivcert.CertFormat
		wantErr error
	}{
		{"empty data", pivcert.PIVSlotAuthentication, nil, pivcert.FormatDER, pivcert.ErrInvalidCertificate},
		{"garbage DER", pivcert.PIVSlotAuthentication, []byte{0x30, 0x00, 0x01}, pivcert.FormatDER, pivcert.ErrInvalidCertificate},
		{"PEM parsed as DER", pivcert.PIVSlotAuthentication, pemData, pivcert.FormatDER, pivcert.ErrInvalidCertificate},
		{"not PEM", pivcert.PIVSlotAuthentication, []byte("plain text"), pivcert.FormatPEM, pivcert.ErrInvalidFormat},
		{"wrong PEM block", pivcert.PIVSlotAuthentication, pemKey, pivcert.FormatPEM, pivcert.ErrInvalidFormat},
		{"unknown format", pivcert.PIVSlotAuthentication, cert.Raw, pivcert.CertFormat(42), pivcert.ErrInvalidFormat},
		{"invalid slot", "zz", cert.Raw, pivcert.FormatDER, pivcert.ErrInvalidSlot},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Import(tt.slot, tt.data, tt.format); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Import() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestExport_InvalidInput covers exports that cannot be satisfied.
func TestExport_InvalidInput(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	if _, err := store.Export(pivcert.PIVSlotAuthentication, pivcert.CertFormat(42)); !errors.Is(err, pivcert.ErrInvalidFormat) {
		t.Errorf("Export(unknown format) error = %v, want ErrInvalidFormat", err)
	}

	if _, err := store.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER); !errors.Is(err, pivcert.ErrCertificateNotFound) {
		t.Errorf("Export(empty slot) error = %v, want ErrCertificateNotFound", err)
	}

	if _, err := store.Export("zz", pivcert.FormatDER); !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("Export(invalid slot) error = %v, want ErrInvalidSlot", err)
	}
}

// TestClose_RefusesFurtherOperations verifies every method reports closed
// storage, and that closing twice is an error rather than a silent no-op.
func TestClose_RefusesFurtherOperations(t *testing.T) {
	tpm := newSimulator(t)

	store, err := New(&Config{TPM: tpm})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cert := generateCert(t, "Closed", 1)
	if err := store.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() before Close error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"Store", func() error { return store.Store(pivcert.PIVSlotAuthentication, cert) }},
		{"Retrieve", func() error { _, err := store.Retrieve(pivcert.PIVSlotAuthentication); return err }},
		{"Delete", func() error { return store.Delete(pivcert.PIVSlotAuthentication) }},
		{"List", func() error { _, err := store.List(); return err }},
		{"Import", func() error { return store.Import(pivcert.PIVSlotAuthentication, cert.Raw, pivcert.FormatDER) }},
		{"Export", func() error { _, err := store.Export(pivcert.PIVSlotAuthentication, pivcert.FormatDER); return err }},
		{"Close", func() error { return store.Close() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, pivcert.ErrStorageClosed) {
				t.Fatalf("%s after Close error = %v, want ErrStorageClosed", tt.name, err)
			}
		})
	}

	// Closing the PIV store must not have closed the caller's TPM.
	capability := gotpm2.GetCapability{
		Capability:    gotpm2.TPMCapHandles,
		Property:      DefaultBaseIndex,
		PropertyCount: 1,
	}
	if _, err := capability.Execute(tpm); err != nil {
		t.Errorf("TPM unusable after Close(): %v", err)
	}
}

// fillNVRAM stores foreign certificate records until the TPM refuses another
// allocation, and returns the IDs it managed to store. It gives tests a
// deterministic way to reach NV RAM exhaustion regardless of how much NV space
// the device has.
func fillNVRAM(t *testing.T, tpm transport.TPM) (hardware.HardwareCertStorage, []string) {
	t.Helper()

	filler, err := hardware.NewTPM2CertStorage(&retainedTPM{tpm: tpm}, hardware.DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}

	cert := generateCert(t, "NV Filler", 1)
	var stored []string
	for i := 0; i < 512; i++ {
		id := "nv-filler-" + strconv.Itoa(i)
		if saveErr := filler.SaveCert(id, cert); saveErr != nil {
			if !errors.Is(saveErr, gotpm2.TPMRCNVSpace) {
				t.Fatalf("SaveCert(%q) error = %v, want NV exhaustion", id, saveErr)
			}
			return filler, stored
		}
		stored = append(stored, id)
	}

	t.Fatal("NV RAM never reported exhaustion")
	return nil, nil
}

// TestStorageFull_ReportsExhaustedNVRAM verifies NV RAM exhaustion is reported
// as ErrStorageFull rather than as an opaque TPM failure, and that freeing NV
// space makes the slot usable again.
func TestStorageFull_ReportsExhaustedNVRAM(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	filler, fillerIDs := fillNVRAM(t, tpm)
	if len(fillerIDs) == 0 {
		t.Fatal("no records were stored before NV RAM was exhausted")
	}

	cert := generateCert(t, "Needs Room", 2)
	storeErr := store.Store(pivcert.PIVSlotAuthentication, cert)
	if !errors.Is(storeErr, pivcert.ErrStorageFull) {
		t.Fatalf("Store() on exhausted NV RAM error = %v, want ErrStorageFull", storeErr)
	}

	// Freeing NV RAM makes the slot writable again.
	for _, id := range fillerIDs {
		if err := filler.DeleteCert(id); err != nil {
			t.Fatalf("DeleteCert(%q) error = %v", id, err)
		}
	}

	if err := store.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() after freeing NV RAM error = %v", err)
	}

	got, err := store.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("Retrieve() returned different DER bytes after recovery")
	}
}

// TestStorageFull_PreservesStoredCertificates verifies certificates written
// before NV RAM filled up stay readable afterwards.
func TestStorageFull_PreservesStoredCertificates(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	cert := generateCert(t, "Written First", 1)
	if err := store.Store(pivcert.PIVSlotDigitalSignature, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	if _, ids := fillNVRAM(t, tpm); len(ids) == 0 {
		t.Fatal("no records were stored before NV RAM was exhausted")
	}

	got, err := store.Retrieve(pivcert.PIVSlotDigitalSignature)
	if err != nil {
		t.Fatalf("Retrieve() after exhaustion error = %v", err)
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("the stored certificate changed when NV RAM filled up")
	}
}

// TestPermissionDenied_WrongOwnerAuth verifies a store configured with the
// wrong TPM owner authorization reports ErrPermissionDenied on both writes and
// reads, instead of reporting the slot as empty.
func TestPermissionDenied_WrongOwnerAuth(t *testing.T) {
	tpm := newSimulator(t)

	authorized := newStore(t, tpm)
	cert := generateCert(t, "Owner Auth", 1)
	if err := authorized.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	if _, err := (gotpm2.HierarchyChangeAuth{
		AuthHandle: gotpm2.AuthHandle{Handle: gotpm2.TPMRHOwner, Auth: gotpm2.PasswordAuth(nil)},
		NewAuth:    gotpm2.TPM2BAuth{Buffer: []byte("owner-password")},
	}).Execute(tpm); err != nil {
		t.Fatalf("HierarchyChangeAuth() error = %v", err)
	}

	unauthorized, err := New(&Config{TPM: tpm, OwnerAuth: []byte("wrong-password")})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = unauthorized.Close() }()

	if _, err := unauthorized.Retrieve(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrPermissionDenied) {
		t.Errorf("Retrieve() with wrong owner auth error = %v, want ErrPermissionDenied", err)
	}
	if err := unauthorized.Store(pivcert.PIVSlotKeyManagement, cert); !errors.Is(err, pivcert.ErrPermissionDenied) {
		t.Errorf("Store() with wrong owner auth error = %v, want ErrPermissionDenied", err)
	}
	if err := unauthorized.Delete(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrPermissionDenied) {
		t.Errorf("Delete() with wrong owner auth error = %v, want ErrPermissionDenied", err)
	}

	// The correct authorization still works, so nothing was destroyed.
	stillAuthorized, err := New(&Config{TPM: tpm, OwnerAuth: []byte("owner-password")})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = stillAuthorized.Close() }()

	got, err := stillAuthorized.Retrieve(pivcert.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() with correct owner auth error = %v", err)
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("certificate changed after unauthorized access attempts")
	}
}

// TestTPMNotAvailable_DeadConnection verifies a TPM that cannot be reached is
// reported as unavailable. A dead link must never look like an empty slot: a
// caller that believed the slot empty would re-issue over a live certificate.
func TestTPMNotAvailable_DeadConnection(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	cert := generateCert(t, "Alive", 1)
	if err := store.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	if err := tpm.Close(); err != nil {
		t.Fatalf("closing the simulator error = %v", err)
	}

	_, retrieveErr := store.Retrieve(pivcert.PIVSlotAuthentication)
	if !errors.Is(retrieveErr, pivcert.ErrTPMNotAvailable) {
		t.Errorf("Retrieve() on a dead TPM error = %v, want ErrTPMNotAvailable", retrieveErr)
	}
	if errors.Is(retrieveErr, pivcert.ErrCertificateNotFound) {
		t.Error("a dead TPM reported the certificate as absent")
	}
	if err := store.Store(pivcert.PIVSlotKeyManagement, cert); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Errorf("Store() on a dead TPM error = %v, want ErrTPMNotAvailable", err)
	}
	if err := store.Delete(pivcert.PIVSlotAuthentication); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Errorf("Delete() on a dead TPM error = %v, want ErrTPMNotAvailable", err)
	}
	if _, err := store.List(); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Errorf("List() on a dead TPM error = %v, want ErrTPMNotAvailable", err)
	}
}

// TestConcurrentAccess exercises the storage from many goroutines to prove the
// documented concurrency guarantee under the race detector.
func TestConcurrentAccess(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	slots := []pivcert.PIVSlot{
		pivcert.PIVSlotAuthentication,
		pivcert.PIVSlotDigitalSignature,
		pivcert.PIVSlotKeyManagement,
		pivcert.PIVSlotCardAuthentication,
	}

	certs := make(map[pivcert.PIVSlot]*x509.Certificate, len(slots))
	for i, slot := range slots {
		cert := generateCert(t, "Concurrent "+string(slot), int64(i+1))
		certs[slot] = cert
		if err := store.Store(slot, cert); err != nil {
			t.Fatalf("Store(%q) error = %v", slot, err)
		}
	}

	const rounds = 8
	var wg sync.WaitGroup
	errCh := make(chan error, len(slots)*rounds*3)

	for _, slot := range slots {
		for i := 0; i < rounds; i++ {
			wg.Add(3)

			go func(slot pivcert.PIVSlot) {
				defer wg.Done()
				if err := store.Store(slot, certs[slot]); err != nil {
					errCh <- err
				}
			}(slot)

			go func(slot pivcert.PIVSlot) {
				defer wg.Done()
				cert, err := store.Retrieve(slot)
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(cert.Raw, certs[slot].Raw) {
					errCh <- errWrongCertificate
				}
			}(slot)

			go func() {
				defer wg.Done()
				if _, err := store.List(); err != nil {
					errCh <- err
				}
			}()
		}
	}

	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Errorf("concurrent operation failed: %v", e)
	}

	// Every slot must still hold exactly what was written.
	for _, slot := range slots {
		got, err := store.Retrieve(slot)
		if err != nil {
			t.Fatalf("Retrieve(%q) after concurrent access error = %v", slot, err)
		}
		if !bytes.Equal(got.Raw, certs[slot].Raw) {
			t.Errorf("slot %q holds different bytes after concurrent access", slot)
		}
	}
}

// errWrongCertificate reports a concurrent read that returned another slot's
// certificate.
var errWrongCertificate = errors.New("pivcert/tpm2: retrieved certificate does not match the stored one")

// TestSlotModel_TracksOccupancy verifies the slot model reflects NV RAM.
func TestSlotModel_TracksOccupancy(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	model, err := NewPIVSlotModel(store.CertStorage())
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	if len(model.AllSlots()) != len(pivcert.AllSlots()) {
		t.Errorf("AllSlots() returned %d slots, want %d", len(model.AllSlots()), len(pivcert.AllSlots()))
	}

	occupied, err := model.OccupiedSlots()
	if err != nil {
		t.Fatalf("OccupiedSlots() error = %v", err)
	}
	if len(occupied) != 0 {
		t.Fatalf("OccupiedSlots() on empty storage = %v", occupied)
	}

	available, err := model.AvailableSlots()
	if err != nil {
		t.Fatalf("AvailableSlots() error = %v", err)
	}
	if len(available) != len(pivcert.AllSlots()) {
		t.Errorf("AvailableSlots() returned %d slots, want %d", len(available), len(pivcert.AllSlots()))
	}

	// Retired slots are handed out first so the primary PIV slots stay free.
	next, err := model.NextAvailable()
	if err != nil {
		t.Fatalf("NextAvailable() error = %v", err)
	}
	if !next.IsRetiredSlot() {
		t.Errorf("NextAvailable() = %q, want a retired slot", next)
	}

	if err := store.Store(next, generateCert(t, "Occupant", 1)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// The model only changes when it is refreshed.
	if isOccupied, err := model.IsOccupied(next); err != nil || isOccupied {
		t.Errorf("IsOccupied(%q) before Refresh = (%v, %v), want (false, nil)", next, isOccupied, err)
	}
	if err := model.Refresh(); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if isOccupied, err := model.IsOccupied(next); err != nil || !isOccupied {
		t.Errorf("IsOccupied(%q) after Refresh = (%v, %v), want (true, nil)", next, isOccupied, err)
	}

	info, err := model.SlotOccupancy(next)
	if err != nil {
		t.Fatalf("SlotOccupancy() error = %v", err)
	}
	if !info.Occupied || !info.HasCert {
		t.Errorf("SlotOccupancy(%q) = %+v, want occupied with a certificate", next, info)
	}
	if info.Name != pivcert.SlotName(next) {
		t.Errorf("SlotOccupancy(%q).Name = %q, want %q", next, info.Name, pivcert.SlotName(next))
	}

	after, err := model.NextAvailable()
	if err != nil {
		t.Fatalf("NextAvailable() after Store error = %v", err)
	}
	if after == next {
		t.Errorf("NextAvailable() returned the occupied slot %q", next)
	}

	// Deleting frees the slot again.
	if err := store.Delete(next); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := model.Refresh(); err != nil {
		t.Fatalf("Refresh() after Delete error = %v", err)
	}
	if isOccupied, err := model.IsOccupied(next); err != nil || isOccupied {
		t.Errorf("IsOccupied(%q) after Delete = (%v, %v), want (false, nil)", next, isOccupied, err)
	}
}

// TestSlotModel_InvalidSlot verifies unknown slots are rejected by the model.
func TestSlotModel_InvalidSlot(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	model, err := NewPIVSlotModel(store.CertStorage())
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	if _, err := model.IsOccupied("zz"); !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("IsOccupied(invalid) error = %v, want ErrInvalidSlot", err)
	}
	if _, err := model.SlotOccupancy("zz"); !errors.Is(err, pivcert.ErrInvalidSlot) {
		t.Errorf("SlotOccupancy(invalid) error = %v, want ErrInvalidSlot", err)
	}
}

// TestSlotModel_IgnoresForeignRecords verifies foreign NV records do not make
// PIV slots look occupied.
func TestSlotModel_IgnoresForeignRecords(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	foreign, err := hardware.NewTPM2CertStorage(&retainedTPM{tpm: tpm}, hardware.DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}
	if err := foreign.SaveCert("platform-root-ca", generateCert(t, "Platform Root", 1)); err != nil {
		t.Fatalf("SaveCert(foreign) error = %v", err)
	}

	model, err := NewPIVSlotModel(store.CertStorage())
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	occupied, err := model.OccupiedSlots()
	if err != nil {
		t.Fatalf("OccupiedSlots() error = %v", err)
	}
	if len(occupied) != 0 {
		t.Errorf("OccupiedSlots() = %v, want none: foreign records are not PIV slots", occupied)
	}
}

// TestSlotModel_RefreshOnDeadTPM verifies the model surfaces a TPM failure
// instead of silently reporting every slot as free.
func TestSlotModel_RefreshOnDeadTPM(t *testing.T) {
	tpm := newSimulator(t)
	store := newStore(t, tpm)

	model, err := NewPIVSlotModel(store.CertStorage())
	if err != nil {
		t.Fatalf("NewPIVSlotModel() error = %v", err)
	}

	if err := tpm.Close(); err != nil {
		t.Fatalf("closing the simulator error = %v", err)
	}

	if err := model.Refresh(); !errors.Is(err, pivcert.ErrTPMNotAvailable) {
		t.Errorf("Refresh() on a dead TPM error = %v, want ErrTPMNotAvailable", err)
	}
}

// TestNewFromCertStorage_SharesNVRecords verifies a PIV store built over an
// existing hardware store reads the records that store wrote.
func TestNewFromCertStorage_SharesNVRecords(t *testing.T) {
	tpm := newSimulator(t)

	hw, err := hardware.NewTPM2CertStorage(&retainedTPM{tpm: tpm}, hardware.DefaultTPM2CertStorageConfig())
	if err != nil {
		t.Fatalf("NewTPM2CertStorage() error = %v", err)
	}

	store, err := NewFromCertStorage(hw)
	if err != nil {
		t.Fatalf("NewFromCertStorage() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	cert := generateCert(t, "Shared", 1)
	if err := store.Store(pivcert.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	id, ok := PIVSlotToCertID(pivcert.PIVSlotAuthentication)
	if !ok {
		t.Fatal("PIVSlotToCertID reported no mapping for the authentication slot")
	}

	got, err := hw.GetCert(id)
	if err != nil {
		t.Fatalf("GetCert(%q) error = %v", id, err)
	}
	if !bytes.Equal(got.Raw, cert.Raw) {
		t.Error("the hardware store returned different bytes for the PIV record")
	}
}

// generateRSACert creates an RSA-2048 certificate, whose PEM encoding is far
// larger than a small NV record budget.
func generateRSACert(t *testing.T, commonName string, serial int64) *x509.Certificate {
	t.Helper()

	key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		t.Fatalf("failed to generate RSA key: %v", keyErr)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create RSA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse RSA certificate: %v", err)
	}

	return cert
}
