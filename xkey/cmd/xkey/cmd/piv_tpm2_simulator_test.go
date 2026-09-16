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

//go:build tpm2 && tpm_simulator

// This file tests the TPM2 PIV certificate storage wiring against the
// in-process TPM 2.0 simulator so the SDK seam createTPM2PIVStorage relies on
// (xkms.NewPIVTPM2Backend over an open TPM transport) is exercised without
// real hardware. The simulator runs entirely in memory; it never touches the
// host filesystem or a physical device.
package cmd

import (
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestPIVTPM2Backend_StoreRetrieveDelete_Simulator proves the TPM2 PIV
// certificate storage createTPM2PIVStorage wires up round-trips a
// certificate through TPM NV RAM: Store, Retrieve, List and Delete all agree,
// and a deleted slot reports ErrPIVCertificateNotFound.
func TestPIVTPM2Backend_StoreRetrieveDelete_Simulator(t *testing.T) {
	sim, err := xkms.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator() error = %v", err)
	}
	defer func() { _ = sim.Close() }()

	storage, err := xkms.NewPIVTPM2Backend(&xkms.PIVTPM2Config{TPM: sim.Transport()})
	if err != nil {
		t.Fatalf("NewPIVTPM2Backend() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	cert := generateTestCertificate(t)

	if err := storage.Store(xkms.PIVSlotAuthentication, cert); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	got, err := storage.Retrieve(xkms.PIVSlotAuthentication)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if !got.Equal(cert) {
		t.Error("Retrieve() returned a certificate that does not match what was stored")
	}

	slots, err := storage.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(slots) != 1 || slots[0].Slot != xkms.PIVSlotAuthentication {
		t.Errorf("List() = %+v, want exactly slot %s populated", slots, xkms.PIVSlotAuthentication)
	}

	if err := storage.Delete(xkms.PIVSlotAuthentication); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := storage.Retrieve(xkms.PIVSlotAuthentication); !errors.Is(err, xkms.ErrPIVCertificateNotFound) {
		t.Errorf("Retrieve() after Delete() error = %v, want ErrPIVCertificateNotFound", err)
	}
}

// TestPIVTPM2Backend_ImportExport_Simulator proves the PEM/DER import and
// export paths round-trip through the simulator's NV RAM.
func TestPIVTPM2Backend_ImportExport_Simulator(t *testing.T) {
	sim, err := xkms.OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator() error = %v", err)
	}
	defer func() { _ = sim.Close() }()

	storage, err := xkms.NewPIVTPM2Backend(&xkms.PIVTPM2Config{TPM: sim.Transport()})
	if err != nil {
		t.Fatalf("NewPIVTPM2Backend() error = %v", err)
	}
	defer func() { _ = storage.Close() }()

	cert := generateTestCertificate(t)

	if err := storage.Import(xkms.PIVSlotDigitalSignature, cert.Raw, xkms.PIVFormatDER); err != nil {
		t.Fatalf("Import(DER) error = %v", err)
	}

	pemBytes, err := storage.Export(xkms.PIVSlotDigitalSignature, xkms.PIVFormatPEM)
	if err != nil {
		t.Fatalf("Export(PEM) error = %v", err)
	}
	if len(pemBytes) == 0 {
		t.Error("Export(PEM) returned no data")
	}

	if err := storage.Import(xkms.PIVSlotDigitalSignature, pemBytes, xkms.PIVFormatPEM); err != nil {
		t.Fatalf("Import(PEM) error = %v", err)
	}

	derBytes, err := storage.Export(xkms.PIVSlotDigitalSignature, xkms.PIVFormatDER)
	if err != nil {
		t.Fatalf("Export(DER) error = %v", err)
	}
	if string(derBytes) != string(cert.Raw) {
		t.Error("Export(DER) after PEM round-trip does not match the original certificate")
	}
}
