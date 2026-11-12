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

package pairing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// This file is the end-to-end proof that BridgeConfig.TPM is wired to
// something real. Every other test in the package drives the enrollment
// handlers with a nil or a fake TPM, which proves the routing but never that
// a Bridge built against an actual TPM answers remote.getTCGCSRIDevID with a
// TCG-CSR-IDEVID that unpacks. That is what breaks when nothing sets
// BridgeConfig.TPM, so that is what is exercised here.
//
// The go-tpm-tools simulator is a process-global singleton, so only one
// enrollment TPM may be live at a time and each test owns it for its duration.

// enrollmentTPM is a provisioned simulator-backed TPM that owns a complete
// device identity: an EK with a certificate the CA can see, the IAK that
// Provision creates, and an IDevID minted on top of both.
func enrollmentTPM(t *testing.T) tpm2.TrustedPlatformModule {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := tpm2.OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	// Release the process-global simulator on every exit path. A cleanup
	// registered only after the fixture finished would be skipped when an
	// earlier require fails, and the next simulator test would block on the
	// simulator lock until the test binary times out.
	t.Cleanup(func() { assert.NoError(t, sim.Close(), "closing the TPM simulator") })

	storageFactory, err := store.NewStorageFactory(logger, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageFactory.Close(), "closing the storage factory") })

	// The simulator has no manufacturer EK certificate in NV RAM, so the
	// certificate store stands in for the manufacturer. A CSR without an EK
	// certificate is not a CSR a CA can act on, so this is required, not
	// convenience.
	certStore := store.NewMemoryCertStore(logger)

	config := tpm2.DefaultConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""
	config.IDevID.CN = "enrollment-device-001"
	config.IDevID.Model = "xkey-test-laptop"
	config.IDevID.Serial = "SN-ENROLL-0001"

	tpm, err := tpm2.NewTPM2(&tpm2.Params{
		Config:    &config,
		Logger:    logger,
		Backend:   storageFactory.KeyBackend(),
		CertStore: certStore,
		Transport: sim.Transport(),
		FQDN:      "laptop.example.com",
	})
	if tpm != nil {
		t.Cleanup(func() { assert.NoError(t, tpm.Close(), "closing the TPM") })
	}
	if err == tpm2.ErrNotInitialized {
		require.NotNil(t, tpm)
		require.NoError(t, tpm.Provision(nil), "provisioning the simulator must succeed")
	} else {
		require.NoError(t, err)
	}

	// Publish an EK certificate over the TPM's real EK public key, then mint
	// the IDevID that the CSR binds to the IAK.
	ekPub, err := tpm.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)
	require.NoError(t, certStore.Save(ekAttrs, manufacturerEKCert(t, ekPub)))

	ekCert, err := tpm.EKCertificate()
	require.NoError(t, err, "the bridge reads the EK certificate through the TPM")

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")

	_, _, err = tpm.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the TPM must be able to mint an IDevID")

	return tpm
}

// manufacturerEKCert issues a throwaway certificate over the TPM's real EK
// public key, standing in for the certificate a TPM vendor ships in NV RAM.
func manufacturerEKCert(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()

	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, issuer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestBridge_GetTCGCSRIDevID_AgainstARealTPM is the first time this path runs
// for real: a Bridge constructed with BridgeConfig.TPM set answers the phone's
// remote.getTCGCSRIDevID with a TCG-CSR-IDEVID that unpacks back into its TCG
// structure and carries this TPM's own EK certificate and key public areas.
func TestBridge_GetTCGCSRIDevID_AgainstARealTPM(t *testing.T) {
	tpm := enrollmentTPM(t)

	bridge, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger: testLogger(),
		TPM:    tpm,
	})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteGetTCGCSRIDevID, pairingproto.RemoteGetTCGCSRIDevIDParams{Backend: "tpm2"})
	resp := bridge.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error, "a bridge with a TPM must not report enrollment as unavailable")

	result := decodeResult[pairingproto.RemoteGetTCGCSRIDevIDResult](t, resp)
	require.NotEmpty(t, result.CSR, "the phone must receive a packed TCG-CSR-IDEVID")

	// The CSR must be the real TCG structure, not an opaque blob: parsing the
	// wire bytes back and unpacking them is exactly what the phone acting as
	// the CA does next.
	parsed, err := tpm2.UnmarshalIDevIDCSR(result.CSR)
	require.NoError(t, err, "the packed CSR must parse as a TCG-CSR-IDEVID")
	csr, err := tpm2.UnpackIDevIDCSR(parsed)
	require.NoError(t, err, "the parsed CSR must unpack into its TCG fields")
	assert.Equal(t, "xkey-test-laptop", string(csr.CsrContents.ProdModel))
	assert.Equal(t, "SN-ENROLL-0001", string(csr.CsrContents.ProdSerial))
	assert.NotEmpty(t, csr.CsrContents.EkCert, "the CA needs the EK certificate inside the CSR")

	// The CA needs the EK certificate to establish the TPM is genuine, and both
	// public areas to verify the IAK and IDevID the CSR attests to.
	ekCert, err := x509.ParseCertificate(result.EKCert)
	require.NoError(t, err, "the EK certificate must be DER the CA can parse")
	assert.Equal(t, "test-ek", ekCert.Subject.CommonName)
	assert.NotEmpty(t, result.IAKPublicKey, "the CSR must carry the IAK public area")
	assert.NotEmpty(t, result.IDevIDPublicKey, "the CSR must carry the IDevID public area")
	assert.NotEmpty(t, result.PlatformManufacturer, "the CA identifies the TPM vendor from this")
}

// TestBridge_GetAttestationQuote_AgainstARealTPM proves the second enrollment
// method reaches the TPM too: a quote over real PCRs, bound to the CA's nonce
// and signed by the IAK.
func TestBridge_GetAttestationQuote_AgainstARealTPM(t *testing.T) {
	tpm := enrollmentTPM(t)

	bridge, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger: testLogger(),
		TPM:    tpm,
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteGetAttestationQuote, pairingproto.RemoteGetAttestationQuoteParams{
		Backend:    "tpm2",
		Nonce:      nonce,
		PCRIndices: []int{0, 7},
	})
	resp := bridge.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error, "a bridge with a TPM must produce a quote")

	result := decodeResult[pairingproto.RemoteGetAttestationQuoteResult](t, resp)
	assert.NotEmpty(t, result.Quoted, "the signed TPMS_ATTEST must reach the CA")
	assert.NotEmpty(t, result.Signature, "the IAK signature over the quote must reach the CA")
}
