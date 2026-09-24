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

package pairing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	gotpm2 "github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTPMEnroller implements TPMEnroller with per-method configurable
// responses, and records the certificates handed to the Provision* methods
// so a test can assert exactly what reached "the TPM".
type mockTPMEnroller struct {
	ekCert    *x509.Certificate
	ekCertErr error

	iakAttrs    *xkms.KeyAttributes
	iakAttrsErr error

	idevidAttrs    *xkms.KeyAttributes
	idevidAttrsErr error

	csr    xkms.TCG_CSR_IDEVID
	csrErr error

	activateSecret []byte
	activateErr    error

	quote    xkms.Quote
	quoteErr error

	fixedProps    *xkms.PropertiesFixed
	fixedPropsErr error

	provisionIAKErr    error
	provisionIDevIDErr error
	provisionedIAK     *x509.Certificate
	provisionedIDevID  *x509.Certificate
}

func (m *mockTPMEnroller) EKCertificate() (*x509.Certificate, error) { return m.ekCert, m.ekCertErr }
func (m *mockTPMEnroller) IAKAttributes() (*xkms.KeyAttributes, error) {
	return m.iakAttrs, m.iakAttrsErr
}
func (m *mockTPMEnroller) IDevIDAttributes() (*xkms.KeyAttributes, error) {
	return m.idevidAttrs, m.idevidAttrsErr
}
func (m *mockTPMEnroller) CreateTCG_CSR_IDEVID(*x509.Certificate, *xkms.KeyAttributes, *xkms.KeyAttributes) (xkms.TCG_CSR_IDEVID, error) {
	return m.csr, m.csrErr
}
func (m *mockTPMEnroller) ActivateCredential([]byte, []byte) ([]byte, error) {
	return m.activateSecret, m.activateErr
}
func (m *mockTPMEnroller) Quote([]uint, []byte) (xkms.Quote, error) {
	return m.quote, m.quoteErr
}
func (m *mockTPMEnroller) FixedProperties() (*xkms.PropertiesFixed, error) {
	return m.fixedProps, m.fixedPropsErr
}
func (m *mockTPMEnroller) ProvisionIAKCert(cert *x509.Certificate) error {
	m.provisionedIAK = cert
	return m.provisionIAKErr
}
func (m *mockTPMEnroller) ProvisionIDevIDCert(cert *x509.Certificate) error {
	m.provisionedIDevID = cert
	return m.provisionIDevIDErr
}

var _ TPMEnroller = (*mockTPMEnroller)(nil)

// tpm2BPublicFromBytes builds a non-empty TPM2B_PUBLIC whose Bytes() returns
// exactly raw, without needing a well-formed TPMT_PUBLIC — publicArea only
// looks at whether Bytes() is empty.
func tpm2BPublicFromBytes(raw []byte) gotpm2.TPM2BPublic {
	return gotpm2.BytesAs2B[gotpm2.TPMTPublic, *gotpm2.TPMTPublic](raw)
}

// selfSignedTestCert builds a minimal self-signed certificate for use as
// fixture DER bytes; the tests here only need something that parses as
// valid X.509, not a real attestation chain.
func selfSignedTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTestBridgeWithTPM(t *testing.T, tpm TPMEnroller) *Bridge {
	t.Helper()
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger: testLogger(),
		TPM:    tpm,
	})
	require.NoError(t, err)
	return b
}

// --- certFingerprint ---

func TestCertFingerprint_Deterministic(t *testing.T) {
	cert := selfSignedTestCert(t, "fingerprint-test")

	fp1 := certFingerprint(cert)
	fp2 := certFingerprint(cert)
	assert.Equal(t, fp1, fp2)
	assert.Len(t, fp1, 64, "SHA-256 hex digest is 64 characters")
}

func TestCertFingerprint_DiffersByCertificate(t *testing.T) {
	a := selfSignedTestCert(t, "cert-a")
	b := selfSignedTestCert(t, "cert-b")
	assert.NotEqual(t, certFingerprint(a), certFingerprint(b))
}

// --- pcrSelection ---

func TestPCRSelection_ValidIndices(t *testing.T) {
	pcrs, err := pcrSelection([]int{0, 7, 23})
	require.NoError(t, err)
	assert.Equal(t, []uint{0, 7, 23}, pcrs)
}

func TestPCRSelection_Empty(t *testing.T) {
	pcrs, err := pcrSelection(nil)
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestPCRSelection_NegativeIndex(t *testing.T) {
	pcrs, err := pcrSelection([]int{-1})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestPCRSelection_IndexTooLarge(t *testing.T) {
	pcrs, err := pcrSelection([]int{maxPCRIndex + 1})
	assert.Nil(t, pcrs)
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestPCRSelection_BoundaryIndex(t *testing.T) {
	pcrs, err := pcrSelection([]int{maxPCRIndex})
	require.NoError(t, err)
	assert.Equal(t, []uint{maxPCRIndex}, pcrs)
}

// --- pcrBankName ---

func TestPCRBankName_KnownAlgorithms(t *testing.T) {
	tests := []struct {
		alg  gotpm2.TPMIAlgHash
		name string
	}{
		{gotpm2.TPMAlgSHA1, "sha1"},
		{gotpm2.TPMAlgSHA256, "sha256"},
		{gotpm2.TPMAlgSHA384, "sha384"},
		{gotpm2.TPMAlgSHA512, "sha512"},
	}
	for _, tt := range tests {
		got, err := pcrBankName(tt.alg)
		require.NoError(t, err)
		assert.Equal(t, tt.name, got)
	}
}

func TestPCRBankName_Unsupported(t *testing.T) {
	_, err := pcrBankName(gotpm2.TPMAlgNull)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// --- pcrValues ---

func TestPCRValues_ReturnsRequestedBank(t *testing.T) {
	encoded, err := xkms.EncodePCRs([]xkms.PCRBank{
		{Algorithm: "sha1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
		{Algorithm: "sha256", PCRs: []xkms.PCR{
			{ID: 0, Value: []byte{0xAA}},
			{ID: 7, Value: []byte{0xBB}},
		}},
	})
	require.NoError(t, err)

	values, err := pcrValues(encoded, "sha256")
	require.NoError(t, err)
	assert.Equal(t, map[int][]byte{0: {0xAA}, 7: {0xBB}}, values)
}

func TestPCRValues_BankNameCaseInsensitive(t *testing.T) {
	encoded, err := xkms.EncodePCRs([]xkms.PCRBank{
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 3, Value: []byte{0x09}}}},
	})
	require.NoError(t, err)

	values, err := pcrValues(encoded, "sha256")
	require.NoError(t, err)
	assert.Equal(t, map[int][]byte{3: {0x09}}, values)
}

func TestPCRValues_BankNotFound(t *testing.T) {
	encoded, err := xkms.EncodePCRs([]xkms.PCRBank{
		{Algorithm: "sha1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
	})
	require.NoError(t, err)

	_, err = pcrValues(encoded, "sha384")
	assert.ErrorIs(t, err, ErrPCRBankUnavailable)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestPCRValues_UndecodableInput(t *testing.T) {
	_, err := pcrValues([]byte("not gob data"), "sha256")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

// --- handleStoreEnrollmentCerts ---

func TestHandleStoreEnrollmentCerts_Success(t *testing.T) {
	tpm := &mockTPMEnroller{}
	b := newTestBridgeWithTPM(t, tpm)

	iak := selfSignedTestCert(t, "iak")
	idevid := selfSignedTestCert(t, "idevid")
	chainCert := selfSignedTestCert(t, "intermediate")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    iak.Raw,
		IDevIDCert: idevid.Raw,
		Chain:      [][]byte{chainCert.Raw},
	})
	require.NoError(t, err)

	result, err := b.handleStoreEnrollmentCerts(context.Background(), params)
	require.NoError(t, err)

	res, ok := result.(*RemoteStoreEnrollmentCertsResult)
	require.True(t, ok)
	assert.True(t, res.Stored)
	assert.Equal(t, certFingerprint(iak), res.IAKCertFingerprint)
	assert.Equal(t, certFingerprint(idevid), res.IDevIDCertFingerprint)
	assert.Equal(t, iak.Raw, tpm.provisionedIAK.Raw)
	assert.Equal(t, idevid.Raw, tpm.provisionedIDevID.Raw)
}

func TestHandleStoreEnrollmentCerts_InvalidParams(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})

	_, err := b.handleStoreEnrollmentCerts(context.Background(), json.RawMessage(`{not-json`))
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleStoreEnrollmentCerts_BackendDenied(t *testing.T) {
	tpm := &mockTPMEnroller{}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:         testLogger(),
		TPM:            tpm,
		DeniedBackends: []string{BackendTPM2},
	})
	require.NoError(t, err)

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    []byte{0x01},
		IDevIDCert: []byte{0x01},
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	require.Error(t, err)
	assert.Nil(t, tpm.provisionedIAK, "a denied backend must never reach the TPM")
}

func TestHandleStoreEnrollmentCerts_TPMNotConfigured(t *testing.T) {
	b := newTestBridgeWithTPM(t, nil)

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    []byte{0x01},
		IDevIDCert: []byte{0x01},
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestHandleStoreEnrollmentCerts_MissingCerts(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})

	tests := []struct {
		name   string
		params RemoteStoreEnrollmentCertsParams
	}{
		{"missing IAK cert", RemoteStoreEnrollmentCertsParams{IDevIDCert: []byte{0x01}}},
		{"missing IDevID cert", RemoteStoreEnrollmentCertsParams{IAKCert: []byte{0x01}}},
		{"both missing", RemoteStoreEnrollmentCertsParams{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.params)
			require.NoError(t, err)

			_, err = b.handleStoreEnrollmentCerts(context.Background(), raw)
			assert.ErrorIs(t, err, ErrBridgeInvalidParams)
		})
	}
}

func TestHandleStoreEnrollmentCerts_IAKCertDoesNotParse(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	idevid := selfSignedTestCert(t, "idevid")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    []byte("not a certificate"),
		IDevIDCert: idevid.Raw,
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestHandleStoreEnrollmentCerts_IDevIDCertDoesNotParse(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	iak := selfSignedTestCert(t, "iak")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    iak.Raw,
		IDevIDCert: []byte("not a certificate"),
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestHandleStoreEnrollmentCerts_ChainCertDoesNotParse(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	iak := selfSignedTestCert(t, "iak")
	idevid := selfSignedTestCert(t, "idevid")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    iak.Raw,
		IDevIDCert: idevid.Raw,
		Chain:      [][]byte{[]byte("garbage")},
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestHandleStoreEnrollmentCerts_ProvisionIAKFails(t *testing.T) {
	tpm := &mockTPMEnroller{provisionIAKErr: errors.New("nvram full")}
	b := newTestBridgeWithTPM(t, tpm)
	iak := selfSignedTestCert(t, "iak")
	idevid := selfSignedTestCert(t, "idevid")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    iak.Raw,
		IDevIDCert: idevid.Raw,
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
	assert.Nil(t, tpm.provisionedIDevID, "IDevID must not be provisioned after an IAK failure")
}

func TestHandleStoreEnrollmentCerts_ProvisionIDevIDFails(t *testing.T) {
	tpm := &mockTPMEnroller{provisionIDevIDErr: errors.New("nvram full")}
	b := newTestBridgeWithTPM(t, tpm)
	iak := selfSignedTestCert(t, "iak")
	idevid := selfSignedTestCert(t, "idevid")

	params, err := json.Marshal(RemoteStoreEnrollmentCertsParams{
		IAKCert:    iak.Raw,
		IDevIDCert: idevid.Raw,
	})
	require.NoError(t, err)

	_, err = b.handleStoreEnrollmentCerts(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
	assert.NotNil(t, tpm.provisionedIAK, "the IAK cert was provisioned before the IDevID failure")
}

// --- publicArea ---

func TestPublicArea_NilAttrs(t *testing.T) {
	_, err := publicArea(nil)
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestPublicArea_NilTPMAttributes(t *testing.T) {
	_, err := publicArea(&xkms.KeyAttributes{})
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
}

func TestPublicArea_EmptyBPublic(t *testing.T) {
	attrs := &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{}}
	_, err := publicArea(attrs)
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
}

func TestPublicArea_Success(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	attrs := &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{
		BPublic: tpm2BPublicFromBytes(raw),
	}}
	got, err := publicArea(attrs)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// --- buildTCGCSRIDevID ---

func validIAKAttrs() *xkms.KeyAttributes {
	return &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{
		BPublic: tpm2BPublicFromBytes([]byte{0xAA, 0xAA}),
		HashAlg: gotpm2.TPMAlgSHA256,
	}}
}

func validIDevIDAttrs() *xkms.KeyAttributes {
	return &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{
		BPublic: tpm2BPublicFromBytes([]byte{0xBB, 0xBB}),
	}}
}

func TestBuildTCGCSRIDevID_EKCertificateError(t *testing.T) {
	tpm := &mockTPMEnroller{ekCertErr: errors.New("ek unreadable")}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestBuildTCGCSRIDevID_EKCertificateMissing(t *testing.T) {
	tpm := &mockTPMEnroller{ekCert: nil}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrEKCertificateMissing)
}

func TestBuildTCGCSRIDevID_IAKAttributesError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{ekCert: ek, iakAttrsErr: errors.New("iak unreadable")}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestBuildTCGCSRIDevID_IDevIDAttributesError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{ekCert: ek, iakAttrs: validIAKAttrs(), idevidAttrsErr: errors.New("idevid unreadable")}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestBuildTCGCSRIDevID_IAKPublicAreaError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    &xkms.KeyAttributes{}, // no TPMAttributes
		idevidAttrs: validIDevIDAttrs(),
	}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
}

func TestBuildTCGCSRIDevID_IDevIDPublicAreaError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    validIAKAttrs(),
		idevidAttrs: &xkms.KeyAttributes{},
	}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
}

func TestBuildTCGCSRIDevID_CreateCSRError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    validIAKAttrs(),
		idevidAttrs: validIDevIDAttrs(),
		csrErr:      errors.New("csr build failed"),
	}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestBuildTCGCSRIDevID_FixedPropertiesError(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:        ek,
		iakAttrs:      validIAKAttrs(),
		idevidAttrs:   validIDevIDAttrs(),
		fixedPropsErr: errors.New("properties unreadable"),
	}
	_, err := buildTCGCSRIDevID(tpm)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestBuildTCGCSRIDevID_Success(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    validIAKAttrs(),
		idevidAttrs: validIDevIDAttrs(),
		fixedProps:  &xkms.PropertiesFixed{Manufacturer: "ACME"},
	}
	result, err := buildTCGCSRIDevID(tpm)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ek.Raw, result.EKCert)
	assert.Equal(t, []byte{0xAA, 0xAA}, result.IAKPublicKey)
	assert.Equal(t, []byte{0xBB, 0xBB}, result.IDevIDPublicKey)
	assert.Equal(t, "ACME", result.PlatformManufacturer)
	assert.NotEmpty(t, result.CSR)
}

func TestBuildTCGCSRIDevID_NilFixedProperties(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    validIAKAttrs(),
		idevidAttrs: validIDevIDAttrs(),
		fixedProps:  nil,
	}
	result, err := buildTCGCSRIDevID(tpm)
	require.NoError(t, err)
	assert.Empty(t, result.PlatformManufacturer)
}

// --- handleGetTCGCSRIDevID ---

func TestHandleGetTCGCSRIDevID_Success(t *testing.T) {
	ek := selfSignedTestCert(t, "ek")
	tpm := &mockTPMEnroller{
		ekCert:      ek,
		iakAttrs:    validIAKAttrs(),
		idevidAttrs: validIDevIDAttrs(),
		fixedProps:  &xkms.PropertiesFixed{Manufacturer: "ACME"},
	}
	b := newTestBridgeWithTPM(t, tpm)

	params, err := json.Marshal(RemoteGetTCGCSRIDevIDParams{})
	require.NoError(t, err)

	result, err := b.handleGetTCGCSRIDevID(context.Background(), params)
	require.NoError(t, err)
	res, ok := result.(*RemoteGetTCGCSRIDevIDResult)
	require.True(t, ok)
	assert.NotEmpty(t, res.CSR)
}

func TestHandleGetTCGCSRIDevID_InvalidParams(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	_, err := b.handleGetTCGCSRIDevID(context.Background(), json.RawMessage(`{not-json`))
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleGetTCGCSRIDevID_BackendDenied(t *testing.T) {
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:         testLogger(),
		TPM:            &mockTPMEnroller{},
		DeniedBackends: []string{BackendTPM2},
	})
	require.NoError(t, err)

	params, err := json.Marshal(RemoteGetTCGCSRIDevIDParams{})
	require.NoError(t, err)

	_, err = b.handleGetTCGCSRIDevID(context.Background(), params)
	require.Error(t, err)
}

func TestHandleGetTCGCSRIDevID_TPMNotConfigured(t *testing.T) {
	b := newTestBridgeWithTPM(t, nil)
	params, err := json.Marshal(RemoteGetTCGCSRIDevIDParams{})
	require.NoError(t, err)

	_, err = b.handleGetTCGCSRIDevID(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestHandleGetTCGCSRIDevID_BuildFails(t *testing.T) {
	tpm := &mockTPMEnroller{ekCertErr: errors.New("ek unreadable")}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetTCGCSRIDevIDParams{})
	require.NoError(t, err)

	_, err = b.handleGetTCGCSRIDevID(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

// --- handleActivateCredential ---

func TestHandleActivateCredential_Success(t *testing.T) {
	tpm := &mockTPMEnroller{activateSecret: []byte("recovered-secret")}
	b := newTestBridgeWithTPM(t, tpm)

	params, err := json.Marshal(RemoteActivateCredentialParams{
		CredentialBlob:  []byte{0x01},
		EncryptedSecret: []byte{0x02},
	})
	require.NoError(t, err)

	result, err := b.handleActivateCredential(context.Background(), params)
	require.NoError(t, err)
	res, ok := result.(*RemoteActivateCredentialResult)
	require.True(t, ok)
	assert.Equal(t, []byte("recovered-secret"), res.DecryptedSecret)
}

func TestHandleActivateCredential_InvalidParams(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	_, err := b.handleActivateCredential(context.Background(), json.RawMessage(`{not-json`))
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleActivateCredential_MissingFields(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})

	tests := []RemoteActivateCredentialParams{
		{EncryptedSecret: []byte{0x01}},
		{CredentialBlob: []byte{0x01}},
		{},
	}
	for _, tt := range tests {
		params, err := json.Marshal(tt)
		require.NoError(t, err)
		_, err = b.handleActivateCredential(context.Background(), params)
		assert.ErrorIs(t, err, ErrBridgeInvalidParams)
	}
}

func TestHandleActivateCredential_TPMNotConfigured(t *testing.T) {
	b := newTestBridgeWithTPM(t, nil)
	params, err := json.Marshal(RemoteActivateCredentialParams{
		CredentialBlob:  []byte{0x01},
		EncryptedSecret: []byte{0x02},
	})
	require.NoError(t, err)

	_, err = b.handleActivateCredential(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestHandleActivateCredential_ActivateFails(t *testing.T) {
	tpm := &mockTPMEnroller{activateErr: errors.New("bad blob")}
	b := newTestBridgeWithTPM(t, tpm)

	params, err := json.Marshal(RemoteActivateCredentialParams{
		CredentialBlob:  []byte{0x01},
		EncryptedSecret: []byte{0x02},
	})
	require.NoError(t, err)

	_, err = b.handleActivateCredential(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

// --- handleGetAttestationQuote ---

func quoteReadyIAKAttrs() *xkms.KeyAttributes {
	return &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{
		HashAlg: gotpm2.TPMAlgSHA256,
	}}
}

func encodedSHA256PCRs(t *testing.T) []byte {
	t.Helper()
	encoded, err := xkms.EncodePCRs([]xkms.PCRBank{
		{Algorithm: "sha256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
	})
	require.NoError(t, err)
	return encoded
}

func TestHandleGetAttestationQuote_Success(t *testing.T) {
	tpm := &mockTPMEnroller{
		iakAttrs: quoteReadyIAKAttrs(),
		quote: xkms.Quote{
			Quoted:    []byte("quoted"),
			Signature: []byte("sig"),
			PCRs:      encodedSHA256PCRs(t),
		},
	}
	b := newTestBridgeWithTPM(t, tpm)

	params, err := json.Marshal(RemoteGetAttestationQuoteParams{
		Nonce:      []byte("nonce"),
		PCRIndices: []int{0, 7},
	})
	require.NoError(t, err)

	result, err := b.handleGetAttestationQuote(context.Background(), params)
	require.NoError(t, err)
	res, ok := result.(*RemoteGetAttestationQuoteResult)
	require.True(t, ok)
	assert.Equal(t, "sha256", res.PCRBank)
	assert.Equal(t, map[int][]byte{0: {0x01}}, res.PCRValues)
}

func TestHandleGetAttestationQuote_InvalidParams(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	_, err := b.handleGetAttestationQuote(context.Background(), json.RawMessage(`{not-json`))
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleGetAttestationQuote_BackendDenied(t *testing.T) {
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:         testLogger(),
		TPM:            &mockTPMEnroller{},
		DeniedBackends: []string{BackendTPM2},
	})
	require.NoError(t, err)

	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	require.Error(t, err)
}

func TestHandleGetAttestationQuote_TPMNotConfigured(t *testing.T) {
	b := newTestBridgeWithTPM(t, nil)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}

func TestHandleGetAttestationQuote_InvalidPCRIndices(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{-1}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleGetAttestationQuote_MissingNonce(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrBridgeInvalidParams)
}

func TestHandleGetAttestationQuote_IAKAttributesError(t *testing.T) {
	tpm := &mockTPMEnroller{iakAttrsErr: errors.New("unreadable")}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestHandleGetAttestationQuote_IAKAttributesNilTPMAttributes(t *testing.T) {
	tpm := &mockTPMEnroller{iakAttrs: &xkms.KeyAttributes{}}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMKeyNotProvisioned)
}

func TestHandleGetAttestationQuote_UnsupportedSigningAlgorithm(t *testing.T) {
	tpm := &mockTPMEnroller{iakAttrs: &xkms.KeyAttributes{TPMAttributes: &xkms.TPMAttributes{
		HashAlg: gotpm2.TPMAlgNull,
	}}}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestHandleGetAttestationQuote_BankMismatch(t *testing.T) {
	tpm := &mockTPMEnroller{iakAttrs: quoteReadyIAKAttrs()} // signs with sha256
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{
		Nonce: []byte("n"), PCRIndices: []int{0}, PCRBank: "sha384",
	})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestHandleGetAttestationQuote_QuoteFails(t *testing.T) {
	tpm := &mockTPMEnroller{
		iakAttrs: quoteReadyIAKAttrs(),
		quoteErr: errors.New("quote failed"),
	}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrTPMOperationFailed)
}

func TestHandleGetAttestationQuote_PCRValuesBankUnavailable(t *testing.T) {
	encoded, err := xkms.EncodePCRs([]xkms.PCRBank{
		{Algorithm: "sha1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x01}}}},
	})
	require.NoError(t, err)

	tpm := &mockTPMEnroller{
		iakAttrs: quoteReadyIAKAttrs(),
		quote:    xkms.Quote{PCRs: encoded},
	}
	b := newTestBridgeWithTPM(t, tpm)
	params, err := json.Marshal(RemoteGetAttestationQuoteParams{Nonce: []byte("n"), PCRIndices: []int{0}})
	require.NoError(t, err)

	_, err = b.handleGetAttestationQuote(context.Background(), params)
	assert.ErrorIs(t, err, ErrPCRBankUnavailable)
}

// --- logTPM ---

// mockAuditLogger implements audit.Logger, recording only what these tests
// need (LogTPMOperation) and failing loudly if an unexpected method is hit.
type mockTPMAuditLogger struct {
	logTPMErr   error
	logTPMCalls int
}

func (m *mockTPMAuditLogger) Log(audit.Entry) error { return errNotImplemented }
func (m *mockTPMAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) error {
	m.logTPMCalls++
	return m.logTPMErr
}
func (m *mockTPMAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return errNotImplemented
}
func (m *mockTPMAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return errNotImplemented
}

var _ audit.Logger = (*mockTPMAuditLogger)(nil)

func TestLogTPM_NoAuditLoggerIsANoop(t *testing.T) {
	b := newTestBridgeWithTPM(t, &mockTPMEnroller{})
	assert.NoError(t, b.logTPM(audit.OpTPMProvisioned, "remote.test", true, nil))
}

func TestLogTPM_DelegatesToAuditLogger(t *testing.T) {
	al := &mockTPMAuditLogger{}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:      testLogger(),
		TPM:         &mockTPMEnroller{},
		AuditLogger: al,
	})
	require.NoError(t, err)

	require.NoError(t, b.logTPM(audit.OpTPMProvisioned, "remote.test", true, nil))
	assert.Equal(t, 1, al.logTPMCalls)
}

func TestLogTPM_PropagatesAuditWriteFailure(t *testing.T) {
	al := &mockTPMAuditLogger{logTPMErr: errors.New("audit store unavailable")}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:      testLogger(),
		TPM:         &mockTPMEnroller{},
		AuditLogger: al,
	})
	require.NoError(t, err)

	err = b.logTPM(audit.OpTPMProvisioned, "remote.test", false, errors.New("cause"))
	assert.Error(t, err)
}
