// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTenant is the tenant the package's tests issue certificates for.
const testTenant = "tenant-test"

// csrClaimingOrganizationalUnits returns a PEM CSR for cn whose subject
// asserts ous, as a caller trying to choose its own tenant would.
func csrClaimingOrganizationalUnits(t *testing.T, cn string, ous ...string) []byte {
	t.Helper()
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, OrganizationalUnit: ous},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, generateTestECDSAKey(t))
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// requireTenant asserts that cert carries tenant as its only organizational
// unit, the Subject.OrganizationalUnit[0] go-qrdb reads its tenant from.
func requireTenant(t *testing.T, cert *x509.Certificate, tenant string) {
	t.Helper()
	require.Equal(t, []string{tenant}, cert.Subject.OrganizationalUnit)
}

func TestStampTenant_ReplacesTheSubjectsOrganizationalUnits(t *testing.T) {
	subject := pkix.Name{
		CommonName:         "device-1",
		OrganizationalUnit: []string{"another-tenant", "admins"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidAttributeOrganizationalUnit, Value: "extra-tenant"},
			{Type: oidAttributeCommonName, Value: "device-1"},
		},
	}

	stamped, raw, err := StampTenant(testTenant, subject, nil)
	require.NoError(t, err)
	assert.Nil(t, raw)
	assert.Equal(t, []string{testTenant}, stamped.OrganizationalUnit)
	assert.Equal(t, "device-1", stamped.CommonName)
	assert.Equal(t, []pkix.AttributeTypeAndValue{{Type: oidAttributeCommonName, Value: "device-1"}}, stamped.ExtraNames)
	assert.Len(t, subject.ExtraNames, 2, "the caller's subject is left unchanged")
}

func TestStampTenant_RefusesARequestWithoutATenant(t *testing.T) {
	_, _, err := StampTenant("", pkix.Name{CommonName: "device-1"}, nil)
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestStampTenant_RawSubjectFirstOrganizationalUnitBecomesTheTenant(t *testing.T) {
	stamped, raw, err := StampTenant(testTenant, pkix.Name{}, holderRawSubject(t, "officer-1", "another-tenant", "custodian"))
	require.NoError(t, err)
	assert.Equal(t, holderRawSubject(t, "officer-1", testTenant, "custodian"), raw)
	assert.Equal(t, []string{testTenant, "custodian"}, stamped.OrganizationalUnit)
	assert.Equal(t, "officer-1", stamped.CommonName)
}

func TestStampTenant_RawSubjectNamingTheTenantIsUnchanged(t *testing.T) {
	original := holderRawSubject(t, "officer-1", testTenant, "custodian")

	_, raw, err := StampTenant(testTenant, pkix.Name{}, original)
	require.NoError(t, err)
	assert.Equal(t, original, raw)
}

func TestStampTenant_RawSubjectWithoutOrganizationalUnitGetsTheTenantBeforeTheCommonName(t *testing.T) {
	original, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidAttributeOrganization, Value: "Example"}},
		{{Type: oidAttributeCommonName, Value: "officer-1"}},
	})
	require.NoError(t, err)

	_, raw, err := StampTenant(testTenant, pkix.Name{}, original)
	require.NoError(t, err)
	want, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidAttributeOrganization, Value: "Example"}},
		{{Type: oidAttributeOrganizationalUnit, Value: testTenant}},
		{{Type: oidAttributeCommonName, Value: "officer-1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, want, raw)
}

func TestStampTenant_RefusesAMalformedRawSubject(t *testing.T) {
	_, _, err := StampTenant(testTenant, pkix.Name{}, []byte("not a distinguished name"))
	require.ErrorIs(t, err, ErrInvalidRawSubject)
}

func TestSignCSR_StampsTheTenantOverTheCSRsOrganizationalUnits(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := csrClaimingOrganizationalUnits(t, "device-1", "another-tenant", "admins")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant})
	require.NoError(t, err)
	requireTenant(t, cert, testTenant)
	assert.Equal(t, "device-1", cert.Subject.CommonName)
}

func TestSignCSR_RefusesARequestWithoutATenant(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := csrClaimingOrganizationalUnits(t, "device-1", "another-tenant")

	_, err := ca.SignCSR(context.Background(), csrPEM, nil)
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestSignCSR_RawSubjectCarriesTheRequestsTenant(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := hostileCSR(t)
	raw := holderRawSubject(t, "officer-1", "another-tenant", "custodian")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{RawSubject: raw, TenantID: testTenant})
	require.NoError(t, err)
	assert.Equal(t, []string{testTenant, "custodian"}, cert.Subject.OrganizationalUnit)
}

func TestIssueCertificateRaw_StampsTheTenant(t *testing.T) {
	ca := setupTestCA(t)

	certPEM, _, _, _, err := ca.IssueCertificateRaw(context.Background(),
		"service.example.com", "Example", nil, 30, "", "", testTenant,
	)
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	requireTenant(t, cert, testTenant)
}

func TestIssueCertificateRaw_RefusesARequestWithoutATenant(t *testing.T) {
	ca := setupTestCA(t)

	_, _, _, _, err := ca.IssueCertificateRaw(context.Background(),
		"service.example.com", "Example", nil, 30, "", "", "",
	)
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestIssueEKCertificate_StampsTheTenantOverTheRequestsOrganizationalUnit(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))
	request.Subject.OrganizationalUnit = "another-tenant"

	cert, err := ca.IssueEKCertificate(context.Background(), request, generateTestECDSAKey(t).Public())
	require.NoError(t, err)
	requireTenant(t, cert, testTenant)
}

func TestIssueEKCertificate_RefusesARequestWithoutATenant(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))
	request.TenantID = ""

	_, err := ca.IssueEKCertificate(context.Background(), request, generateTestECDSAKey(t).Public())
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestIssueAKCertificate_StampsTheTenantOverTheRequestsOrganizationalUnit(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))
	request.Subject.OrganizationalUnit = "another-tenant"

	cert, err := ca.IssueAKCertificate(context.Background(), request, generateTestECDSAKey(t).Public())
	require.NoError(t, err)
	requireTenant(t, cert, testTenant)
}

func TestIssueAKCertificate_RefusesARequestWithoutATenant(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))
	request.TenantID = ""

	_, err := ca.IssueAKCertificate(context.Background(), request, generateTestECDSAKey(t).Public())
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestSignTCGCSRIDevID_StampsTheTenantOnTheIAKAndIDevID(t *testing.T) {
	ca := createTestCAForTCG(t)

	_, _, iakDER, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)
	for _, der := range [][]byte{iakDER, idevidDER} {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		requireTenant(t, cert, testTenant)
	}
}

func TestSignTCGCSRIDevID_RefusesARequestWithoutATenant(t *testing.T) {
	ca := createTestCAForTCG(t)
	device := buildSoftwareTCGCSR(t, softwareCSRModel, softwareCSRSerial)
	trustSoftwareCSREKCertificate(t, ca, device)
	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))
	request.TenantID = ""

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), device.csr, request)
	require.ErrorIs(t, err, ErrTenantRequired)
}
