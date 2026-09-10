//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcgEnrollmentCA is a CA that completes a TCG-CSR-IDEVID enrollment with real
// DER certificates, which the ACME handler must be able to parse.
type tcgEnrollmentCA struct {
	MockCA

	iakDER    []byte
	idevidDER []byte

	// idevidCN records the subject the handler asked the CA to sign, so the
	// test can confirm the audited common name is the one that was issued.
	idevidCN string
}

func (c *tcgEnrollmentCA) SignTCGCSRIDevID(
	_ context.Context, _ *tpm2.TCG_CSR_IDEVID, request *ca.CertificateRequest) ([]byte, []byte, error) {
	c.idevidCN = request.Subject.CommonName
	return c.iakDER, c.idevidDER, nil
}

// selfSignedDER issues a self-signed certificate usable as test DER.
func selfSignedDER(t *testing.T, commonName string, serial *big.Int, validity time.Duration) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(validity),
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	return der
}

// packTCGCSR builds a TCG-CSR-IDEVID carrying the supplied device identity and
// EK certificate, in the wire form the ACME handler unpacks.
func packTCGCSR(t *testing.T, prodModel, prodSerial string, ekCertDER []byte) []byte {
	t.Helper()

	size := func(n int) [4]byte {
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], uint32(n))
		return out
	}

	attestPub := []byte("attestation-public-area")
	signingPub := []byte("signing-public-area")

	content := tpm2.TCG_IDEVID_CONTENT{
		ProdModelSz:  size(len(prodModel)),
		ProdSerialSz: size(len(prodSerial)),
		EkCertSZ:     size(len(ekCertDER)),
		AttestPubSZ:  size(len(attestPub)),
		SigningPubSZ: size(len(signingPub)),
		ProdModel:    []byte(prodModel),
		ProdSerial:   []byte(prodSerial),
		EkCert:       ekCertDER,
		AttestPub:    attestPub,
		SigningPub:   signingPub,
	}

	// The unpacker reads SigSz bytes of signature, and a zero-length read at
	// end-of-input fails, so the CSR always carries a signature.
	signature := []byte("device-signature")

	csr := &tpm2.TCG_CSR_IDEVID{
		SigSz:       size(len(signature)),
		CsrContents: content,
		Signature:   signature,
	}
	packed, err := tpm2.PackIDevIDCSR(csr)
	require.NoError(t, err)

	return packed
}

// TestAuditTrail_TPMEnrollmentIsRecorded verifies that an enroll-01 enrollment
// records both the TPM enrollment decision and the IDevID certificate it
// produced, and that both are readable through GET /admin/audit.
func TestAuditTrail_TPMEnrollmentIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	const (
		prodModel  = "xkms-node"
		prodSerial = "SN-0001"
	)
	idevidSerial := big.NewInt(987654321)

	enrollCA := &tcgEnrollmentCA{
		iakDER:    selfSignedDER(t, "iak-"+prodModel+"-"+prodSerial, big.NewInt(11), 30*24*time.Hour),
		idevidDER: selfSignedDER(t, prodModel+"-"+prodSerial, idevidSerial, 60*24*time.Hour),
	}
	service.ca = enrollCA

	ekCertDER := selfSignedDER(t, "ek-"+prodSerial, big.NewInt(22), 365*24*time.Hour)
	csrDER := packTCGCSR(t, prodModel, prodSerial, ekCertDER)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := &entities.ACMEOrder{
		ID:        4711,
		AccountID: account.ID,
		Status:    common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypePermanentIdentifier, Value: prodModel + "-" + prodSerial},
		},
	}

	req := httptest.NewRequest("POST", service.baseRESTURI+"/acme/order/4711/finalize", nil)
	req.Header.Set("X-Request-ID", "enrollment-correlation-id")

	serialNumber, pemBytes, err := service.finalizeTCGCSR("198.51.100.20:4444", csrDER, req, account, order)
	require.NoError(t, err)
	require.Equal(t, idevidSerial.Uint64(), serialNumber)
	require.NotEmpty(t, pemBytes)

	enrollment := trail.expectEvents(t, "event_type=TPM_ENROLLMENT", 1)
	require.Len(t, enrollment.Items, 1)
	assert.Equal(t, auditAccountRef(account.ID), enrollment.Items[0].Actor)
	assert.Equal(t, fmt.Sprintf("device:%s-%s", prodModel, prodSerial), enrollment.Items[0].Resource)
	assert.Equal(t, "enroll", enrollment.Items[0].Action)
	assert.Equal(t, audit.ResultSuccess, enrollment.Items[0].Result)
	assert.Equal(t, "enrollment-correlation-id", enrollment.Items[0].RequestID)

	require.Equal(t, prodModel+"-"+prodSerial, enrollCA.idevidCN,
		"the audited common name must be the one the CA was asked to sign")

	issued := trail.expectEvents(t, "event_type=CERTIFICATE_ISSUED", 1)
	require.Len(t, issued.Items, 1)
	assert.Equal(t, auditAccountRef(account.ID), issued.Items[0].Actor)
	assert.Equal(t, fmt.Sprintf("order:%d", order.ID), issued.Items[0].Resource)
	assert.Equal(t, idevidSerial.String(), issued.Items[0].Details["serial_number"])
	assert.Equal(t, prodModel+"-"+prodSerial, issued.Items[0].Details["common_name"])
	assert.EqualValues(t, 60, issued.Items[0].Details["validity_days"])

	// The two records share the correlation ID, so one enrollment is one
	// traceable story in the trail.
	assert.Equal(t, enrollment.Items[0].RequestID, issued.Items[0].RequestID)
}

// TestAuditTrail_TPMEnrollmentFailureIsNotRecordedAsIssuance verifies that a
// TCG enrollment that never reaches the CA leaves no issuance record: the trail
// must not claim a certificate that was never signed.
func TestAuditTrail_TPMEnrollmentFailureIsNotRecordedAsIssuance(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := &entities.ACMEOrder{ID: 4712, AccountID: account.ID, Status: common.StatusReady}

	req := httptest.NewRequest("POST", service.baseRESTURI+"/acme/order/4712/finalize", nil)

	// A malformed CSR fails before any certificate can be produced.
	_, _, err := service.finalizeTCGCSR("198.51.100.20:4444", []byte("not-a-tcg-csr"), req, account, order)
	require.Error(t, err)

	require.NoError(t, trail.logger.Flush())
	assert.Equal(t, 0, trail.events(t, "event_type=CERTIFICATE_ISSUED").Total)
	assert.Equal(t, 0, trail.events(t, "event_type=TPM_ENROLLMENT").Total)
}
