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
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct/cttest"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/issuance"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

const serverInternalType = "urn:ietf:params:acme:error:serverInternal"

// singleLogParams is Params whose issuer submits every precertificate to log alone
// and requires its SCT (RFC 6962 §3.3), giving up on it after timeout.
func singleLogParams(log *cttest.Log, timeout time.Duration) *Params {
	return &Params{
		Lint: linter.PrivatePKIConfig(),
		CT: ct.PolicyConfig{
			LogGroups:         []ct.LogGroup{log.Group("only", "operator-a")},
			MinSCTs:           1,
			MinOperators:      1,
			SubmissionTimeout: timeout,
		},
	}
}

func TestIssuanceProblemNamesTheUnmetCTPolicy(t *testing.T) {
	ctFailure := func(cause ...error) error {
		return &errs.Joined{Lead: issuance.ErrCertificateTransparency, Cause: errors.Join(cause...)}
	}
	refused := ct.NewCTSubmissionError("only", "https://log.example", ct.ErrCTSubmissionFailed)
	timedOut := ct.NewCTSubmissionError("only", "https://log.example", ct.ErrCTSubmissionTimeout)

	tests := []struct {
		name   string
		err    error
		detail string
	}{
		{
			name:   "too few operators",
			err:    ctFailure(ct.NewPolicyViolationError("operators", 1, 2)),
			detail: "Certificate transparency policy not met: 1 operators obtained, 2 required",
		},
		{
			name:   "log refused",
			err:    ctFailure(ct.NewPolicyViolationError("SCTs", 0, 1), refused),
			detail: "Certificate transparency policy not met: 0 SCTs obtained, 1 required; a log returned no valid SCT",
		},
		{
			name:   "log unreachable",
			err:    ctFailure(ct.NewPolicyViolationError("SCTs", 0, 1), timedOut),
			detail: "Certificate transparency policy not met: 0 SCTs obtained, 1 required; a log did not respond in time",
		},
		{
			name:   "no RFC 6962 log",
			err:    ctFailure(ct.ErrNoRFC6962Log),
			detail: "Certificate transparency policy not met: no SCT from an RFC 6962 log",
		},
		{
			name:   "no log for the expiry",
			err:    ctFailure(ct.ErrNoEligibleLogs),
			detail: "Certificate transparency policy not met: no log accepts the certificate's expiry",
		},
		{
			name:   "other CT failure",
			err:    ctFailure(ct.ErrInvalidSCT),
			detail: "Certificate transparency submission failed",
		},
		{
			name:   "not a CT failure",
			err:    errors.New("signer unavailable"),
			detail: "Failed to sign CSR",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problem := issuanceProblem(tt.err)

			assert.Equal(t, serverInternalType, problem.Type)
			assert.Equal(t, tt.detail, problem.Detail)
			assert.NotContains(t, problem.Detail, "log.example", "the problem never names a log's URL")
		})
	}
}

func TestFinalizeEnforcesTheCTPolicy(t *testing.T) {
	dns := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}

	t.Run("policy met", func(t *testing.T) {
		log := cttest.NewLog(t, cttest.Issues)

		resp := finalizeIdentifierThroughCA(t, elliptic.P256(), singleLogParams(log, time.Minute), dns)

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		assert.Len(t, log.Submitted(), 1, "the precertificate went to the log")
	})

	t.Run("policy not met", func(t *testing.T) {
		log := cttest.NewLog(t, cttest.Refuses)

		resp := finalizeIdentifierThroughCA(t, elliptic.P256(), singleLogParams(log, time.Minute), dns)

		assertCTProblem(t, resp, "Certificate transparency policy not met: 0 SCTs obtained, 1 required; a log returned no valid SCT")
	})

	t.Run("log unreachable", func(t *testing.T) {
		log := cttest.NewLog(t, cttest.Hangs)

		resp := finalizeIdentifierThroughCA(t, elliptic.P256(), singleLogParams(log, 100*time.Millisecond), dns)

		assertCTProblem(t, resp, "Certificate transparency policy not met: 0 SCTs obtained, 1 required; a log did not respond in time")
	})
}

func assertCTProblem(t *testing.T, resp *httptest.ResponseRecorder, detail string) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, resp.Code, resp.Body.String())
	problem := parseErrorResponse(t, resp)
	assert.Equal(t, serverInternalType, problem.Type)
	assert.Equal(t, detail, problem.Detail)
}

// An EK certificate is not CT-logged, so a CT policy no log can meet does not
// stop endorse-01 issuance.
func TestFinalizeEKCertificateIsNotCTLogged(t *testing.T) {
	log := cttest.NewLog(t, cttest.Refuses)
	f := newEndorse01Fixture(t)
	setCAWithParams(t, f.service, f.mockCA, singleLogParams(log, time.Minute))

	resp := f.finalize(t, createEndorse01CSRWithManufacturer(t, &x509.CertificateRequest{}, endorse01CSRKey(t), testEndorseTPMManufacturer))

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.NotNil(t, f.mockCA.lastEKRequest, "the CA issued the EK certificate")
	assert.Empty(t, log.Submitted(), "the EK certificate went to a CT log")
}

// A TCG-CSR-IDEVID enrollment's IAK and IDevID certificates are not CT-logged,
// so a CT policy no log can meet does not stop the enrollment.
func TestFinalizeTCGCSRIsNotCTLogged(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	const (
		model  = "xkms-node"
		serial = "SN-0745"
	)
	enrollCA := &tcgEnrollmentCA{
		iakDER:    selfSignedDER(t, ca.IAKCommonName(model, serial), big.NewInt(41), 30*24*time.Hour),
		idevidDER: selfSignedDER(t, model+"-"+serial, big.NewInt(42), 60*24*time.Hour),
	}
	log := cttest.NewLog(t, cttest.Refuses)
	setCAWithParams(t, service, enrollCA, singleLogParams(log, time.Minute))

	csrDER := packTCGCSR(t, model, serial, selfSignedDER(t, "ek-"+serial, big.NewInt(43), 365*24*time.Hour))
	account := createTestAccount(t, service, generateTestKey(t))
	order := &entities.ACMEOrder{
		ID:          745,
		AccountID:   account.ID,
		Status:      common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{{Type: common.AuthzTypePermanentIdentifier, Value: model + "-" + serial}},
	}
	req := httptest.NewRequest("POST", service.baseRESTURI+"/acme/order/745/finalize", nil)

	_, pemBytes, err := service.finalizeTCGCSR("198.51.100.21:4444", csrDER, req, account, order, nil)

	require.NoError(t, err)
	assert.NotEmpty(t, pemBytes)
	assert.Empty(t, log.Submitted(), "the IAK or IDevID certificate went to a CT log")
}
