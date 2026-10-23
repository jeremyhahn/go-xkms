//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// go-xkms#1391: enroll-01 finalize must be bound to the TPM that passed
// credential activation. Challenge-time activation proves a TPM holds an
// endorsement key and an activation key; the TCG-CSR arrives one request later
// and, unbound, could be built in software around another device's PUBLIC
// endorsement key certificate.

const (
	enrollProdModel  = "xkms-node"
	enrollProdSerial = "SN-1391"
)

// enrollFinalizeSetup is a ready order that an enroll-01 challenge validated
// for the TPM (activatedEK, activatedIAK), served by a CA that issues for any
// TCG-CSR it is given -- so a TCG-CSR that reaches the CA was one the handler
// accepted.
type enrollFinalizeSetup struct {
	service      *RestService
	enrollCA     *tcgEnrollmentCA
	accountKey   *TestKey
	account      *entities.ACMEAccount
	order        *entities.ACMEOrder
	activatedEK  []byte
	activatedIAK []byte
}

// newEnrollFinalizeSetup creates the order. validatedBy is the challenge type
// that validated its authorization, and record, when non-nil, is persisted on
// that challenge.
func newEnrollFinalizeSetup(t *testing.T, validatedBy string, withRecord bool) *enrollFinalizeSetup {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	enrollCA := &tcgEnrollmentCA{
		iakDER:    selfSignedDER(t, ca.IAKCommonName(enrollProdModel, enrollProdSerial), big.NewInt(31), 30*24*time.Hour),
		idevidDER: selfSignedDER(t, enrollProdModel+"-"+enrollProdSerial, big.NewInt(32), 60*24*time.Hour),
	}
	setCA(t, service, enrollCA)

	accountKey := generateTestKey(t)
	account := createTestAccount(t, service, accountKey)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{{Type: common.AuthzTypePermanentIdentifier, Value: "device.example.com"}}

	activatedEK := selfSignedDER(t, "ek-activated", big.NewInt(41), 365*24*time.Hour)
	activatedIAK := []byte("activated-iak-public-area")

	authz := authorizeOrder(t, service, account, order, order.Identifiers[0], validatedBy)
	if withRecord {
		ek, err := parseCertificateDER(activatedEK)
		require.NoError(t, err)
		permanentIdentifier, err := ca.EKCertificatePermanentIdentifier(ek)
		require.NoError(t, err)
		authz.Challenges[0].DeviceAttestation = &entities.DeviceAttestation{
			Format:              "enroll-01",
			DeviceIdentityType:  common.AuthzTypePermanentIdentifier,
			DeviceIdentityValue: permanentIdentifier,
			LeafDER:             activatedEK,
			PubArea:             activatedIAK,
		}
		authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
		require.NoError(t, err)
		require.NoError(t, authzDAO.Save(context.Background(), authz))
	}

	return &enrollFinalizeSetup{
		service: service, enrollCA: enrollCA, accountKey: accountKey, account: account, order: order,
		activatedEK: activatedEK, activatedIAK: activatedIAK,
	}
}

// finalize submits csrDER to the order.
func (e *enrollFinalizeSetup) finalize(t *testing.T, csrDER []byte) *httptest.ResponseRecorder {
	t.Helper()
	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", e.service.baseRESTURI, e.order.ID)
	req := createJWSRequest(t, e.service, e.accountKey, url, payload, true, e.account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", e.order.ID)})
	resp := httptest.NewRecorder()
	e.service.OrderFinalizeHandler(resp, req)
	return resp
}

func (e *enrollFinalizeSetup) assertStillReady(t *testing.T) {
	t.Helper()
	orderDAO, err := e.service.storageFactory.OrderDAO(e.account.ID)
	require.NoError(t, err)
	stored, err := orderDAO.Get(context.Background(), e.order.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusReady, stored.Status, "a refused finalize leaves the order ready")
	assert.Empty(t, e.enrollCA.idevidCN, "the CA was asked to sign a TCG-CSR the handler should have refused")
}

func TestOrderFinalize_TCGCSR_ActivatedTPMIsIssued(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEnroll01, true)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, setup.activatedEK, setup.activatedIAK))

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, enrollProdModel+"-"+enrollProdSerial, setup.enrollCA.idevidCN)
}

// The attack of #1391: the client passed activation once, then submits a
// TCG-CSR built around another device's public EK certificate. Without the
// binding the CA is asked to issue an IDevID carrying that device's identity.
func TestOrderFinalize_TCGCSR_AnotherTPMsEKIsRefused(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEnroll01, true)
	anotherEK := selfSignedDER(t, "ek-of-another-device", big.NewInt(42), 365*24*time.Hour)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, anotherEK, setup.activatedIAK))

	body := resp.Body.String()
	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	assert.Contains(t, body, "endorsement key")
	setup.assertStillReady(t)
}

// The activated EK with an activation key (IAK) that was not the one the
// credential was bound to.
func TestOrderFinalize_TCGCSR_AnotherIAKIsRefused(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEnroll01, true)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, setup.activatedEK, []byte("software-iak-public-area")))

	body := resp.Body.String()
	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	assert.Contains(t, body, "attestation key")
	setup.assertStillReady(t)
}

// An enroll-01 challenge that left no activation record leaves nothing to
// compare the TCG-CSR with, which is a refusal and not a pass.
func TestOrderFinalize_TCGCSR_NoActivationRecordIsRefused(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEnroll01, false)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, setup.activatedEK, setup.activatedIAK))

	body := resp.Body.String()
	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	assert.Contains(t, body, "no enroll-01 credential activation")
	setup.assertStillReady(t)
}

// go-xkms#1392: an authorization an endorse-01 challenge validated may become
// an EK certificate and nothing else. EAB authorized the account; nothing proved
// the account holds the key, so it cannot be turned into an IDevID.
func TestOrderFinalize_TCGCSR_EndorseValidatedOrderIsRefused(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEndorse01, false)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, setup.activatedEK, setup.activatedIAK))

	body := resp.Body.String()
	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	assert.Contains(t, body, "endorse-01")
	setup.assertStillReady(t)
}

// A TCG-CSR for an order no attestation challenge validated -- an ip
// identifier http-01 validated -- is not enroll-01's to finalize.
func TestOrderFinalize_TCGCSR_OrderNoAttestationValidatedIsRefused(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeHTTP01, false)

	resp := setup.finalize(t, packTCGCSRWithAttestKey(t, enrollProdModel, enrollProdSerial, setup.activatedEK, setup.activatedIAK))

	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
	setup.assertStillReady(t)
}

func TestOrderFinalize_TCGCSR_UnparseableIsMalformed(t *testing.T) {
	setup := newEnrollFinalizeSetup(t, common.ChallengeTypeEnroll01, true)

	resp := setup.finalize(t, []byte("not-a-tcg-csr"))

	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
	setup.assertStillReady(t)
}

func TestBindEnrollActivation(t *testing.T) {
	ekDER := selfSignedDER(t, "ek", big.NewInt(51), time.Hour)
	ek, err := parseCertificateDER(ekDER)
	require.NoError(t, err)
	permanentIdentifier, err := ca.EKCertificatePermanentIdentifier(ek)
	require.NoError(t, err)
	record := &entities.DeviceAttestation{DeviceIdentityValue: permanentIdentifier, PubArea: []byte("iak")}

	t.Run("the activated keys are accepted", func(t *testing.T) {
		assert.Nil(t, bindEnrollActivation([]*entities.DeviceAttestation{record}, 1, ekDER, []byte("iak")))
	})

	t.Run("one of several activated TPMs is accepted", func(t *testing.T) {
		other := &entities.DeviceAttestation{DeviceIdentityValue: "other", PubArea: []byte("other-iak")}
		assert.Nil(t, bindEnrollActivation([]*entities.DeviceAttestation{other, record}, 1, ekDER, []byte("iak")))
	})

	t.Run("another endorsement key is refused", func(t *testing.T) {
		other := selfSignedDER(t, "another-ek", big.NewInt(52), time.Hour)
		assert.NotNil(t, bindEnrollActivation([]*entities.DeviceAttestation{record}, 1, other, []byte("iak")))
	})

	t.Run("an activated endorsement key with another IAK is refused", func(t *testing.T) {
		assert.NotNil(t, bindEnrollActivation([]*entities.DeviceAttestation{record}, 1, ekDER, []byte("not-the-iak")))
	})

	t.Run("a record naming this IAK for another endorsement key does not vouch for this one", func(t *testing.T) {
		stolen := &entities.DeviceAttestation{DeviceIdentityValue: "another-tpm", PubArea: []byte("iak")}
		assert.NotNil(t, bindEnrollActivation([]*entities.DeviceAttestation{stolen}, 1, ekDER, []byte("iak")))
	})

	t.Run("no activation record is refused", func(t *testing.T) {
		assert.NotNil(t, bindEnrollActivation(nil, 1, ekDER, []byte("iak")))
	})

	t.Run("an unreadable endorsement key certificate is refused", func(t *testing.T) {
		assert.NotNil(t, bindEnrollActivation([]*entities.DeviceAttestation{record}, 1, []byte("garbage"), []byte("iak")))
		assert.NotNil(t, bindEnrollActivation([]*entities.DeviceAttestation{record}, 1, nil, []byte("iak")))
	})
}

func TestEnrollActivationErrors(t *testing.T) {
	notFound := &ErrEnrollActivationNotFound{OrderID: 3}
	assert.Contains(t, notFound.Error(), "order 3")

	cause := errors.New("bad certificate")
	mismatch := &ErrEnrollActivationMismatch{OrderID: 3, Subject: "endorsement key certificate", Cause: cause}
	assert.ErrorIs(t, mismatch, cause)
	assert.Contains(t, mismatch.Error(), "cannot be read")

	assert.Contains(t, (&ErrEnrollActivationMismatch{OrderID: 3, Subject: "attestation key"}).Error(), "is not the one that passed")
}

// requireOnly is the single rule behind every finalize flow: the validated
// challenge decides, and only that challenge's request is honored.
func TestValidatedAttestationsRequireOnly(t *testing.T) {
	validatedBy := func(types ...string) *validatedAttestations {
		v := &validatedAttestations{challenges: map[string][]*entities.ACMEChallenge{}}
		for _, challengeType := range types {
			v.challenges[challengeType] = append(v.challenges[challengeType], &entities.ACMEChallenge{Type: challengeType, Status: common.StatusValid})
		}
		return v
	}

	tests := []struct {
		name      string
		validated *validatedAttestations
		required  string
		wantOK    bool
	}{
		{"the required challenge alone", validatedBy(common.ChallengeTypeEnroll01), common.ChallengeTypeEnroll01, true},
		{"two authorizations by the required challenge", validatedBy(common.ChallengeTypeEnroll01, common.ChallengeTypeEnroll01), common.ChallengeTypeEnroll01, true},
		{"no attestation challenge validated", validatedBy(), common.ChallengeTypeEnroll01, false},
		{"another challenge validated", validatedBy(common.ChallengeTypeEndorse01), common.ChallengeTypeEnroll01, false},
		{"required challenge beside another", validatedBy(common.ChallengeTypeEnroll01, common.ChallengeTypeEndorse01), common.ChallengeTypeEnroll01, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problem := tt.validated.requireOnly(9, tt.required, "test")
			if tt.wantOK {
				assert.Nil(t, problem)
				return
			}
			require.NotNil(t, problem)
			assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeBadCSR, problem.Type)
		})
	}

	assert.Equal(t, []string{"endorse-01", "enroll-01"}, validatedBy("enroll-01", "endorse-01").types())
	assert.Contains(t, (&ErrFinalizeRequestNotPermitted{OrderID: 9, Request: "TCG-CSR-IDEVID", Required: "enroll-01"}).Error(), "validated by no attestation challenge")
	assert.Contains(t, (&ErrFinalizeRequestNotPermitted{OrderID: 9, Request: "TCG-CSR-IDEVID", Required: "enroll-01", Validated: []string{"endorse-01"}}).Error(), "validated by endorse-01")
}

func parseCertificateDER(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }
