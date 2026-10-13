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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// The key binding of go-xkms#789 follows the device the certificate request
// names, in every order shape that can carry a device-attest-01 authorization:
// not the first identifier listed, and not the first attestation recorded.

// deviceFinalizeSetup is a ready order with one validated device-attest-01
// authorization per device, each attesting its own key.
type deviceFinalizeSetup struct {
	service    *RestService
	mockCA     *MockCAForFinalize
	accountKey *TestKey
	accountID  uint64
	order      *entities.ACMEOrder
	deviceKeys map[string]*ecdsa.PrivateKey
}

func newDeviceFinalizeSetup(t *testing.T, leadingIdentifiers []entities.ACMEIdentifier, devices ...string) *deviceFinalizeSetup {
	t.Helper()
	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	t.Cleanup(cleanup)

	accountKey := generateTestKey(t)
	account := createTestAccount(t, service, accountKey)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = append([]entities.ACMEIdentifier(nil), leadingIdentifiers...)

	deviceKeys := make(map[string]*ecdsa.PrivateKey, len(devices))
	var authorizations []string
	for _, device := range devices {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		deviceKeys[device] = key
		order.Identifiers = append(order.Identifiers, entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: device})
		attachDeviceAttestation(t, service, order, account.ID, device, key)
		authorizations = append(authorizations, order.Authorizations...)
	}
	order.Authorizations = authorizations

	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))

	return &deviceFinalizeSetup{service: service, mockCA: mockCA, accountKey: accountKey, accountID: account.ID, order: order, deviceKeys: deviceKeys}
}

// finalize posts the possession request device sends, signed by signer.
func (d *deviceFinalizeSetup) finalize(t *testing.T, device string, signer *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	return d.finalizeCSR(t, devicePossessionCSR(t, signer, device, deviceAttestTestKeyAuth))
}

// finalizeCSR posts csr as the order's finalize request.
func (d *deviceFinalizeSetup) finalizeCSR(t *testing.T, csr *x509.CertificateRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csr.Raw)}

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", d.service.baseRESTURI, d.order.ID)
	req := createJWSRequest(t, d.service, d.accountKey, url, payload, true, d.accountID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", d.order.ID)})
	resp := httptest.NewRecorder()
	d.service.OrderFinalizeHandler(resp, req)
	return resp
}

// Device identities as an order names a DICE device: hex of its DeviceID.
const (
	deviceA = "0a0a0a0a"
	deviceB = "0b0b0b0b"
)

// A device-attest-01 authorization that follows a dns identifier in the same
// order still binds the request's key: the order's first identifier is not
// what decides whether the binding applies. A DICE device's possession request
// names the device alone (go-xkms#1441), so such an order cannot be issued.
func TestOrderFinalize_DeviceAttest01_MixedOrderStillBindsTheKey(t *testing.T) {
	dns := []entities.ACMEIdentifier{{Type: common.AuthzTypeDNS, Value: "host.example.com"}}
	withDNS := func(t *testing.T, signer *ecdsa.PrivateKey) *x509.CertificateRequest {
		return createPermanentIdentifierCSR(t, &x509.CertificateRequest{DNSNames: []string{"host.example.com"}}, signer, deviceA)
	}

	t.Run("a key the device did not attest is refused", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, dns, deviceA)
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		assertErrorType(t, setup.finalizeCSR(t, withDNS(t, software)), common.ErrTypeBadCSR, http.StatusBadRequest)
	})

	t.Run("the attested key asking for the dns name too is refused", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, dns, deviceA)

		resp := setup.finalizeCSR(t, withDNS(t, setup.deviceKeys[deviceA]))
		body := resp.Body.String()
		assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
		require.Contains(t, body, deviceattest01.ErrPossessionCSRMalformed.Error())
	})

	t.Run("the possession request does not cover the dns name", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, dns, deviceA)

		assertErrorType(t, setup.finalize(t, deviceA, setup.deviceKeys[deviceA]), common.ErrTypeRejectedIdentifier, http.StatusForbidden)
	})
}

// An order that authorizes two devices binds each request to the device it
// names: device B cannot be certified for device A's attested key. Nor can
// device B be certified at all, since its possession request names it alone
// and the order holds two devices.
func TestOrderFinalize_DeviceAttest01_BindsTheKeyOfTheDeviceNamed(t *testing.T) {
	t.Run("another device's attested key is refused", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, deviceA, deviceB)

		assertErrorType(t, setup.finalize(t, deviceB, setup.deviceKeys[deviceA]), common.ErrTypeBadCSR, http.StatusBadRequest)
	})

	t.Run("the named device's own key is refused for an order holding two devices", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, deviceA, deviceB)

		resp := setup.finalize(t, deviceB, setup.deviceKeys[deviceB])
		body := resp.Body.String()
		assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
		require.Contains(t, body, deviceattest01.ErrPossessionIdentifierMismatch.Error())
		require.Nil(t, setup.mockCA.lastSignOptions, "nothing was signed")
	})
}

func TestFindDeviceAttestation_SelectsTheRecordOfTheNamedDevice(t *testing.T) {
	setup := newDeviceFinalizeSetup(t, nil, deviceA, deviceB)
	authzDAO, err := setup.service.storageFactory.AuthorizationDAO(setup.accountID)
	require.NoError(t, err)

	rec, problem := setup.service.findDeviceAttestation(context.Background(), authzDAO, setup.order, deviceB)
	require.Nil(t, problem)
	require.NotNil(t, rec)
	require.Equal(t, deviceB, rec.DeviceIdentityValue)

	rec, problem = setup.service.findDeviceAttestation(context.Background(), authzDAO, setup.order, "device-unknown")
	require.Nil(t, problem)
	require.Nil(t, rec, "a device the order holds no attestation for has no record to bind against")
}

// A TCG-CSR-IDEVID is enroll-01's finalize request. Submitted for an order a
// device-attest-01 challenge validated, it would carry keys nothing attested,
// so it is refused rather than routed past the key binding.
func TestOrderFinalize_DeviceAttest01_RefusesATCGCSR(t *testing.T) {
	setup := newDeviceFinalizeSetup(t, nil, deviceA)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString([]byte("not-a-pkcs10-request"))}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", setup.service.baseRESTURI, setup.order.ID)
	req := createJWSRequest(t, setup.service, setup.accountKey, url, payload, true, setup.accountID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", setup.order.ID)})
	resp := httptest.NewRecorder()
	setup.service.OrderFinalizeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
}

// A device identity can decode as a public key, which is what marks an order
// endorse-01. The validated challenge decides, not the identifier's bytes: a
// device-attest-01 order is never finalized as an endorse-01 EK certificate.
func TestOrderFinalize_DeviceAttest01_IdentityThatDecodesAsAKeyIsNotEndorse01(t *testing.T) {
	spki, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(spki.Public())
	require.NoError(t, err)
	identity := base64.RawURLEncoding.EncodeToString(der)
	_, decodesAsKey := decodeEndorse01PublicKey(identity)
	require.True(t, decodesAsKey, "the fixture must be an identity the endorse-01 heuristic accepts")

	setup := newDeviceFinalizeSetup(t, nil, identity)
	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	assertErrorType(t, setup.finalizeCSR(t, createPermanentIdentifierCSR(t, &x509.CertificateRequest{}, software, identity)), common.ErrTypeBadCSR, http.StatusBadRequest)
}

// dropAuthorizations makes the order reference authorizations storage does not
// hold: what a partial restore or a replication fault leaves behind.
func dropAuthorizations(t *testing.T, setup *deviceFinalizeSetup) {
	t.Helper()
	setup.order.Authorizations = []string{fmt.Sprintf("%s/acme/authz/%d", setup.service.baseRESTURI, uint64(987654321))}
	orderDAO, err := setup.service.storageFactory.OrderDAO(setup.accountID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), setup.order))
}

// An order whose referenced authorization is missing is NOT an order no
// device-attest-01 challenge validated. Read that way it would skip the key
// binding exactly when state is incomplete: an endorse-01 EK certificate (or a
// TCG-CSR) would be issued for a key nothing attested.
func TestOrderFinalize_MissingAuthorizationRefusesFinalize(t *testing.T) {
	spki, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(spki.Public())
	require.NoError(t, err)
	identity := base64.RawURLEncoding.EncodeToString(der)

	t.Run("an endorse-01 request is not issued for a software key", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, identity)
		dropAuthorizations(t, setup)
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		resp := setup.finalizeCSR(t, createPermanentIdentifierCSR(t, &x509.CertificateRequest{}, software, identity))

		assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
		stored, err := mustOrderDAO(t, setup).Get(context.Background(), setup.order.ID)
		require.NoError(t, err)
		require.Equal(t, common.StatusReady, stored.Status, "a refused finalize leaves the order ready, not issued")
	})

	t.Run("a TCG-CSR is not routed past the missing authorization", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, deviceA)
		dropAuthorizations(t, setup)

		payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString([]byte("not-a-pkcs10-request"))}
		url := fmt.Sprintf("%s/acme/orders/%d/finalize", setup.service.baseRESTURI, setup.order.ID)
		req := createJWSRequest(t, setup.service, setup.accountKey, url, payload, true, setup.accountID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", setup.order.ID)})
		resp := httptest.NewRecorder()
		setup.service.OrderFinalizeHandler(resp, req)

		assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
	})

	t.Run("the same order finalizes while its authorization exists", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, deviceA)

		resp := setup.finalize(t, deviceA, setup.deviceKeys[deviceA])
		require.Equal(t, http.StatusOK, resp.Code)
	})
}

func mustOrderDAO(t *testing.T, setup *deviceFinalizeSetup) interface {
	Get(context.Context, uint64) (*entities.ACMEOrder, error)
} {
	t.Helper()
	orderDAO, err := setup.service.storageFactory.OrderDAO(setup.accountID)
	require.NoError(t, err)
	return orderDAO
}

func TestOrderAuthorizations(t *testing.T) {
	setup := newDeviceFinalizeSetup(t, nil, deviceA, deviceB)
	authzDAO, err := setup.service.storageFactory.AuthorizationDAO(setup.accountID)
	require.NoError(t, err)

	t.Run("loads every referenced authorization in order", func(t *testing.T) {
		authzs, problem := setup.service.orderAuthorizations(context.Background(), authzDAO, setup.order)
		require.Nil(t, problem)
		require.Len(t, authzs, 2)
		require.Equal(t, deviceA, authzs[0].Identifier.Value)
		require.Equal(t, deviceB, authzs[1].Identifier.Value)
	})

	t.Run("a missing authorization is a server fault, not an empty set", func(t *testing.T) {
		order := *setup.order
		order.Authorizations = append(append([]string(nil), setup.order.Authorizations...),
			fmt.Sprintf("%s/acme/authz/%d", setup.service.baseRESTURI, uint64(987654321)))

		authzs, problem := setup.service.orderAuthorizations(context.Background(), authzDAO, &order)
		require.Nil(t, authzs)
		require.NotNil(t, problem)
		require.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeServerInternal, problem.Type)
	})

	t.Run("an unparseable reference is malformed", func(t *testing.T) {
		order := *setup.order
		order.Authorizations = []string{"https://acme.example/authz/not-a-number"}

		authzs, problem := setup.service.orderAuthorizations(context.Background(), authzDAO, &order)
		require.Nil(t, authzs)
		require.NotNil(t, problem)
		require.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeMalformedError, problem.Type)
	})
}

func TestErrOrderAuthorizationMissing(t *testing.T) {
	err := &ErrOrderAuthorizationMissing{OrderID: 7, AuthorizationID: 9}
	require.Contains(t, err.Error(), "order 7")
	require.Contains(t, err.Error(), "authorization 9")
	require.Equal(t, http.StatusInternalServerError, err.Problem().Status)
}

// A device identity can decode as a public key. The challenge that validated
// the order decides what it is, so a device-attest-01 order whose identity
// happens to be key-shaped is bound to the attested key -- never issued an EK
// certificate for the identifier's key. A DICE identity is the hex of its
// DeviceID, which never decodes as a key, so no possession request can name
// a key-shaped one and even the attested key is refused (go-xkms#1441).
func TestOrderFinalize_DeviceAttest01_KeyShapedIdentityIsStillADeviceAttest01Order(t *testing.T) {
	spki, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(spki.Public())
	require.NoError(t, err)
	identity := base64.RawURLEncoding.EncodeToString(der)
	_, decodesAsKey := decodeEndorse01PublicKey(identity)
	require.True(t, decodesAsKey)

	t.Run("the attested key is refused, and not as an endorse-01 order", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, identity)
		csr := createPermanentIdentifierCSR(t, &x509.CertificateRequest{}, setup.deviceKeys[identity], identity)

		resp := setup.finalizeCSR(t, csr)

		body := resp.Body.String()
		assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
		require.Contains(t, body, deviceattest01.ErrPossessionCSRMalformed.Error())
		require.Nil(t, setup.mockCA.lastEKRequest, "an EK certificate was issued for the identity's key")
	})

	t.Run("a key the device did not attest is refused", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, identity)
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		assertErrorType(t, setup.finalizeCSR(t, createPermanentIdentifierCSR(t, &x509.CertificateRequest{}, software, identity)), common.ErrTypeBadCSR, http.StatusBadRequest)
	})
}

// The certificate asserts the identity the attestation established. The CA
// copies no otherName a CSR requests, so the handler hands the verified
// identity to it, or the issued certificate would carry no device identity.
func TestOrderFinalize_DeviceAttest01_CertificateAssertsTheAttestedIdentity(t *testing.T) {
	t.Run("a device-attest-01 order", func(t *testing.T) {
		setup := newDeviceFinalizeSetup(t, nil, deviceA)

		resp := setup.finalize(t, deviceA, setup.deviceKeys[deviceA])

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		require.NotNil(t, setup.mockCA.lastSignOptions)
		require.Len(t, setup.mockCA.lastSignOptions.OtherNames, 1)
		other := setup.mockCA.lastSignOptions.OtherNames[0]
		require.True(t, other.TypeID.Equal(ca.OIDPermanentIdentifier))
		parsed, err := ca.ParsePermanentIdentifierExtension(other.Value)
		require.NoError(t, err)
		require.Equal(t, deviceA, parsed.IdentifierValue)

		// The possession request's UCCS evidence answered the challenge; it
		// is never carried onto the certificate.
		for _, ext := range setup.mockCA.lastSignOptions.ExtraExtensions {
			require.False(t, ext.Id.Equal(dice.OIDUccsEvidence), "the requested UCCS evidence was copied onto the certificate")
		}
	})

	t.Run("an order no device attested asserts none", func(t *testing.T) {
		service, mockCA, cleanup := setupTestServiceWithMockCA(t)
		defer cleanup()
		key := generateTestKey(t)
		account := createTestAccount(t, service, key)
		order := createTestOrderSimple(t, service, account.ID)
		order.Status = common.StatusReady
		orderDAO, err := service.storageFactory.OrderDAO(account.ID)
		require.NoError(t, err)
		require.NoError(t, orderDAO.Save(context.Background(), order))

		csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.com"}}, csrKey)
		require.NoError(t, err)
		payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(der)}
		url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
		req := createJWSRequest(t, service, key, url, payload, true, account.ID)
		req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
		resp := httptest.NewRecorder()
		service.OrderFinalizeHandler(resp, req)

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		require.NotNil(t, mockCA.lastSignOptions)
		require.Empty(t, mockCA.lastSignOptions.OtherNames)
	})
}
