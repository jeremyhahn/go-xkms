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
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/stretchr/testify/require"
)

const deviceAttestTestKeyAuth = "test-token.test-thumbprint"

// deviceAttestTestIdentity is a DICE device identity as an order names it:
// the lower-case hex of the device's DeviceID.
const deviceAttestTestIdentity = "deadbeef"

// newDICEAliasDeviceKey generates the P-256 key pkg/attestation/dice requires
// of every DICE-resident key.
func newDICEAliasDeviceKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// newDICEAliasCert mints a self-signed DICE alias certificate for key,
// echoing keyAuth's nonce in its eat_nonce claim -- the same construction
// deviceattest01's own tests use for a "dice" leaf, built here from the
// package's exported primitives (dice.CreateUccsEvidenceExtension,
// deviceattest01.DICENonce) so this orchestration test does not carry a
// second, unexported copy of DICE evidence construction. A non-nil ueid adds
// the tcg-dice-Ueid extension DeviceIdentity reads as the device's identity;
// nil leaves it off, matching a device that has attested but is not carrying
// a device identity in this evidence.
func newDICEAliasCert(t *testing.T, key *ecdsa.PrivateKey, keyAuth string, ueid []byte) []byte {
	t.Helper()

	extensions := []pkix.Extension{}
	uccs, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: deviceattest01.DICENonce(keyAuth)})
	require.NoError(t, err)
	extensions = append(extensions, uccs)

	if ueid != nil {
		ext, err := dice.CreateUeidExtension(ueid)
		require.NoError(t, err)
		extensions = append(extensions, ext)
	}

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "test dice alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	return der
}

// deviceAttestPayload is the body a device-attest-01 client POSTs to the
// challenge URL for a "dice" attestation statement carrying leafDER
// (draft-ietf-acme-device-attest-10): {"attObj": base64url(CBOR)}.
func deviceAttestPayload(t *testing.T, leafDER []byte) json.RawMessage {
	t.Helper()

	payload, err := deviceattest01.EncodeAttestationRequest(&deviceattest01.AttestationObject{
		Format: string(deviceattest01.FormatDICE),
		AttStatement: deviceattest01.AttestationStatement{
			X5c: []interface{}{leafDER},
		},
	})
	require.NoError(t, err)
	return payload
}

// deviceAttestCSR builds the possession request a DICE device sends at
// finalization for rec: the deviceattest01 template, signed by key, naming
// rec's device identity and carrying the nonce of rec's key authorization.
func deviceAttestCSR(t *testing.T, key *ecdsa.PrivateKey, rec *entities.DeviceAttestation) *x509.CertificateRequest {
	t.Helper()
	return devicePossessionCSR(t, key, rec.DeviceIdentityValue, rec.KeyAuthorization)
}

// deviceAttestOrder is the order rec authorizes: rec's device identity as its
// one permanent-identifier.
func deviceAttestOrder(rec *entities.DeviceAttestation) *entities.ACMEOrder {
	return &entities.ACMEOrder{
		ID: 1,
		Identifiers: []entities.ACMEIdentifier{{
			Type:  common.AuthzTypePermanentIdentifier,
			Value: rec.DeviceIdentityValue,
		}},
	}
}

// newDICEDeviceAttestation is the record a device-attest-01 challenge leaves
// for the DICE device whose UEID is ueid and whose provisioned DeviceID key,
// and alias key, is key.
func newDICEDeviceAttestation(t *testing.T, key *ecdsa.PrivateKey, keyAuth, deviceIdentity string, ueid []byte) *entities.DeviceAttestation {
	t.Helper()
	return &entities.DeviceAttestation{
		Format:              "dice",
		DeviceIdentityType:  common.AuthzTypePermanentIdentifier,
		DeviceIdentityValue: deviceIdentity,
		KeyAuthorization:    keyAuth,
		LeafDER:             newDICEAliasCert(t, key, keyAuth, ueid),
		AttestedSPKI:        marshalSPKI(t, key),
	}
}

// deviceBindSetup is a service whose device registry provisions one DICE
// device, and the record that device's challenge left.
type deviceBindSetup struct {
	service  *RestService
	registry *registeredDevices
	key      *ecdsa.PrivateKey
	ueid     []byte
	rec      *entities.DeviceAttestation
}

func newDeviceBindSetup(t *testing.T) *deviceBindSetup {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	key := newDICEAliasDeviceKey(t)
	ueid := newTestUeid(t)
	registry := serviceRegistry(t, service)
	registry.provision(t, ueid, key)
	return &deviceBindSetup{
		service:  service,
		registry: registry,
		key:      key,
		ueid:     ueid,
		rec:      newDICEDeviceAttestation(t, key, deviceAttestTestKeyAuth, hex.EncodeToString(ueid), ueid),
	}
}

// bind finalizes the order d.rec authorizes with a possession request signed
// by signer, against the record rec (nil when the challenge left none).
func (d *deviceBindSetup) bind(t *testing.T, rec *entities.DeviceAttestation, signer *ecdsa.PrivateKey) *entities.Error {
	t.Helper()
	return d.service.bindDeviceAttestationKey(context.Background(), rec, deviceAttestOrder(d.rec), deviceAttestCSR(t, signer, d.rec))
}

func requireProblem(t *testing.T, problem *entities.Error, errType string) {
	t.Helper()
	require.NotNil(t, problem)
	require.Equal(t, "urn:ietf:params:acme:error:"+errType, problem.Type)
}

// TestBindDeviceAttestationKey_MatchingKeySucceeds is go-xkms#789: a
// certificate request for the key a device-attest-01 challenge attested, and
// the device registry still vouches for, must be accepted.
func TestBindDeviceAttestationKey_MatchingKeySucceeds(t *testing.T) {
	setup := newDeviceBindSetup(t)

	require.Nil(t, setup.bind(t, setup.rec, setup.key))
}

// TestBindDeviceAttestationKey_DifferentKeyRefused is go-xkms#789's central
// case: a device-attest-01 challenge attested key A, and the CSR at
// finalization asks for a certificate on key B. Before this fix, nothing
// compared the two and the CSR was signed regardless.
func TestBindDeviceAttestationKey_DifferentKeyRefused(t *testing.T) {
	setup := newDeviceBindSetup(t)

	problem := setup.bind(t, setup.rec, newDICEAliasDeviceKey(t))
	requireProblem(t, problem, common.ErrTypeBadCSR)
	require.Contains(t, problem.Detail, deviceattest01.ErrPossessionKeyMismatch.Error())
}

// TestBindDeviceAttestationKey_NoRecordRefused proves a permanent-identifier
// order with no validated device-attest-01 attestation is refused rather than
// signed as an ordinary certificate request -- the fail-closed half of
// go-xkms#789.
func TestBindDeviceAttestationKey_NoRecordRefused(t *testing.T) {
	setup := newDeviceBindSetup(t)

	requireProblem(t, setup.bind(t, nil, setup.key), common.ErrTypeBadCSR)
}

// A DICE record without the attested SPKI was never anchored in the device
// registry, so there is no key to bind the request to (go-xkms#1441).
func TestBindDeviceAttestationKey_NoAttestedSPKIRefused(t *testing.T) {
	setup := newDeviceBindSetup(t)
	setup.rec.AttestedSPKI = nil

	requireProblem(t, setup.bind(t, setup.rec, setup.key), common.ErrTypeBadCSR)
}

// Finalization re-queries the registry: a device withdrawn, or re-keyed,
// between the challenge and the finalize is no longer authorized
// (go-xkms#1441).
func TestBindDeviceAttestationKey_RegistryChangedRefused(t *testing.T) {
	t.Run("the device was withdrawn", func(t *testing.T) {
		setup := newDeviceBindSetup(t)
		setup.registry.withdraw(setup.ueid)

		requireProblem(t, setup.bind(t, setup.rec, setup.key), common.ErrTypeUnauthorized)
	})

	t.Run("the device was re-keyed", func(t *testing.T) {
		setup := newDeviceBindSetup(t)
		setup.registry.provision(t, setup.ueid, newDICEAliasDeviceKey(t))

		requireProblem(t, setup.bind(t, setup.rec, setup.key), common.ErrTypeUnauthorized)
	})

	t.Run("no device registry is wired", func(t *testing.T) {
		setup := newDeviceBindSetup(t)
		setup.service.attestingVerifiers = nil

		requireProblem(t, setup.bind(t, setup.rec, setup.key), common.ErrTypeUnauthorized)
	})
}

// TestBindDeviceAttestationKey_DICERequiresThePossessionRequest is
// go-xkms#1441: for a DICE device the attested key is not enough. An ordinary
// request on that key, which the key binding alone accepts, is refused because
// it is not the device's possession request; so is a possession request
// answering another challenge, or naming identifiers the order does not hold.
func TestBindDeviceAttestationKey_DICERequiresThePossessionRequest(t *testing.T) {
	setup := newDeviceBindSetup(t)
	key, rec := setup.key, setup.rec

	ordinaryDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	require.NoError(t, err)
	ordinary, err := x509.ParseCertificateRequest(ordinaryDER)
	require.NoError(t, err)

	otherChallenge := *rec
	otherChallenge.KeyAuthorization = "other-token.test-thumbprint"

	mixedOrder := deviceAttestOrder(rec)
	mixedOrder.Identifiers = append(mixedOrder.Identifiers,
		entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "device.example.com"})

	tests := []struct {
		name  string
		order *entities.ACMEOrder
		csr   *x509.CertificateRequest
		want  error
	}{
		{"an ordinary request on the attested key", deviceAttestOrder(rec), ordinary, deviceattest01.ErrPossessionCSRMalformed},
		{"another challenge's nonce", deviceAttestOrder(rec), deviceAttestCSR(t, key, &otherChallenge), deviceattest01.ErrPossessionNonceMismatch},
		{"an order holding more than the device", mixedOrder, deviceAttestCSR(t, key, rec), deviceattest01.ErrPossessionIdentifierMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problem := setup.service.bindDeviceAttestationKey(context.Background(), rec, tt.order, tt.csr)
			requireProblem(t, problem, common.ErrTypeBadCSR)
			require.Contains(t, problem.Detail, tt.want.Error())
		})
	}
}

// TestFindDeviceAttestation_LocatesTheValidatedChallenge proves
// findDeviceAttestation reads the record a validated device-attest-01
// challenge left on the order's permanent-identifier authorization.
func TestFindDeviceAttestation_LocatesTheValidatedChallenge(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	ctx := context.Background()

	authzDAO, err := service.storageFactory.AuthorizationDAO(1)
	require.NoError(t, err)

	key := newDICEAliasDeviceKey(t)
	rec := newDICEDeviceAttestation(t, key, deviceAttestTestKeyAuth, "urn:dice:device:example", newTestUeid(t))

	authz := &entities.ACMEAuthorization{
		AccountID: 1,
		Identifier: entities.ACMEIdentifier{
			Type:  common.AuthzTypePermanentIdentifier,
			Value: "urn:dice:device:example",
		},
		Status: common.StatusValid,
		Challenges: []entities.ACMEChallenge{{
			Type:              common.ChallengeTypeDeviceAttest01,
			Status:            common.StatusValid,
			AccountID:         1,
			DeviceAttestation: rec,
		}},
	}
	require.NoError(t, authzDAO.Save(ctx, authz))

	order := &entities.ACMEOrder{
		ID:             1,
		AccountID:      1,
		Authorizations: []string{fmt.Sprintf("%d", authz.ID)},
	}

	got, problem := service.findDeviceAttestation(ctx, authzDAO, order, "urn:dice:device:example")
	require.Nil(t, problem)
	require.NotNil(t, got)
	require.Equal(t, rec, got)
}

// TestFindDeviceAttestation_NoValidatedChallengeReturnsNil proves an
// authorization with no validated device-attest-01 challenge yields no
// record rather than an error, so the caller's own fail-closed check
// (bindDeviceAttestationKey) is what refuses the request.
func TestFindDeviceAttestation_NoValidatedChallengeReturnsNil(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	ctx := context.Background()

	authzDAO, err := service.storageFactory.AuthorizationDAO(1)
	require.NoError(t, err)

	authz := &entities.ACMEAuthorization{
		AccountID: 1,
		Identifier: entities.ACMEIdentifier{
			Type:  common.AuthzTypePermanentIdentifier,
			Value: "urn:dice:device:example",
		},
		Status: common.StatusPending,
		Challenges: []entities.ACMEChallenge{{
			Type:      common.ChallengeTypeDeviceAttest01,
			Status:    common.StatusPending,
			AccountID: 1,
		}},
	}
	require.NoError(t, authzDAO.Save(ctx, authz))

	order := &entities.ACMEOrder{
		ID:             2,
		AccountID:      1,
		Authorizations: []string{fmt.Sprintf("%d", authz.ID)},
	}

	got, problem := service.findDeviceAttestation(ctx, authzDAO, order, "urn:dice:device:example")
	require.Nil(t, problem)
	require.Nil(t, got)
}

// TestNewDeviceAttestVerifier_ReturnsAttestedIdentityAndEvidence proves the
// verifier itself -- independent of ChallengeHandler's identity match -- reads
// the device identity the evidence carries from the client's payload and
// returns it alongside the verified evidence for finalize-time key binding
// (go-xkms#789, go-xkms#828). It is given no dial target and no port: nothing
// is contacted.
func TestNewDeviceAttestVerifier_ReturnsAttestedIdentityAndEvidence(t *testing.T) {
	setup := newDeviceBindSetup(t)
	verifier := setup.service.attestingVerifiers[common.ChallengeTypeDeviceAttest01]
	leafDER := newDICEAliasCert(t, setup.key, deviceAttestTestKeyAuth, setup.ueid)

	attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
		IdentifierType:   common.AuthzTypePermanentIdentifier,
		IdentifierValue:  "irrelevant-declared-value",
		Token:            "token",
		KeyAuthorization: deviceAttestTestKeyAuth,
		Payload:          deviceAttestPayload(t, leafDER),
	})
	require.NoError(t, err)
	require.NotNil(t, attested)
	require.Equal(t, hex.EncodeToString(setup.ueid), attested.Identifier)

	rec := attested.Attestation
	require.NotNil(t, rec, "the verified evidence must be returned for persistence")
	require.Equal(t, leafDER, rec.LeafDER)
	require.Equal(t, hex.EncodeToString(setup.ueid), rec.DeviceIdentityValue,
		"the record must name the attested identity, not the order's declared value")
	require.Equal(t, marshalSPKI(t, setup.key), rec.AttestedSPKI,
		"the record must carry the key the registry vouched for")

	// And the recorded evidence binds the device's own key at finalization.
	require.Nil(t, setup.bind(t, rec, setup.key))
}

// A device the registry does not provision is refused at the challenge, as
// unauthorized, however well formed its evidence (go-xkms#1441).
func TestNewDeviceAttestVerifier_UnregisteredDeviceRefused(t *testing.T) {
	verifier := NewDeviceAttestVerifier(newRegisteredDevices(t))
	key := newDICEAliasDeviceKey(t)

	attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
		IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "device",
		Token: "token", KeyAuthorization: deviceAttestTestKeyAuth,
		Payload: deviceAttestPayload(t, newDICEAliasCert(t, key, deviceAttestTestKeyAuth, newTestUeid(t))),
	})
	require.ErrorIs(t, err, deviceattest01.ErrDeviceNotAuthorized)
	require.ErrorIs(t, err, deviceattest01.ErrDeviceNotProvisioned)
	require.Nil(t, attested)
}

// TestNewDeviceAttestVerifier_UndecodablePayloadRefused proves a client that
// answers with anything but {"attObj": base64url(CBOR)} gets no identity.
func TestNewDeviceAttestVerifier_UndecodablePayloadRefused(t *testing.T) {
	verifier := NewDeviceAttestVerifier(newRegisteredDevices(t))

	for name, payload := range map[string][]byte{
		"an empty object (what a bare accept sends)": []byte(`{}`),
		"not JSON": []byte(`attObj`),
		"not CBOR": []byte(`{"attObj":"AAAA"}`),
	} {
		attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
			IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "device",
			Token: "token", KeyAuthorization: deviceAttestTestKeyAuth, Payload: payload,
		})
		require.Error(t, err, name)
		require.Nil(t, attested, name)
	}
}

// TestNewDeviceAttestVerifier_NoVerifierRefused proves a verifier built with
// no trust policy refuses every attestation rather than accepting a chain it
// cannot anchor.
func TestNewDeviceAttestVerifier_NoVerifierRefused(t *testing.T) {
	verifier := NewDeviceAttestVerifier(nil)

	leafDER := newDICEAliasCert(t, newDICEAliasDeviceKey(t), deviceAttestTestKeyAuth, []byte{0x01})
	attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
		IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "device",
		Token: "token", KeyAuthorization: deviceAttestTestKeyAuth, Payload: deviceAttestPayload(t, leafDER),
	})
	require.ErrorIs(t, err, deviceattest01.ErrNoAttestationVerifier)
	require.Nil(t, attested)
}

// TestNewDeviceAttestVerifier_WrongIdentifierTypeRefused proves an
// authorization of any type other than permanent-identifier is refused
// before a device identity is even read: draft-ietf-acme-device-attest-10's
// identity binding is defined for permanent-identifier, and this server offers
// no other identifier type for device-attest-01.
func TestNewDeviceAttestVerifier_WrongIdentifierTypeRefused(t *testing.T) {
	verifier := NewDeviceAttestVerifier(newRegisteredDevices(t))

	attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
		IdentifierType: common.AuthzTypeDNS, IdentifierValue: "example.com",
		Token: "token", KeyAuthorization: deviceAttestTestKeyAuth,
	})
	var typeErr *ErrAttestationIdentifierType
	require.ErrorAs(t, err, &typeErr)
	require.Equal(t, common.ChallengeTypeDeviceAttest01, typeErr.Challenge)
	require.Equal(t, common.AuthzTypeDNS, typeErr.Type)
	require.Nil(t, attested)
}

// deviceAttestChallengeSetup is what a device-attest-01 ChallengeHandler test
// needs: a service wired with the real verifier, an order for identifier, and
// the account that answers the challenge.
type deviceAttestChallengeSetup struct {
	service    *RestService
	account    *entities.ACMEAccount
	accountKey *TestKey
	authz      *entities.ACMEAuthorization
	deviceKey  *ecdsa.PrivateKey
	payload    json.RawMessage

	registry       *registeredDevices
	deviceIdentity []byte
}

// newDeviceAttestChallengeSetup attests a device with identity deviceIdentity
// against an order for identifier. The payload is the attestation the client
// POSTs; no server stands in for the device because the handler never
// contacts it.
func newDeviceAttestChallengeSetup(t *testing.T, identifier string, deviceIdentity []byte) *deviceAttestChallengeSetup {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	accountKey := generateTestKey(t)
	account := createTestAccount(t, service, accountKey)
	id := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: identifier}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{id})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, id,
		[]string{common.ChallengeTypeDeviceAttest01})

	keyAuth, err := KeyAuthorization(authz.Challenges[0].Token, accountKey.PublicKey)
	require.NoError(t, err)

	deviceKey := newDICEAliasDeviceKey(t)
	registry := serviceRegistry(t, service)
	registry.provision(t, deviceIdentity, deviceKey)

	return &deviceAttestChallengeSetup{
		service: service, account: account, accountKey: accountKey, authz: authz, deviceKey: deviceKey,
		registry: registry, deviceIdentity: deviceIdentity,
		payload: deviceAttestPayload(t, newDICEAliasCert(t, deviceKey, keyAuth, deviceIdentity)),
	}
}

// run POSTs payload to the challenge and returns the stored challenge.
func (d *deviceAttestChallengeSetup) run(t *testing.T, payload interface{}) entities.ACMEChallenge {
	t.Helper()
	challenge := d.authz.Challenges[0]
	url := fmt.Sprintf("%s/acme/challenge/%d", d.service.baseRESTURI, challenge.ID)
	req := createJWSRequest(t, d.service, d.accountKey, url, payload, true, d.account.ID)
	req.RemoteAddr = "192.0.2.1:12345"

	resp := httptest.NewRecorder()
	d.service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	authzDAO, err := d.service.storageFactory.AuthorizationDAO(d.account.ID)
	require.NoError(t, err)
	stored, err := authzDAO.Get(context.Background(), d.authz.ID)
	require.NoError(t, err)
	return stored.Challenges[0]
}

// TestChallengeHandler_DeviceAttest01_IdentityMismatchRefused is go-xkms#828
// end to end with the real verifier: a genuine attestation from device X,
// presented against an order for a different identifier, leaves the
// challenge invalid and unauthorized even though the evidence itself
// verifies (a real device, a real chain, a real key).
func TestChallengeHandler_DeviceAttest01_IdentityMismatchRefused(t *testing.T) {
	setup := newDeviceAttestChallengeSetup(t, "device-b", []byte{0xDE, 0xAD, 0xBE, 0xEF})

	stored := setup.run(t, setup.payload)
	require.Equal(t, common.StatusInvalid, stored.Status,
		"a valid attestation for device X must not authorize an order for identifier \"device-b\"")
	require.NotNil(t, stored.Error)
	require.Equal(t, "urn:ietf:params:acme:error:unauthorized", stored.Error.Type)
	require.Nil(t, stored.DeviceAttestation, "no record may be persisted when the identity does not authorize the order")
}

// TestChallengeHandler_DeviceAttest01_MatchingIdentityPersistsRecord is the
// positive direction: when the attested identity is the order's identifier
// the challenge validates and the verified evidence is persisted, bound to
// the device's own key, for finalization (go-xkms#789). The identifier is a
// device identity, not an address, and the handler needs nothing else.
func TestChallengeHandler_DeviceAttest01_MatchingIdentityPersistsRecord(t *testing.T) {
	identity := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	setup := newDeviceAttestChallengeSetup(t, hex.EncodeToString(identity), identity)

	stored := setup.run(t, setup.payload)
	require.Equal(t, common.StatusValid, stored.Status)
	require.NotNil(t, stored.DeviceAttestation, "the verified evidence must be persisted for finalization")
	require.Equal(t, hex.EncodeToString(identity), stored.DeviceAttestation.DeviceIdentityValue)
	require.Equal(t, marshalSPKI(t, setup.deviceKey), stored.DeviceAttestation.AttestedSPKI,
		"the attested SPKI must survive storage to reach finalization")
	rec := stored.DeviceAttestation
	require.Nil(t, setup.service.bindDeviceAttestationKey(context.Background(), rec, deviceAttestOrder(rec), deviceAttestCSR(t, setup.deviceKey, rec)))
}

// A device the registry does not provision leaves the challenge invalid and
// unauthorized, with no record persisted (go-xkms#1441).
func TestChallengeHandler_DeviceAttest01_UnregisteredDeviceRefused(t *testing.T) {
	identity := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	setup := newDeviceAttestChallengeSetup(t, hex.EncodeToString(identity), identity)
	setup.registry.withdraw(setup.deviceIdentity)

	stored := setup.run(t, setup.payload)
	require.Equal(t, common.StatusInvalid, stored.Status)
	require.NotNil(t, stored.Error)
	require.Equal(t, "urn:ietf:params:acme:error:unauthorized", stored.Error.Type)
	require.Nil(t, stored.DeviceAttestation)
}

// TestChallengeHandler_DeviceAttest01_EmptyResponseRefused is the client that
// accepts the challenge the way every other challenge type is accepted, with
// "{}". The server has nothing to verify and, because it never dials, nothing
// to go and fetch: the challenge is invalid, not pending forever.
func TestChallengeHandler_DeviceAttest01_EmptyResponseRefused(t *testing.T) {
	identity := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	setup := newDeviceAttestChallengeSetup(t, hex.EncodeToString(identity), identity)

	stored := setup.run(t, map[string]interface{}{})
	require.Equal(t, common.StatusInvalid, stored.Status)
	require.Nil(t, stored.DeviceAttestation)
}

// TestChallengeHandler_DeviceAttest01_NeverDialsTheDevice pins draft-ietf-acme-
// device-attest's model at the handler: what the verifier is handed is the
// client's payload, and no address or port, even for the loopback identifier
// enroll-01 substitutes the client's address for.
func TestChallengeHandler_DeviceAttest01_NeverDialsTheDevice(t *testing.T) {
	setup := newDeviceAttestChallengeSetup(t, loopbackIdentifier, []byte{0x01})
	setup.service.allowLoopbackIdentifier = true

	var seen common.AttestationChallenge
	setup.service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeDeviceAttest01: common.AttestingVerifierFunc(func(
			_ *net.Resolver, _ common.CertificateAuthority, challenge common.AttestationChallenge,
		) (*common.AttestedIdentity, error) {
			seen = challenge
			return &common.AttestedIdentity{Identifier: challenge.IdentifierValue}, nil
		}),
	}

	stored := setup.run(t, setup.payload)
	require.Equal(t, common.StatusValid, stored.Status)
	require.Empty(t, seen.DialTarget, "device-attest-01 must not be handed an address to contact")
	require.Empty(t, seen.Port, "device-attest-01 must not be handed a port to contact")
	require.JSONEq(t, string(setup.payload), string(seen.Payload), "the verifier is handed the client's payload")
}

// TestChallengeHandler_Enroll01_StillDialsTheDevice is the other side of the
// same split: enroll-01 and endorse-01 answer by contacting the device, so
// they are still handed the address and port.
func TestChallengeHandler_Enroll01_StillDialsTheDevice(t *testing.T) {
	require.True(t, dialsDevice(common.ChallengeTypeEnroll01))
	require.True(t, dialsDevice(common.ChallengeTypeEndorse01))
	require.False(t, dialsDevice(common.ChallengeTypeDeviceAttest01))
	require.False(t, dialsDevice(common.ChallengeTypeHTTP01))
}
