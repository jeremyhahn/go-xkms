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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// go-xkms#1392: endorse-01 proves nothing about the key it certifies, so the
// External Account Binding is its only control. It is required by default, it
// must name the EK it authorizes, and what it names is the identity endorse-01
// reports.

// newEndorseEK returns an endorse-01 identifier (the base64url PKIX EK public
// key) and the SHA-256 hex hash an EAB binds it by.
func newEndorseEK(t *testing.T) (identifier, hash string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	digest := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(der), hex.EncodeToString(digest[:])
}

func TestEndorseEABValidator_BindsTheEKByHash(t *testing.T) {
	identifier, hash := newEndorseEK(t)
	otherIdentifier, _ := newEndorseEK(t)
	dao := NewMockEABDAO()
	binding := createTestEABBinding("kid-hash", 7, entities.EABStatusUsed)
	binding.DeviceInfo = &entities.EABDeviceInfo{EKPublicKeyHash: strings.ToUpper(hash)}
	require.NoError(t, dao.Save(context.Background(), binding))
	validator := NewEndorseEABValidator(dao, true, "")
	account := createTestAccountWithEAB(7, "kid-hash")

	t.Run("the bound EK is authorized, whatever the hash's case", func(t *testing.T) {
		result, err := validator.ValidateEndorseAuthorization(context.Background(), account, identifier)
		require.NoError(t, err)
		assert.Equal(t, identifier, result.AuthorizedIdentity)
		assert.False(t, result.Unauthenticated)
	})

	t.Run("another EK is refused", func(t *testing.T) {
		result, err := validator.ValidateEndorseAuthorization(context.Background(), account, otherIdentifier)
		assert.ErrorIs(t, err, ErrEndorseEABKeyMismatch)
		assert.Nil(t, result)
	})

	t.Run("an identifier that is not a base64url key is refused", func(t *testing.T) {
		result, err := validator.ValidateEndorseAuthorization(context.Background(), account, "not base64!")
		assert.ErrorIs(t, err, ErrEndorseEABKeyMismatch)
		assert.Nil(t, result)
	})
}

func TestEndorseEABValidator_BindsTheEKByMetadata(t *testing.T) {
	identifier, _ := newEndorseEK(t)
	dao := NewMockEABDAO()
	require.NoError(t, dao.Save(context.Background(), createTestEABBindingWithMetadata("kid-meta", 8, map[string]string{"ek": identifier})))
	validator := NewEndorseEABValidator(dao, true, "ek")
	account := createTestAccountWithEAB(8, "kid-meta")

	// The identity reported is the value the EAB holds, not the request's.
	result, err := validator.ValidateEndorseAuthorization(context.Background(), account, identifier)
	require.NoError(t, err)
	assert.Equal(t, identifier, result.AuthorizedIdentity)

	otherIdentifier, _ := newEndorseEK(t)
	_, err = validator.ValidateEndorseAuthorization(context.Background(), account, otherIdentifier)
	require.Error(t, err)
}

func TestEndorseEABValidator_RefusesABindingThatNamesNoKey(t *testing.T) {
	identifier, _ := newEndorseEK(t)
	dao := NewMockEABDAO()
	require.NoError(t, dao.Save(context.Background(), createTestEABBinding("kid-open", 9, entities.EABStatusUsed)))
	validator := NewEndorseEABValidator(dao, true, "")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), createTestAccountWithEAB(9, "kid-open"), identifier)

	assert.ErrorIs(t, err, ErrEndorseEABKeyNotBound)
	assert.Nil(t, result)
}

// With EAB waived nothing authorizes the identifier, and the result says so.
func TestEndorseEABValidator_WaivedEABIsUnauthenticated(t *testing.T) {
	validator := NewEndorseEABValidator(NewMockEABDAO(), false, "")

	result, err := validator.ValidateEndorseAuthorization(context.Background(), createTestAccountWithoutEAB(1), "any-key")

	require.NoError(t, err)
	assert.True(t, result.Authorized)
	assert.True(t, result.Unauthenticated)
	assert.Equal(t, "any-key", result.AuthorizedIdentity)
}

func TestEkIdentifierHashMatches(t *testing.T) {
	identifier, hash := newEndorseEK(t)
	assert.True(t, ekIdentifierHashMatches(identifier, hash))
	assert.True(t, ekIdentifierHashMatches(identifier, " "+strings.ToUpper(hash)+" "))
	assert.True(t, ekIdentifierHashMatches(identifier, "sha256:"+hash), "the form the admin API reference shows")
	assert.True(t, ekIdentifierHashMatches(identifier, "SHA256:"+strings.ToUpper(hash)))
	assert.False(t, ekIdentifierHashMatches(identifier, "sha1:"+hash), "another algorithm's prefix is not accepted")
	flipped := "0"
	if strings.HasSuffix(hash, "0") {
		flipped = "1"
	}
	assert.False(t, ekIdentifierHashMatches(identifier, hash[:len(hash)-1]+flipped), "a hash differing in its last digit")
	assert.False(t, ekIdentifierHashMatches("!!!", hash))
	assert.False(t, ekIdentifierHashMatches(identifier, ""))
}

// The verifier reports the EAB-authorized identity, and refuses to report any
// other: with no authorization there is nothing to attest.
func TestNewEndorseVerifier(t *testing.T) {
	verifier := NewEndorseVerifier()

	t.Run("reports the identity the EAB authorized", func(t *testing.T) {
		attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
			IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "the-order-identifier",
			AuthorizedIdentity: "the-eab-identity",
		})
		require.NoError(t, err)
		assert.Equal(t, "the-eab-identity", attested.Identifier, "the order's own identifier must not stand in for it")
	})

	t.Run("with no authorized identity there is nothing to attest", func(t *testing.T) {
		attested, err := verifier.VerifyAttested(nil, nil, common.AttestationChallenge{
			IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "the-order-identifier",
		})
		assert.ErrorIs(t, err, ErrEndorseNoAuthorizedIdentity)
		assert.Nil(t, attested)
	})
}

// newServiceWith builds a RestService from the test parameters with
// tweak applied, as an embedder would.
func newServiceWith(t *testing.T, tweak func(*Params)) *RestService {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)
	params := &Params{
		BaseRESTURI:    "https://acme.test.example.com",
		CA:             &MockCA{},
		CAAIdentities:  []string{"acme.test.example.com"},
		ChallengeMap:   make(map[string]common.ChallengeVerifierFunc),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		StorageFactory: factory,
	}
	tweak(params)
	service, err := NewRestService(params)
	require.NoError(t, err)
	return service.(*RestService)
}

// EAB is required by default, with no setting at all: a server built without
// mentioning endorse-01 fails closed.
func TestNewRestService_EndorseEABRequiredByDefault(t *testing.T) {
	tests := map[string]struct {
		tweak func(*Params)
		want  bool
	}{
		"zero value":                    {func(*Params) {}, true},
		"deprecated field set":          {func(p *Params) { p.EndorseEABRequired = true }, true},
		"explicitly optional":           {func(p *Params) { p.EndorseEABOptional = true }, false},
		"deprecated field beats waiver": {func(p *Params) { p.EndorseEABRequired = true; p.EndorseEABOptional = true }, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, newServiceWith(t, tt.tweak).endorseEABRequired)
		})
	}
}

// endorseChallengeSetup is an endorse-01 order for an EK, answered by an
// account that holds the EAB binding (if any).
type endorseChallengeSetup struct {
	service    *RestService
	key        *TestKey
	account    *entities.ACMEAccount
	authz      *entities.ACMEAuthorization
	identifier string
}

// newEndorseChallengeSetup creates the order and its authorization. bind, when
// non-nil, registers an endorse-01 EAB for the account bound to the EK hash it
// returns for the order's identifier; nil leaves the account with no EAB.
func newEndorseChallengeSetup(t *testing.T, bind func(identifier string) string) *endorseChallengeSetup {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)
	service.attestingVerifiers = map[string]common.AttestingVerifier{common.ChallengeTypeEndorse01: NewEndorseVerifier()}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	identifier, _ := newEndorseEK(t)
	id := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: identifier}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{id})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, id, []string{common.ChallengeTypeEndorse01})

	if bind != nil {
		binding := createTestEABBinding("endorse-kid", account.ID, entities.EABStatusUsed)
		binding.DeviceInfo = &entities.EABDeviceInfo{EKPublicKeyHash: bind(identifier)}
		eabDAO, err := service.storageFactory.ExternalAccountBindingDAO()
		require.NoError(t, err)
		require.NoError(t, eabDAO.Save(context.Background(), binding))

		account.ExternalAccountBinding = map[string]interface{}{"kid": binding.ID}
		accountDAO, err := service.storageFactory.AccountDAO()
		require.NoError(t, err)
		require.NoError(t, accountDAO.Save(context.Background(), account))
	}
	return &endorseChallengeSetup{service: service, key: key, account: account, authz: authz, identifier: identifier}
}

// hashOf is the hash an EAB binds an endorse-01 identifier by.
func hashOf(identifier string) string {
	der, err := base64.RawURLEncoding.DecodeString(identifier)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func (e *endorseChallengeSetup) run(t *testing.T) (*httptest.ResponseRecorder, entities.ACMEChallenge) {
	t.Helper()
	url := fmt.Sprintf("%s/acme/challenge/%d", e.service.baseRESTURI, e.authz.Challenges[0].ID)
	req := createJWSRequest(t, e.service, e.key, url, map[string]interface{}{}, true, e.account.ID)
	resp := httptest.NewRecorder()
	e.service.ChallengeHandler(resp, req)

	authzDAO, err := e.service.storageFactory.AuthorizationDAO(e.account.ID)
	require.NoError(t, err)
	stored, err := authzDAO.Get(context.Background(), e.authz.ID)
	require.NoError(t, err)
	return resp, stored.Challenges[0]
}

// The finding: with the old default (EAB not required) every account was
// authorized, so any ACME account could obtain an EK certificate for any key.
func TestChallengeHandler_Endorse01_RefusedWithoutEABByDefault(t *testing.T) {
	setup := newEndorseChallengeSetup(t, nil)

	resp, challenge := setup.run(t)

	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, common.StatusPending, challenge.Status, "an unauthorized account does not validate anything")
}

func TestChallengeHandler_Endorse01_BoundEKValidates(t *testing.T) {
	setup := newEndorseChallengeSetup(t, hashOf)

	resp, challenge := setup.run(t)

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, common.StatusValid, challenge.Status)
}

// An account bound to one EK cannot have another certified: the EAB, not the
// order, names the identity.
func TestChallengeHandler_Endorse01_AnotherEKThanTheBoundOneIsRefused(t *testing.T) {
	_, otherHash := newEndorseEK(t)
	setup := newEndorseChallengeSetup(t, func(string) string { return otherHash })

	resp, challenge := setup.run(t)

	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.NotEqual(t, common.StatusValid, challenge.Status)
}

// Waiving EAB is the operator's explicit choice and still validates, with
// nothing but the account behind the request.
func TestChallengeHandler_Endorse01_WaivedEABValidates(t *testing.T) {
	setup := newEndorseChallengeSetup(t, nil)
	setup.service.endorseEABRequired = false

	resp, challenge := setup.run(t)

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Equal(t, common.StatusValid, challenge.Status)
}

// go-xkms#1392: an endorse-01 authorization may finalize only the
// EK-certificate path, and the EK-certificate path belongs to endorse-01 alone.
// The challenge that validated the order decides, not what the identifier's
// bytes or the request look like.
func TestOrderFinalize_EKCertificate_OnlyForAnEndorse01Order(t *testing.T) {
	template := &x509.CertificateRequest{}

	t.Run("an endorse-01 order is issued the EK certificate", func(t *testing.T) {
		f := newEndorse01Fixture(t)

		resp := f.finalize(t, createEndorse01CSRWithManufacturer(t, template, endorse01CSRKey(t), testEndorseTPMManufacturer))

		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})

	// An identifier that decodes as a public key is not an endorse-01 order
	// unless endorse-01 validated it.
	for _, validatedBy := range []string{common.ChallengeTypeEnroll01, common.ChallengeTypeDeviceAttest01, common.ChallengeTypeHTTP01} {
		t.Run("an order "+validatedBy+" validated is not issued an EK certificate", func(t *testing.T) {
			f := newEndorse01FixtureValidatedBy(t, validatedBy)

			resp := f.finalize(t, createEndorse01CSRWithManufacturer(t, template, endorse01CSRKey(t), testEndorseTPMManufacturer))

			assertErrorType(t, resp, common.ErrTypeBadCSR, http.StatusBadRequest)
			assert.Nil(t, f.mockCA.lastEKRequest, "an EK certificate was requested from the CA")
		})
	}
}

// The other direction: an endorse-01-validated authorization for an identifier
// that is not an EK (so the EK path does not apply) cannot be finalized as a
// device-attest-01 certificate either.
func TestOrderFinalize_Endorse01OrderCannotBeFinalizedAsAnotherFlow(t *testing.T) {
	setup := newDeviceFinalizeSetup(t, nil, "device-a")
	finalized := func() *httptest.ResponseRecorder {
		return setup.finalize(t, "device-a", nil, setup.deviceKeys["device-a"])
	}
	require.Equal(t, http.StatusOK, finalized().Code, "the device-attest-01 order alone is issued")

	setup = newDeviceFinalizeSetup(t, nil, "device-a")
	// A second authorization on the same order, validated by endorse-01.
	authorizeOrderAlso(t, setup, "another-device", common.ChallengeTypeEndorse01)

	assertErrorType(t, finalized(), common.ErrTypeBadCSR, http.StatusBadRequest)
}

// authorizeOrderAlso adds to the setup's order a validated authorization for
// identifier by challengeType. (createTestAuthorizationWithChallenges appends
// it to the order and saves the order.)
func authorizeOrderAlso(t *testing.T, setup *deviceFinalizeSetup, identifier, challengeType string) {
	t.Helper()
	account := &entities.ACMEAccount{ID: setup.accountID}
	id := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: identifier}
	authz := createTestAuthorizationWithChallenges(t, setup.service, account, setup.order, id, []string{challengeType})
	authz.Status = common.StatusValid
	authz.Challenges[0].Status = common.StatusValid
	authzDAO, err := setup.service.storageFactory.AuthorizationDAO(setup.accountID)
	require.NoError(t, err)
	require.NoError(t, authzDAO.Save(context.Background(), authz))
}
