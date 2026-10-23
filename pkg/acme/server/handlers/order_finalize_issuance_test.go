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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newIssuanceCA returns an initialized in-memory pkg/ca CA.
func newIssuanceCA(t *testing.T) ca.TCGCA {
	t.Helper()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	certStore, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := ca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Finalize Issuance Test CA"
	config.Identity[0].Keys[0].KeyType = "CA"
	trustedCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:   config,
		KeyStore: backend,
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return backend, nil
		},
		RevocationStore: storage.NewMemory(),
		CertStore:       certStore,
		Profiles:        ca.NewDefaultProfileRegistry(),
	})
	require.NoError(t, err)
	require.NoError(t, trustedCA.Init(context.Background()))
	tcgCA, ok := trustedCA.(ca.TCGCA)
	require.True(t, ok, "pkg/ca CA is a TCGCA")
	return tcgCA
}

// finalizeThroughCA finalizes a ready example.com order with a CSR for a key
// on curve, issued by a real CA through the issuer under lint (RFC 8555
// §7.4).
func finalizeThroughCA(t *testing.T, curve elliptic.Curve, lint linter.Config) *httptest.ResponseRecorder {
	t.Helper()
	return finalizeIdentifierThroughCA(t, curve, &Params{Lint: lint},
		entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"})
}

// finalizeIdentifierThroughCA finalizes a ready order for id with a CSR for
// id on a key of curve, through an issuer built from params' Lint and Policy.
func finalizeIdentifierThroughCA(t *testing.T, curve elliptic.Curve, params *Params, id entities.ACMEIdentifier) *httptest.ResponseRecorder {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)
	setCAWithParams(t, service, newIssuanceCA(t), params)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{id}
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))

	csrKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.Value}}
	if id.Type == common.AuthzTypeIP {
		template.IPAddresses = []net.IP{net.ParseIP(id.Value)}
	} else {
		template.DNSNames = []string{id.Value}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url,
		OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	return resp
}

// problemType decodes the RFC 7807 problem document of a refused finalize.
func problemType(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	var problem entities.Error
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&problem))
	return problem.Type
}

func TestFinalizeIssuesThroughTheIssuer(t *testing.T) {
	resp := finalizeThroughCA(t, elliptic.P256(), linter.PrivatePKIConfig())

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	var order entities.ACMEOrder
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&order))
	assert.Equal(t, common.StatusValid, order.Status)
	assert.Contains(t, order.Certificate, "/acme/cert/")
}

func TestFinalizeRefusesAWeakKeyAsBadPublicKey(t *testing.T) {
	resp := finalizeThroughCA(t, elliptic.P224(), linter.PrivatePKIConfig())

	require.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	assert.Equal(t, "urn:ietf:params:acme:error:badPublicKey", problemType(t, resp))
}

func TestFinalizeRefusesALintErrorAsBadCSR(t *testing.T) {
	// The zero linter.Config runs every zlint lint, including the Baseline
	// Requirements lints the private-PKI leaf profile does not meet.
	resp := finalizeThroughCA(t, elliptic.P256(), linter.Config{})

	require.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemType(t, resp))
}

// finalizeDeviceThroughCA finalizes a device-attest-01 order for deviceA
// through a real CA that lints under lint.
func finalizeDeviceThroughCA(t *testing.T, lint linter.Config) *httptest.ResponseRecorder {
	t.Helper()
	setup := newDeviceFinalizeSetup(t, nil, deviceA)
	setCAWithParams(t, setup.service, newIssuanceCA(t), &Params{Lint: lint})
	return setup.finalize(t, deviceA, setup.deviceKeys[deviceA])
}

func TestFinalizeIssuesAnAttestedDeviceIdentityUnderThePrivatePKILint(t *testing.T) {
	// The certificate asserts the verified identity as a permanentIdentifier
	// otherName, which e_ext_san_other_name_present refuses outside this path.
	resp := finalizeDeviceThroughCA(t, linter.PrivatePKIConfig())

	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestFinalizeRefusesAnAttestedDeviceIdentityThatFailsLintAsBadCSR(t *testing.T) {
	resp := finalizeDeviceThroughCA(t, linter.Config{})

	require.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
	assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemType(t, resp))
}

// privateIdentifiers are identifiers the Baseline Requirements prohibit that
// a private-PKI identifier policy authorizes.
var privateIdentifiers = map[string]entities.ACMEIdentifier{
	"internal name": {Type: common.AuthzTypeDNS, Value: "db.internal"},
	"reserved IP":   {Type: common.AuthzTypeIP, Value: "10.0.0.1"},
}

func TestFinalizeIssuesIdentifiersThePolicyAuthorizes(t *testing.T) {
	// The default policy enforces neither a public suffix nor public IPs, so
	// finalize must not lint away what authorization accepted.
	for name, id := range privateIdentifiers {
		t.Run(name, func(t *testing.T) {
			resp := finalizeIdentifierThroughCA(t, elliptic.P256(), &Params{Lint: linter.PrivatePKIConfig()}, id)

			require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		})
	}
}

func TestFinalizeRefusesIdentifiersThePolicyProhibitsAsBadCSR(t *testing.T) {
	strict := &policy.PolicyConfig{RequirePublicSuffix: true, RejectReservedIPs: true}
	for name, id := range privateIdentifiers {
		t.Run(name, func(t *testing.T) {
			resp := finalizeIdentifierThroughCA(t, elliptic.P256(), &Params{Lint: linter.PrivatePKIConfig(), Policy: strict}, id)

			require.Equal(t, http.StatusBadRequest, resp.Code, resp.Body.String())
			assert.Equal(t, "urn:ietf:params:acme:error:badCSR", problemType(t, resp))
		})
	}
}
