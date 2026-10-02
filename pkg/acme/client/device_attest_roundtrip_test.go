//go:build tpm_simulator

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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/test/mocks"
)

// These tests run the Go client's DeviceAttest against the real ACME server
// handlers (pkg/acme/server/handlers) and the real device-attest-01 verifier.
// The server refuses a challenge whose attested identity is not the order's
// identifier (go-xkms#828), so a client that names anything but the device's
// own identity -- the IP address it used to send -- cannot get a certificate.
//
// The client opens no listener and names no address: draft-ietf-acme-device-
// attest has it POST the attestation, and the test server is built with no way
// to reach the device at all.

// attestingCA is the server's CA: the test AIK root and a mock for issuance.
// Anchoring the device's evidence is the production
// deviceattest01.TrustAnchorVerifier's job, configured with that root.
type attestingCA struct {
	*mocks.MockCertificateAuthority
	*attestationCA
	issued chan *x509.Certificate
}

// SignCSR issues a short-lived certificate for the CSR's key, signed by the
// test root, and records it for the test to compare with the client's.
func (a *attestingCA) SignCSR(_ context.Context, csrPEM []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	a.issued <- cert
	return cert, nil
}

// deviceAttestServer is a real ACME server with only device-attest-01 offered.
type deviceAttestServer struct {
	*httptest.Server
	issued chan *x509.Certificate
}

// startDeviceAttestServer serves the real handlers over TLS, verifying
// attestations with the production trust-anchor verifier rooted at issuer. The
// server is given no way to reach the device: it verifies only what the client
// POSTs, so the device needs no listener and no address.
func startDeviceAttestServer(t *testing.T, issuer *attestationCA) *deviceAttestServer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	issued := make(chan *x509.Certificate, 1)
	mockCA := &mocks.MockCertificateAuthority{}
	mockCA.On("Verify", mock.Anything, mock.Anything).Return([][]*x509.Certificate{}, nil)
	mockCA.On("CABundle").Return(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.cert.Raw}), nil)
	mockCA.On("TrustedIntermediate").Return(issuer.cert, nil).Maybe()
	mockCA.On("TrustedRoot").Return(issuer.cert, nil).Maybe()

	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)

	service, err := handlers.NewRestService(&handlers.Params{
		BaseRESTURI:    server.URL,
		CA:             &attestingCA{MockCertificateAuthority: mockCA, attestationCA: issuer, issued: issued},
		CAAIdentities:  []string{"acme.test"},
		ChallengeMap:   map[string]common.ChallengeVerifierFunc{},
		Logger:         logger,
		StorageFactory: factory,
		AttestingVerifiers: map[string]common.AttestingVerifier{
			common.ChallengeTypeDeviceAttest01: handlers.NewDeviceAttestVerifier(issuer.verifier(t)),
		},
	})
	require.NoError(t, err)
	rest := service.(*handlers.RestService)

	router := mux.NewRouter()
	acme := router.PathPrefix("/acme").Subrouter()
	acme.HandleFunc("/directory", rest.DirectoryHandler).Methods("GET", "HEAD")
	acme.HandleFunc("/new-nonce", rest.NewNonceHandler).Methods("HEAD", "GET")
	acme.HandleFunc("/new-account", rest.NewAccountHandler).Methods("POST")
	acme.HandleFunc("/new-order", rest.NewOrderHandler).Methods("POST")
	acme.HandleFunc("/order/{id}", rest.OrderHandler).Methods("POST", "GET")
	acme.HandleFunc("/order/{id}/finalize", rest.OrderFinalizeHandler).Methods("POST")
	acme.HandleFunc("/authz/{id}", rest.AuthorizationHandler).Methods("POST", "GET")
	acme.HandleFunc("/challenge/{id}", rest.ChallengeHandler).Methods("POST", "GET")
	acme.HandleFunc("/cert/{id}", rest.CertificateHandler).Methods("POST", "GET")
	server.Config.Handler = router

	return &deviceAttestServer{Server: server, issued: issued}
}

func newDeviceAttestRoundTripClient(t *testing.T, server *deviceAttestServer) *Client {
	t.Helper()
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})

	client, err := NewClient(&Params{
		AccountEmail:  "device@example.com",
		AccountSigner: accountKey,
		Config: &Config{
			DirectoryURL: server.URL + "/acme/directory",
			TrustedRoots: []string{string(certPEM)},
			Timeout:      30 * time.Second,
		},
		Storage:            newMockStorage(),
		CertificateStorage: newMockCertStorage(),
		OrderStorage:       newMockOrderStorage(),
	})
	require.NoError(t, err)
	_, err = client.RegisterAccount()
	require.NoError(t, err)
	return client
}

// TestDeviceAttestRoundTripAgainstTheRealServer is the client-to-server round
// trip: the client names the device's own identity, the real handler
// validates the challenge against the real verifier, and the certificate that
// finalization issues is for the attested key and carries that identity.
func TestDeviceAttestRoundTripAgainstTheRealServer(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	server := startDeviceAttestServer(t, issuer)
	client := newDeviceAttestRoundTripClient(t, server)

	cert, err := client.DeviceAttest(context.Background(), &EnrollmentConfig{
		Challenge:  string(ChallengeTypeDeviceAttest01),
		TPMModule:  adapter,
		CommonName: "device.example.com",
		Timeout:    10 * time.Second,
	})
	require.NoError(t, err)

	attested, err := adapter.CreateAttestedKey("device.example.com", "unused.keyauth")
	require.NoError(t, err)
	assert.True(t, cert.PublicKey.(*ecdsa.PublicKey).Equal(attested.Signer.Public()),
		"the certificate must be for the key the TPM attested")
	assert.Equal(t, "device.example.com", cert.Subject.CommonName)
	select {
	case issued := <-server.issued:
		assert.Equal(t, issued.Raw, cert.Raw)
	default:
		t.Fatal("the server issued no certificate")
	}
}

// impersonatingTPM is a device that claims an identity its AIK certificate
// does not carry.
type impersonatingTPM struct {
	*XKMSTPMAdapter
	claimed string
}

func (d impersonatingTPM) DeviceIdentity() (string, error) { return d.claimed, nil }

// A device that names another device's identity is refused: the evidence is
// genuine, but the attested identity is not the order's identifier, so the
// challenge is unauthorized and no certificate is issued.
func TestDeviceAttestRoundTripRefusesAnotherDevicesIdentity(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	server := startDeviceAttestServer(t, issuer)
	client := newDeviceAttestRoundTripClient(t, server)

	cert, err := client.DeviceAttest(context.Background(), &EnrollmentConfig{
		Challenge:  string(ChallengeTypeDeviceAttest01),
		TPMModule:  impersonatingTPM{XKMSTPMAdapter: adapter, claimed: "some-other-device"},
		CommonName: "device.example.com",
		Timeout:    10 * time.Second,
	})
	require.ErrorContains(t, err, "urn:ietf:params:acme:error:unauthorized")
	assert.Nil(t, cert)
	assert.Empty(t, server.issued, "no certificate may be issued for an identity the evidence does not carry")
}

func TestXKMSTPMAdapterDeviceIdentityIsTheIAKCertificatesPermanentIdentifier(t *testing.T) {
	adapter := newSimulatedDeviceAdapter(t, newAttestationCA(t))

	identity, err := adapter.DeviceIdentity()
	require.NoError(t, err)
	assert.Equal(t, simulatedDeviceIdentity, identity)
}

// device-attest-01 contacts no device, so its configuration needs no address:
// the server never dials one and the client opens no listener. The challenges
// whose server does dial the device still require it.
func TestEnrollmentConfigValidate_AddressByChallenge(t *testing.T) {
	adapter := newSimulatedDeviceAdapter(t, newAttestationCA(t))

	t.Run("device-attest-01 needs no address", func(t *testing.T) {
		config := &EnrollmentConfig{Challenge: string(ChallengeTypeDeviceAttest01), TPMModule: adapter}
		require.NoError(t, config.Validate())
	})

	for _, challenge := range []ChallengeType{ChallengeTypeEnroll01, ChallengeTypeEndorse01} {
		t.Run(string(challenge)+" requires the address the server dials", func(t *testing.T) {
			config := &EnrollmentConfig{Challenge: string(challenge), TPMModule: adapter}
			assert.ErrorIs(t, config.Validate(), ErrInvalidIPAddress)
		})
	}
}
