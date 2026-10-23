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

package client

import (
	"context"
	"crypto"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/test/mocks"
)

// attestingCA is the server's CA: a signing root and a mock for the rest of
// the CA surface. It issues; it does not judge the device's evidence.
// Anchoring that is the production deviceattest01.TrustAnchorVerifier's job,
// which the test configures separately.
type attestingCA struct {
	*mocks.MockCertificateAuthority
	cert   *x509.Certificate
	key    crypto.Signer
	issued chan *x509.Certificate
}

// SignCSR issues a short-lived certificate for the CSR's key, signed by the
// test root, and records it for the test to compare with the client's. The
// otherNames the server asks the CA to assert (SignOptions.OtherNames: the
// permanentIdentifier read from the verified evidence, never from the CSR)
// become the certificate's subjectAltName, as in the production CA, so a test
// can read the identity the certificate is bound to. It uses the issuer's
// reserved serial and notBefore and poisons a precertificate, as the
// production CA does (RFC 6962 §3.1), and records the final certificate only.
func (a *attestingCA) SignCSR(_ context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: opts.Serial,
		Subject:      csr.Subject,
		NotBefore:    opts.NotBefore,
		NotAfter:     opts.NotBefore.Add(time.Hour),
	}
	if opts.Precertificate {
		template.ExtraExtensions = append(template.ExtraExtensions, ct.MakePrecertPoisonExtension())
	}
	if len(opts.OtherNames) > 0 {
		san, err := ca.BuildSubjectAltName(csr.Subject, nil, nil, nil, nil, opts.OtherNames, nil)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = append(template.ExtraExtensions, san)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !opts.Precertificate {
		a.issued <- cert
	}
	return cert, nil
}

// ReserveSerial reserves the serial the issuer signs the precertificate and
// the certificate with.
func (a *attestingCA) ReserveSerial(_ context.Context) (*big.Int, error) {
	return big.NewInt(time.Now().UnixNano()), nil
}

// deviceAttestServer is a real ACME server with only device-attest-01 offered.
type deviceAttestServer struct {
	*httptest.Server
	issued chan *x509.Certificate
}

// startDeviceAttestServer serves the real handlers over TLS, verifying
// attestations with verifier -- the production trust-anchor verifier, whose
// roots the caller chose -- and issuing from the root issuerCert/issuerKey. The
// server is given no way to reach the device: it verifies only what the client
// POSTs, so the device needs no listener and no address.
func startDeviceAttestServer(t *testing.T, issuerCert *x509.Certificate, issuerKey crypto.Signer, verifier deviceattest01.AttestationVerifier) *deviceAttestServer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	issued := make(chan *x509.Certificate, 1)
	mockCA := &mocks.MockCertificateAuthority{}
	mockCA.On("Verify", mock.Anything, mock.Anything).Return([][]*x509.Certificate{}, nil)
	mockCA.On("CABundle").Return(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw}), nil)
	mockCA.On("TrustedIntermediate").Return(issuerCert, nil).Maybe()
	mockCA.On("TrustedRoot").Return(issuerCert, nil).Maybe()

	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)

	service, err := handlers.NewRestService(&handlers.Params{
		BaseRESTURI:    server.URL,
		CA:             &attestingCA{MockCertificateAuthority: mockCA, cert: issuerCert, key: issuerKey, issued: issued},
		CAAIdentities:  []string{"acme.test"},
		ChallengeMap:   map[string]common.ChallengeVerifierFunc{},
		Logger:         logger,
		StorageFactory: factory,
		AttestingVerifiers: map[string]common.AttestingVerifier{
			common.ChallengeTypeDeviceAttest01: handlers.NewDeviceAttestVerifier(verifier),
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
