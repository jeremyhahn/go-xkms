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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// These tests answer device-attest-01 challenges with XKMSTPMAdapter over a
// simulated go-xkms device and hand the response to the server's verifier,
// pkg/acme/challenges/device-attest-01, unchanged -- the verifier a TrustedCA
// runs.

// attestationCA issues AIK certificates to the WebAuthn Level 2 section 8.3.1
// profile and is the root the server anchors x5c to.
type attestationCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAttestationCA(t *testing.T) *attestationCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AIK CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &attestationCA{cert: cert, key: key}
}

// issueAIK certifies an attestation key: an empty subject, a subjectAltName
// naming the TPM, tcg-kp-AIKCertificate, and not a CA.
func (c *attestationCA) issueAIK(t *testing.T, public crypto.PublicKey) *x509.Certificate {
	t.Helper()
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil, nil, []pkix.Name{{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: ca.OIDTCGAttributeTPMManufacturer, Value: "id:53494D00"},
			{Type: ca.OIDTCGAttributeTPMModel, Value: "SIM"},
			{Type: ca.OIDTCGAttributeTPMVersion, Value: "id:00020000"},
		},
	}})
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ca.OIDTCGKpAIKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{san},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, public, c.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// VerifyAttestationObject adds no policy beyond the format's own checks.
func (c *attestationCA) VerifyAttestationObject(*deviceattest01.AttestationObject, []byte) error {
	return nil
}

// VerifyAKCertificateChain anchors x5c to this CA. An AIK certificate's
// subjectAltName is critical and holds only a directoryName, which
// crypto/x509 reports as unhandled; the format verifier reads it, so it is
// marked handled here as any anchoring implementation for "tpm" must.
func (c *attestationCA) VerifyAKCertificateChain(chain [][]byte) error {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	handled := leaf.UnhandledCriticalExtensions[:0]
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !oid.Equal(certstore.OIDSubjectAltName) {
			handled = append(handled, oid)
		}
	}
	leaf.UnhandledCriticalExtensions = handled

	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// newSimulatedDeviceAdapter provisions the simulator as a go-xkms device --
// EK, Shared SRK, IAK, Platform SRK, and an IAK certificate from issuer --
// and returns the adapter a device-attest-01 client uses over it.
func newSimulatedDeviceAdapter(t *testing.T, issuer *attestationCA) *XKMSTPMAdapter {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xkmssdk.OpenSimulator()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sim.Close()) })

	factory, err := store.NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, factory.Close()) })

	config := xkmssdk.DefaultTPMConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""

	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Config:    &config,
		Logger:    logger,
		Backend:   factory.KeyBackend(),
		BlobStore: factory.BlobStore(),
		CertStore: store.NewMemoryCertStore(logger),
		Transport: sim.Transport(),
	})
	if tpm != nil {
		t.Cleanup(func() { assert.NoError(t, tpm.Close()) })
	}
	if err == xkmssdk.ErrTPMNotInitialized {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	require.NoError(t, tpm2test.EnrollPlatformSRK(tpm, &config))

	iak, err := tpm.IAK()
	require.NoError(t, err)
	require.NoError(t, tpm.ProvisionIAKCert(issuer.issueAIK(t, iak)))

	return NewXKMSTPMAdapter(tpm, factory.KeyBackend())
}

// verifyServed serves a challenge response and runs the server's verifier
// over it for keyAuth.
func verifyServed(t *testing.T, issuer *attestationCA, statement []byte, keyAuth string) (*deviceattest01.VerifiedAttestation, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(statement)
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)
	return deviceattest01.VerifyAttestation(validation.NewClient(validation.Config{AllowPrivateTargets: true}), issuer, host, port, "token", keyAuth)
}

func csrSignedBy(t *testing.T, signer crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device.example.com"},
	}, signer)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestDeviceAttestChallengeIsAcceptedByTheVerifier is issue 1059 end to end on
// the client: the challenge response setupAttestChallenge produces is
// accepted by the server's device-attest-01 verifier, and the certificate key
// it returns makes a CSR the verifier binds to that response.
func TestDeviceAttestChallengeIsAcceptedByTheVerifier(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	client := createTestClient(t)
	config := &EnrollmentConfig{TPMModule: adapter, CommonName: "device.example.com"}
	const keyAuth = "token.thumbprint-of-the-account-key"

	attested, err := client.setupAttestChallenge(config, keyAuth)
	require.NoError(t, err)

	verified, err := verifyServed(t, issuer, attested.Statement, keyAuth)
	require.NoError(t, err)
	require.NoError(t, verified.BindCSRKey(csrSignedBy(t, attested.Signer)))

	// The account key -- what the CSR used to be signed with -- is refused.
	assert.ErrorIs(t, verified.BindCSRKey(csrSignedBy(t, client.accountSigner)), attestation.ErrKeyNotBound)
}

// A later challenge for the same certificate certifies the same key again,
// for the new key authorization only.
func TestDeviceAttestChallengeReusesTheCertificateKey(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)

	first, err := adapter.CreateAttestedKey("device.example.com", "first-token.thumbprint")
	require.NoError(t, err)
	second, err := adapter.CreateAttestedKey("device.example.com", "second-token.thumbprint")
	require.NoError(t, err)
	assert.Equal(t, first.Signer.Public(), second.Signer.Public())

	verified, err := verifyServed(t, issuer, second.Statement, "second-token.thumbprint")
	require.NoError(t, err)
	require.NoError(t, verified.BindCSRKey(csrSignedBy(t, first.Signer)))

	// The first response answered another challenge.
	_, err = verifyServed(t, issuer, first.Statement, "second-token.thumbprint")
	assert.ErrorIs(t, err, attestation.ErrStaleEvidence)
}

// Another certificate's key is another key: a CSR for it is refused against
// this certificate's attestation.
func TestDeviceAttestChallengeRefusesAnotherCertificatesKey(t *testing.T) {
	issuer := newAttestationCA(t)
	adapter := newSimulatedDeviceAdapter(t, issuer)
	const keyAuth = "token.thumbprint"

	attested, err := adapter.CreateAttestedKey("device.example.com", keyAuth)
	require.NoError(t, err)
	other, err := adapter.CreateAttestedKey("other.example.com", keyAuth)
	require.NoError(t, err)

	verified, err := verifyServed(t, issuer, attested.Statement, keyAuth)
	require.NoError(t, err)
	assert.ErrorIs(t, verified.BindCSRKey(csrSignedBy(t, other.Signer)), attestation.ErrKeyNotBound)
}
