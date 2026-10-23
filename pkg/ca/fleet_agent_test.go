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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fleetCSR returns a PEM CSR for a fresh key carrying the given requested
// extensions.
func fleetCSR(t *testing.T, requested ...pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "node-1"},
		ExtraExtensions: requested,
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// fleetRoots returns verify options trusting only ca's certificate.
func fleetRoots(t *testing.T, ca *CA) x509.VerifyOptions {
	t.Helper()
	root, err := ca.CACertificate()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return x509.VerifyOptions{Roots: roots}
}

func TestSignCSR_FleetAgentStampsTheClaim(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.SignCSR(context.Background(), fleetCSR(t), &SignOptions{TenantID: testTenant, FleetAgent: true})
	require.NoError(t, err)

	require.NoError(t, VerifyFleetAgentClaim(cert, fleetRoots(t, ca)))
	var claims []pkix.Extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDFleetAgent) {
			claims = append(claims, ext)
		}
	}
	require.Len(t, claims, 1)
	assert.False(t, claims[0].Critical)
	assert.Equal(t, []byte{0x05, 0x00}, claims[0].Value, "the value is DER NULL")
}

func TestSignCSR_WithoutFleetAgentCarriesNoClaim(t *testing.T) {
	ca := setupTestCA(t)

	cert, err := ca.SignCSR(context.Background(), fleetCSR(t), &SignOptions{TenantID: testTenant})
	require.NoError(t, err)

	require.ErrorIs(t, VerifyFleetAgentClaim(cert, fleetRoots(t, ca)), ErrFleetAgentClaimAbsent)
}

// A CSR asking for the claim through the generic sign path, or through the
// SPIFFE adapter every transport calls, is refused and yields no
// certificate, whether or not the issuer stamps the claim itself.
func TestSignCSR_RefusesACSRRequestingTheClaim(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := fleetCSR(t, fleetAgentExtension())

	for name, sign := range map[string]func() (*x509.Certificate, error){
		"generic": func() (*x509.Certificate, error) {
			return ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant})
		},
		"issuer stamps too": func() (*x509.Certificate, error) {
			return ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant, FleetAgent: true})
		},
		"nil options": func() (*x509.Certificate, error) {
			return ca.SignCSR(context.Background(), csrPEM, nil)
		},
		"raw adapter": func() (*x509.Certificate, error) {
			return ca.SignCSRRaw(context.Background(), csrPEM, "", 0, testTenant)
		},
		"spiffe adapter": func() (*x509.Certificate, error) {
			return ca.SignCSRWithSPIFFE(context.Background(), csrPEM, "", 0, "cluster.example", testTenant, "svc", "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := sign()
			require.ErrorIs(t, err, ErrFleetAgentClaimRequested)
			assert.Nil(t, cert)
		})
	}
}

func TestSignCSR_RefusesTheClaimInExtraExtensions(t *testing.T) {
	ca := setupTestCA(t)

	for _, fleetAgent := range []bool{false, true} {
		_, err := ca.SignCSR(context.Background(), fleetCSR(t), &SignOptions{
			TenantID:        testTenant,
			FleetAgent:      fleetAgent,
			ExtraExtensions: []pkix.Extension{fleetAgentExtension()},
		})
		require.ErrorIs(t, err, ErrFleetAgentClaimReserved, "FleetAgent=%v", fleetAgent)
	}
}

// Stamping the claim never writes into the caller's ExtraExtensions array.
func TestStampFleetAgentClaim_LeavesTheCallersSliceAlone(t *testing.T) {
	other := pkix.Extension{Id: OIDAttestationEvidence, Value: []byte{0x05, 0x00}}
	extra := make([]pkix.Extension, 1, 4)
	extra[0] = other

	stamped, err := stampFleetAgentClaim(extra, true)
	require.NoError(t, err)

	require.Len(t, stamped, 2)
	assert.True(t, stamped[1].Id.Equal(OIDFleetAgent))
	assert.Equal(t, pkix.Extension{}, extra[:2][1], "the caller's spare capacity is untouched")

	unchanged, err := stampFleetAgentClaim(extra, false)
	require.NoError(t, err)
	assert.Equal(t, extra, unchanged)
}

func TestVerifyFleetAgentClaim_RejectsAnotherCAsClaim(t *testing.T) {
	trusted := setupTestCA(t)
	other := setupTestCA(t)

	cert, err := other.SignCSR(context.Background(), fleetCSR(t), &SignOptions{TenantID: testTenant, FleetAgent: true})
	require.NoError(t, err)
	require.NoError(t, VerifyFleetAgentClaim(cert, fleetRoots(t, other)), "the claim is valid from its own CA")

	require.ErrorIs(t, VerifyFleetAgentClaim(cert, fleetRoots(t, trusted)), ErrFleetAgentClaimUntrusted)
}

func TestVerifyFleetAgentClaim_RefusesInvalidInput(t *testing.T) {
	ca := setupTestCA(t)
	cert, err := ca.SignCSR(context.Background(), fleetCSR(t), &SignOptions{TenantID: testTenant, FleetAgent: true})
	require.NoError(t, err)

	require.ErrorIs(t, VerifyFleetAgentClaim(nil, fleetRoots(t, ca)), ErrFleetAgentClaimAbsent)
	require.ErrorIs(t, VerifyFleetAgentClaim(cert, x509.VerifyOptions{}), ErrFleetAgentClaimUntrusted,
		"the system trust store is never consulted")
}

// A claim that is critical or not DER NULL is malformed, even from a
// trusted issuer.
func TestVerifyFleetAgentClaim_RefusesAMalformedClaim(t *testing.T) {
	for name, claim := range map[string]pkix.Extension{
		"critical":      {Id: OIDFleetAgent, Critical: true, Value: []byte{0x05, 0x00}},
		"not NULL":      {Id: OIDFleetAgent, Value: []byte{0x01, 0x01, 0xff}},
		"trailing data": {Id: OIDFleetAgent, Value: []byte{0x05, 0x00, 0x00}},
	} {
		t.Run(name, func(t *testing.T) {
			cert, opts := selfSignedWithExtension(t, claim)
			require.ErrorIs(t, VerifyFleetAgentClaim(cert, opts), ErrFleetAgentClaimMalformed)
		})
	}
}

// selfSignedWithExtension returns a self-signed certificate carrying ext and
// verify options that trust it.
func selfSignedWithExtension(t *testing.T, ext pkix.Extension) (*x509.Certificate, x509.VerifyOptions) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return cert, x509.VerifyOptions{Roots: roots}
}
