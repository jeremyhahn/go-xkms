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

package xkms

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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttestPIVSlot_OutputIsVerifiable closes the loop #206 was filed about:
// xkms produced attestation material that nothing in the stack could read
// back. This drives the real producer — AttestPIVSlot — and feeds its output
// straight into the verifier, so the two directions are covered at once and
// cannot drift apart independently.
//
// It does not claim the material matches a physical device; the certificate is
// synthesised here. What it establishes is that the producer's output is
// shaped so the verifier can consume it: PEM, leaf-first, chain in Chain.
func TestAttestPIVSlot_OutputIsVerifiable(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)

	// A vendor-style root and a slot certificate carrying real attestation
	// extensions, placed in the store AttestPIVSlot reads.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Vendor PIV Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	fw := pivcert.FirmwareVersion{Major: 5, Minor: 4, Patch: 3}
	serial := uint64(24681357)
	pinPolicy := pivcert.PINPolicyOnce
	touchPolicy := pivcert.TouchPolicyAlways
	exts, err := pivcert.BuildAttestationExtensions(&pivcert.Attestation{
		FirmwareVersion: &fw,
		SerialNumber:    &serial,
		PINPolicy:       &pinPolicy,
		TouchPolicy:     &touchPolicy,
	})
	require.NoError(t, err)

	slotKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	slotTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: PivSlotCN(slot)},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: exts,
	}
	slotDER, err := x509.CreateCertificate(rand.Reader, slotTmpl, rootCert, &slotKey.PublicKey, rootKey)
	require.NoError(t, err)
	slotCert, err := x509.ParseCertificate(slotDER)
	require.NoError(t, err)

	store := setupPIVForOps(t, nil)
	require.NoError(t, store.Store(slot, slotCert))

	// Drive the real producer.
	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Certificate)

	// Feed its output straight back in, exactly as a consumer would.
	block, _ := pem.Decode(resp.Certificate)
	require.NotNil(t, block, "AttestPIVSlot must emit PEM the verifier can decode")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	att, err := pivcert.VerifyAttestation([]*x509.Certificate{leaf},
		&pivcert.AttestationVerifyOptions{TrustedRoots: roots})
	require.NoError(t, err)

	require.NotNil(t, att.TouchPolicy)
	assert.Equal(t, pivcert.TouchPolicyAlways, *att.TouchPolicy,
		"the touch policy the producer emitted must survive to the verifier")
	require.NotNil(t, att.SerialNumber)
	assert.Equal(t, uint64(24681357), *att.SerialNumber)
	require.NotNil(t, att.FirmwareVersion)
	assert.Equal(t, "5.4.3", att.FirmwareVersion.String())
}

// TestAttestPIVSlot_SoftwareSlotCarriesNoAttestation is the counterpart, and
// the one that stops a caller reading a successful AttestPIV as a hardware
// verdict. A software-backed slot's certificate is one xkms self-signed: the
// call succeeds, and there is no device evidence in it at all.
func TestAttestPIVSlot_SoftwareSlotCarriesNoAttestation(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cert, _ := makeSelfSignedECDSA(t, PivSlotCN(slot))

	store := setupPIVForOps(t, nil)
	require.NoError(t, store.Store(slot, cert))

	resp, err := AttestPIVSlot(context.Background(), &transport.PIVAttestRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.NoError(t, err, "attestation of a software slot still returns material")

	block, _ := pem.Decode(resp.Certificate)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	att, err := pivcert.ParseAttestation(leaf)
	require.NoError(t, err)
	assert.False(t, att.HasAttestationExtensions(),
		"a software slot carries no device attestation, and a caller must be able to tell")
	assert.Nil(t, att.TouchPolicy)
}
