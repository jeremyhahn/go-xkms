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

package deviceattest01

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	xtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests run the device side of the "tpm" format against a go-xkms TPM
// provisioned the way a device is -- EK, Shared SRK, IAK, Platform SRK, and
// an IAK certificate from an attestation CA -- and hand what Setup produced to
// the server's verifier unchanged.

// provisionedDevice is a simulated go-xkms device.
type provisionedDevice struct {
	tpm     xtpm2.TrustedPlatformModule
	keys    store.KeyBackend
	backend *tpm2backend.Backend
}

// newProvisionedDevice provisions the simulator and has issuer certify its
// IAK. iak, when set, changes the IAK's configuration before provisioning.
func newProvisionedDevice(t *testing.T, issuer *aikIssuer, iak func(*xtpm2.IAKConfig)) *provisionedDevice {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := xtpm2.OpenSimulator()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sim.Close()) })

	factory, err := store.NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, factory.Close()) })

	config := xtpm2.DefaultConfig
	config.UseSimulator = false // the transport is supplied explicitly
	config.Device = ""
	iakConfig := *config.IAK
	if iak != nil {
		iak(&iakConfig)
	}
	config.IAK = &iakConfig

	tpm, err := xtpm2.NewTPM2(&xtpm2.Params{
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
	if err == xtpm2.ErrNotInitialized {
		require.NoError(t, tpm.Provision(nil))
	} else {
		require.NoError(t, err)
	}
	require.NoError(t, tpm2test.EnrollPlatformSRK(tpm, &config))

	iakPublic, err := tpm.IAK()
	require.NoError(t, err)
	iakCertificate, err := x509.ParseCertificate(issuer.issue(t, iakPublic, nil))
	require.NoError(t, err)
	require.NoError(t, tpm.ProvisionIAKCert(iakCertificate))

	backend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        tpm,
		KeyBackend: factory.KeyBackend(),
		Logger:     logger,
	})
	require.NoError(t, err)

	return &provisionedDevice{tpm: tpm, keys: factory.KeyBackend(), backend: backend}
}

// certificateKey creates a P-256 signing key under the Platform SRK, the key
// a device-attest-01 certificate is issued for.
func (d *provisionedDevice) certificateKey(t *testing.T, name string) (*types.KeyAttributes, crypto.Signer) {
	t.Helper()
	attrs := &types.KeyAttributes{
		CN:                 name,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            types.KeyTypeTLS,
		Hash:               crypto.SHA256,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ECCAttributes:      &types.ECCAttributes{Curve: elliptic.P256()},
	}
	key, err := d.backend.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	psrk, err := d.tpm.PlatformSRKAttributes()
	require.NoError(t, err)
	require.Equal(t, psrk.TPMAttributes.Handle, attrs.Parent.TPMAttributes.Handle, "the key must be parented to the Platform SRK")
	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	return attrs, signer
}

// decodePayload reads a challenge response back into its attestation object.
func decodePayload(t *testing.T, payload []byte) *AttestationObject {
	t.Helper()
	object, err := ParseAttestationRequest(payload)
	require.NoError(t, err)
	return object
}

func signedCSR(t *testing.T, signer crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, signer)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// iakConfigurations are the IAKs a device can hold, with the alg each answers
// with: the default RSA-PSS key and an ECDSA one, which exercise the two sig
// encodings.
var iakConfigurations = map[string]struct {
	configure func(*xtpm2.IAKConfig)
	alg       int64
}{
	"RSA-PSS (default)": {alg: -37},
	"ECDSA P-256": {
		configure: func(iak *xtpm2.IAKConfig) {
			iak.KeyAlgorithm = x509.ECDSA.String()
			iak.RSAConfig = nil
			iak.ECCConfig = &store.ECCConfig{Curve: elliptic.P256().Params().Name}
			iak.SignatureAlgorithm = x509.ECDSAWithSHA256.String()
		},
		alg: coseES256,
	},
}

// TestSetupIsAcceptedByTheVerifier is issue 1059: the client's evidence, as
// Setup produces it, passes the server's challenge verification and binds to
// a CSR signed by the certified key.
func TestSetupIsAcceptedByTheVerifier(t *testing.T) {
	for name, iak := range iakConfigurations {
		t.Run(name, func(t *testing.T) {
			issuer := newAIKIssuer(t, "AIK CA")
			device := newProvisionedDevice(t, issuer, iak.configure)
			key, signer := device.certificateKey(t, "device-attest")

			payload, err := Setup(tpmKeyAuth, device.tpm, key, device.keys)
			require.NoError(t, err)
			assert.Equal(t, iak.alg, decodePayload(t, payload).AttStatement.Alg)

			ca := anchoredTo(issuer)
			verified, err := VerifyAttestation(ca, payload, tpmKeyAuth)
			require.NoError(t, err)
			assert.True(t, ca.chainChecked, "x5c was never anchored")
			assert.Equal(t, FormatTPM, verified.Format)

			// The one-shot verifier still defers to the binding.
			assert.ErrorIs(t, Verify(ca, payload, tpmKeyAuth), ErrKeyBindingRequired)

			require.NoError(t, verified.BindCSRKey(signedCSR(t, signer)))
		})
	}
}

func TestSetupEvidenceRefusesACSRForAnotherKey(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	device := newProvisionedDevice(t, issuer, nil)
	key, _ := device.certificateKey(t, "device-attest")

	payload, err := Setup(tpmKeyAuth, device.tpm, key, device.keys)
	require.NoError(t, err)

	verified, err := VerifyAttestation(anchoredTo(issuer), payload, tpmKeyAuth)
	require.NoError(t, err)

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.ErrorIs(t, verified.BindCSRKey(signedCSR(t, software)), attestation.ErrKeyNotBound)

	// Another key under the same Platform SRK is no better.
	_, sibling := device.certificateKey(t, "sibling")
	assert.ErrorIs(t, verified.BindCSRKey(signedCSR(t, sibling)), attestation.ErrKeyNotBound)
}

// The certification must be made by the key x5c[0] certifies. Presenting the
// device's genuine certInfo and sig under an AIK certificate for another key
// -- from the same trusted CA -- is refused.
func TestSetupEvidenceRefusesACertificationUnderAnotherAIK(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	device := newProvisionedDevice(t, issuer, nil)
	key, _ := device.certificateKey(t, "device-attest")

	payload, err := Setup(tpmKeyAuth, device.tpm, key, device.keys)
	require.NoError(t, err)

	object := decodePayload(t, payload)
	otherAIK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	object.AttStatement.X5c = []interface{}{issuer.issue(t, otherAIK.Public(), nil)}

	_, err = verifyServed(t, anchoredTo(issuer), object)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
	assert.ErrorIs(t, err, xtpm2.ErrCertifySignature)
}

// A key that is not in this TPM cannot be certified, and Setup says so rather
// than producing a statement.
func TestSetupRefusesAKeyTheTPMDoesNotHold(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	device := newProvisionedDevice(t, issuer, nil)
	psrk, err := device.tpm.PlatformSRKAttributes()
	require.NoError(t, err)

	missing := &types.KeyAttributes{
		CN:            "never-created",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeTLS,
		StoreType:     types.StoreTPM2,
		Parent:        psrk,
		TPMAttributes: &types.TPMAttributes{},
	}
	payload, err := Setup(tpmKeyAuth, device.tpm, missing, device.keys)
	assert.ErrorIs(t, err, ErrCertifyFailed)
	assert.Nil(t, payload)
}
