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

package service

import (
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// unanchoredVerifier accepts any x5c chain. The simulator's IAK certificate is
// signed by a throwaway key no server would trust, so anchoring is not what
// these tests are about: everything after it -- the section 8.3.1 profile and
// the TPM2_Certify itself -- still runs.
type unanchoredVerifier struct{}

func (unanchoredVerifier) VerifyAttestationObject(*deviceattest01.AttestationObject, []byte) error {
	return nil
}

func (unanchoredVerifier) VerifyAKCertificateChain(chain [][]byte) error {
	_, err := x509.ParseCertificate(chain[0])
	return err
}

// A simulator device, opened the way DeviceManager.Attest opens it, answers a
// device-attest-01 challenge with evidence the server's verifier accepts:
// the Platform SRK exists to parent the certificate key, and the IAK
// certificate has the shape x5c[0] must have.
func TestOpenDeviceTPM_SimulatorAnswersDeviceAttest(t *testing.T) {
	spec := &DeviceSpec{Identifier: "device-under-test"}
	module, err := openDeviceTPM("dev1", spec, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, module.Close()) })

	const keyAuth = "token.thumbprint-of-the-account-key"
	attested, err := module.CreateAttestedKey("device-under-test", keyAuth)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(attested.Statement)
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)

	verified, err := deviceattest01.VerifyAttestation(net.DefaultResolver, unanchoredVerifier{}, host, port, "token", keyAuth)
	require.NoError(t, err)
	assert.Empty(t, verified.Leaf.Subject.Names, "section 8.3.1 requires an empty subject")
	assert.NotEmpty(t, certstore.ParseTCGAttributes(verified.Leaf).Manufacturer)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, attested.Signer)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	require.NoError(t, verified.BindCSRKey(csr))
}

func TestProvisionSimulatorIdentity_RequiresThePlatformSRKConfiguration(t *testing.T) {
	config := xkmssdk.DefaultTPMConfig
	config.PlatformSRK = nil

	err := provisionSimulatorIdentity("dev1", nil, &config)
	var incomplete ErrDeviceTPMConfigIncomplete
	require.ErrorAs(t, err, &incomplete)
	assert.Equal(t, "dev1", incomplete.Name)
}

// A TPM with no IAK has nothing for the certificate to certify.
func TestProvisionSimulatorIAKCertificate_RequiresAnIAK(t *testing.T) {
	sim, err := xkmssdk.OpenSimulator()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sim.Close()) })

	factory, err := xkmssdk.NewTPMStorageFactory(testLogger(), t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, factory.Close()) })

	config := xkmssdk.DefaultTPMConfig
	config.UseSimulator = false
	config.Device = ""
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{
		Config:    &config,
		Backend:   factory.KeyBackend(),
		BlobStore: factory.BlobStore(),
		Logger:    testLogger(),
		Transport: sim.Transport(),
	})
	require.ErrorIs(t, err, xkmssdk.ErrTPMNotInitialized, "the simulator must start unprovisioned")
	t.Cleanup(func() { assert.NoError(t, tpm.Close()) })

	err = provisionSimulatorIAKCertificate("dev1", tpm)
	var failed ErrDeviceTPMProvisionFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "dev1", failed.Name)
}
