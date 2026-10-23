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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

var (
	errC704dTPMOpenFailed  = errors.New("c704d: tpm open failed")
	errC704dTPMCloseFailed = errors.New("c704d: tpm close failed")
)

// c704dDeliverSignal replaces notifySignals with one that hands the waiting
// command an os.Interrupt at once, as the operator's Ctrl+C would. It returns
// the signals the command asked to be notified of.
func c704dDeliverSignal(t *testing.T) *[]os.Signal {
	t.Helper()
	requested := &[]os.Signal{}
	original := notifySignals
	notifySignals = func(c chan<- os.Signal, sig ...os.Signal) {
		*requested = append(*requested, sig...)
		c <- os.Interrupt
	}
	t.Cleanup(func() { notifySignals = original })
	return requested
}

// c704dClosingTPM is a TPM that records its Close; nothing else is called on
// it by the flows under test.
type c704dClosingTPM struct {
	xkms.TrustedPlatformModule
	closed   bool
	closeErr error
}

func (m *c704dClosingTPM) Close() error {
	m.closed = true
	return m.closeErr
}

// c704dStubAttestationTPM replaces newAttestationTPM with one that returns
// tpm and err, and returns the params it was opened with.
func c704dStubAttestationTPM(t *testing.T, tpm xkms.TrustedPlatformModule, err error) **xkms.TPMParams {
	t.Helper()
	var opened *xkms.TPMParams
	original := newAttestationTPM
	newAttestationTPM = func(params *xkms.TPMParams) (xkms.TrustedPlatformModule, error) {
		opened = params
		return tpm, err
	}
	t.Cleanup(func() { newAttestationTPM = original })
	return &opened
}

// c704dWriteAgentCredentials writes a self-signed ECDSA certificate and its
// key, the certificate doubling as the CA bundle, and returns their paths.
func c704dWriteAgentCredentials(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(704),
		Subject:               pkix.Name{CommonName: "c704d-agent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "agent-cert.pem")
	keyPath = filepath.Join(dir, "agent-key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func TestRunDeviceConnect_DisconnectsOnSignal(t *testing.T) {
	requested := c704dDeliverSignal(t)
	certPath, keyPath := c704dWriteAgentCredentials(t)

	var out bytes.Buffer
	cmd := newDeviceConnectCmd(&out)
	require.NoError(t, cmd.Flags().Set("tls-cert", certPath))
	require.NoError(t, cmd.Flags().Set("tls-key", keyPath))
	require.NoError(t, cmd.Flags().Set("tls-ca", certPath))

	require.NoError(t, runDeviceConnect(cmd, []string{"127.0.0.1:1"}))

	assert.Contains(t, out.String(), "Connected to master at 127.0.0.1:1")
	assert.Contains(t, out.String(), "TLS Cert: "+certPath)
	assert.Contains(t, out.String(), "Disconnecting...")
	assert.ElementsMatch(t, []os.Signal{syscall.SIGINT, syscall.SIGTERM}, *requested)
}

func TestRunDeviceConnect_UnparseableCABundleRefuses(t *testing.T) {
	requested := c704dDeliverSignal(t)
	certPath, keyPath := c704dWriteAgentCredentials(t)
	badCA := filepath.Join(t.TempDir(), "ca-cert.pem")
	require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))

	var out bytes.Buffer
	cmd := newDeviceConnectCmd(&out)
	require.NoError(t, cmd.Flags().Set("tls-cert", certPath))
	require.NoError(t, cmd.Flags().Set("tls-key", keyPath))
	require.NoError(t, cmd.Flags().Set("tls-ca", badCA))

	err := runDeviceConnect(cmd, []string{"127.0.0.1:1"})

	require.ErrorIs(t, err, ErrAgentConnectFailed)
	assert.ErrorIs(t, err, agent.ErrCertificateInvalid)
	assert.NotContains(t, out.String(), "Connected to master")
	assert.Empty(t, *requested, "a refused connect never waits for a signal")
}

func TestRunDeviceRelay_StopsOnSignal(t *testing.T) {
	requested := c704dDeliverSignal(t)
	cmd, out := pairedRelayCommand(t, "0s")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "software"))

	require.NoError(t, runDeviceRelay(cmd, nil))

	assert.Contains(t, out.String(), "Stopping relay server...")
	assert.NotContains(t, out.String(), "Relay timeout reached")
	assert.ElementsMatch(t, []os.Signal{os.Interrupt, syscall.SIGTERM}, *requested)
}

func TestRunDeviceRelay_TPM2AttestationServesAndClosesTPM(t *testing.T) {
	c704dDeliverSignal(t)
	tpm := &c704dClosingTPM{closeErr: errC704dTPMCloseFailed}
	c704dStubAttestationTPM(t, tpm, nil)
	cmd, out := pairedRelayCommand(t, "0s")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "tpm2"))

	require.NoError(t, runDeviceRelay(cmd, nil), "a TPM close failure is logged, not returned")

	assert.Contains(t, out.String(), "Attestation mode: TPM2 (hardware)")
	assert.True(t, tpm.closed, "the relay closes the TPM it opened")
}

func TestRunDeviceRelay_AutoModeFallsBackToSoftware(t *testing.T) {
	c704dDeliverSignal(t)
	c704dStubAttestationTPM(t, nil, errC704dTPMOpenFailed)
	cmd, out := pairedRelayCommand(t, "0s")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "attestation-mode", "auto"))

	require.NoError(t, runDeviceRelay(cmd, nil))

	assert.Contains(t, out.String(), "Attestation mode: software")
}

func TestInitTPMForAttestation_OpensTheConfiguredDevice(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		wantDevice string
	}{
		{name: "default device", device: "", wantDevice: defaultTPMDevice},
		{name: "explicit device", device: "/dev/tpmrm7", wantDevice: "/dev/tpmrm7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := &c704dClosingTPM{}
			opened := c704dStubAttestationTPM(t, tpm, nil)

			got, err := initTPMForAttestation(tt.device, discardLogger())

			require.NoError(t, err)
			assert.Same(t, tpm, got)
			require.NotNil(t, *opened)
			assert.Equal(t, tt.wantDevice, (*opened).Config.Device)
			assert.Equal(t, "SHA-256", (*opened).Config.Hash)
		})
	}
}

func TestInitTPMForAttestation_ReturnsTheOpenError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "not provisioned", err: xkms.ErrTPMNotInitialized},
		{name: "open failed", err: errC704dTPMOpenFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c704dStubAttestationTPM(t, nil, tt.err)

			got, err := initTPMForAttestation("", discardLogger())

			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, got)
		})
	}
}
