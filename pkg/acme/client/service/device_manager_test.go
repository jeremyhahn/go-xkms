//go:build tpm_simulator

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

package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// deviceTestAccountConfig returns an AccountConfig that authenticates
// against the in-process fake ACME directory at directoryURL.
func deviceTestAccountConfig(directoryURL string) *AccountConfig {
	return &AccountConfig{
		DirectoryURL: directoryURL,
		Email:        "device-test@example.com",
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
	}
}

// newDeviceTestManager builds a DeviceManager whose sole account resolves
// against directoryURL through an in-memory storage factory (no filesystem
// or KMS dependency) and whose sole device spec is spec, registered as
// "dev1".
func newDeviceTestManager(t *testing.T, directoryURL string, spec *DeviceSpec) DeviceManager {
	t.Helper()

	cfg := testConfig()
	cfg.Accounts["acct"] = deviceTestAccountConfig(directoryURL)
	cfg.Devices = map[string]*DeviceSpec{"dev1": spec}

	accounts := NewAccountManager(cfg, testLogger()).(*accountManager)
	accounts.factories.Store("acct", newMemoryFactory(t))

	return NewDeviceManager(cfg, accounts, testLogger())
}

// selfSignedTestCert mints a throwaway self-signed certificate for use as a
// canned Finalize response from testutil.FakeACMEDirectory; its content is
// never inspected by go-xkms's enroll-01/device-attest-01 client code, only
// parsed as a well-formed X.509 certificate.
func selfSignedTestCert(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// iakCertDERFromCSR mints a self-signed certificate for the IAK public key
// packedCSR's TCG-CSR-IDEVID actually carries. go-xkms#1100 made EnrollDevice
// install the issued IAK certificate via TPM2.ProvisionIAKCert, which
// refuses a certificate whose public key does not match the TPM's real IAK
// (validateCertPublicKey, pkg/tpm2/cert_idevid.go) -- a certificate fixed
// before the TPM simulator that owns the real key exists can never pass
// that check, so the IAK certificate a fake ACME server hands back must be
// derived from the CSR the client actually submitted.
func iakCertDERFromCSR(packedCSR []byte) ([]byte, error) {
	tcgCSR, err := tpm2.UnmarshalIDevIDCSR(packedCSR)
	if err != nil {
		return nil, err
	}
	unpacked, err := tpm2.UnpackIDevIDCSR(tcgCSR)
	if err != nil {
		return nil, err
	}
	iakPubKey, err := tpm2.ExtractPublicKeyFromTPMPublic(unpacked.CsrContents.AttestPub)
	if err != nil {
		return nil, err
	}

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-iak"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, template, template, iakPubKey, signer)
}

// TestDeviceManager_Enroll_Success drives DeviceManager.Enroll through the
// real production openDeviceTPM path — the in-process TPM 2.0 simulator is
// opened and provisioned (EK, SSRK, IAK, throwaway EK certificate) exactly
// as it would be for a real device left with TPM: nil — against an
// in-process fake ACME directory offering enroll-01, proving the manager,
// the TPM opening/provisioning path and client.EnrollDevice compose
// end to end.
func TestDeviceManager_Enroll_Success(t *testing.T) {
	idevid := selfSignedTestCert(t, "test-idevid")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"}, nil)
	// The IAK certificate must name the TPM simulator's real IAK public
	// key (see iakCertDERFromCSR), which is only known once the simulator
	// under test opens -- so it is computed from the submitted CSR rather
	// than fixed at server construction like idevid above.
	server.SetCertsFromCSR(func(csr []byte) ([][]byte, error) {
		iakDER, err := iakCertDERFromCSR(csr)
		if err != nil {
			return nil, err
		}
		return [][]byte{iakDER, idevid}, nil
	})

	spec := &DeviceSpec{
		Account:    "acct",
		CommonName: "device-under-test",
		Identifier: "device-under-test",
		Challenge:  DeviceChallengeConfig{Port: "19801", Timeout: 30 * time.Second},
	}
	dm := newDeviceTestManager(t, server.DirectoryURL(), spec)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := dm.Enroll(ctx, "dev1")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.IAKCertificate)
	require.NotNil(t, result.IDevIDCertificate)

	info, err := dm.Show("dev1")
	require.NoError(t, err)
	require.NotNil(t, info.Enrollment)
	require.NotNil(t, info.EnrolledAt)
	require.Equal(t, result.IDevIDCertificate.SerialNumber, info.Enrollment.IDevIDCertificate.SerialNumber)
}

// TestDeviceManager_Enroll_InvalidEKCertificatePEM drives Enroll through
// openDeviceTPM far enough to open and provision the TPM simulator, then
// fail ensureEKCertificate on a malformed configured EKCertificatePEM. This
// exercises openDeviceTPM's cleanup path (closing the now-open TPM module
// before returning), verifying the original ErrInvalidEKCertificatePEM is
// still the error DeviceManager.Enroll's caller observes — the cleanup
// itself succeeding must not replace or hide it.
func TestDeviceManager_Enroll_InvalidEKCertificatePEM(t *testing.T) {
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"}, nil)

	spec := &DeviceSpec{
		Account:    "acct",
		CommonName: "device-under-test",
		Identifier: "device-under-test",
		Challenge:  DeviceChallengeConfig{Port: "19802", Timeout: 30 * time.Second},
		TPM: &DeviceTPMConfig{
			EKCertificatePEM: "not a valid PEM block",
		},
	}
	dm := newDeviceTestManager(t, server.DirectoryURL(), spec)

	_, err := dm.Enroll(context.Background(), "dev1")
	require.Error(t, err)

	var pemErr ErrInvalidEKCertificatePEM
	require.Truef(t, errors.As(err, &pemErr), "expected ErrInvalidEKCertificatePEM in chain, got %v", err)
	require.Equal(t, "dev1", pemErr.Name)
}

// TestDeviceManager_Enroll_UnknownSpec verifies Enroll returns
// ErrDeviceSpecNotFound for a device name absent from the configuration.
func TestDeviceManager_Enroll_UnknownSpec(t *testing.T) {
	cfg := testConfig()
	dm := NewDeviceManager(cfg, NewAccountManager(cfg, testLogger()), testLogger())

	_, err := dm.Enroll(context.Background(), "missing")
	var target ErrDeviceSpecNotFound
	require.True(t, errors.As(err, &target))
	require.Equal(t, "missing", target.Name)
}

// TestDeviceManager_Enroll_UnknownAccount verifies Enroll surfaces
// ErrAccountNotFound when the spec references an account that does not
// exist, before ever touching the TPM.
func TestDeviceManager_Enroll_UnknownAccount(t *testing.T) {
	cfg := testConfig()
	cfg.Devices = map[string]*DeviceSpec{"dev1": {Account: "ghost", Identifier: "device-under-test"}}
	dm := NewDeviceManager(cfg, NewAccountManager(cfg, testLogger()), testLogger())

	_, err := dm.Enroll(context.Background(), "dev1")
	var target ErrAccountNotFound
	require.True(t, errors.As(err, &target))
	require.Equal(t, "ghost", target.Name)
}

// TestDeviceManager_Attest_Success drives DeviceManager.Attest through the
// same real TPM-simulator path as Enroll, against a fake ACME directory
// offering device-attest-01 and returning a single attestation certificate.
func TestDeviceManager_Attest_Success(t *testing.T) {
	attestCert := selfSignedTestCert(t, "device-attest")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"},
		[][]byte{attestCert})

	spec := &DeviceSpec{
		Account:      "acct",
		CommonName:   "device-under-test",
		Identifier:   "device-under-test",
		PCRSelection: []int{0, 1, 7},
		Challenge:    DeviceChallengeConfig{Port: "19802", Timeout: 30 * time.Second},
	}
	dm := newDeviceTestManager(t, server.DirectoryURL(), spec)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := dm.Attest(ctx, "dev1")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Certificate)

	info, err := dm.Show("dev1")
	require.NoError(t, err)
	require.NotNil(t, info.Attestation)
	require.NotNil(t, info.AttestedAt)
}

// TestDeviceManager_Attest_UnknownSpec verifies Attest returns
// ErrDeviceSpecNotFound for a device name absent from the configuration.
func TestDeviceManager_Attest_UnknownSpec(t *testing.T) {
	cfg := testConfig()
	dm := NewDeviceManager(cfg, NewAccountManager(cfg, testLogger()), testLogger())

	_, err := dm.Attest(context.Background(), "missing")
	var target ErrDeviceSpecNotFound
	require.True(t, errors.As(err, &target))
}

// TestDeviceManager_Show_NotEnrolled verifies Show distinguishes a device
// spec that exists but has never been enrolled or attested from one that
// does not exist at all.
func TestDeviceManager_Show_NotEnrolled(t *testing.T) {
	cfg := testConfig()
	cfg.Devices = map[string]*DeviceSpec{"dev1": {Account: "acct", Identifier: "device-under-test"}}
	dm := NewDeviceManager(cfg, NewAccountManager(cfg, testLogger()), testLogger())

	_, err := dm.Show("dev1")
	var target ErrDeviceNotEnrolled
	require.True(t, errors.As(err, &target))

	_, err = dm.Show("missing")
	var notFound ErrDeviceSpecNotFound
	require.True(t, errors.As(err, &notFound))
}

// TestDeviceManager_List_FilterByAccount verifies List filters device specs
// by account name, exactly as CertificateManager.List does for certs.
func TestDeviceManager_List_FilterByAccount(t *testing.T) {
	cfg := testConfig()
	cfg.Devices = map[string]*DeviceSpec{
		"dev1": {Account: "acct-a", Identifier: "a"},
		"dev2": {Account: "acct-b", Identifier: "b"},
	}
	dm := NewDeviceManager(cfg, NewAccountManager(cfg, testLogger()), testLogger())

	all := dm.List("")
	require.Len(t, all, 2)

	filtered := dm.List("acct-a")
	require.Len(t, filtered, 1)
	require.Contains(t, filtered, "dev1")
}
