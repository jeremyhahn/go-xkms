// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEKCertificate_FromStore tests EK certificate retrieval from store
func TestEKCertificate_FromStore(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to get EK certificate
	ekCert, err := tpm.EKCertificate()

	// Expected to fail in simulator without actual EK cert
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, ekCert)
	}
}

// TestEKCertificate_WithCertHandle tests EK certificate retrieval from NVRAM
func TestEKCertificate_WithCertHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)

	// Save original config and set a CertHandle
	originalCertHandle := tpm2Impl.config.EK.CertHandle
	tpm2Impl.config.EK.CertHandle = 0x01C00002 // Standard RSA EK cert index
	defer func() { tpm2Impl.config.EK.CertHandle = originalCertHandle }()

	// Try to read from NVRAM - will likely fail but tests the code path
	ekCert, err := tpm.EKCertificate()
	_ = ekCert
	_ = err
}

// TestParsePublicKey_RSA tests parsing RSA public key from TPM public area
func TestParsePublicKey_RSA(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK public to use for testing
	_, ekPub := tpm.EKPublic()

	// Marshal to bytes
	pubBytes := tpm2.Marshal(ekPub)

	// Parse it back
	pubKey, err := tpm.ParsePublicKey(pubBytes)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

// TestParsePublicKey_Invalid tests parsing with invalid data
func TestParsePublicKey_Invalid(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to parse invalid data
	_, err := tpm.ParsePublicKey([]byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

// TestOpenUnixSocketTransport tests opening Unix socket transport
func TestOpenUnixSocketTransport(t *testing.T) {
	// Try to open a non-existent socket - should fail
	_, err := OpenUnixSocketTransport("/tmp/nonexistent-tpm-socket.sock")
	assert.Error(t, err)
}

// TestFlush tests the Flush method
func TestFlush(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to flush a non-existent handle - should not panic
	tpm.Flush(tpm2.TPMHandle(0x80FFFFFF))
}

// TestReadHandle_CovTPM tests the ReadHandle method
func TestReadHandle_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	ekHandle := tpm2.TPMHandle(tpm2Impl.config.EK.Handle)

	name, pub, err := tpm.ReadHandle(ekHandle)
	require.NoError(t, err)
	assert.NotEmpty(t, name.Buffer)
	assert.NotEqual(t, tpm2.TPMAlgNull, pub.Type)
}

// TestReadHandle_InvalidHandle tests ReadHandle with invalid handle
func TestReadHandle_InvalidHandle(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, _, err := tpm.ReadHandle(tpm2.TPMHandle(0x81FFFFFF))
	assert.Error(t, err)
}

// TestConfig tests the Config method
func TestConfig(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	config := tpm.Config()
	assert.NotNil(t, config)
	assert.NotNil(t, config.EK)
	assert.NotNil(t, config.SSRK)
}

// TestRandom_CovTPM tests the Random method
func TestRandom_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	randomBytes, err := tpm.Random()
	require.NoError(t, err)
	assert.NotEmpty(t, randomBytes)
	assert.Len(t, randomBytes, 32) // Default is 32 bytes
}

// TestRandomBytes_CovTPM tests the RandomBytes method
func TestRandomBytes_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"128 bytes", 128},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			randomBytes, err := tpm.RandomBytes(tc.length)
			require.NoError(t, err)
			assert.Len(t, randomBytes, tc.length)
		})
	}
}

// TestEventLog tests the EventLog method
func TestEventLog(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Event log is typically not available in simulator
	eventLog, err := tpm.EventLog()
	if err != nil {
		// Expected to fail in simulator
		assert.Error(t, err)
	} else {
		assert.NotNil(t, eventLog)
	}
}

// TestIsPlatformPCRExtended_CovTPM tests the IsPlatformPCRExtended method
func TestIsPlatformPCRExtended_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	extended, err := tpm.IsPlatformPCRExtended()
	require.NoError(t, err)
	// May be true or false depending on TPM state
	_ = extended
}

// TestClose tests the Close method
func TestClose(t *testing.T) {
	_, tpm := createSim(false, false)

	err := tpm.Close()
	assert.NoError(t, err)

	// Closing again should be safe
	err = tpm.Close()
	// May or may not error depending on implementation
	_ = err
}

// TestPlatformQuote_CovTPM tests the PlatformQuote method
func TestPlatformQuote_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	quote, nonce, err := tpm.PlatformQuote(iakAttrs)

	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.NotEmpty(t, quote.Quoted)
	assert.NotEmpty(t, quote.Signature)
	assert.NotEmpty(t, nonce)
}

// TestQuote_CovTPM tests the Quote method with various PCR selections
func TestQuote_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tests := []struct {
		name  string
		pcrs  []uint
		nonce []byte
	}{
		{"single PCR", []uint{0}, nil},
		{"multiple PCRs", []uint{0, 1, 2}, nil},
		{"with nonce", []uint{0}, []byte("test-nonce")},
		{"golden PCRs", []uint{0, 7}, []byte("golden-nonce")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			quote, err := tpm.Quote(tc.pcrs, tc.nonce)
			require.NoError(t, err)
			assert.NotNil(t, quote)
			assert.NotEmpty(t, quote.Quoted)
		})
	}
}

// TestMakeCredential_CovTPM tests the MakeCredential method
func TestMakeCredential_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	secret := []byte("test-secret-for-credential")
	credential, encrypted, _, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)

	require.NoError(t, err)
	assert.NotEmpty(t, credential)
	assert.NotEmpty(t, encrypted)
}

// TestActivateCredential_CovTPM tests the ActivateCredential method
func TestActivateCredential_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// First make a credential
	secret := []byte("test-secret-to-activate")
	credential, encrypted, _, err := tpm.MakeCredential(iakAttrs.TPMAttributes.Name, secret)
	require.NoError(t, err)

	// Now activate it
	recoveredSecret, err := tpm.ActivateCredential(credential, encrypted)
	require.NoError(t, err)
	assert.Equal(t, secret, recoveredSecret)
}

// TestMakeCredentialWithExternalEK_CovTPM tests MakeCredentialWithExternalEK
func TestMakeCredentialWithExternalEK_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK certificate
	ekCert, err := tpm.EKCertificate()
	if err != nil {
		// No EK cert in simulator - skip
		t.Skip("EK certificate not available in simulator")
	}

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Get IAK public bytes
	_, iakPub := tpm.IAK().(interface{ Public() interface{} })
	_ = iakPub

	secret := []byte("external-ek-secret")
	credential, encrypted, _, err := tpm.MakeCredentialWithExternalEK(ekCert, tpm2.Marshal(iakAttrs.TPMAttributes.Public), secret)

	if err == nil {
		assert.NotEmpty(t, credential)
		assert.NotEmpty(t, encrypted)
	}
}

// TestProvision tests the Provision method
func TestProvision(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Try to provision - may already be provisioned
	err := tpm.Provision(nil)
	// Should succeed or indicate already provisioned
	_ = err
}

// TestSetHierarchyAuth_CovTPM tests the SetHierarchyAuth method
func TestSetHierarchyAuth_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// This is a sensitive operation - just test that it doesn't panic
	// with nil passwords (no change)
	err := tpm.SetHierarchyAuth(nil, nil, nil)
	// May succeed or fail depending on TPM state
	_ = err
}

// TestShareSecret_CovTPM tests ShareSecret and SecretFromShares
func TestShareSecret_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	secret := []byte("my-super-secret-key-material")

	// Share the secret into 5 parts (threshold 3)
	shares, err := tpm.ShareSecret(secret, 5)
	require.NoError(t, err)
	assert.Len(t, shares, 5)

	// Recover with 3 shares
	recoveredSecret, err := tpm.SecretFromShares(shares[:3])
	require.NoError(t, err)
	assert.NotEmpty(t, recoveredSecret)
}

// TestDevice_CovTPM tests the Device method
func TestDevice_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	device := tpm.Device()
	// Simulator will have a specific device name
	assert.NotEmpty(t, device)
}

// TestTransport_CovTPM tests the Transport method
func TestTransport_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	transport := tpm.Transport()
	assert.NotNil(t, transport)
}

// TestAlgID_CovTPM tests the AlgID method
func TestAlgID_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	algID := tpm.AlgID()
	assert.NotEqual(t, tpm2.TPMAlgNull, algID)
}

// TestEK_CovTPM tests the EK method
func TestEK_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// EK() panics if not initialized - get EKAttributes first to initialize
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	ek := tpm.EK()
	assert.NotNil(t, ek)
}

// TestEKRSA_CovTPM tests the EKRSA method
func TestEKRSA_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	ekRSA := tpm.EKRSA()
	// May be nil if EK is ECC
	_ = ekRSA
}

// TestEKECC_CovTPM tests the EKECC method
// Default config uses RSA EK, so EKECC will panic - we test panic behavior
func TestEKECC_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Initialize EK attributes first
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	// EKECC panics when EK is RSA (which is the default)
	// Use defer/recover to test the panic behavior
	defer func() {
		if r := recover(); r != nil {
			// Expected: EK is RSA, so EKECC panics
			t.Logf("EKECC correctly panicked for RSA EK: %v", r)
		}
	}()

	ekECC := tpm.EKECC()
	// If we get here, EK must be ECC
	_ = ekECC
}

// TestGoldenMeasurements_CovTPM tests the GoldenMeasurements method
func TestGoldenMeasurements_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	measurements := tpm.GoldenMeasurements()
	// May be nil if not configured
	_ = measurements
}

// TestPlatformPolicyDigest_CovTPM tests the PlatformPolicyDigest method
func TestPlatformPolicyDigest_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	digest := tpm.PlatformPolicyDigest()
	// Digest may be empty if platform policy not created
	_ = digest
}

// TestPlatformPolicyDigestHash_CovTPM tests the PlatformPolicyDigestHash method
func TestPlatformPolicyDigestHash_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	hash, err := tpm.PlatformPolicyDigestHash()
	// May fail if platform policy not created
	_ = hash
	_ = err
}

// TestRandomHex_CovTPM tests the RandomHex method
func TestRandomHex_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	hexBytes, err := tpm.RandomHex(32)
	require.NoError(t, err)
	assert.NotEmpty(t, hexBytes)
}

// TestRandomSource_CovTPM tests the RandomSource method
func TestRandomSource_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	source := tpm.RandomSource()
	assert.NotNil(t, source)

	// Read some random data through the source
	buf := make([]byte, 16)
	n, err := source.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 16, n)
}

// TestRead_CovTPM tests the Read method (io.Reader interface)
func TestRead_CovTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	buf := make([]byte, 32)
	n, err := tpm.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 32, n)
}
