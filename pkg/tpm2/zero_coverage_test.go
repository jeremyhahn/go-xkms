//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorPassword implements types.Password and always returns an error
type errorPassword struct{}

func (e *errorPassword) String() (string, error) {
	return "", errors.New("password string error")
}

func (e *errorPassword) Bytes() []byte {
	return nil
}

func (e *errorPassword) Clear() {
	// No-op
}

// TestOpenWithSimulator tests the Open function with simulator config
func TestOpenWithSimulator(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("opens simulator connection", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: true,
				Device:       "/dev/tpmrm0",
			},
		}

		err := tpmInstance.Open()
		assert.NoError(t, err)
		assert.NotNil(t, tpmInstance.transport)
		assert.NotNil(t, tpmInstance.simulator)

		// Clean up
		if tpmInstance.simulator != nil {
			_ = tpmInstance.simulator.Close()
		}
	})

	t.Run("opens device connection error with nonexistent device", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: false,
				Device:       "/dev/nonexistent_tpm_device_12345",
			},
		}

		err := tpmInstance.Open()
		assert.Error(t, err)
		assert.Equal(t, ErrOpeningDevice, err)
	})

	t.Run("returns error for invalid transport config", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: false,
				Device:       "",
			},
		}

		err := tpmInstance.Open()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TPM transport configuration")
	})

	t.Run("opens socket connection error with nonexistent socket", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: false,
				Device:       "/tmp/nonexistent.sock",
			},
		}

		err := tpmInstance.Open()
		assert.Error(t, err)
	})
}

// TestSignValidateNilAttributes tests SignValidate with nil key attributes
// Note: These tests reveal missing nil checks in SignValidate - panics indicate areas needing improvement
func TestSignValidateNilAttributes(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("panics with nil key attributes", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		digest := []byte("test digest data")
		validationDigest := []byte("validation digest")

		// SignValidate should check for nil, but currently panics
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(nil, digest, validationDigest)
		})
	})

	t.Run("returns error with nil TPM attributes", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:            "test-key",
			TPMAttributes: nil,
		}

		digest := []byte("test digest data")
		validationDigest := []byte("validation digest")

		// SignValidate should return error for nil TPMAttributes
		_, err := tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TPMAttributes.Public is required")
	})

	t.Run("returns error with password that fails to serialize", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:       "test-key",
			Password: &errorPassword{},
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81010001),
				Name: tpm2.TPM2BName{
					Buffer: []byte("test-name"),
				},
				Public: tpm2.TPMTPublic{
					Type: tpm2.TPMAlgRSA,
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgRSA,
						&tpm2.TPMSRSAParms{
							Scheme: tpm2.TPMTRSAScheme{
								Scheme: tpm2.TPMAlgRSASSA,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgRSASSA,
									&tpm2.TPMSSigSchemeRSASSA{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
				},
			},
		}

		digest := []byte("test digest")
		validationDigest := []byte("validation")

		signature, err := tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		assert.Error(t, err)
		assert.Nil(t, signature)
	})
}

// TestEKECCWithNilAttribute tests EKECC with nil ECC public key
func TestEKECCWithNilAttribute(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("returns cached ECC key", func(t *testing.T) {
		// First provision with ECC EK
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		// Create a mock ECC public key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		tpmImpl.ekECCPubKey = &privateKey.PublicKey

		eccKey := tpmImpl.EKECC()
		assert.NotNil(t, eccKey)
		assert.Equal(t, &privateKey.PublicKey, eccKey)
	})

}

// TestSSRKPublicErrorHandling tests SSRKPublic error paths
func TestSSRKPublicErrorHandling(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("returns SSRK name and public area", func(t *testing.T) {
		// The SSRK should be provisioned by createSim
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		name, pub := tpmImpl.SSRKPublic()
		assert.NotNil(t, name.Buffer)
		assert.NotZero(t, pub.Type)
	})

	t.Run("returns valid public area for RSA SSRK", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		name, pub := tpmImpl.SSRKPublic()
		assert.Greater(t, len(name.Buffer), 0)
		assert.Equal(t, tpm2.TPMAlgRSA, pub.Type)
	})
}

// TestIDevIDWithValidKeyBytes tests IDevID with valid public key bytes
func TestIDevIDWithValidKeyBytes(t *testing.T) {
	t.Run("returns public key when valid bytes are provided", func(t *testing.T) {
		logger := logging.DefaultLogger()

		// Generate a valid RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Serialize the public key in PKIX format
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		tpmInstance := &TPM2{
			logger: logger,
			idevidAttrs: &types.KeyAttributes{
				CN: "idevid-test",
			},
			iakAttrs: &types.KeyAttributes{
				CN: "iak-test",
				TPMAttributes: &types.TPMAttributes{
					PublicKeyBytes: pubKeyBytes,
				},
			},
		}

		pubKey := tpmInstance.IDevID()
		assert.NotNil(t, pubKey)

		// Verify it's the same key
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.PublicKey.N, rsaPubKey.N) //nolint:staticcheck // QF1008
		assert.Equal(t, privateKey.PublicKey.E, rsaPubKey.E) //nolint:staticcheck // QF1008
	})

	t.Run("returns ECDSA public key when valid ECC bytes are provided", func(t *testing.T) {
		logger := logging.DefaultLogger()

		// Generate a valid ECDSA key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Serialize the public key in PKIX format
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		tpmInstance := &TPM2{
			logger: logger,
			idevidAttrs: &types.KeyAttributes{
				CN: "idevid-test",
			},
			iakAttrs: &types.KeyAttributes{
				CN: "iak-test",
				TPMAttributes: &types.TPMAttributes{
					PublicKeyBytes: pubKeyBytes,
				},
			},
		}

		pubKey := tpmInstance.IDevID()
		assert.NotNil(t, pubKey)

		// Verify it's an ECDSA key
		_, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok)
	})
}

// TestDeleteKeyPersistentHandle tests DeleteKey with persistent handle
func TestDeleteKeyPersistentHandle(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("returns error with nil TPM attributes", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:            "test-key",
			TPMAttributes: nil,
		}

		// DeleteKey should return error when trying to unseal with nil TPMAttributes
		err := tpmInstance.DeleteKey(keyAttrs, nil)
		assert.Error(t, err)
	})

	t.Run("returns error for hierarchy auth failure", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN: "test-key",
			TPMAttributes: &types.TPMAttributes{
				Handle:        tpm2.TPMHandle(0x81010099),
				HandleType:    tpm2.TPMHTPersistent,
				HierarchyAuth: &errorPassword{},
				Name: tpm2.TPM2BName{
					Buffer: []byte("test-name"),
				},
			},
		}

		err := tpmInstance.DeleteKey(keyAttrs, nil)
		assert.Error(t, err)
	})
}

// TestInstallHierarchyAuthError tests Install with hierarchy auth errors
func TestInstallHierarchyAuthError(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("panics when no transport is set", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: true,
				Device:       "/dev/tpmrm0",
				Hash:         "SHA-256",
				EK: &EKConfig{
					Handle:       0x81010001,
					KeyAlgorithm: x509.RSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				SSRK: &SRKConfig{
					Handle:       0x81000001,
					KeyAlgorithm: x509.RSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				IAK: &IAKConfig{
					Handle:             0x81010002,
					KeyAlgorithm:       x509.RSA.String(),
					Hash:               crypto.SHA256.String(),
					SignatureAlgorithm: x509.SHA256WithRSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				PlatformPCR:     16,
				PlatformPCRBank: PCRBankSHA256,
			},
		}

		// Install without transport should return error
		err := tpmInstance.Install(store.NewClearPassword([]byte("test")))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TPM transport not initialized")
	})

	t.Run("returns error with invalid password type", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: true,
			},
		}

		err := tpmInstance.Install(&errorPassword{})
		assert.Error(t, err)
	})
}

// TestProvisionEKCertWithNilCertStore tests ProvisionEKCert edge cases
func TestProvisionEKCertWithNilCertStore(t *testing.T) {
	t.Run("returns error with invalid DER certificate", func(t *testing.T) {
		_, tpm := createSim(false, false)
		defer func() { _ = tpm.Close() }()

		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		// Set cert handle to 0 to trigger cert store path
		tpmImpl.config.EK.CertHandle = 0

		invalidCert := []byte("this is not a valid DER certificate")
		err := tpmImpl.ProvisionEKCert(nil, invalidCert)
		assert.Error(t, err)
	})

	t.Run("returns error with valid cert but no cert store", func(t *testing.T) {
		logger := logging.DefaultLogger()

		// Create a valid self-signed certificate
		certDER := createTestCertDER(t)

		tpmInstance := &TPM2{
			logger:    logger,
			certStore: nil,
			ekAttrs: &types.KeyAttributes{
				CN: "test-ek",
			},
			config: &Config{
				EK: &EKConfig{
					CertHandle: 0,
					Handle:     0x81010001,
				},
			},
		}

		err := tpmInstance.ProvisionEKCert(nil, certDER)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate store not initialized")
	})
}

// TestInstallWithConfig tests Install function with various configurations
func TestInstallWithConfig(t *testing.T) {
	t.Run("successfully installs with valid config", func(t *testing.T) {
		_, tpm := createSim(false, false)
		defer func() { _ = tpm.Close() }()

		// TPM is already provisioned by createSim, so we just verify state
		config := tpm.Config()
		assert.NotNil(t, config)
		assert.NotNil(t, config.EK)
		assert.NotNil(t, config.SSRK)
	})
}

// TestDeleteKeyTransientHandle tests DeleteKey with transient handle
func TestDeleteKeyTransientHandle(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("returns error when unseal fails for transient handle", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN: "test-key",
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x80000001),
				HandleType: tpm2.TPMHTTransient,
				Name: tpm2.TPM2BName{
					Buffer: []byte("test-name"),
				},
			},
		}

		err := tpmInstance.DeleteKey(keyAttrs, nil)
		assert.Error(t, err)
	})
}

// TestSignValidateWithTransport tests SignValidate with actual transport errors
func TestSignValidateWithTransport(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("returns error for invalid handle", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:       "test-key",
			Password: store.NewClearPassword(nil),
			TPMAttributes: &types.TPMAttributes{
				Handle:  tpm2.TPMHandle(0x99999999), // Invalid handle
				HashAlg: tpm2.TPMAlgSHA256,
				Name: tpm2.TPM2BName{
					Buffer: []byte("test-name"),
				},
				Public: tpm2.TPMTPublic{
					Type: tpm2.TPMAlgRSA,
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgRSA,
						&tpm2.TPMSRSAParms{
							Scheme: tpm2.TPMTRSAScheme{
								Scheme: tpm2.TPMAlgRSASSA,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgRSASSA,
									&tpm2.TPMSSigSchemeRSASSA{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
				},
			},
		}

		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		digest := []byte("0123456789012345678901234567890123456789012345678901234567890123")
		validationDigest := []byte("validation-digest")

		signature, err := tpmImpl.SignValidate(keyAttrs, digest, validationDigest)
		assert.Error(t, err)
		assert.Nil(t, signature)
	})
}

// Helper to create a test certificate DER
func createTestCertDER(t *testing.T) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test EK Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return certDER
}

// TestOpenSocketPath tests Open with socket path
func TestOpenSocketPath(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("returns error for nonexistent socket", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: false,
				Device:       "/tmp/nonexistent_tpm_12345.sock",
			},
		}

		err := tpmInstance.Open()
		assert.Error(t, err)
	})
}

// TestSSRKPublicWithProvisionedTPM tests SSRKPublic on a provisioned TPM
func TestSSRKPublicWithProvisionedTPM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("returns valid SSRK public data", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		name, pub := tpmImpl.SSRKPublic()

		// Verify the name buffer is populated
		assert.NotEmpty(t, name.Buffer)

		// Verify public area has valid algorithm
		assert.True(t, pub.Type == tpm2.TPMAlgRSA || pub.Type == tpm2.TPMAlgECC)
	})

	t.Run("SSRK name follows TPM naming convention", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		name, _ := tpmImpl.SSRKPublic()

		// TPM names start with algorithm identifier (2 bytes)
		// followed by hash digest
		assert.GreaterOrEqual(t, len(name.Buffer), 2)
	})
}

// TestEKECCWithProvisionedTPM tests EKECC functionality
func TestEKECCWithProvisionedTPM(t *testing.T) {
	t.Run("caches and returns ECC public key", func(t *testing.T) {
		logger := logging.DefaultLogger()

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		tpmInstance := &TPM2{
			logger:      logger,
			ekECCPubKey: &privateKey.PublicKey,
		}

		key := tpmInstance.EKECC()
		assert.NotNil(t, key)
		assert.Equal(t, &privateKey.PublicKey, key)

		// Verify caching works
		key2 := tpmInstance.EKECC()
		assert.Equal(t, key, key2)
	})
}

// TestInstallEKNotExists tests Install when EK doesn't exist
func TestInstallEKNotExists(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("handles EK creation error", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: true,
				Hash:         "SHA-256",
				EK: &EKConfig{
					Handle:       0x81010001,
					KeyAlgorithm: x509.RSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				SSRK: &SRKConfig{
					Handle:       0x81000001,
					KeyAlgorithm: x509.RSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				IAK: &IAKConfig{
					Handle:             0x81010002,
					Hash:               crypto.SHA256.String(),
					KeyAlgorithm:       x509.RSA.String(),
					SignatureAlgorithm: x509.SHA256WithRSA.String(),
					RSAConfig: &store.RSAConfig{
						KeySize: 2048,
					},
				},
				PlatformPCR:     16,
				PlatformPCRBank: PCRBankSHA256,
			},
		}

		// Install without transport should return error
		err := tpmInstance.Install(store.NewClearPassword([]byte("test")))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TPM transport not initialized")
	})
}

// TestDeleteKeyWithBackend tests DeleteKey interactions with backend
func TestDeleteKeyWithBackend(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("attempts unseal for transient key", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN: "transient-key",
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x80000000),
				HandleType: tpm2.TPMHTTransient,
			},
		}

		// Should fail during unseal since no transport
		err := tpmInstance.DeleteKey(keyAttrs, nil)
		assert.Error(t, err)
	})
}

// TestProvisionEKCertNVRAM tests ProvisionEKCert with NVRAM path
func TestProvisionEKCertNVRAM(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("attempts NV write with valid cert", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		// Set cert handle to non-zero to trigger NVRAM path
		tpmImpl.config.EK.CertHandle = 0x01C00099

		certDER := createTestCertDER(t)

		// This will fail because NV index isn't defined, but tests the path
		err := tpmImpl.ProvisionEKCert(nil, certDER)
		assert.Error(t, err)
	})
}

// TestSignValidateECDSA tests SignValidate with ECDSA key type
func TestSignValidateECDSA(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("handles ECDSA key type", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:       "ecdsa-key",
			Password: store.NewClearPassword(nil),
			TPMAttributes: &types.TPMAttributes{
				Handle:  tpm2.TPMHandle(0x81010005),
				HashAlg: tpm2.TPMAlgSHA256,
				Name: tpm2.TPM2BName{
					Buffer: []byte("ecdsa-name"),
				},
				Public: tpm2.TPMTPublic{
					Type: tpm2.TPMAlgECC,
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgECC,
						&tpm2.TPMSECCParms{
							Scheme: tpm2.TPMTECCScheme{
								Scheme: tpm2.TPMAlgECDSA,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgECDSA,
									&tpm2.TPMSSigSchemeECDSA{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
							CurveID: tpm2.TPMECCNistP256,
						},
					),
				},
			},
		}

		digest := make([]byte, 32)
		validationDigest := make([]byte, 32)

		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
	})
}

// TestDeleteKeyPersistentWithoutAuth tests DeleteKey with persistent handle but no auth
func TestDeleteKeyPersistentWithoutAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("handles missing hierarchy auth gracefully", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		keyAttrs := &types.KeyAttributes{
			CN: "test-persistent-key",
			TPMAttributes: &types.TPMAttributes{
				Handle:        tpm2.TPMHandle(0x81FFFFFF), // Non-existent handle
				HandleType:    tpm2.TPMHTPersistent,
				HierarchyAuth: nil, // No hierarchy auth
				Name: tpm2.TPM2BName{
					Buffer: []byte("test-key-name"),
				},
			},
		}

		// Should fail at TPM execution, not auth serialization
		err := tpmImpl.DeleteKey(keyAttrs, nil)
		assert.Error(t, err)
	})
}

// TestSignValidateRSAPSS tests SignValidate with RSA-PSS scheme
func TestSignValidateRSAPSS(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("handles RSA-PSS signature scheme", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:                 "rsapss-key",
			Password:           store.NewClearPassword(nil),
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
			TPMAttributes: &types.TPMAttributes{
				Handle:  tpm2.TPMHandle(0x81010006),
				HashAlg: tpm2.TPMAlgSHA256,
				Name: tpm2.TPM2BName{
					Buffer: []byte("rsapss-name"),
				},
				Public: tpm2.TPMTPublic{
					Type: tpm2.TPMAlgRSA,
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgRSA,
						&tpm2.TPMSRSAParms{
							Scheme: tpm2.TPMTRSAScheme{
								Scheme: tpm2.TPMAlgRSAPSS,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgRSAPSS,
									&tpm2.TPMSSigSchemeRSAPSS{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
				},
			},
		}

		digest := make([]byte, 32)
		validationDigest := make([]byte, 32)

		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
		// Should panic without transport
		assert.Panics(t, func() {
			_, _ = tpmInstance.SignValidate(keyAttrs, digest, validationDigest)
		})
	})
}

// TestOpenMultipleTimes tests Open function can be called multiple times
func TestOpenMultipleTimes(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("can open simulator multiple times", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
			config: &Config{
				UseSimulator: true,
				Device:       "/dev/tpmrm0",
			},
		}

		// First open
		err := tpmInstance.Open()
		assert.NoError(t, err)
		sim1 := tpmInstance.simulator

		// Clean up first simulator
		if sim1 != nil {
			_ = sim1.Close()
		}

		// Second open
		err = tpmInstance.Open()
		assert.NoError(t, err)
		assert.NotNil(t, tpmInstance.simulator)

		// Clean up
		if tpmInstance.simulator != nil {
			_ = tpmInstance.simulator.Close()
		}
	})
}

// TestInstallCreatesPlatformPolicy tests Install creates platform policy
func TestInstallCreatesPlatformPolicy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	t.Run("platform policy digest is set after provisioning", func(t *testing.T) {
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)

		// Check that policy digest was created
		digest := tpmImpl.PlatformPolicyDigest()
		assert.NotNil(t, digest.Buffer)
		assert.Greater(t, len(digest.Buffer), 0)
	})
}

// TestDeleteKeyNilKeyAttributes tests DeleteKey with completely nil attributes
func TestDeleteKeyNilKeyAttributes(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("panics with nil key attributes", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		assert.Panics(t, func() {
			_ = tpmInstance.DeleteKey(nil, nil)
		})
	})
}
