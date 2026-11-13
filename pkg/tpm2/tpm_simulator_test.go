//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Random with invalid length
func TestRandomBytes_InvalidLength_Simulator(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	_, err := tpm.RandomBytes(0)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	_, err = tpm.RandomBytes(-1)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)
}

// Test TPM Info
func TestInfo_Simulator(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	info, err := tpm.Info()
	require.NoError(t, err)
	assert.NotEmpty(t, info)
}

// Test PCR operations with invalid index
func TestReadPCRs_InvalidIndex_Simulator(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	_, err := tpm.ReadPCRs([]uint{24})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPCRIndex, err)

	_, err = tpm.ReadPCRs([]uint{100})
	assert.Error(t, err)
}

// Benchmark random byte generation
func BenchmarkRandomBytes_Simulator(b *testing.B) {
	logger := slog.Default()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		b.Fatal(err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = storageFactory.Close() }()

	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		UseEntropy:   false,
		Device:       "/dev/tpmrm0",
		UseSimulator: true,
		Hash:         "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: secrettest.Literal(b, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity:                []string{},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCRs:    DefaultPlatformPCRs(),
		PlatformPCRBank: PCRBankSHA256,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: secrettest.Literal(b, []byte(store.DEFAULT_PASSWORD)),

			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:  logger,
		Config:  config,
		Backend: fileBackend,
		FQDN:    "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				b.Fatal(err)
			}
		} else {
			b.Fatal(err)
		}
	}
	defer func() { _ = tpm.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tpm.RandomBytes(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestOpenSimulatorFunction tests the OpenSimulator function
func TestOpenSimulatorFunction(t *testing.T) {
	t.Run("opens simulator successfully", func(t *testing.T) {
		sim, err := OpenSimulator()
		require.NoError(t, err)
		require.NotNil(t, sim)

		// Clean up
		err = sim.Close()
		assert.NoError(t, err)
	})

	t.Run("simulator provides transport", func(t *testing.T) {
		sim, err := OpenSimulator()
		require.NoError(t, err)
		require.NotNil(t, sim)
		defer func() { _ = sim.Close() }()

		transport := sim.Transport()
		assert.NotNil(t, transport)
	})

	t.Run("simulator provides read writer", func(t *testing.T) {
		sim, err := OpenSimulator()
		require.NoError(t, err)
		require.NotNil(t, sim)
		defer func() { _ = sim.Close() }()

		rw := sim.ReadWriter()
		assert.NotNil(t, rw)
	})

	// A zero-value simulatorWrapper (sim == nil) never comes from
	// OpenSimulator, but newSimHarness's cleanup pattern -- "always call
	// Close, even after a partial failure" -- means Close must not dereference
	// a nil *simulator.Simulator if construction never got that far.
	t.Run("close on zero-value wrapper is a no-op", func(t *testing.T) {
		wrapper := &simulatorWrapper{}
		assert.NoError(t, wrapper.Close())
	})
}

// TestExtractPublicKeyFromTPMPublic_Errors tests error paths
func TestExtractPublicKeyFromTPMPublic_Errors(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic(nil)
		assert.Error(t, err)
	})

	t.Run("invalid TPM public data", func(t *testing.T) {
		_, err := ExtractPublicKeyFromTPMPublic([]byte{0x00, 0x01, 0x02, 0x03})
		assert.Error(t, err)
	})

	t.Run("unsupported key type", func(t *testing.T) {
		symPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
		}
		pubBytes := tpm2.Marshal(symPub)
		_, err := ExtractPublicKeyFromTPMPublic(pubBytes)
		assert.Error(t, err)
	})
}

// TestVerifyTCG_CSR_IDevID_Wrapper tests the convenience wrapper function
func TestVerifyTCG_CSR_IDevID_Wrapper(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
	_, _, err := VerifyTCG_CSR_IDevID(csr, x509.SHA256WithRSAPSS)
	// Should error (invalid CSR content) but tests the wrapper path
	assert.Error(t, err)
}

// TestVerifyTCG_CSR_IAK_Wrapper tests the convenience wrapper function
func TestVerifyTCG_CSR_IAK_Wrapper(t *testing.T) {
	csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
	_, _, err := VerifyTCG_CSR_IAK(csr, x509.SHA256WithRSAPSS)
	assert.Error(t, err)
}

// TestVerifyRSASignatureStateless_AllPSSVariants tests all PSS hash variants
func TestVerifyRSASignatureStateless_AllPSSVariants(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		hash    crypto.Hash
	}{
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, crypto.SHA256},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, crypto.SHA384},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, crypto.SHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpmPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)

			h := tc.hash.New()
			h.Write([]byte("test data"))
			digest := h.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       tc.hash,
			}
			signature, err := rsa.SignPSS(rand.Reader, rsaKey, tc.hash, digest, pssOpts)
			require.NoError(t, err)

			extractedKey, err := verifyRSASignatureStateless(&tpmPub, digest, signature, tc.sigAlgo, tc.hash)
			require.NoError(t, err)
			assert.NotNil(t, extractedKey)
		})
	}
}

// TestVerifyRSASignatureStateless_PKCS1v15Default tests default PKCS#1 v1.5
func TestVerifyRSASignatureStateless_PKCS1v15Default(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpmPub := createRSATPMPublicForCSR(&rsaKey.PublicKey, false)

	digest := sha256.Sum256([]byte("test data"))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	// Use a non-PSS algorithm to trigger PKCS#1 v1.5 branch
	extractedKey, err := verifyRSASignatureStateless(&tpmPub, digest[:], signature, x509.SHA256WithRSA, crypto.SHA256)
	require.NoError(t, err)
	assert.NotNil(t, extractedKey)
}

// TestVerifyECDSASignatureStateless_InvalidSignature_Cov tests ECDSA signature validation
func TestVerifyECDSASignatureStateless_InvalidSignature_Cov(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tpmPub := createECDSATPMPublicForCSR(&ecKey.PublicKey)

	digest := sha256.Sum256([]byte("test data"))
	invalidSig := []byte("not a valid ECDSA signature")

	_, err = verifyECDSASignatureStateless(&tpmPub, digest[:], invalidSig)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

// TestCreateTCG_CSR_IDEVID_NilEKCert tests that CreateTCG_CSR_IDEVID
// returns an error when EK certificate is nil
func TestCreateTCG_CSR_IDEVID_NilEKCert(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)

	// Set valid enrollment strategy
	originalStrategy := tpm2Impl.config.IdentityProvisioningStrategy
	tpm2Impl.config.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK)
	defer func() { tpm2Impl.config.IdentityProvisioningStrategy = originalStrategy }()

	// Ensure IDevID config exists
	if tpm2Impl.config.IDevID == nil {
		tpm2Impl.config.IDevID = &IDevIDConfig{
			Model:  "test-model",
			Serial: "test-serial",
		}
	}

	akAttrs := createMockKeyAttributesForCSR(t)
	idevidAttrs := createMockKeyAttributesForCSR(t)

	// Should fail with nil EK certificate
	_, err := tpm.CreateTCG_CSR_IDEVID(nil, akAttrs, idevidAttrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEKCert)
}

// Helper to create mock key attributes for CSR tests
func createMockKeyAttributesForCSR(t *testing.T) *types.KeyAttributes {
	return &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSAAKTemplate),
			CreationTicketDigest: []byte("creation-ticket-digest"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}
}

// errorPassword implements types.Password and always returns an error
type errorPassword struct{}

func (e *errorPassword) WithBytes(func([]byte) error) error {
	return errors.New("password read error")
}

func (e *errorPassword) String() string {
	return types.PasswordRedacted
}

func (e *errorPassword) Bytes() []byte {
	return nil
}

func (e *errorPassword) Clear() {
	// No-op
}

// TestOpenWithSimulator tests the Open function with simulator config
func TestOpenWithSimulator(t *testing.T) {
	logger := slog.Default()

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
		assert.ErrorIs(t, err, ErrInvalidTPMTransport)
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

// TestIDevIDWithValidKeyBytes tests IDevID with valid public key bytes
func TestIDevIDWithValidKeyBytes(t *testing.T) {
	t.Run("returns public key when valid bytes are provided", func(t *testing.T) {
		logger := slog.Default()

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
				TPMAttributes: &types.TPMAttributes{
					PublicKeyBytes: pubKeyBytes,
				},
			},
		}

		pubKey, idevidErr := tpmInstance.IDevID()
		assert.NoError(t, idevidErr)
		assert.NotNil(t, pubKey)

		// Verify it's the same key
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.PublicKey.N, rsaPubKey.N) //nolint:staticcheck // QF1008
		assert.Equal(t, privateKey.PublicKey.E, rsaPubKey.E) //nolint:staticcheck // QF1008
	})

	t.Run("returns ECDSA public key when valid ECC bytes are provided", func(t *testing.T) {
		logger := slog.Default()

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
				TPMAttributes: &types.TPMAttributes{
					PublicKeyBytes: pubKeyBytes,
				},
			},
		}

		pubKey, idevidErr := tpmInstance.IDevID()
		assert.NoError(t, idevidErr)
		assert.NotNil(t, pubKey)

		// Verify it's an ECDSA key
		_, ok := pubKey.(*ecdsa.PublicKey)
		require.True(t, ok)
	})
}

// TestDeleteKeyPersistentHandle tests DeleteKey with persistent handle
func TestDeleteKeyPersistentHandle(t *testing.T) {
	logger := slog.Default()

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
	logger := slog.Default()

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
				PlatformPCRs:    DefaultPlatformPCRs(),
				PlatformPCRBank: PCRBankSHA256,
			},
		}

		// Install without transport should return error
		err := tpmInstance.Install(mustPassword(t, []byte("test")), nil)
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

		err := tpmInstance.Install(&errorPassword{}, nil)
		assert.Error(t, err)
	})
}

// TestProvisionEKCertWithNilCertStore tests ProvisionEKCert edge cases
func TestProvisionEKCertWithNilCertStore(t *testing.T) {
	t.Run("returns error with invalid DER certificate", func(t *testing.T) {
		_, tpm := createSim(t, false)
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
		logger := slog.Default()

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

// TestSignValidateWithTransport tests SignValidate with actual transport errors
func TestSignValidateWithTransport(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	t.Run("returns error for invalid handle", func(t *testing.T) {
		keyAttrs := &types.KeyAttributes{
			CN:       "test-key",
			Password: mustPassword(t, nil),
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

// TestSignValidateECDSA tests SignValidate with ECDSA key type
func TestSignValidateECDSA(t *testing.T) {
	logger := slog.Default()

	t.Run("handles ECDSA key type", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:       "ecdsa-key",
			Password: mustPassword(t, nil),
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
	_, tpm := createSim(t, false)
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
	logger := slog.Default()

	t.Run("handles RSA-PSS signature scheme", func(t *testing.T) {
		tpmInstance := &TPM2{
			logger: logger,
		}

		keyAttrs := &types.KeyAttributes{
			CN:                 "rsapss-key",
			Password:           mustPassword(t, nil),
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

// TestInstallCreatesIDevID tests that Install creates IDevID when configured
func TestInstallCreatesIDevID(t *testing.T) {
	t.Run("Install creates all keys including IDevID", func(t *testing.T) {
		// Create a fresh simulator without provisioning
		config := &Config{
			Device:       "simulator",
			UseSimulator: true,
			Hash:         "SHA-256",
			EK: &EKConfig{
				CN:             "test-ek",
				Handle:         0x81010001,
				KeyAlgorithm:   "RSA",
				RSAConfig:      &store.RSAConfig{KeySize: 2048},
				PlatformPolicy: true,
			},
			SSRK: &SRKConfig{
				CN:           "test-srk",
				Handle:       0x81000001,
				KeyAlgorithm: "RSA",
			},
			IAK: &IAKConfig{
				CN:                 "test-iak",
				Handle:             0x81010002,
				Hash:               "SHA-256",
				KeyAlgorithm:       "RSA",
				SignatureAlgorithm: "SHA256-RSA",
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
				PlatformPolicy:     true,
			},
			IDevID: &IDevIDConfig{
				CN:                 "test-idevid",
				Handle:             0x81020000,
				Hash:               "SHA-256",
				KeyAlgorithm:       "RSA",
				SignatureAlgorithm: "SHA256-RSA",
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
				PlatformPolicy:     true,
				Model:              "test-device",
				Serial:             "001",
			},
			PlatformPCRs:    DefaultPlatformPCRs(),
			PlatformPCRBank: "sha256",
		}

		logger := slog.Default()
		certStore := store.NewMemoryCertStore(logger)
		params := &Params{
			Config:    config,
			Logger:    logger,
			CertStore: certStore,
		}

		// Create TPM instance with simulator
		tpm, err := NewTPM2(params)
		// Install may return ErrNotInitialized for fresh TPM, which is expected
		if err != nil && !errors.Is(err, ErrNotInitialized) {
			t.Fatalf("Failed to create TPM2: %v", err)
		}
		if tpm == nil {
			t.Fatal("TPM instance is nil")
		}
		defer func() { _ = tpm.Close() }()

		// Pre-seed a synthetic EK certificate. CreateIDevID requires a
		// non-nil EK certificate to populate the TCG-CSR-IDEVID structure
		// (see createIDevIDContent/ErrInvalidEKCert); this simulator-backed
		// EK has no manufacturer-issued certificate, so without seeding one
		// here Install's "Creating Initial Device Identity Key" step fails.
		// Matches the convention used by TestCSRCreateTCG_CSR_IDEVID_WithSimulator.
		tpmImpl, ok := tpm.(*TPM2)
		require.True(t, ok)
		require.NoError(t, tpmImpl.writeCertToStore(
			&types.KeyAttributes{CN: config.EK.CN}, createTestEKCertificate(t)))

		// Run Install
		err = tpm.Install(nil, nil)
		require.NoError(t, err, "Install should succeed")

		// Verify EK was created or preserved
		ekAttrs, err := tpm.EKAttributes()
		require.NoError(t, err, "EKAttributes should succeed after Install")
		assert.NotNil(t, ekAttrs)
		assert.Equal(t, types.KeyTypeEndorsement, ekAttrs.KeyType)

		// Verify SSRK was created
		ssrkAttrs, err := tpm.SSRKAttributes()
		require.NoError(t, err, "SSRKAttributes should succeed after Install")
		assert.NotNil(t, ssrkAttrs)
		assert.Equal(t, types.KeyTypeStorage, ssrkAttrs.KeyType)

		// Verify IAK was created
		iakAttrs, err := tpm.IAKAttributes()
		require.NoError(t, err, "IAKAttributes should succeed after Install")
		assert.NotNil(t, iakAttrs)
		assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)

		// Verify IDevID was created (this is the new functionality)
		idevidAttrs, err := tpm.IDevIDAttributes()
		require.NoError(t, err, "IDevIDAttributes should succeed after Install")
		assert.NotNil(t, idevidAttrs)
		assert.Equal(t, types.KeyTypeIDevID, idevidAttrs.KeyType)
		assert.Equal(t, tpm2.TPMHandle(0x81020000), idevidAttrs.TPMAttributes.Handle)
	})
}

// TestInstallPreservesExistingKeys tests that Install doesn't overwrite existing keys
func TestInstallPreservesExistingKeys(t *testing.T) {
	t.Run("Install preserves existing keys", func(t *testing.T) {
		// Use createSim which provisions the TPM
		_, tpm := createSim(t, false)
		defer func() { _ = tpm.Close() }()

		// Get EK attributes before re-running Install
		ekAttrsBefore, err := tpm.EKAttributes()
		require.NoError(t, err)
		ekHandleBefore := ekAttrsBefore.TPMAttributes.Handle

		// Run Install again - should preserve existing keys
		err = tpm.Install(nil, nil)
		require.NoError(t, err)

		// Verify EK handle is the same (not recreated)
		ekAttrsAfter, err := tpm.EKAttributes()
		require.NoError(t, err)
		assert.Equal(t, ekHandleBefore, ekAttrsAfter.TPMAttributes.Handle,
			"EK handle should be preserved after re-running Install")
	})
}

// createRSATPMPublicForCSR creates an RSA TPM public area for the CSR
// simulator tests. It lives here because these are its only callers; the
// untagged build must not carry it (lint: unused).
func createRSATPMPublicForCSR(pub *rsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	modBytes := pub.N.Bytes()
	keySize := 2048 / 8
	if len(modBytes) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(modBytes):], modBytes)
		modBytes = padded
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
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
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: modBytes,
			},
		),
	}
}
