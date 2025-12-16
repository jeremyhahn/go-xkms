//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

var (
	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailWithDA = tpm2.TPMRC(0x98e)

	// TPM_RC_ATTRIBUTES (session 1): inconsistent attributes
	ErrInconsistentAttributes = tpm2.TPMRC(0x982)

	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailHMACWithDA = tpm2.TPMRC(0x99d)

	// TPM_RC_POLICY_FAIL (session 1): a policy check failed
	ErrPolicyCheckFailed = tpm2.TPMRC(0x99d)

	currentWorkingDirectory, _ = os.Getwd()
	TEST_DIR                   = fmt.Sprintf("%s/testdata", currentWorkingDirectory)
	CLEAN_TMP                  = false

	keyStoreHandle = tpm2.TPMHandle(0x81000003)
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {

}

func setup() {
	_ = os.RemoveAll(TEST_DIR)
}

func TestOpenAndCloseTPM(t *testing.T) {

	_, tpm := createSim(false, false)
	_ = tpm.Close()

	_, tpm = createSim(false, false)
	_ = tpm.Close()

	_, tpm = createSim(false, false)
	defer func() { _ = tpm.Close() }()
}

// Extends the debug PCR with random bytes
func extendRandomBytes(transport transport.TPM) {

	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		logging.DefaultLogger().FatalError(err)
	}

	fmt.Printf(
		"tpm: extending %s measurement to platform PCR %d\n",
		string(bytes), debugPCR)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(debugPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  bytes,
				},
			},
		},
	}.Execute(transport)
	if err != nil {
		logging.DefaultLogger().FatalError(err)
	}
}

func createKey(
	tpm TrustedPlatformModule,
	platformPolicy bool) *types.KeyAttributes {

	srkTemplate := tpm2.RSASRKTemplate
	srkTemplate.ObjectAttributes.NoDA = false

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		logging.DefaultLogger().FatalError(err)
	}

	srkAttrs := &types.KeyAttributes{
		CN:             "srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeTPM,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-pass")),
		PlatformPolicy: platformPolicy,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      srkTemplate,
		}}
	err = tpm.CreateSRK(srkAttrs)
	if err != nil {
		logging.DefaultLogger().FatalError(err)
	}

	return &types.KeyAttributes{
		CN:             "key",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		PlatformPolicy: platformPolicy,
		Password:       store.NewClearPassword([]byte("key-pass")),
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule) {

	logger := logging.DefaultLogger()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.FatalError(err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create go-objstore backed storage using the factory
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		logger.FatalError(err)
	}
	// Note: In a real test, we'd defer storageFactory.Close() but this helper
	// doesn't return a cleanup function. The temp dir will be cleaned up on program exit.

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity: []string{
			"./",
		},
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
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		KeyStore: &KeyStoreConfig{
			// SRKAuth:        store.DEFAULT_PASSWORD,
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logging.DefaultLogger(),
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	return logger, tpm
}
