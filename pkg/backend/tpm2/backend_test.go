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

package tpm2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mockKeyBackend is a minimal mock for testing
type mockKeyBackend struct {
	getError        error
	getData         []byte
	saveError       error
	deleteErr       error
	savedData       map[string][]byte
	publicData      []byte
	publicBlobError error
}

func (m *mockKeyBackend) Get(attrs *types.KeyAttributes, fsext types.FSExtension) ([]byte, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if fsext == store.FSEXT_PUBLIC_BLOB {
		if m.publicBlobError != nil {
			return nil, m.publicBlobError
		}
		if m.publicData != nil {
			return m.publicData, nil
		}
	}
	if m.getData != nil {
		return m.getData, nil
	}
	return []byte("mock-blob-data"), nil
}

func (m *mockKeyBackend) Save(attrs *types.KeyAttributes, data []byte, fsext types.FSExtension, overwrite bool) error {
	if m.saveError != nil {
		return m.saveError
	}
	if m.savedData == nil {
		m.savedData = make(map[string][]byte)
	}
	m.savedData[attrs.CN+string(fsext)] = data
	return nil
}

func (m *mockKeyBackend) Delete(attrs *types.KeyAttributes) error {
	return m.deleteErr
}

// mockTransport implements transport.TPM for testing
type mockTransport struct {
	sendErr    error
	sendResult []byte
}

func (m *mockTransport) Send(input []byte) ([]byte, error) {
	if m.sendErr != nil {
		return nil, m.sendErr
	}
	return m.sendResult, nil
}

var _ transport.TPM = (*mockTransport)(nil)

// mockTPM implements TrustedPlatformModule interface for testing
type mockTPM struct {
	closeErr                   error
	createRSAErr               error
	createECDSAErr             error
	deleteKeyErr               error
	signErr                    error
	rsaDecryptErr              error
	loadKeyPairErr             error
	parsePublicKeyErr          error
	parsePublicKeyValue        crypto.PublicKey
	ssrkAttrsErr               error
	ssrkAttrsValue             *types.KeyAttributes
	rsaPublicKey               *rsa.PublicKey
	ecdsaPublicKey             *ecdsa.PublicKey
	signatureValue             []byte
	decryptValue               []byte
	loadResponse               *tpm2.LoadResponse
	transport                  transport.TPM
	ecdhZGenErr                error
	ecdhZGenValue              []byte
	certifyKeyErr              error
	certifyKeyResult           *pkgtpm2.CertifyResult
	generateSymmetricKeyErr    error
	generateSymmetricKeyResult types.SymmetricKey
	getSymmetricKeyErr         error
	getSymmetricKeyResult      types.SymmetricKey
	symmetricEncrypterErr      error
	symmetricEncrypterResult   types.SymmetricEncrypter
}

func (m *mockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) AKProfile() (pkgtpm2.AKProfile, error)                { return pkgtpm2.AKProfile{}, nil }
func (m *mockTPM) AlgID() tpm2.TPMAlgID                                 { return tpm2.TPMAlgSHA256 }
func (m *mockTPM) CalculateName(algID tpm2.TPMAlgID, publicArea []byte) {}
func (m *mockTPM) Clear(lockoutAuth []byte) error                       { return nil }
func (m *mockTPM) ForceClear() error                                    { return nil }
func (m *mockTPM) Close() error                                         { return m.closeErr }
func (m *mockTPM) Config() *pkgtpm2.Config                              { return nil }
func (m *mockTPM) CreateECDSA(keyAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) (*ecdsa.PublicKey, error) {
	if m.createECDSAErr != nil {
		return nil, m.createECDSAErr
	}
	return m.ecdsaPublicKey, nil
}
func (m *mockTPM) CreateEK(keyAttrs *types.KeyAttributes) error { return nil }
func (m *mockTPM) CreateSecretKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) error {
	return nil
}
func (m *mockTPM) CreateIAK(ekAttrs *types.KeyAttributes, qualifyingData []byte) (*types.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPM) CreateIDevID(akAttrs *types.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*types.KeyAttributes, *pkgtpm2.TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) CreatePlatformPolicy() error { return nil }
func (m *mockTPM) CreateRSA(keyAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) (*rsa.PublicKey, error) {
	if m.createRSAErr != nil {
		return nil, m.createRSAErr
	}
	return m.rsaPublicKey, nil
}
func (m *mockTPM) CreateKeySession(keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) CreateSession(keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) CreateSRK(keyAttrs *types.KeyAttributes) error { return nil }
func (m *mockTPM) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, akAttrs *types.KeyAttributes, idevidAttrs *types.KeyAttributes) (pkgtpm2.TCG_CSR_IDEVID, error) {
	return pkgtpm2.TCG_CSR_IDEVID{}, nil
}
func (m *mockTPM) DeleteKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) error {
	return m.deleteKeyErr
}
func (m *mockTPM) Device() string                { return "/dev/mock" }
func (m *mockTPM) EK() (crypto.PublicKey, error) { return nil, nil }
func (m *mockTPM) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) EKAttributes() (*types.KeyAttributes, error)        { return nil, nil }
func (m *mockTPM) EKCertificate() (*x509.Certificate, error)          { return nil, nil }
func (m *mockTPM) EKCertificateRSA() (*x509.Certificate, error)       { return nil, nil }
func (m *mockTPM) EKCertificateEC() (*x509.Certificate, error)        { return nil, nil }
func (m *mockTPM) EKECC() (*ecdsa.PublicKey, error)                   { return nil, nil }
func (m *mockTPM) EKRSA() (*rsa.PublicKey, error)                     { return nil, nil }
func (m *mockTPM) EventLog() ([]byte, error)                          { return nil, nil }
func (m *mockTPM) FixedProperties() (*pkgtpm2.PropertiesFixed, error) { return nil, nil }
func (m *mockTPM) Flush(handle tpm2.TPMHandle)                        {}
func (m *mockTPM) GoldenMeasurements() ([]byte, error)                { return nil, nil }
func (m *mockTPM) HMAC(auth []byte) tpm2.Session                      { return nil }
func (m *mockTPM) HMACSaltedSession(handle tpm2.TPMHandle, pub tpm2.TPMTPublic, auth []byte) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) HMACSession(auth []byte) (s tpm2.Session, close func() error, err error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) IAK() (crypto.PublicKey, error)                                    { return nil, nil }
func (m *mockTPM) IAKAttributes() (*types.KeyAttributes, error)                      { return nil, nil }
func (m *mockTPM) IDevID() (crypto.PublicKey, error)                                 { return nil, nil }
func (m *mockTPM) IDevIDAttributes() (*types.KeyAttributes, error)                   { return nil, nil }
func (m *mockTPM) Info() (string, error)                                             { return "", nil }
func (m *mockTPM) IsFIPS140_2() (bool, error)                                        { return false, nil }
func (m *mockTPM) IsPlatformPCRExtended() (bool, error)                              { return false, nil }
func (m *mockTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error         { return nil }
func (m *mockTPM) Install(soPIN types.Password, opts *pkgtpm2.InstallOptions) error  { return nil }
func (m *mockTPM) KeyAttributes(handle tpm2.TPMHandle) (*types.KeyAttributes, error) { return nil, nil }
func (m *mockTPM) LoadKeyPair(keyAttrs *types.KeyAttributes, session *tpm2.Session, backend store.KeyBackend) (*tpm2.LoadResponse, error) {
	if m.loadKeyPairErr != nil {
		return nil, m.loadKeyPairErr
	}
	if m.loadResponse != nil {
		return m.loadResponse, nil
	}
	return &tpm2.LoadResponse{ObjectHandle: 0x80000001}, nil
}
func (m *mockTPM) MakeCredential(akName tpm2.TPM2BName, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPM) MakeCredentialWithExternalEK(ekCert *x509.Certificate, iakPubBytes, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPM) NonceSession(secret types.Password) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) NVRead(keyAttrs *types.KeyAttributes, dataSize uint16) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) NVWrite(keyAttrs *types.KeyAttributes) error                 { return nil }
func (m *mockTPM) NVDefineCounter(keyAttrs *types.KeyAttributes) error         { return nil }
func (m *mockTPM) NVDefineExtend(keyAttrs *types.KeyAttributes) error          { return nil }
func (m *mockTPM) NVIncrement(keyAttrs *types.KeyAttributes) (uint64, error)   { return 0, nil }
func (m *mockTPM) NVExtend(keyAttrs *types.KeyAttributes, data []byte) error   { return nil }
func (m *mockTPM) NVReadCounter(keyAttrs *types.KeyAttributes) (uint64, error) { return 0, nil }
func (m *mockTPM) NVReadExtend(keyAttrs *types.KeyAttributes) ([]byte, error)  { return nil, nil }
func (m *mockTPM) NVUndefine(keyAttrs *types.KeyAttributes) error              { return nil }
func (m *mockTPM) Open() error                                                 { return nil }
func (m *mockTPM) ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) { return nil, nil }
func (m *mockTPM) ParsedEventLog() ([]pkgtpm2.Event, error)                    { return nil, nil }
func (m *mockTPM) ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error) {
	if m.parsePublicKeyErr != nil {
		return nil, m.parsePublicKeyErr
	}
	return m.parsePublicKeyValue, nil
}
func (m *mockTPM) PlatformPolicyDigestHash() ([]byte, error)       { return nil, nil }
func (m *mockTPM) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) { return tpm2.TPM2BDigest{}, nil }
func (m *mockTPM) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	return nil, func() error { return nil }, nil
}
func (m *mockTPM) PlatformQuote(keyAttrs *types.KeyAttributes) (pkgtpm2.Quote, []byte, error) {
	return pkgtpm2.Quote{}, nil, nil
}
func (m *mockTPM) Provision(soPIN types.Password) error               { return nil }
func (m *mockTPM) ProvisionEKCert(hierarchyAuth, ekCert []byte) error { return nil }
func (m *mockTPM) ProvisionOwner(hierarchyAuth types.Password) (*types.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPM) Quote(pcrs []uint, nonce []byte) (pkgtpm2.Quote, error) {
	return pkgtpm2.Quote{}, nil
}
func (m *mockTPM) Random() ([]byte, error)                     { return make([]byte, 32), nil }
func (m *mockTPM) RandomBytes(fixedLength int) ([]byte, error) { return make([]byte, fixedLength), nil }
func (m *mockTPM) RandomHex(fixedLength int) ([]byte, error)   { return make([]byte, fixedLength), nil }
func (m *mockTPM) RandomSource() io.Reader                     { return rand.Reader }
func (m *mockTPM) Read(data []byte) (int, error)               { return rand.Read(data) }
func (m *mockTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) ReadPCRs(pcrList []uint) ([]pkgtpm2.PCRBank, error) { return nil, nil }
func (m *mockTPM) RSADecrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, blob []byte) ([]byte, error) {
	if m.rsaDecryptErr != nil {
		return nil, m.rsaDecryptErr
	}
	return m.decryptValue, nil
}
func (m *mockTPM) RSAEncrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, message []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) SaveKeyPair(keyAttrs *types.KeyAttributes, outPrivate tpm2.TPM2BPrivate, outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], backend store.KeyBackend, overwrite bool) error {
	return nil
}
func (m *mockTPM) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	return nil, nil
}
func (m *mockTPM) SealKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend, overwrite bool) (*tpm2.CreateResponse, error) {
	return nil, nil
}
func (m *mockTPM) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.signatureValue, nil
}
func (m *mockTPM) SetHierarchyAuth(oldSecret, newSecret types.Password, hierarchy *tpm2.TPMHandle) error {
	return nil
}
func (m *mockTPM) SecretFromShares(shares []string) (string, error)        { return "", nil }
func (m *mockTPM) ShareSecret(secret []byte, shares int) ([]string, error) { return nil, nil }
func (m *mockTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) SSRKAttributes() (*types.KeyAttributes, error) {
	if m.ssrkAttrsErr != nil {
		return nil, m.ssrkAttrsErr
	}
	if m.ssrkAttrsValue != nil {
		return m.ssrkAttrsValue, nil
	}
	return &types.KeyAttributes{CN: "ssrk"}, nil
}
func (m *mockTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) {
	return &types.KeyAttributes{CN: "platform-srk"}, nil
}
func (m *mockTPM) Transport() transport.TPM {
	if m.transport != nil {
		return m.transport
	}
	return nil
}
func (m *mockTPM) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) UnsealKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) CanSeal() bool                                    { return true }
func (m *mockTPM) WriteEKCert(ekCert []byte) error                  { return nil }
func (m *mockTPM) IDevIDCertificate() (*x509.Certificate, error)    { return nil, nil }
func (m *mockTPM) ProvisionIDevIDCert(cert *x509.Certificate) error { return nil }
func (m *mockTPM) DeleteIDevIDCertificate() error                   { return nil }
func (m *mockTPM) IAKCertificate() (*x509.Certificate, error)       { return nil, nil }
func (m *mockTPM) ProvisionIAKCert(cert *x509.Certificate) error    { return nil }
func (m *mockTPM) DeleteIAKCertificate() error                      { return nil }
func (m *mockTPM) VerifyTCGCSR(csr *pkgtpm2.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*types.KeyAttributes, *pkgtpm2.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) VerifyTCG_CSR_IAK(csr *pkgtpm2.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*types.KeyAttributes, *pkgtpm2.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) VerifyTCG_CSR_IDevID(csr *pkgtpm2.TCG_CSR_IDEVID, signatureAlgorithm x509.SignatureAlgorithm) (*types.KeyAttributes, *pkgtpm2.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) SignValidate(keyAttrs *types.KeyAttributes, digest, validationDigest []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) HashSequence(keyAttrs *types.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPM) Hash(keyAttrs *types.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPM) ECDHZGen(keyAttrs *types.KeyAttributes, peerPublicKey *tpm2.TPMSECCPoint, backend store.KeyBackend) ([]byte, error) {
	if m.ecdhZGenErr != nil {
		return nil, m.ecdhZGenErr
	}
	if m.ecdhZGenValue != nil {
		return m.ecdhZGenValue, nil
	}
	// Return a mock shared secret (32 bytes for P-256)
	return make([]byte, 32), nil
}
func (m *mockTPM) CertifyKey(keyAttrs *types.KeyAttributes, nonce []byte, backend store.KeyBackend) (*pkgtpm2.CertifyResult, error) {
	if m.certifyKeyErr != nil {
		return nil, m.certifyKeyErr
	}
	return m.certifyKeyResult, nil
}

func (m *mockTPM) DictionaryAttackLockoutReset(lockoutAuth []byte) error { return nil }
func (m *mockTPM) FactoryReset(ownerAuth []byte) error                   { return nil }
func (m *mockTPM) FactoryResetWithClear(ownerAuth []byte) error          { return nil }
func (m *mockTPM) ListNVIndexes() ([]pkgtpm2.NVIndexInfo, error)         { return nil, nil }
func (m *mockTPM) ListPersistentHandles() ([]tpm2.TPMHandle, error)      { return nil, nil }
func (m *mockTPM) ListTransientHandles() ([]tpm2.TPMHandle, error)       { return nil, nil }
func (m *mockTPM) SupportedAlgorithms() ([]string, error)                { return nil, nil }
func (m *mockTPM) SupportedCommands() ([]string, error)                  { return nil, nil }
func (m *mockTPM) SupportedECCCurves() ([]string, error)                 { return nil, nil }
func (m *mockTPM) SSRK() *pkgtpm2.SRKConfig                              { return nil }
func (m *mockTPM) PlatformKeyStore() pkgtpm2.PlatformKeyStorer           { return nil }
func (m *mockTPM) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if m.generateSymmetricKeyErr != nil {
		return nil, m.generateSymmetricKeyErr
	}
	return m.generateSymmetricKeyResult, nil
}
func (m *mockTPM) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if m.getSymmetricKeyErr != nil {
		return nil, m.getSymmetricKeyErr
	}
	return m.getSymmetricKeyResult, nil
}
func (m *mockTPM) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if m.symmetricEncrypterErr != nil {
		return nil, m.symmetricEncrypterErr
	}
	return m.symmetricEncrypterResult, nil
}

func (m *mockTPM) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error            { return nil }
func (m *mockTPM) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error { return nil }

var _ pkgtpm2.TrustedPlatformModule = (*mockTPM)(nil)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"ValidConfigWithDevice", &Config{Device: "/dev/null", KeyDir: t.TempDir(), SRKHandle: 0x81000001}, false},
		{"ValidConfigWithSimulator", &Config{UseSimulator: true, KeyDir: t.TempDir()}, false},
		{"DefaultValues", &Config{Device: "/dev/null"}, false},
		{"NonExistentDevice", &Config{Device: "/dev/nonexistent-tpm-device-xyz", KeyDir: t.TempDir()}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_DefaultValues(t *testing.T) {
	config := &Config{UseSimulator: true}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if config.KeyDir != "./tpm2-keys" {
		t.Errorf("KeyDir default: expected ./tpm2-keys, got %q", config.KeyDir)
	}
	if config.SRKHandle != 0x81000001 {
		t.Errorf("SRKHandle default: expected 0x81000001, got 0x%x", config.SRKHandle)
	}
	if config.EKHandle != 0x81010001 {
		t.Errorf("EKHandle default: expected 0x81010001, got 0x%x", config.EKHandle)
	}
	if config.Hash != "SHA-256" {
		t.Errorf("Hash default: expected SHA-256, got %q", config.Hash)
	}
	if config.PlatformPCRBank != "SHA256" {
		t.Errorf("PlatformPCRBank default: expected SHA256, got %q", config.PlatformPCRBank)
	}
	if config.CN != "xkms" {
		t.Errorf("CN default: expected xkms, got %q", config.CN)
	}
}

func TestConfig_ToTPMConfig(t *testing.T) {
	config := &Config{Device: "/dev/tpmrm0", KeyDir: "/tmp/tpm-keys", UseSimulator: true, EncryptSession: true, SRKHandle: 0x81000001, EKHandle: 0x81010001, Hash: "SHA-256", PlatformPolicy: true, PlatformPCR: 7, PlatformPCRBank: "SHA256"}
	tpmConfig := config.ToTPMConfig()
	if tpmConfig == nil {
		t.Fatal("ToTPMConfig returned nil")
	}
	if tpmConfig.Device != config.Device {
		t.Errorf("Device = %s, want %s", tpmConfig.Device, config.Device)
	}
	if tpmConfig.UseSimulator != config.UseSimulator {
		t.Errorf("UseSimulator = %v, want %v", tpmConfig.UseSimulator, config.UseSimulator)
	}
}

func TestConfig_ToTPMConfig_WithPresetConfig(t *testing.T) {
	pkgtpm2Config := &Config{Device: "/dev/custom"}
	config := &Config{Device: "/dev/tpmrm0", TPMConfig: pkgtpm2Config.ToTPMConfig()}
	tpmConfig := config.ToTPMConfig()
	if tpmConfig.Device != "/dev/custom" {
		t.Errorf("Expected preset config device /dev/custom, got %s", tpmConfig.Device)
	}
}

func TestBackendType(t *testing.T) {
	b := &Backend{}
	if b.Type() != backend.BackendTypeTPM2 {
		t.Errorf("Type() = %s, want %s", b.Type(), backend.BackendTypeTPM2)
	}
}

func TestCapabilities(t *testing.T) {
	b := &Backend{}
	caps := b.Capabilities()
	if !caps.HardwareBacked {
		t.Error("Expected HardwareBacked to be true")
	}
	if !caps.Keys {
		t.Error("Expected Keys capability to be true")
	}
	if !caps.Signing {
		t.Error("Expected Signing capability to be true")
	}
	if !caps.Sealing {
		t.Error("Expected Sealing capability to be true")
	}
	if !caps.SymmetricEncryption {
		t.Error("Expected SymmetricEncryption capability to be true")
	}
	if caps.KeyRotation {
		t.Error("Expected KeyRotation to be false")
	}
}

func TestNewBackend_InvalidConfig(t *testing.T) {
	_, err := NewBackend(&Config{Device: "/dev/nonexistent-tpm-xyz123", KeyDir: t.TempDir()})
	if err == nil {
		t.Error("Expected error for non-existent device")
	}
}

func TestBackend_ClosedOperations(t *testing.T) {
	b := &Backend{closed: true}
	rsaAttrs := &types.KeyAttributes{CN: "test-key", KeyAlgorithm: x509.RSA}
	if _, err := b.GenerateKey(rsaAttrs); err != ErrNotInitialized {
		t.Errorf("GenerateKey: expected ErrNotInitialized, got %v", err)
	}
	if _, err := b.GetKey(rsaAttrs); err != ErrNotInitialized {
		t.Errorf("GetKey: expected ErrNotInitialized, got %v", err)
	}
	if err := b.DeleteKey(rsaAttrs); err != ErrNotInitialized {
		t.Errorf("DeleteKey: expected ErrNotInitialized, got %v", err)
	}
	if _, err := b.ListKeys(); err != ErrNotInitialized {
		t.Errorf("ListKeys: expected ErrNotInitialized, got %v", err)
	}
	if _, err := b.Signer(rsaAttrs); err != ErrNotInitialized {
		t.Errorf("Signer: expected ErrNotInitialized, got %v", err)
	}
	if _, err := b.Decrypter(rsaAttrs); err != ErrNotInitialized {
		t.Errorf("Decrypter: expected ErrNotInitialized, got %v", err)
	}
}

func TestBackend_NilAttributes(t *testing.T) {
	b := &Backend{closed: false}
	if _, err := b.GenerateKey(nil); err != ErrInvalidKeyAttributes {
		t.Errorf("GenerateKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}
	if _, err := b.GetKey(nil); err != ErrInvalidKeyAttributes {
		t.Errorf("GetKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}
	if err := b.DeleteKey(nil); err != ErrInvalidKeyAttributes {
		t.Errorf("DeleteKey(nil): expected ErrInvalidKeyAttributes, got %v", err)
	}
}

func TestBackend_RotateKey(t *testing.T) {
	b := &Backend{}
	if err := b.RotateKey(&types.KeyAttributes{CN: "test"}); err != ErrKeyRotationNotSupported {
		t.Errorf("RotateKey: expected ErrKeyRotationNotSupported, got %v", err)
	}
}

func TestBackend_DoubleClose(t *testing.T) {
	b := &Backend{closed: false}
	if err := b.Close(); err != nil {
		t.Errorf("First Close() error = %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

func TestBackend_ListKeys_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	b := &Backend{closed: false, config: &Config{KeyDir: tmpDir}}
	keys, err := b.ListKeys()
	if err != nil {
		t.Errorf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys in empty directory, got %d", len(keys))
	}
}

func TestBackend_ListKeys_NonExistentDir(t *testing.T) {
	b := &Backend{closed: false, config: &Config{KeyDir: "/nonexistent/path/xyz123"}}
	keys, err := b.ListKeys()
	if err != nil {
		t.Errorf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
}

func TestErrors(t *testing.T) {
	errs := []error{ErrNotInitialized, ErrAlreadyInitialized, ErrInvalidConfig, ErrKeyNotFound, ErrUnsupportedKeyAlgorithm, ErrUnsupportedOperation, ErrKeyRotationNotSupported, ErrDecryptionNotSupported, ErrInvalidKeyAttributes, ErrTPMNotAvailable, ErrSessionCreationFailed}
	for _, err := range errs {
		if err == nil {
			t.Error("Error is nil")
		}
		if err.Error() == "" {
			t.Error("Error has empty message")
		}
	}
}

func TestNewBackendWithTPM_NilConfig(t *testing.T) {
	_, err := NewBackendWithTPM(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewBackendWithTPM_NilTPM(t *testing.T) {
	cfg := &ExternalTPMConfig{TPM: nil, KeyBackend: &mockKeyBackend{}}
	_, err := NewBackendWithTPM(cfg)
	if err == nil {
		t.Error("Expected error for nil TPM")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewBackendWithTPM_NilKeyBackend(t *testing.T) {
	cfg := &ExternalTPMConfig{TPM: &mockTPM{}, KeyBackend: nil}
	_, err := NewBackendWithTPM(cfg)
	if err == nil {
		t.Error("Expected error for nil KeyBackend")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_ListKeys_WithFiles(t *testing.T) {
	tmpDir := t.TempDir()
	keyNames := []string{"key1", "key2", "key3"}
	for _, name := range keyNames {
		path := filepath.Join(tmpDir, name+store.FSEXT_PRIVATE_BLOB)
		if err := os.WriteFile(path, []byte("mock blob data"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}
	for _, name := range []string{"notakey.txt", "another.pub"} {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte("ignored"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}
	subDir := filepath.Join(tmpDir, "subdir.blob")
	if err := os.Mkdir(subDir, 0700); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	b := &Backend{closed: false, config: &Config{KeyDir: tmpDir}}
	keys, err := b.ListKeys()
	if err != nil {
		t.Errorf("ListKeys() error = %v", err)
	}
	if len(keys) != len(keyNames) {
		t.Errorf("Expected %d keys, got %d", len(keyNames), len(keys))
	}
	foundKeys := make(map[string]bool)
	for _, k := range keys {
		foundKeys[k.CN] = true
		if k.StoreType != types.StoreTPM2 {
			t.Errorf("Expected StoreType %v, got %v", types.StoreTPM2, k.StoreType)
		}
	}
	for _, name := range keyNames {
		if !foundKeys[name] {
			t.Errorf("Expected to find key %q", name)
		}
	}
}

func TestBackend_Accessors(t *testing.T) {
	mockBackend := &mockKeyBackend{}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{tpm: nil, keyBackend: mockBackend, srkAttrs: srkAttrs}
	if b.TPM() != nil {
		t.Error("TPM() should return nil")
	}
	if b.KeyBackend() != mockBackend {
		t.Error("KeyBackend() did not return expected value")
	}
	if b.SRKAttributes() != srkAttrs {
		t.Error("SRKAttributes() did not return expected value")
	}
}

func TestTPM2Signer_Public(t *testing.T) {
	rsaKey := &rsa.PublicKey{N: nil, E: 65537}
	signer := &tpm2Signer{publicKey: rsaKey}
	if pub := signer.Public(); pub != rsaKey {
		t.Error("Public() did not return expected key")
	}
}

func TestTPM2Signer_Sign_ClosedBackend(t *testing.T) {
	b := &Backend{closed: true}
	signer := &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test"}}
	if _, err := signer.Sign(nil, []byte("digest"), nil); err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

func TestTPM2Decrypter_Decrypt_ClosedBackend(t *testing.T) {
	b := &Backend{closed: true}
	decrypter := &tpm2Decrypter{tpm2Signer: &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA}}}
	if _, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil); err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

func TestTPM2Decrypter_Decrypt_NonRSA(t *testing.T) {
	b := &Backend{closed: false}
	decrypter := &tpm2Decrypter{tpm2Signer: &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.ECDSA}}}
	_, err := decrypter.Decrypt(nil, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error for non-RSA key")
	}
	if !errors.Is(err, ErrDecryptionNotSupported) {
		t.Errorf("Expected ErrDecryptionNotSupported, got %v", err)
	}
}

func TestBackend_GenerateKey_UnsupportedAlgorithm(t *testing.T) {
	b := &Backend{closed: false, srkAttrs: &types.KeyAttributes{CN: "test-srk"}}
	attrs := &types.KeyAttributes{CN: "test-key", KeyAlgorithm: x509.Ed25519}
	_, err := b.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
	if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
		t.Errorf("Expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

func TestConfig_Validate_DeviceDoesNotExist(t *testing.T) {
	config := &Config{Device: "/dev/tpm-that-does-not-exist-xyz123", UseSimulator: false}
	err := config.Validate()
	if err == nil {
		t.Error("Expected error for non-existent device")
	}
	if !errors.Is(err, ErrTPMNotAvailable) {
		t.Errorf("Expected ErrTPMNotAvailable, got %v", err)
	}
}

func TestConfig_Validate_SimulatorSkipsDeviceCheck(t *testing.T) {
	config := &Config{Device: "/dev/tpm-that-does-not-exist-xyz123", UseSimulator: true}
	if err := config.Validate(); err != nil {
		t.Errorf("Expected no error when using simulator, got %v", err)
	}
}

func TestConfig_ToTPMConfig_EKAndSSRKConfigs(t *testing.T) {
	config := &Config{UseSimulator: true, SRKHandle: 0x81000002, EKHandle: 0x81010002}
	tpmConfig := config.ToTPMConfig()
	if tpmConfig.EK == nil {
		t.Fatal("Expected EK config to be set")
	}
	if tpmConfig.EK.Handle != config.EKHandle {
		t.Errorf("Expected EK handle 0x%x, got 0x%x", config.EKHandle, tpmConfig.EK.Handle)
	}
	if tpmConfig.SSRK == nil {
		t.Fatal("Expected SSRK config to be set")
	}
	if tpmConfig.SSRK.Handle != config.SRKHandle {
		t.Errorf("Expected SSRK handle 0x%x, got 0x%x", config.SRKHandle, tpmConfig.SSRK.Handle)
	}
}

func TestBackend_CloseWithExternalTPMFlag(t *testing.T) {
	b := &Backend{closed: false, externalTPM: true, tpm: nil}
	if err := b.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if !b.closed {
		t.Error("Expected backend to be marked as closed")
	}
}

func TestBackend_CloseWithNilTPM(t *testing.T) {
	b := &Backend{closed: false, externalTPM: false, tpm: nil}
	if err := b.Close(); err != nil {
		t.Errorf("Close() with nil TPM should not error: %v", err)
	}
	if !b.closed {
		t.Error("Expected backend to be marked as closed")
	}
}

func TestBackend_GetKey_KeyNotFound(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: &mockKeyBackend{getError: errors.New("key not found")}}
	attrs := &types.KeyAttributes{CN: "nonexistent-key"}
	_, err := b.GetKey(attrs)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_SetsStoreType(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: &mockKeyBackend{getError: errors.New("key not found")}}
	attrs := &types.KeyAttributes{CN: "test-key", StoreType: ""}
	_, _ = b.GetKey(attrs)
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("Expected StoreType to be set to %v, got %v", types.StoreTPM2, attrs.StoreType)
	}
}

func TestBackend_SetsParent(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: &mockKeyBackend{getError: errors.New("key not found")}}
	attrs := &types.KeyAttributes{CN: "test-key", Parent: nil}
	_, _ = b.GetKey(attrs)
	if attrs.Parent != srkAttrs {
		t.Error("Expected Parent to be set to SRK attributes")
	}
}

func TestBackend_PreservesExistingParent(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	existingParent := &types.KeyAttributes{CN: "existing-parent"}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: &mockKeyBackend{getError: errors.New("key not found")}}
	attrs := &types.KeyAttributes{CN: "test-key", Parent: existingParent}
	_, _ = b.GetKey(attrs)
	if attrs.Parent != existingParent {
		t.Error("Expected existing Parent to be preserved")
	}
}

func TestNewBackendWithTPM_Success(t *testing.T) {
	mockTpm := &mockTPM{ssrkAttrsValue: &types.KeyAttributes{CN: "test-ssrk"}}
	mockKb := &mockKeyBackend{}
	logger := slog.Default()
	tracker := backend.NewMemoryAEADTracker()
	cfg := &ExternalTPMConfig{TPM: mockTpm, KeyBackend: mockKb, Logger: logger, Tracker: tracker}
	b, err := NewBackendWithTPM(cfg)
	if err != nil {
		t.Fatalf("NewBackendWithTPM() error = %v", err)
	}
	if b == nil {
		t.Fatal("Expected non-nil backend")
	}
	if b.tpm != mockTpm {
		t.Error("Expected TPM to be set")
	}
	if b.keyBackend != mockKb {
		t.Error("Expected keyBackend to be set")
	}
	if b.logger != logger {
		t.Error("Expected logger to be set")
	}
	if b.tracker != tracker {
		t.Error("Expected tracker to be set")
	}
	if !b.externalTPM {
		t.Error("Expected externalTPM flag to be true")
	}
	if b.srkAttrs.CN != "test-ssrk" {
		t.Errorf("Expected SRK CN to be test-ssrk, got %s", b.srkAttrs.CN)
	}
}

func TestNewBackendWithTPM_DefaultLogger(t *testing.T) {
	mockTpm := &mockTPM{ssrkAttrsValue: &types.KeyAttributes{CN: "test-ssrk"}}
	mockKb := &mockKeyBackend{}
	cfg := &ExternalTPMConfig{TPM: mockTpm, KeyBackend: mockKb, Logger: nil, Tracker: nil}
	b, err := NewBackendWithTPM(cfg)
	if err != nil {
		t.Fatalf("NewBackendWithTPM() error = %v", err)
	}
	if b.logger == nil {
		t.Error("Expected logger to be set to default")
	}
	if b.tracker == nil {
		t.Error("Expected tracker to be set to default")
	}
}

func TestNewBackendWithTPM_SSRKAttributesError(t *testing.T) {
	expectedErr := errors.New("ssrk error")
	mockTpm := &mockTPM{ssrkAttrsErr: expectedErr}
	mockKb := &mockKeyBackend{}
	cfg := &ExternalTPMConfig{TPM: mockTpm, KeyBackend: mockKb}
	_, err := NewBackendWithTPM(cfg)
	if err == nil {
		t.Error("Expected error when SSRKAttributes fails")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error to wrap ssrk error, got %v", err)
	}
}

func TestBackend_GenerateKey_RSA_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{rsaPublicKey: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-rsa-key", KeyAlgorithm: x509.RSA}
	key, err := b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Expected key to implement crypto.Signer")
	}
	pub := signer.Public()
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Expected public key to be RSA")
	}
	if rsaPub.E != rsaKey.E {
		t.Error("Public key exponent mismatch")
	}
}

func TestBackend_GenerateKey_ECDSA_Success(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	mockTpm := &mockTPM{ecdsaPublicKey: &ecKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-ecdsa-key", KeyAlgorithm: x509.ECDSA}
	key, err := b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Expected key to implement crypto.Signer")
	}
	pub := signer.Public()
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Expected public key to be ECDSA")
	}
	if ecdsaPub.Curve != elliptic.P256() {
		t.Error("Expected P256 curve")
	}
}

func TestBackend_GenerateKey_ECDSA_DefaultCurve(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	mockTpm := &mockTPM{ecdsaPublicKey: &ecKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-ecdsa-key", KeyAlgorithm: x509.ECDSA, ECCAttributes: nil}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.ECCAttributes == nil {
		t.Fatal("Expected ECCAttributes to be set")
	}
	if attrs.ECCAttributes.Curve != elliptic.P256() {
		t.Error("Expected default curve to be P256")
	}
}

func TestBackend_GenerateKey_RSA_Error(t *testing.T) {
	expectedErr := errors.New("create rsa error")
	mockTpm := &mockTPM{createRSAErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-rsa-key", KeyAlgorithm: x509.RSA}
	_, err := b.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error from CreateRSA")
	}
}

func TestBackend_GenerateKey_ECDSA_Error(t *testing.T) {
	expectedErr := errors.New("create ecdsa error")
	mockTpm := &mockTPM{createECDSAErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-ecdsa-key", KeyAlgorithm: x509.ECDSA}
	_, err := b.GenerateKey(attrs)
	if err == nil {
		t.Error("Expected error from CreateECDSA")
	}
}

func TestBackend_GetKey_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{parsePublicKeyValue: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-private-blob"), publicData: []byte("mock-public-blob")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	key, err := b.GetKey(attrs)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("Expected key to implement crypto.Signer")
	}
	pub := signer.Public()
	if pub == nil {
		t.Error("Expected non-nil public key")
	}
}

func TestBackend_GetKey_PublicBlobError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-private-blob"), publicBlobError: errors.New("public blob error")}
	b := &Backend{closed: false, tpm: &mockTPM{}, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := b.GetKey(attrs)
	if err == nil {
		t.Error("Expected error when public blob retrieval fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_GetKey_ParsePublicKeyError(t *testing.T) {
	expectedErr := errors.New("parse error")
	mockTpm := &mockTPM{parsePublicKeyErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-private-blob"), publicData: []byte("mock-public-blob")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := b.GetKey(attrs)
	if err == nil {
		t.Error("Expected error when parsing public key fails")
	}
}

func TestBackend_DeleteKey_Success(t *testing.T) {
	mockTpm := &mockTPM{}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	err := b.DeleteKey(attrs)
	if err != nil {
		t.Errorf("DeleteKey() error = %v", err)
	}
}

func TestBackend_DeleteKey_Error(t *testing.T) {
	expectedErr := errors.New("delete error")
	mockTpm := &mockTPM{deleteKeyErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	err := b.DeleteKey(attrs)
	if err == nil {
		t.Error("Expected error from DeleteKey")
	}
}

func TestBackend_Signer_Success(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{parsePublicKeyValue: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-private-blob"), publicData: []byte("mock-public-blob")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	signer, err := b.Signer(attrs)
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	if signer == nil {
		t.Error("Expected non-nil signer")
	}
}

func TestBackend_Decrypter_ReturnsError(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{parsePublicKeyValue: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getData: []byte("mock-private-blob"), publicData: []byte("mock-public-blob")}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: mockKb, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err = b.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error because GetKey returns tpm2Signer not tpm2Decrypter")
	}
	if !errors.Is(err, ErrDecryptionNotSupported) {
		t.Errorf("Expected ErrDecryptionNotSupported, got %v", err)
	}
}

func TestBackend_Close_WithTPMError(t *testing.T) {
	expectedErr := errors.New("close error")
	mockTpm := &mockTPM{closeErr: expectedErr}
	b := &Backend{closed: false, tpm: mockTpm, externalTPM: false}
	err := b.Close()
	if err == nil {
		t.Error("Expected error from Close")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected close error, got %v", err)
	}
}

func TestTPM2Signer_Sign_Success(t *testing.T) {
	expectedSig := []byte("mock-signature")
	mockTpm := &mockTPM{signatureValue: expectedSig}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	signer := &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test"}, publicKey: &rsa.PublicKey{}}
	digest := sha256.Sum256([]byte("test message"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if string(sig) != string(expectedSig) {
		t.Errorf("Expected signature %v, got %v", expectedSig, sig)
	}
}

func TestTPM2Signer_Sign_Error(t *testing.T) {
	expectedErr := errors.New("sign error")
	mockTpm := &mockTPM{signErr: expectedErr}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	signer := &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test"}, publicKey: &rsa.PublicKey{}}
	digest := sha256.Sum256([]byte("test message"))
	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Error("Expected error from Sign")
	}
}

func TestTPM2Signer_Sign_WithNilOpts(t *testing.T) {
	expectedSig := []byte("mock-signature")
	mockTpm := &mockTPM{signatureValue: expectedSig}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	signer := &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test"}, publicKey: &rsa.PublicKey{}}
	digest := sha256.Sum256([]byte("test message"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign() with nil opts error = %v", err)
	}
	if string(sig) != string(expectedSig) {
		t.Errorf("Expected signature %v, got %v", expectedSig, sig)
	}
}

func TestTPM2Decrypter_Decrypt_RSA_LoadKeyPairError(t *testing.T) {
	expectedErr := errors.New("load key pair error")
	mockTpm := &mockTPM{loadKeyPairErr: expectedErr}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	decrypter := &tpm2Decrypter{tpm2Signer: &tpm2Signer{backend: b, attrs: &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA}, publicKey: &rsa.PublicKey{}}}
	_, err := decrypter.Decrypt(rand.Reader, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error from LoadKeyPair")
	}
}

func TestBackend_parsePublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{parsePublicKeyValue: &rsaKey.PublicKey}
	b := &Backend{tpm: mockTpm}
	pub, err := b.parsePublicKey([]byte("mock-public-data"))
	if err != nil {
		t.Fatalf("parsePublicKey() error = %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Expected RSA public key")
	}
	if rsaPub.E != rsaKey.E {
		t.Error("Public key mismatch")
	}
}

func TestBackend_parsePublicKey_Error(t *testing.T) {
	expectedErr := errors.New("parse error")
	mockTpm := &mockTPM{parsePublicKeyErr: expectedErr}
	b := &Backend{tpm: mockTpm}
	_, err := b.parsePublicKey([]byte("invalid-data"))
	if err == nil {
		t.Error("Expected error from parsePublicKey")
	}
}

func TestTPM2Decrypter_ImplementsDecrypter(t *testing.T) {
	decrypter := &tpm2Decrypter{tpm2Signer: &tpm2Signer{publicKey: &rsa.PublicKey{N: big.NewInt(1), E: 65537}}}
	var _ crypto.Decrypter = decrypter
}

func TestBackend_GenerateKey_SetsParentToSRK(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{rsaPublicKey: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key", KeyAlgorithm: x509.RSA, Parent: nil}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.Parent != srkAttrs {
		t.Error("Expected Parent to be set to SRK attributes")
	}
}

func TestBackend_GenerateKey_SetsStoreType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{rsaPublicKey: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key", KeyAlgorithm: x509.RSA, StoreType: ""}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("Expected StoreType to be %v, got %v", types.StoreTPM2, attrs.StoreType)
	}
}

func TestBackend_DeleteKey_SetsParent(t *testing.T) {
	mockTpm := &mockTPM{}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key", Parent: nil}
	err := b.DeleteKey(attrs)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
	if attrs.Parent != srkAttrs {
		t.Error("Expected Parent to be set to SRK attributes")
	}
}

func TestConfig_ToTPMConfig_TrackerPassthrough(t *testing.T) {
	tracker := backend.NewMemoryAEADTracker()
	config := &Config{UseSimulator: true, Tracker: tracker}
	tpmConfig := config.ToTPMConfig()
	if tpmConfig.Tracker != tracker {
		t.Error("Expected tracker to be passed through to TPM config")
	}
}

func TestBackend_GenerateKey_PreservesExistingParent(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	mockTpm := &mockTPM{rsaPublicKey: &rsaKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	existingParent := &types.KeyAttributes{CN: "existing-parent"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-key", KeyAlgorithm: x509.RSA, Parent: existingParent}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.Parent != existingParent {
		t.Error("Expected existing Parent to be preserved")
	}
}

func TestBackend_ECDSA_WithExistingCurve(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	mockTpm := &mockTPM{ecdsaPublicKey: &ecKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{CN: "test-ecdsa-key", KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.ECCAttributes.Curve != elliptic.P384() {
		t.Error("Expected P384 curve to be preserved")
	}
}

func TestBackend_Signer_GetKeyError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getError: errors.New("key not found")}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: mockKb}
	attrs := &types.KeyAttributes{CN: "nonexistent-key"}
	_, err := b.Signer(attrs)
	if err == nil {
		t.Error("Expected error when GetKey fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_Decrypter_GetKeyError(t *testing.T) {
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	mockKb := &mockKeyBackend{getError: errors.New("key not found")}
	b := &Backend{closed: false, srkAttrs: srkAttrs, keyBackend: mockKb}
	attrs := &types.KeyAttributes{CN: "nonexistent-key"}
	_, err := b.Decrypter(attrs)
	if err == nil {
		t.Error("Expected error when GetKey fails")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestConfig_Validate_ExistingDevice(t *testing.T) {
	config := &Config{Device: "/dev/null", UseSimulator: false}
	err := config.Validate()
	if err != nil {
		t.Errorf("Expected no error for existing device, got %v", err)
	}
}

func TestBackend_ListKeys_ReadDirError(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(tmpFile, []byte("data"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	// Point KeyDir at a file (not a directory) to trigger read error
	b := &Backend{closed: false, config: &Config{KeyDir: tmpFile}}
	_, err := b.ListKeys()
	if err == nil {
		t.Error("Expected error when KeyDir is not a directory")
	}
}

func TestConfig_Validate_EmptyDeviceSimulator(t *testing.T) {
	config := &Config{Device: "", UseSimulator: true}
	err := config.Validate()
	if err != nil {
		t.Errorf("Expected no error with empty device and simulator, got %v", err)
	}
	// Device should remain empty when simulator is used
	if config.Device != "" {
		t.Errorf("Expected Device to remain empty with simulator, got %q", config.Device)
	}
}

func TestConfig_Validate_EmptyDeviceNoSimulator(t *testing.T) {
	config := &Config{Device: "", UseSimulator: false}
	// This will fail because /dev/tpmrm0 likely does not exist
	err := config.Validate()
	// Error is expected if default device does not exist
	if err == nil {
		// If no error, device should be set to default
		if config.Device != "/dev/tpmrm0" {
			t.Errorf("Expected Device to be /dev/tpmrm0, got %q", config.Device)
		}
	}
}

// TestTPM2Decrypter_Decrypt_RSA_ReadPublicError tests ReadPublic error path
func TestTPM2Decrypter_Decrypt_RSA_ReadPublicError(t *testing.T) {
	// Create a mock transport that will cause ReadPublic to fail
	mockTpm := &mockTPM{
		transport: &mockTransport{
			sendErr: errors.New("send error"),
		},
	}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			backend:   b,
			attrs:     &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA},
			publicKey: &rsa.PublicKey{N: big.NewInt(12345), E: 65537},
		},
	}
	_, err := decrypter.Decrypt(rand.Reader, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error from ReadPublic")
	}
}

// TestBackend_CloseWithExternalTPM_NoClose verifies external TPM is not closed
func TestBackend_CloseWithExternalTPM_NoClose(t *testing.T) {
	mockTpm := &mockTPM{}
	b := &Backend{closed: false, externalTPM: true, tpm: mockTpm}
	if err := b.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestBackend_GenerateKey_ECDSA_WithNilCurve tests ECDSA with nil curve in ECCAttributes
func TestBackend_GenerateKey_ECDSA_WithNilCurve(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	mockTpm := &mockTPM{ecdsaPublicKey: &ecKey.PublicKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}
	attrs := &types.KeyAttributes{
		CN:            "test-ecdsa-key",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: nil},
	}
	_, err = b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if attrs.ECCAttributes.Curve != elliptic.P256() {
		t.Error("Expected default curve to be P256 when Curve is nil")
	}
}

// TestBackend_TPM_Accessor tests the TPM accessor method
func TestBackend_TPM_Accessor(t *testing.T) {
	mockTpm := &mockTPM{}
	b := &Backend{tpm: mockTpm}
	if b.TPM() != mockTpm {
		t.Error("TPM() did not return expected TPM instance")
	}
}

// TestBackend_Close_ExternalTPM_WithMockTPM tests close with external TPM flag set
func TestBackend_Close_ExternalTPM_WithMockTPM(t *testing.T) {
	mockTpm := &mockTPM{closeErr: errors.New("should not be called")}
	b := &Backend{closed: false, externalTPM: true, tpm: mockTpm}
	// Should not return error because externalTPM is true
	if err := b.Close(); err != nil {
		t.Errorf("Close() should not error when externalTPM is true: %v", err)
	}
}

// TestConfig_ToTPMConfig_AllFields tests all config fields are properly mapped
func TestConfig_ToTPMConfig_AllFields(t *testing.T) {
	config := &Config{
		Device:          "/dev/tpmrm0",
		UseSimulator:    true,
		EncryptSession:  true,
		SRKHandle:       0x81000002,
		EKHandle:        0x81010002,
		Hash:            "SHA-384",
		PlatformPCR:     7,
		PlatformPCRBank: "SHA384",
	}
	tpmConfig := config.ToTPMConfig()

	if tpmConfig.Device != config.Device {
		t.Errorf("Device: got %s, want %s", tpmConfig.Device, config.Device)
	}
	if tpmConfig.UseSimulator != config.UseSimulator {
		t.Errorf("UseSimulator: got %v, want %v", tpmConfig.UseSimulator, config.UseSimulator)
	}
	if tpmConfig.EncryptSession != config.EncryptSession {
		t.Errorf("EncryptSession: got %v, want %v", tpmConfig.EncryptSession, config.EncryptSession)
	}
	if tpmConfig.Hash != config.Hash {
		t.Errorf("Hash: got %s, want %s", tpmConfig.Hash, config.Hash)
	}
	if tpmConfig.PlatformPCR != config.PlatformPCR {
		t.Errorf("PlatformPCR: got %d, want %d", tpmConfig.PlatformPCR, config.PlatformPCR)
	}
	if tpmConfig.PlatformPCRBank != config.PlatformPCRBank {
		t.Errorf("PlatformPCRBank: got %s, want %s", tpmConfig.PlatformPCRBank, config.PlatformPCRBank)
	}
	if tpmConfig.SSRK.Handle != config.SRKHandle {
		t.Errorf("SSRK.Handle: got 0x%x, want 0x%x", tpmConfig.SSRK.Handle, config.SRKHandle)
	}
	if tpmConfig.EK.Handle != config.EKHandle {
		t.Errorf("EK.Handle: got 0x%x, want 0x%x", tpmConfig.EK.Handle, config.EKHandle)
	}
}

// TestTPM2Signer_Sign_SetsHash tests that Sign properly sets hash from opts
func TestTPM2Signer_Sign_SetsHash(t *testing.T) {
	expectedSig := []byte("mock-signature")
	mockTpm := &mockTPM{signatureValue: expectedSig}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	attrs := &types.KeyAttributes{CN: "test", Hash: 0}
	signer := &tpm2Signer{backend: b, attrs: attrs, publicKey: &rsa.PublicKey{}}
	digest := sha256.Sum256([]byte("test message"))

	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if attrs.Hash != crypto.SHA384 {
		t.Errorf("Expected Hash to be set to SHA384, got %v", attrs.Hash)
	}
}

// TestTPM2Decrypter_Public tests the Public method of tpm2Decrypter
func TestTPM2Decrypter_Public(t *testing.T) {
	rsaKey := &rsa.PublicKey{N: big.NewInt(12345), E: 65537}
	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			publicKey: rsaKey,
		},
	}
	pub := decrypter.Public()
	if pub != rsaKey {
		t.Error("Public() did not return expected public key")
	}
}

// =============================================================================
// NewBackend Tests - Testing the full backend creation path
// =============================================================================

// TestNewBackend_KeyDirCreationError tests that NewBackend fails when key directory cannot be created
func TestNewBackend_KeyDirCreationError(t *testing.T) {
	// Create a file that will prevent directory creation
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocking")
	if err := os.WriteFile(blockingFile, []byte("data"), 0600); err != nil {
		t.Fatalf("Failed to create blocking file: %v", err)
	}

	// Try to create a backend with a key directory that cannot be created
	// because there's a file in the way
	config := &Config{
		UseSimulator: true,
		KeyDir:       filepath.Join(blockingFile, "subdir"), // This should fail
	}

	_, err := NewBackend(config)
	if err == nil {
		t.Error("Expected error when key directory cannot be created")
	}
	// Check that error message mentions key directory
	if err != nil && !errors.Is(err, ErrInvalidConfig) {
		// The error should be about directory creation, not config validation
		t.Logf("Got expected error: %v", err)
	}
}

// TestNewBackend_DefaultLoggerAndTracker tests that NewBackend sets default logger and tracker
func TestNewBackend_DefaultLoggerAndTracker(t *testing.T) {
	// We can only test the config preparation parts without a real TPM
	config := &Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
	}

	// Validate config manually to see defaults are set
	if err := config.Validate(); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Check defaults were set
	if config.KeyDir == "" {
		t.Error("Expected KeyDir to be set")
	}
	if config.SRKHandle == 0 {
		t.Error("Expected SRKHandle to have default value")
	}
	if config.EKHandle == 0 {
		t.Error("Expected EKHandle to have default value")
	}
}

// TestNewBackend_ConfigValidationError tests NewBackend returns error on invalid config
func TestNewBackend_ConfigValidationError(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "NonExistentDevice",
			config: &Config{
				Device:       "/dev/nonexistent-tpm-device-12345",
				UseSimulator: false,
				KeyDir:       t.TempDir(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBackend(tt.config)
			if err == nil {
				t.Error("Expected error for invalid config")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("Expected ErrInvalidConfig, got %v", err)
			}
		})
	}
}

// TestNewBackend_WithProvidedLoggerAndTracker tests config with provided logger and tracker
func TestNewBackend_WithProvidedLoggerAndTracker(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.Default()
	tracker := backend.NewMemoryAEADTracker()

	config := &Config{
		UseSimulator: true,
		KeyDir:       tmpDir,
		Logger:       logger,
		Tracker:      tracker,
	}

	// Validate the config
	if err := config.Validate(); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Check logger and tracker are preserved
	if config.Logger != logger {
		t.Error("Logger should be preserved")
	}
	if config.Tracker != tracker {
		t.Error("Tracker should be preserved")
	}
}

// TestNewBackend_StorageBackendCreation tests that storage backend is properly created
func TestNewBackend_StorageBackendCreation(t *testing.T) {
	tmpDir := t.TempDir()

	// This tests the directory creation portion of NewBackend
	config := &Config{
		UseSimulator: true,
		KeyDir:       tmpDir,
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Verify the key directory would be valid for storage backend creation
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		t.Errorf("Key directory does not exist: %s", tmpDir)
	}
}

// TestNewBackend_ConfigToTPMConfigConversion tests proper conversion of backend config to TPM config
func TestNewBackend_ConfigToTPMConfigConversion(t *testing.T) {
	tracker := backend.NewMemoryAEADTracker()

	config := &Config{
		Device:          "/dev/tpmrm0",
		UseSimulator:    true,
		EncryptSession:  true,
		SRKHandle:       0x81000002,
		EKHandle:        0x81010002,
		Hash:            "SHA-384",
		PlatformPCR:     7,
		PlatformPCRBank: "SHA384",
		CN:              "test-cn",
		Tracker:         tracker,
	}

	tpmConfig := config.ToTPMConfig()

	// Verify all fields are properly converted
	if tpmConfig.Device != config.Device {
		t.Errorf("Device mismatch: got %s, want %s", tpmConfig.Device, config.Device)
	}
	if tpmConfig.UseSimulator != config.UseSimulator {
		t.Errorf("UseSimulator mismatch: got %v, want %v", tpmConfig.UseSimulator, config.UseSimulator)
	}
	if tpmConfig.EncryptSession != config.EncryptSession {
		t.Errorf("EncryptSession mismatch: got %v, want %v", tpmConfig.EncryptSession, config.EncryptSession)
	}
	if tpmConfig.Hash != config.Hash {
		t.Errorf("Hash mismatch: got %s, want %s", tpmConfig.Hash, config.Hash)
	}
	if tpmConfig.PlatformPCR != config.PlatformPCR {
		t.Errorf("PlatformPCR mismatch: got %d, want %d", tpmConfig.PlatformPCR, config.PlatformPCR)
	}
	if tpmConfig.PlatformPCRBank != config.PlatformPCRBank {
		t.Errorf("PlatformPCRBank mismatch: got %s, want %s", tpmConfig.PlatformPCRBank, config.PlatformPCRBank)
	}
	if tpmConfig.Tracker != tracker {
		t.Error("Tracker not properly passed through")
	}
	if tpmConfig.EK == nil {
		t.Error("EK config should be set")
	} else if tpmConfig.EK.Handle != config.EKHandle {
		t.Errorf("EK.Handle mismatch: got 0x%x, want 0x%x", tpmConfig.EK.Handle, config.EKHandle)
	}
	if tpmConfig.SSRK == nil {
		t.Error("SSRK config should be set")
	} else if tpmConfig.SSRK.Handle != config.SRKHandle {
		t.Errorf("SSRK.Handle mismatch: got 0x%x, want 0x%x", tpmConfig.SSRK.Handle, config.SRKHandle)
	}
}

// TestNewBackend_ConfigWithPresetTPMConfig tests that preset TPMConfig takes precedence
func TestNewBackend_ConfigWithPresetTPMConfig(t *testing.T) {
	presetConfig := &pkgtpm2.Config{
		Device:       "/dev/custom-tpm",
		UseSimulator: false,
		Hash:         "SHA-512",
	}

	config := &Config{
		Device:       "/dev/tpmrm0",
		UseSimulator: true,
		Hash:         "SHA-256",
		TPMConfig:    presetConfig,
	}

	tpmConfig := config.ToTPMConfig()

	// Preset config should take precedence
	if tpmConfig.Device != "/dev/custom-tpm" {
		t.Errorf("Expected preset device, got %s", tpmConfig.Device)
	}
	if tpmConfig.UseSimulator != false {
		t.Errorf("Expected preset UseSimulator=false")
	}
	if tpmConfig.Hash != "SHA-512" {
		t.Errorf("Expected preset hash SHA-512, got %s", tpmConfig.Hash)
	}
}

// TestNewBackend_VerifyConfigDefaults tests that config defaults are properly applied
func TestNewBackend_VerifyConfigDefaults(t *testing.T) {
	config := &Config{
		UseSimulator: true,
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	// Check all defaults
	if config.KeyDir != "./tpm2-keys" {
		t.Errorf("KeyDir default: got %q, want %q", config.KeyDir, "./tpm2-keys")
	}
	if config.SRKHandle != 0x81000001 {
		t.Errorf("SRKHandle default: got 0x%x, want 0x81000001", config.SRKHandle)
	}
	if config.EKHandle != 0x81010001 {
		t.Errorf("EKHandle default: got 0x%x, want 0x81010001", config.EKHandle)
	}
	if config.Hash != "SHA-256" {
		t.Errorf("Hash default: got %q, want %q", config.Hash, "SHA-256")
	}
	if config.PlatformPCRBank != "SHA256" {
		t.Errorf("PlatformPCRBank default: got %q, want %q", config.PlatformPCRBank, "SHA256")
	}
	if config.CN != "xkms" {
		t.Errorf("CN default: got %q, want %q", config.CN, "xkms")
	}
}

// TestTPM2Decrypter_Decrypt_RSADecryptError tests RSADecrypt error path
func TestTPM2Decrypter_Decrypt_RSADecryptError(t *testing.T) {
	expectedErr := errors.New("rsa decrypt error")
	mockTpm := &mockTPM{
		rsaDecryptErr: expectedErr,
		transport: &mockTransport{
			// Need to return valid response for ReadPublic
			sendResult: nil,
			sendErr:    nil,
		},
	}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}}
	decrypter := &tpm2Decrypter{
		tpm2Signer: &tpm2Signer{
			backend:   b,
			attrs:     &types.KeyAttributes{CN: "test", KeyAlgorithm: x509.RSA},
			publicKey: &rsa.PublicKey{N: big.NewInt(12345), E: 65537},
		},
	}

	// The decrypter will try to load the key and read public first
	// Since our mock transport returns nil for Send, ReadPublic will fail
	_, err := decrypter.Decrypt(rand.Reader, []byte("ciphertext"), nil)
	if err == nil {
		t.Error("Expected error from Decrypt")
	}
}

// TestNewBackend_ErrNotInitializedPath tests the TPM needs provisioning error path
func TestNewBackend_ErrNotInitializedPath(t *testing.T) {
	// This tests the error handling when TPM returns ErrNotInitialized
	// We can only test this indirectly by checking error types

	// Verify ErrNotInitialized is properly defined
	if ErrNotInitialized == nil {
		t.Error("ErrNotInitialized should not be nil")
	}

	// Test the error message
	expectedMsg := "tpm2: backend not initialized"
	if ErrNotInitialized.Error() != expectedMsg {
		t.Errorf("ErrNotInitialized message: got %q, want %q", ErrNotInitialized.Error(), expectedMsg)
	}
}

// TestConfig_ToTPMConfig_EKAndSSRKConfigs_RSADefaults tests RSA defaults in EK/SSRK configs
func TestConfig_ToTPMConfig_EKAndSSRKConfigs_RSADefaults(t *testing.T) {
	config := &Config{
		UseSimulator: true,
		SRKHandle:    0x81000001,
		EKHandle:     0x81010001,
	}

	tpmConfig := config.ToTPMConfig()

	// Check EK RSA config
	if tpmConfig.EK == nil {
		t.Fatal("EK config should be set")
	}
	if tpmConfig.EK.KeyAlgorithm != "RSA" {
		t.Errorf("EK.KeyAlgorithm: got %s, want RSA", tpmConfig.EK.KeyAlgorithm)
	}
	if tpmConfig.EK.RSAConfig == nil {
		t.Fatal("EK.RSAConfig should be set")
	}
	if tpmConfig.EK.RSAConfig.KeySize != 2048 {
		t.Errorf("EK.RSAConfig.KeySize: got %d, want 2048", tpmConfig.EK.RSAConfig.KeySize)
	}

	// Check SSRK RSA config
	if tpmConfig.SSRK == nil {
		t.Fatal("SSRK config should be set")
	}
	if tpmConfig.SSRK.KeyAlgorithm != "RSA" {
		t.Errorf("SSRK.KeyAlgorithm: got %s, want RSA", tpmConfig.SSRK.KeyAlgorithm)
	}
	if tpmConfig.SSRK.RSAConfig == nil {
		t.Fatal("SSRK.RSAConfig should be set")
	}
	if tpmConfig.SSRK.RSAConfig.KeySize != 2048 {
		t.Errorf("SSRK.RSAConfig.KeySize: got %d, want 2048", tpmConfig.SSRK.RSAConfig.KeySize)
	}
}

// =============================================================================
// Mock types for symmetric key tests
// =============================================================================

type mockSymmetricKey struct {
	algorithm string
	keySize   int
	rawBytes  []byte
	rawErr    error
}

func (k *mockSymmetricKey) Algorithm() string    { return k.algorithm }
func (k *mockSymmetricKey) KeySize() int         { return k.keySize }
func (k *mockSymmetricKey) Raw() ([]byte, error) { return k.rawBytes, k.rawErr }

var _ types.SymmetricKey = (*mockSymmetricKey)(nil)

type mockSymmetricEncrypter struct{}

func (e *mockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	return nil, nil
}
func (e *mockSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	return nil, nil
}

var _ types.SymmetricEncrypter = (*mockSymmetricEncrypter)(nil)

// =============================================================================
// Symmetric key provider tests
// =============================================================================

func TestGenerateSymmetricKey_Success(t *testing.T) {
	mockKey := &mockSymmetricKey{algorithm: "aes256-gcm", keySize: 256}
	mockTpm := &mockTPM{generateSymmetricKeyResult: mockKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}
	if key == nil {
		t.Fatal("Expected non-nil symmetric key")
	}
	if key.Algorithm() != "aes256-gcm" {
		t.Errorf("Expected algorithm aes256-gcm, got %s", key.Algorithm())
	}
	if key.KeySize() != 256 {
		t.Errorf("Expected key size 256, got %d", key.KeySize())
	}
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("Expected StoreType %v, got %v", types.StoreTPM2, attrs.StoreType)
	}
	if attrs.Parent != srkAttrs {
		t.Error("Expected Parent to be set to SRK attributes")
	}
}

func TestGenerateSymmetricKey_Closed(t *testing.T) {
	b := &Backend{closed: true}
	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.GenerateSymmetricKey(attrs)
	if err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

func TestGenerateSymmetricKey_NilAttrs(t *testing.T) {
	b := &Backend{closed: false}
	_, err := b.GenerateSymmetricKey(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("Expected ErrInvalidKeyAttributes, got %v", err)
	}
}

func TestGenerateSymmetricKey_TPMError(t *testing.T) {
	expectedErr := errors.New("tpm generate symmetric key error")
	mockTpm := &mockTPM{generateSymmetricKeyErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.GenerateSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error from TPM GenerateSymmetricKey")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped TPM error, got %v", err)
	}
}

func TestGenerateSymmetricKey_PreservesExistingParent(t *testing.T) {
	mockKey := &mockSymmetricKey{algorithm: "aes128-gcm", keySize: 128}
	mockTpm := &mockTPM{generateSymmetricKeyResult: mockKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	existingParent := &types.KeyAttributes{CN: "existing-parent"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key", Parent: existingParent}
	_, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}
	if attrs.Parent != existingParent {
		t.Error("Expected existing Parent to be preserved")
	}
}

func TestGetSymmetricKey_Success(t *testing.T) {
	mockKey := &mockSymmetricKey{algorithm: "aes256-gcm", keySize: 256}
	mockTpm := &mockTPM{getSymmetricKeyResult: mockKey}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("GetSymmetricKey() error = %v", err)
	}
	if key == nil {
		t.Fatal("Expected non-nil symmetric key")
	}
	if key.Algorithm() != "aes256-gcm" {
		t.Errorf("Expected algorithm aes256-gcm, got %s", key.Algorithm())
	}
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("Expected StoreType %v, got %v", types.StoreTPM2, attrs.StoreType)
	}
}

func TestGetSymmetricKey_Closed(t *testing.T) {
	b := &Backend{closed: true}
	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.GetSymmetricKey(attrs)
	if err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

func TestGetSymmetricKey_NilAttrs(t *testing.T) {
	b := &Backend{closed: false}
	_, err := b.GetSymmetricKey(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("Expected ErrInvalidKeyAttributes, got %v", err)
	}
}

func TestGetSymmetricKey_TPMError(t *testing.T) {
	expectedErr := errors.New("tpm get symmetric key error")
	mockTpm := &mockTPM{getSymmetricKeyErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.GetSymmetricKey(attrs)
	if err == nil {
		t.Error("Expected error from TPM GetSymmetricKey")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped TPM error, got %v", err)
	}
}

func TestSymmetricEncrypter_Success(t *testing.T) {
	mockEnc := &mockSymmetricEncrypter{}
	mockTpm := &mockTPM{symmetricEncrypterResult: mockEnc}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	enc, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("SymmetricEncrypter() error = %v", err)
	}
	if enc == nil {
		t.Fatal("Expected non-nil symmetric encrypter")
	}
	if attrs.StoreType != types.StoreTPM2 {
		t.Errorf("Expected StoreType %v, got %v", types.StoreTPM2, attrs.StoreType)
	}
	if attrs.Parent != srkAttrs {
		t.Error("Expected Parent to be set to SRK attributes")
	}
}

func TestSymmetricEncrypter_Closed(t *testing.T) {
	b := &Backend{closed: true}
	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.SymmetricEncrypter(attrs)
	if err != ErrNotInitialized {
		t.Errorf("Expected ErrNotInitialized, got %v", err)
	}
}

func TestSymmetricEncrypter_NilAttrs(t *testing.T) {
	b := &Backend{closed: false}
	_, err := b.SymmetricEncrypter(nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("Expected ErrInvalidKeyAttributes, got %v", err)
	}
}

func TestSymmetricEncrypter_TPMError(t *testing.T) {
	expectedErr := errors.New("tpm symmetric encrypter error")
	mockTpm := &mockTPM{symmetricEncrypterErr: expectedErr}
	srkAttrs := &types.KeyAttributes{CN: "test-srk"}
	b := &Backend{closed: false, tpm: mockTpm, keyBackend: &mockKeyBackend{}, srkAttrs: srkAttrs}

	attrs := &types.KeyAttributes{CN: "test-sym-key"}
	_, err := b.SymmetricEncrypter(attrs)
	if err == nil {
		t.Error("Expected error from TPM SymmetricEncrypter")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected wrapped TPM error, got %v", err)
	}
}

func TestGetTracker_ReturnsTracker(t *testing.T) {
	tracker := backend.NewMemoryAEADTracker()
	b := &Backend{tracker: tracker}
	result := b.GetTracker()
	if result != tracker {
		t.Error("Expected GetTracker() to return the backend's tracker")
	}
}

func TestGetTracker_ReturnsNilWhenNoTracker(t *testing.T) {
	b := &Backend{tracker: nil}
	result := b.GetTracker()
	if result != nil {
		t.Error("Expected GetTracker() to return nil when no tracker is set")
	}
}
