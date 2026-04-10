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

package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// allPanicTPM implements tpm2pkg.TrustedPlatformModule and panics on every
// method call. Used to trigger defer/recover blocks in TPMService and
// PlatformPolicyService methods.
// ---------------------------------------------------------------------------

type allPanicTPM struct{}

func (m *allPanicTPM) ActivateCredential(_, _ []byte) ([]byte, error) {
	panic("allPanicTPM: ActivateCredential")
}
func (m *allPanicTPM) AKProfile() (tpm2pkg.AKProfile, error) {
	panic("allPanicTPM: AKProfile")
}
func (m *allPanicTPM) AlgID() tpm2.TPMAlgID { panic("allPanicTPM: AlgID") }
func (m *allPanicTPM) CalculateName(_ tpm2.TPMAlgID, _ []byte) {
	panic("allPanicTPM: CalculateName")
}
func (m *allPanicTPM) Clear(_ []byte) error    { panic("allPanicTPM: Clear") }
func (m *allPanicTPM) ForceClear() error       { panic("allPanicTPM: ForceClear") }
func (m *allPanicTPM) Close() error            { panic("allPanicTPM: Close") }
func (m *allPanicTPM) Config() *tpm2pkg.Config { panic("allPanicTPM: Config") }
func (m *allPanicTPM) CreateECDSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*ecdsa.PublicKey, error) {
	panic("allPanicTPM: CreateECDSA")
}
func (m *allPanicTPM) CreateEK(_ *types.KeyAttributes) error { panic("allPanicTPM: CreateEK") }
func (m *allPanicTPM) CreateSecretKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	panic("allPanicTPM: CreateSecretKey")
}
func (m *allPanicTPM) CreateIAK(_ *types.KeyAttributes, _ []byte) (*types.KeyAttributes, error) {
	panic("allPanicTPM: CreateIAK")
}
func (m *allPanicTPM) CreateIDevID(_ *types.KeyAttributes, _ *x509.Certificate, _ []byte) (*types.KeyAttributes, *tpm2pkg.TCG_CSR_IDEVID, error) {
	panic("allPanicTPM: CreateIDevID")
}
func (m *allPanicTPM) CreatePlatformPolicy() error { panic("allPanicTPM: CreatePlatformPolicy") }
func (m *allPanicTPM) CreateRSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*rsa.PublicKey, error) {
	panic("allPanicTPM: CreateRSA")
}
func (m *allPanicTPM) CreateKeySession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: CreateKeySession")
}
func (m *allPanicTPM) CreateSession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: CreateSession")
}
func (m *allPanicTPM) CreateSRK(_ *types.KeyAttributes) error { panic("allPanicTPM: CreateSRK") }
func (m *allPanicTPM) CreateTCG_CSR_IDEVID(_ *x509.Certificate, _, _ *types.KeyAttributes) (tpm2pkg.TCG_CSR_IDEVID, error) {
	panic("allPanicTPM: CreateTCG_CSR_IDEVID")
}
func (m *allPanicTPM) DeleteKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	panic("allPanicTPM: DeleteKey")
}
func (m *allPanicTPM) Device() string                { panic("allPanicTPM: Device") }
func (m *allPanicTPM) EK() (crypto.PublicKey, error) { panic("allPanicTPM: EK") }
func (m *allPanicTPM) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("allPanicTPM: EKPublic")
}
func (m *allPanicTPM) EKAttributes() (*types.KeyAttributes, error) {
	panic("allPanicTPM: EKAttributes")
}
func (m *allPanicTPM) EKCertificate() (*x509.Certificate, error) {
	panic("allPanicTPM: EKCertificate")
}
func (m *allPanicTPM) EKCertificateRSA() (*x509.Certificate, error) {
	panic("allPanicTPM: EKCertificateRSA")
}
func (m *allPanicTPM) EKCertificateEC() (*x509.Certificate, error) {
	panic("allPanicTPM: EKCertificateEC")
}
func (m *allPanicTPM) EKECC() (*ecdsa.PublicKey, error) { panic("allPanicTPM: EKECC") }
func (m *allPanicTPM) EKRSA() (*rsa.PublicKey, error)   { panic("allPanicTPM: EKRSA") }
func (m *allPanicTPM) EventLog() ([]byte, error)        { panic("allPanicTPM: EventLog") }
func (m *allPanicTPM) FixedProperties() (*tpm2pkg.PropertiesFixed, error) {
	panic("allPanicTPM: FixedProperties")
}
func (m *allPanicTPM) Flush(_ tpm2.TPMHandle)              { panic("allPanicTPM: Flush") }
func (m *allPanicTPM) GoldenMeasurements() ([]byte, error) { panic("allPanicTPM: GoldenMeasurements") }
func (m *allPanicTPM) HMAC(_ []byte) tpm2.Session          { panic("allPanicTPM: HMAC") }
func (m *allPanicTPM) HMACSaltedSession(_ tpm2.TPMHandle, _ tpm2.TPMTPublic, _ []byte) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: HMACSaltedSession")
}
func (m *allPanicTPM) HMACSession(_ []byte) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: HMACSession")
}
func (m *allPanicTPM) IAK() (crypto.PublicKey, error) { panic("allPanicTPM: IAK") }
func (m *allPanicTPM) IAKAttributes() (*types.KeyAttributes, error) {
	panic("allPanicTPM: IAKAttributes")
}
func (m *allPanicTPM) IDevID() (crypto.PublicKey, error) { panic("allPanicTPM: IDevID") }
func (m *allPanicTPM) IDevIDAttributes() (*types.KeyAttributes, error) {
	panic("allPanicTPM: IDevIDAttributes")
}
func (m *allPanicTPM) Info() (string, error)      { panic("allPanicTPM: Info") }
func (m *allPanicTPM) IsFIPS140_2() (bool, error) { panic("allPanicTPM: IsFIPS140_2") }
func (m *allPanicTPM) IsPlatformPCRExtended() (bool, error) {
	panic("allPanicTPM: IsPlatformPCRExtended")
}
func (m *allPanicTPM) ExtendPCR(_ int, _ string, _ []byte) error {
	panic("allPanicTPM: ExtendPCR")
}
func (m *allPanicTPM) Install(_ types.Password, _ *tpm2pkg.InstallOptions) error {
	panic("allPanicTPM: Install")
}
func (m *allPanicTPM) KeyAttributes(_ tpm2.TPMHandle) (*types.KeyAttributes, error) {
	panic("allPanicTPM: KeyAttributes")
}
func (m *allPanicTPM) LoadKeyPair(_ *types.KeyAttributes, _ *tpm2.Session, _ store.KeyBackend) (*tpm2.LoadResponse, error) {
	panic("allPanicTPM: LoadKeyPair")
}
func (m *allPanicTPM) MakeCredential(_ tpm2.TPM2BName, _ []byte) ([]byte, []byte, []byte, error) {
	panic("allPanicTPM: MakeCredential")
}
func (m *allPanicTPM) MakeCredentialWithExternalEK(_ *x509.Certificate, _, _ []byte) ([]byte, []byte, []byte, error) {
	panic("allPanicTPM: MakeCredentialWithExternalEK")
}
func (m *allPanicTPM) NonceSession(_ types.Password) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: NonceSession")
}
func (m *allPanicTPM) NVRead(_ *types.KeyAttributes, _ uint16) ([]byte, error) {
	panic("allPanicTPM: NVRead")
}
func (m *allPanicTPM) NVWrite(_ *types.KeyAttributes) error { panic("allPanicTPM: NVWrite") }
func (m *allPanicTPM) NVDefineCounter(_ *types.KeyAttributes) error {
	panic("allPanicTPM: NVDefineCounter")
}
func (m *allPanicTPM) NVDefineExtend(_ *types.KeyAttributes) error {
	panic("allPanicTPM: NVDefineExtend")
}
func (m *allPanicTPM) NVIncrement(_ *types.KeyAttributes) (uint64, error) {
	panic("allPanicTPM: NVIncrement")
}
func (m *allPanicTPM) NVExtend(_ *types.KeyAttributes, _ []byte) error {
	panic("allPanicTPM: NVExtend")
}
func (m *allPanicTPM) NVReadCounter(_ *types.KeyAttributes) (uint64, error) {
	panic("allPanicTPM: NVReadCounter")
}
func (m *allPanicTPM) NVReadExtend(_ *types.KeyAttributes) ([]byte, error) {
	panic("allPanicTPM: NVReadExtend")
}
func (m *allPanicTPM) NVUndefine(_ *types.KeyAttributes) error { panic("allPanicTPM: NVUndefine") }
func (m *allPanicTPM) Open() error                             { panic("allPanicTPM: Open") }
func (m *allPanicTPM) ParseEKCertificate(_ []byte) (*x509.Certificate, error) {
	panic("allPanicTPM: ParseEKCertificate")
}
func (m *allPanicTPM) ParsedEventLog() ([]tpm2pkg.Event, error) {
	panic("allPanicTPM: ParsedEventLog")
}
func (m *allPanicTPM) ParsePublicKey(_ []byte) (crypto.PublicKey, error) {
	panic("allPanicTPM: ParsePublicKey")
}
func (m *allPanicTPM) PlatformPolicyDigestHash() ([]byte, error) {
	panic("allPanicTPM: PlatformPolicyDigestHash")
}
func (m *allPanicTPM) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {
	panic("allPanicTPM: PlatformPolicyDigest")
}
func (m *allPanicTPM) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	panic("allPanicTPM: PlatformPolicySession")
}
func (m *allPanicTPM) PlatformQuote(_ *types.KeyAttributes) (tpm2pkg.Quote, []byte, error) {
	panic("allPanicTPM: PlatformQuote")
}
func (m *allPanicTPM) Provision(_ types.Password) error { panic("allPanicTPM: Provision") }
func (m *allPanicTPM) ProvisionEKCert(_, _ []byte) error {
	panic("allPanicTPM: ProvisionEKCert")
}
func (m *allPanicTPM) ProvisionOwner(_ types.Password) (*types.KeyAttributes, error) {
	panic("allPanicTPM: ProvisionOwner")
}
func (m *allPanicTPM) Quote(_ []uint, _ []byte) (tpm2pkg.Quote, error) {
	panic("allPanicTPM: Quote")
}
func (m *allPanicTPM) CertifyKey(_ *types.KeyAttributes, _ []byte, _ store.KeyBackend) (*tpm2pkg.CertifyResult, error) {
	panic("allPanicTPM: CertifyKey")
}
func (m *allPanicTPM) Random() ([]byte, error)           { panic("allPanicTPM: Random") }
func (m *allPanicTPM) RandomBytes(_ int) ([]byte, error) { panic("allPanicTPM: RandomBytes") }
func (m *allPanicTPM) RandomHex(_ int) ([]byte, error)   { panic("allPanicTPM: RandomHex") }
func (m *allPanicTPM) RandomSource() io.Reader           { panic("allPanicTPM: RandomSource") }
func (m *allPanicTPM) Read(_ []byte) (int, error)        { panic("allPanicTPM: Read") }
func (m *allPanicTPM) ReadHandle(_ tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("allPanicTPM: ReadHandle")
}
func (m *allPanicTPM) ReadPCRs(_ []uint) ([]tpm2pkg.PCRBank, error) {
	panic("allPanicTPM: ReadPCRs")
}
func (m *allPanicTPM) RSADecrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	panic("allPanicTPM: RSADecrypt")
}
func (m *allPanicTPM) RSAEncrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	panic("allPanicTPM: RSAEncrypt")
}
func (m *allPanicTPM) SaveKeyPair(_ *types.KeyAttributes, _ tpm2.TPM2BPrivate, _ tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], _ store.KeyBackend, _ bool) error {
	panic("allPanicTPM: SaveKeyPair")
}
func (m *allPanicTPM) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	panic("allPanicTPM: Seal")
}
func (m *allPanicTPM) SealKey(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*tpm2.CreateResponse, error) {
	panic("allPanicTPM: SealKey")
}
func (m *allPanicTPM) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	panic("allPanicTPM: Sign")
}
func (m *allPanicTPM) SetHierarchyAuth(_, _ types.Password, _ *tpm2.TPMHandle) error {
	panic("allPanicTPM: SetHierarchyAuth")
}
func (m *allPanicTPM) SecretFromShares(_ []string) (string, error) {
	panic("allPanicTPM: SecretFromShares")
}
func (m *allPanicTPM) ShareSecret(_ []byte, _ int) ([]string, error) {
	panic("allPanicTPM: ShareSecret")
}
func (m *allPanicTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("allPanicTPM: SRKPublic")
}
func (m *allPanicTPM) SSRKAttributes() (*types.KeyAttributes, error) {
	panic("allPanicTPM: SSRKAttributes")
}
func (m *allPanicTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) {
	panic("allPanicTPM: PlatformSRKAttributes")
}
func (m *allPanicTPM) SSRK() *tpm2pkg.SRKConfig { panic("allPanicTPM: SSRK") }
func (m *allPanicTPM) PlatformKeyStore() tpm2pkg.PlatformKeyStorer {
	panic("allPanicTPM: PlatformKeyStore")
}
func (m *allPanicTPM) SupportedAlgorithms() ([]string, error) {
	panic("allPanicTPM: SupportedAlgorithms")
}
func (m *allPanicTPM) SupportedCommands() ([]string, error) { panic("allPanicTPM: SupportedCommands") }
func (m *allPanicTPM) SupportedECCCurves() ([]string, error) {
	panic("allPanicTPM: SupportedECCCurves")
}
func (m *allPanicTPM) Transport() transport.TPM { panic("allPanicTPM: Transport") }
func (m *allPanicTPM) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	panic("allPanicTPM: Unseal")
}
func (m *allPanicTPM) UnsealKey(_ *types.KeyAttributes, _ store.KeyBackend) ([]byte, error) {
	panic("allPanicTPM: UnsealKey")
}
func (m *allPanicTPM) CanSeal() bool              { panic("allPanicTPM: CanSeal") }
func (m *allPanicTPM) WriteEKCert(_ []byte) error { panic("allPanicTPM: WriteEKCert") }
func (m *allPanicTPM) IDevIDCertificate() (*x509.Certificate, error) {
	panic("allPanicTPM: IDevIDCertificate")
}
func (m *allPanicTPM) ProvisionIDevIDCert(_ *x509.Certificate) error {
	panic("allPanicTPM: ProvisionIDevIDCert")
}
func (m *allPanicTPM) DeleteIDevIDCertificate() error { panic("allPanicTPM: DeleteIDevIDCertificate") }
func (m *allPanicTPM) IAKCertificate() (*x509.Certificate, error) {
	panic("allPanicTPM: IAKCertificate")
}
func (m *allPanicTPM) ProvisionIAKCert(_ *x509.Certificate) error {
	panic("allPanicTPM: ProvisionIAKCert")
}
func (m *allPanicTPM) DeleteIAKCertificate() error { panic("allPanicTPM: DeleteIAKCertificate") }
func (m *allPanicTPM) VerifyTCGCSR(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("allPanicTPM: VerifyTCGCSR")
}
func (m *allPanicTPM) VerifyTCG_CSR_IAK(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("allPanicTPM: VerifyTCG_CSR_IAK")
}
func (m *allPanicTPM) VerifyTCG_CSR_IDevID(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("allPanicTPM: VerifyTCG_CSR_IDevID")
}
func (m *allPanicTPM) FactoryReset(_ []byte) error { panic("allPanicTPM: FactoryReset") }
func (m *allPanicTPM) FactoryResetWithClear(_ []byte) error {
	panic("allPanicTPM: FactoryResetWithClear")
}
func (m *allPanicTPM) DictionaryAttackLockoutReset(_ []byte) error {
	panic("allPanicTPM: DictionaryAttackLockoutReset")
}
func (m *allPanicTPM) SignValidate(_ *types.KeyAttributes, _, _ []byte) ([]byte, error) {
	panic("allPanicTPM: SignValidate")
}
func (m *allPanicTPM) HashSequence(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("allPanicTPM: HashSequence")
}
func (m *allPanicTPM) Hash(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("allPanicTPM: Hash")
}
func (m *allPanicTPM) ECDHZGen(_ *types.KeyAttributes, _ *tpm2.TPMSECCPoint, _ store.KeyBackend) ([]byte, error) {
	panic("allPanicTPM: ECDHZGen")
}
func (m *allPanicTPM) SSRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("allPanicTPM: SSRKPublic")
}
func (m *allPanicTPM) GenerateSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	panic("allPanicTPM: GenerateSymmetricKey")
}
func (m *allPanicTPM) GetSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	panic("allPanicTPM: GetSymmetricKey")
}
func (m *allPanicTPM) SymmetricEncrypter(_ *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	panic("allPanicTPM: SymmetricEncrypter")
}

func (m *allPanicTPM) VerifyAuth(_ tpm2.TPMHandle, _ []byte) error { panic("allPanicTPM: VerifyAuth") }
func (m *allPanicTPM) ChangeAuth(_ tpm2.TPMHandle, _, _ []byte) error {
	panic("allPanicTPM: ChangeAuth")
}

// compile-time check
var _ tpm2pkg.TrustedPlatformModule = (*allPanicTPM)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// panicTPMService creates a TPMService wired to the allPanicTPM mock.
func panicTPMService(t *testing.T) *TPMService {
	t.Helper()
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &allPanicTPM{}
	}))
	return svc
}

// panicTPMServiceWithSafeMock creates a TPMService with the safe defaultMockTPM
// for setup operations that must not panic (e.g. creating policies on disk).
func panicTPMServiceWithSafeMock(t *testing.T) *TPMService {
	t.Helper()
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return defaultMockTPM()
	}))
	return svc
}

// switchToPanicTPM replaces the service's TPM accessor with the allPanicTPM mock.
func switchToPanicTPM(svc *TPMService) {
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &allPanicTPM{}
	}))
}

// panicPlatformPolicyService creates a PlatformPolicyService wired to the
// allPanicTPM mock with a stored policy definition so methods don't early-return.
func panicPlatformPolicyService(t *testing.T) *PlatformPolicyService {
	t.Helper()
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		return &allPanicTPM{}
	}))
	svc.policy.Store(&PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa", 7: "bb"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	return svc
}

// panicTestCertPEM returns a valid self-signed PEM certificate for tests
// that require valid PEM to reach the TPM code path.
func panicTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "panic-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}

// assertPanicRecovered asserts that the error is non-nil and contains "panic".
func assertPanicRecovered(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err, "expected a panic-recovered error but got nil")
	assert.Contains(t, err.Error(), "panic")
}

// =========================================================================
// TPMService panic recovery tests
// =========================================================================

func TestPanic_TPMService_GetStatus(t *testing.T) {
	svc := panicTPMService(t)
	status, err := svc.GetStatus()
	// GetStatus catches panics and returns a safe status.
	assert.NoError(t, err)
	assert.NotNil(t, status)
}

func TestPanic_TPMService_GetInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetInfo()
	// GetInfo catches panics and returns empty info.
	assert.NoError(t, err)
	assert.NotNil(t, info)
}

func TestPanic_TPMService_GetEKInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetEKInfo()
	// GetEKInfo catches panics and returns safe default.
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestPanic_TPMService_GetEKECCInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetEKECCInfo()
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestPanic_TPMService_GetIAKInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetIAKInfo()
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestPanic_TPMService_GetIDevIDInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetIDevIDInfo()
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.False(t, info.Present)
}

func TestPanic_TPMService_GetSharedSRKInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetSharedSRKInfo()
	assert.NoError(t, err)
	assert.NotNil(t, info)
}

func TestPanic_TPMService_GetPlatformSRKInfo(t *testing.T) {
	svc := panicTPMService(t)
	info, err := svc.GetPlatformSRKInfo()
	assert.NoError(t, err)
	assert.NotNil(t, info)
}

func TestPanic_TPMService_GetPCRs(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetPCRs("sha256")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_Provision(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.Provision(&ProvisionOptions{Mode: "install"})
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_Install(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.Install("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_InitializePlatformKeyStore(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.InitializePlatformKeyStore("so", "user")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_InitializePlatformKeyStoreWithDefaults(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_FactoryReset(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.FactoryReset("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ProvisionIAK(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ProvisionIAK("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ProvisionIDevID(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ProvisionIDevID("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GenerateQuote(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GenerateQuote("", []int{0}, "sha256")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetEventLog(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetEventLog()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetRandomBytes(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetRandomBytes(32)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetPlatformPolicy(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetPlatformPolicy()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExportEKCert(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ExportEKCert("pem")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ImportEKCert(t *testing.T) {
	svc := panicTPMService(t)
	certPEM := panicTestCertPEM(t)
	err := svc.ImportEKCert(certPEM)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExportEKECCCert(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ExportEKECCCert("pem")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ImportEKECCCert(t *testing.T) {
	svc := panicTPMService(t)
	certPEM := panicTestCertPEM(t)
	err := svc.ImportEKECCCert(certPEM)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExportIAKCert(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ExportIAKCert("pem")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ImportIAKCert(t *testing.T) {
	svc := panicTPMService(t)
	certPEM := panicTestCertPEM(t)
	err := svc.ImportIAKCert(certPEM)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExportIDevIDCert(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ExportIDevIDCert("pem")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ImportIDevIDCert(t *testing.T) {
	svc := panicTPMService(t)
	certPEM := panicTestCertPEM(t)
	err := svc.ImportIDevIDCert(certPEM)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ListPersistentHandles(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ListPersistentHandles()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ListTransientHandles(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ListTransientHandles()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetLockoutInfo(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetLockoutInfo()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ResetLockout(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ResetLockout("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ForceResetLockout(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ForceResetLockout("auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_CertifyKey(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.CertifyKey("0x81000001")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ViewKey_EK(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ViewKey("EK")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GenerateIDevIDCSR(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GenerateIDevIDCSR()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ChangeOwnerAuth(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ChangeOwnerAuth("old", "new")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ChangeEndorsementAuth(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ChangeEndorsementAuth("old", "new")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ChangeLockoutAuth(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ChangeLockoutAuth("old", "new")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetNVSummary(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetNVSummary()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_DefineNVOrdinary(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.DefineNVOrdinary(0x01500001, 32, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_DefineNVCounter(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.DefineNVCounter(0x01500002, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_DefineNVExtend(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.DefineNVExtend(0x01500003, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ReadNVData(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ReadNVData(0x01500001, 32, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_WriteNVData(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.WriteNVData(0x01500001, "aabb", "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_IncrementNVCounter(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.IncrementNVCounter(0x01500002, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ReadNVCounter(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ReadNVCounter(0x01500002, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExtendNV(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.ExtendNV(0x01500003, "aabb", "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ReadNVExtend(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ReadNVExtend(0x01500003, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_DeleteNVIndex(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.DeleteNVIndex(0x01500001, "auth")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ImportManufacturerCA(t *testing.T) {
	svc := panicTPMService(t)
	certPEM := panicTestCertPEM(t)
	err := svc.ImportManufacturerCA(certPEM)
	// ImportManufacturerCA does not call getTPM. It parses the cert,
	// appends to mfgCACerts, and checks trustStore (nil, so skipped).
	// No panic occurs -- the defer/recover block is purely defensive.
	assert.NoError(t, err)
}

func TestPanic_TPMService_VerifyTPM(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.VerifyTPM()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_GetVerificationStatus(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.GetVerificationStatus()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_RefreshPolicyPCRs(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "test-policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	// Switch to panic TPM. RefreshPolicyPCRs calls getTPM -> ReadPCRs -> panic.
	switchToPanicTPM(svc)
	_, err := svc.RefreshPolicyPCRs("test-policy")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ExportPolicy(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "export-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
	}))
	// ExportPolicy is file-only, should succeed even with panic TPM.
	switchToPanicTPM(svc)
	val, err := svc.ExportPolicy("export-test")
	assert.NoError(t, err)
	assert.NotEmpty(t, val)
}

func TestPanic_TPMService_ExportCompositePolicy(t *testing.T) {
	// Use safe mock for creation so the composite policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-export-test",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))
	// ExportCompositePolicy is file-only, should succeed even with panic TPM.
	switchToPanicTPM(svc)
	val, err := svc.ExportCompositePolicy("comp-export-test")
	assert.NoError(t, err)
	assert.NotEmpty(t, val)
}

func TestPanic_TPMService_CreateCompositePolicy(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "panic-composite",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	})
	// CreateCompositePolicy calls getTPM -> readPCRDigests -> ReadPCRs -> panic.
	// readPCRDigests has no recover, so the panic propagates to
	// CreateCompositePolicy's defer/recover.
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ListCompositePoliciesWithDigests(t *testing.T) {
	// Use safe mock for creation so the composite policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "lcwd-test",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))
	// Switch to panic TPM. ListCompositePoliciesWithDigests calls
	// getTPM -> ReadPCRs -> panic.
	switchToPanicTPM(svc)
	_, err := svc.ListCompositePoliciesWithDigests()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_RefreshCompositePolicyPCRs(t *testing.T) {
	// Use safe mock for creation so the composite policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "refresh-comp-test",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}},
		},
	}))
	// Switch to panic TPM.
	switchToPanicTPM(svc)
	_, err := svc.RefreshCompositePolicyPCRs("refresh-comp-test")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ListPoliciesWithDigests(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "lpwd-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	// Switch to panic TPM.
	switchToPanicTPM(svc)
	_, err := svc.ListPoliciesWithDigests()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ComparePolicyPCRs(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk with digests.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "compare-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
	}))
	// Switch to panic TPM.
	switchToPanicTPM(svc)
	_, err := svc.ComparePolicyPCRs("compare-test")
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_ReplayEventLog(t *testing.T) {
	svc := panicTPMService(t)
	_, err := svc.ReplayEventLog()
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_VerifyPolicyPassword(t *testing.T) {
	// Use safe mock for creation so the password policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePasswordPolicy("pw-test", "desc", "secret123", false))
	// VerifyPolicyPassword is file-only (no TPM), so won't panic.
	valid, err := svc.VerifyPolicyPassword("pw-test", "secret123")
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestPanic_TPMService_CreatePasswordPolicy(t *testing.T) {
	svc := panicTPMService(t)
	// CreatePasswordPolicy calls CreateCompositePolicy which doesn't have
	// PCR elements, so getTPM is never called. No panic expected.
	err := svc.CreatePasswordPolicy("pw-panic", "desc", "secret123", false)
	assert.NoError(t, err)
}

func TestPanic_TPMService_CreatePCROrPasswordPolicy(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.CreatePCROrPasswordPolicy(
		"pcr-or-pw-panic", "desc",
		[]PCRSelection{{Index: 0, Bank: "sha256"}},
		"sha256", "secret123", false,
	)
	// This creates a composite with PCR elements, which calls getTPM +
	// ReadPCRs during creation -> panic.
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_CreatePCRAndPasswordPolicy(t *testing.T) {
	svc := panicTPMService(t)
	err := svc.CreatePCRAndPasswordPolicy(
		"pcr-and-pw-panic", "desc",
		[]PCRSelection{{Index: 0, Bank: "sha256"}},
		"sha256", "secret123", false,
	)
	assertPanicRecovered(t, err)
}

func TestPanic_TPMService_AssignPolicyToKeys(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{Name: "assign-test"}))
	// AssignPolicyToKeys is file-only, no panic expected.
	err := svc.AssignPolicyToKeys("assign-test", []string{"0x81000001"})
	assert.NoError(t, err)
}

func TestPanic_TPMService_UpdatePolicy(t *testing.T) {
	// Use safe mock for creation so the policy is saved to disk.
	svc := panicTPMServiceWithSafeMock(t)
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "update-panic-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	// Switch to panic TPM.
	switchToPanicTPM(svc)
	_, err := svc.UpdatePolicy("update-panic-test", &PCRPolicy{
		Name:          "update-panic-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	})
	assertPanicRecovered(t, err)
}

// =========================================================================
// PlatformPolicyService panic recovery tests
// =========================================================================

func TestPanic_PlatformPolicy_GetStatus(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	// GetStatus calls verifyDigests -> readPCRDigests -> ReadPCRs -> panic.
	// verifyDigests has its own defer/recover, so the panic is caught there.
	// GetStatus discards the error from verifyDigests.
	status, err := svc.GetStatus()
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.True(t, status.Configured)
}

func TestPanic_PlatformPolicy_CreatePolicy(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	status, err := svc.CreatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assertPanicRecovered(t, err)
}

func TestPanic_PlatformPolicy_UpdatePolicy(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	status, err := svc.UpdatePolicy([]int{0}, "sha256")
	assert.Nil(t, status)
	assertPanicRecovered(t, err)
}

func TestPanic_PlatformPolicy_VerifyPolicy(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	valid, err := svc.VerifyPolicy()
	assert.False(t, valid)
	assertPanicRecovered(t, err)
}

func TestPanic_PlatformPolicy_ExportPolicy(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	// ExportPolicy is file-only (reads from stored policy definition), no TPM.
	val, err := svc.ExportPolicy()
	assert.NoError(t, err)
	assert.NotEmpty(t, val)
}

func TestPanic_PlatformPolicy_GetPlatformPolicyAsPCRPolicy(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	// This calls validatePlatformPolicyDigests -> verifyDigests ->
	// readPCRDigests -> ReadPCRs -> panic. The panic is caught in
	// verifyDigests's own defer/recover. GetPlatformPolicyAsPCRPolicy
	// gets nil from validatePlatformPolicyDigests.
	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	assert.NoError(t, err)
	assert.NotNil(t, policy)
}

func TestPanic_PlatformPolicy_RefreshPlatformPolicyPCRs(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	_, err := svc.RefreshPlatformPolicyPCRs()
	assertPanicRecovered(t, err)
}

func TestPanic_PlatformPolicy_ReadPCRDigests(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	// readPCRDigests is a private method with its own defer/recover.
	digests, err := svc.readPCRDigests([]int{0}, "sha256")
	assert.Nil(t, digests)
	assertPanicRecovered(t, err)
}

func TestPanic_PlatformPolicy_VerifyDigests(t *testing.T) {
	svc := panicPlatformPolicyService(t)
	// verifyDigests is a private method with its own defer/recover.
	def := svc.policy.Load()
	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assertPanicRecovered(t, err)
}
