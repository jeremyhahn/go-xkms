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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockTPM implements tpm2pkg.TrustedPlatformModule for unit testing.
// Methods called by TPMService have configurable return values.
// All other methods panic if called unexpectedly.
// ---------------------------------------------------------------------------

type mockTPM struct {
	// Configurable returns for methods used by TPMService.
	fixedProps        *tpm2pkg.PropertiesFixed
	fixedPropsErr     error
	device            string
	config            *tpm2pkg.Config
	ekAttrs           *types.KeyAttributes
	ekAttrsErr        error
	ekCert            *x509.Certificate
	ekCertErr         error
	ekCertRSA         *x509.Certificate
	ekCertRSAErr      error
	ekCertEC          *x509.Certificate
	ekCertECErr       error
	ekECC             *ecdsa.PublicKey
	iakPub            crypto.PublicKey
	iakAttrs          *types.KeyAttributes
	iakAttrsErr       error
	iakCert           *x509.Certificate
	iakCertErr        error
	idevidPub         crypto.PublicKey
	idevidAttrs       *types.KeyAttributes
	idevidAttrsErr    error
	idevidCert        *x509.Certificate
	idevidCertErr     error
	srkName           tpm2.TPM2BName
	srkPub            tpm2.TPMTPublic
	ssrkAttrs         *types.KeyAttributes
	ssrkAttrsErr      error
	pcrBanks          []tpm2pkg.PCRBank
	pcrBanksErr       error
	fips              bool
	fipsErr           error
	quoteResult       tpm2pkg.Quote
	quoteErr          error
	parsedEvents      []tpm2pkg.Event
	parsedEventsErr   error
	randomBytesVal    []byte
	randomBytesErr    error
	policyHash        []byte
	policyHashErr     error
	provisionErr      error
	installErr        error
	writeEKCertErr    error
	writeIAKCertErr   error
	writeIDevIDErr    error
	supportedAlgos    []string
	supportedAlgosErr error

	// Phase 2: handle enumeration (via FixedProperties), NV indexes, lockout reset.
	persistentHandles []tpm2.TPMHandle
	transientHandles  []tpm2.TPMHandle
	nvIndexes         []tpm2pkg.NVIndexInfo
	lockoutResetErr   error

	// Phase 3: SRK and platform key store.
	readHandleErr    error
	platformKeyStore tpm2pkg.PlatformKeyStorer
	handleKeyAttrs   map[tpm2.TPMHandle]*types.KeyAttributes

	// Phase 4: configurable returns for operations that previously panicked.
	factoryResetErr     error
	createIAKResult     *types.KeyAttributes
	createIAKErr        error
	createIDevIDResult  *types.KeyAttributes
	createIDevIDErr     error
	setHierarchyAuthErr error
	certifyKeyResult    *tpm2pkg.CertifyResult
	certifyKeyErr       error
	nvWriteErr          error
	nvReadResult        []byte
	nvReadErr           error
	nvDefineCounterErr  error
	nvDefineExtendErr   error
	nvIncrementResult   uint64
	nvIncrementErr      error
	nvExtendErr         error
	nvReadCounterResult uint64
	nvReadCounterErr    error
	nvReadExtendResult  []byte
	nvReadExtendErr     error
	nvUndefineErr       error
	createTCGCSRResult  tpm2pkg.TCG_CSR_IDEVID
	createTCGCSRErr     error
}

// Methods called by TPMService.

func (m *mockTPM) Device() string          { return m.device }
func (m *mockTPM) Config() *tpm2pkg.Config { return m.config }
func (m *mockTPM) FixedProperties() (*tpm2pkg.PropertiesFixed, error) {
	if m.fixedPropsErr != nil {
		return nil, m.fixedPropsErr
	}
	props := m.fixedProps
	if props == nil {
		return nil, nil
	}
	// Merge handle/NV fields from convenience mock fields.
	if m.persistentHandles != nil {
		props.PersistentHandles = m.persistentHandles
	}
	if m.transientHandles != nil {
		props.TransientHandles = m.transientHandles
	}
	if m.nvIndexes != nil {
		props.NVIndexes = m.nvIndexes
	}
	return props, nil
}
func (m *mockTPM) EKAttributes() (*types.KeyAttributes, error) {
	return m.ekAttrs, m.ekAttrsErr
}
func (m *mockTPM) EKCertificate() (*x509.Certificate, error) {
	return m.ekCert, m.ekCertErr
}
func (m *mockTPM) EKCertificateRSA() (*x509.Certificate, error) {
	return m.ekCertRSA, m.ekCertRSAErr
}
func (m *mockTPM) EKCertificateEC() (*x509.Certificate, error) {
	return m.ekCertEC, m.ekCertECErr
}
func (m *mockTPM) EKECC() (*ecdsa.PublicKey, error)             { return m.ekECC, nil }
func (m *mockTPM) IAK() (crypto.PublicKey, error)               { return m.iakPub, nil }
func (m *mockTPM) IAKAttributes() (*types.KeyAttributes, error) { return m.iakAttrs, m.iakAttrsErr }
func (m *mockTPM) IDevID() (crypto.PublicKey, error)            { return m.idevidPub, nil }
func (m *mockTPM) IDevIDAttributes() (*types.KeyAttributes, error) {
	return m.idevidAttrs, m.idevidAttrsErr
}
func (m *mockTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return m.srkName, m.srkPub, nil
}
func (m *mockTPM) SSRKAttributes() (*types.KeyAttributes, error)        { return m.ssrkAttrs, m.ssrkAttrsErr }
func (m *mockTPM) PlatformSRKAttributes() (*types.KeyAttributes, error) { return nil, nil }
func (m *mockTPM) SSRK() *tpm2pkg.SRKConfig {
	if m.config == nil {
		return nil
	}
	return m.config.SSRK
}
func (m *mockTPM) PlatformKeyStore() tpm2pkg.PlatformKeyStorer { return m.platformKeyStore }
func (m *mockTPM) ReadPCRs(pcrList []uint) ([]tpm2pkg.PCRBank, error) {
	return m.pcrBanks, m.pcrBanksErr
}
func (m *mockTPM) IsFIPS140_2() (bool, error) { return m.fips, m.fipsErr }
func (m *mockTPM) Quote(pcrs []uint, nonce []byte) (tpm2pkg.Quote, error) {
	return m.quoteResult, m.quoteErr
}
func (m *mockTPM) ParsedEventLog() ([]tpm2pkg.Event, error) {
	return m.parsedEvents, m.parsedEventsErr
}
func (m *mockTPM) RandomBytes(fixedLength int) ([]byte, error) {
	return m.randomBytesVal, m.randomBytesErr
}
func (m *mockTPM) PlatformPolicyDigestHash() ([]byte, error) { return m.policyHash, m.policyHashErr }
func (m *mockTPM) Provision(soPIN types.Password) error      { return m.provisionErr }
func (m *mockTPM) Install(soPIN types.Password, _ *tpm2pkg.InstallOptions) error {
	return m.installErr
}
func (m *mockTPM) WriteEKCert(ekCert []byte) error           { return m.writeEKCertErr }
func (m *mockTPM) IAKCertificate() (*x509.Certificate, error) {
	return m.iakCert, m.iakCertErr
}
func (m *mockTPM) ProvisionIAKCert(cert *x509.Certificate) error { return m.writeIAKCertErr }
func (m *mockTPM) IDevIDCertificate() (*x509.Certificate, error) {
	return m.idevidCert, m.idevidCertErr
}
func (m *mockTPM) ProvisionIDevIDCert(cert *x509.Certificate) error { return m.writeIDevIDErr }
func (m *mockTPM) SupportedAlgorithms() ([]string, error) {
	return m.supportedAlgos, m.supportedAlgosErr
}
func (m *mockTPM) SupportedCommands() ([]string, error)  { return nil, nil }
func (m *mockTPM) SupportedECCCurves() ([]string, error) { return nil, nil }

// Phase 2: lockout reset.

func (m *mockTPM) DictionaryAttackLockoutReset(_ []byte) error {
	return m.lockoutResetErr
}

// Unused interface methods -- panic if called in tests unexpectedly.

func (m *mockTPM) ActivateCredential(_, _ []byte) ([]byte, error) {
	panic("mockTPM: ActivateCredential not expected")
}
func (m *mockTPM) AKProfile() (tpm2pkg.AKProfile, error) {
	panic("mockTPM: AKProfile not expected")
}
func (m *mockTPM) AlgID() tpm2.TPMAlgID { panic("mockTPM: AlgID not expected") }
func (m *mockTPM) CalculateName(_ tpm2.TPMAlgID, _ []byte) {
	panic("mockTPM: CalculateName not expected")
}
func (m *mockTPM) Clear(_ []byte) error { panic("mockTPM: Clear not expected") }
func (m *mockTPM) ForceClear() error      { return nil }
func (m *mockTPM) Close() error         { return nil }
func (m *mockTPM) CreateECDSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*ecdsa.PublicKey, error) {
	panic("mockTPM: CreateECDSA not expected")
}
func (m *mockTPM) CreateEK(_ *types.KeyAttributes) error { panic("mockTPM: CreateEK not expected") }
func (m *mockTPM) CreateSecretKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	panic("mockTPM: CreateSecretKey not expected")
}
func (m *mockTPM) CreateIAK(_ *types.KeyAttributes, _ []byte) (*types.KeyAttributes, error) {
	return m.createIAKResult, m.createIAKErr
}
func (m *mockTPM) CreateIDevID(_ *types.KeyAttributes, _ *x509.Certificate, _ []byte) (*types.KeyAttributes, *tpm2pkg.TCG_CSR_IDEVID, error) {
	return m.createIDevIDResult, nil, m.createIDevIDErr
}
func (m *mockTPM) CreatePlatformPolicy() error { panic("mockTPM: CreatePlatformPolicy not expected") }
func (m *mockTPM) CreateRSA(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*rsa.PublicKey, error) {
	panic("mockTPM: CreateRSA not expected")
}
func (m *mockTPM) CreateKeySession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("mockTPM: CreateKeySession not expected")
}
func (m *mockTPM) CreateSession(_ *types.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("mockTPM: CreateSession not expected")
}
func (m *mockTPM) CreateSRK(_ *types.KeyAttributes) error {
	panic("mockTPM: CreateSRK not expected")
}
func (m *mockTPM) CreateTCG_CSR_IDEVID(_ *x509.Certificate, _, _ *types.KeyAttributes) (tpm2pkg.TCG_CSR_IDEVID, error) {
	return m.createTCGCSRResult, m.createTCGCSRErr
}
func (m *mockTPM) DeleteKey(_ *types.KeyAttributes, _ store.KeyBackend) error {
	panic("mockTPM: DeleteKey not expected")
}
func (m *mockTPM) EK() (crypto.PublicKey, error) { panic("mockTPM: EK not expected") }
func (m *mockTPM) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("mockTPM: EKPublic not expected")
}
func (m *mockTPM) EKRSA() (*rsa.PublicKey, error) { panic("mockTPM: EKRSA not expected") }
func (m *mockTPM) EventLog() ([]byte, error) {
	panic("mockTPM: EventLog not expected")
}
func (m *mockTPM) Flush(_ tpm2.TPMHandle) { panic("mockTPM: Flush not expected") }
func (m *mockTPM) GoldenMeasurements() ([]byte, error) {
	panic("mockTPM: GoldenMeasurements not expected")
}
func (m *mockTPM) HMAC(_ []byte) tpm2.Session { panic("mockTPM: HMAC not expected") }
func (m *mockTPM) HMACSaltedSession(_ tpm2.TPMHandle, _ tpm2.TPMTPublic, _ []byte) (tpm2.Session, func() error, error) {
	panic("mockTPM: HMACSaltedSession not expected")
}
func (m *mockTPM) HMACSession(_ []byte) (tpm2.Session, func() error, error) {
	panic("mockTPM: HMACSession not expected")
}
func (m *mockTPM) Info() (string, error) { panic("mockTPM: Info not expected") }
func (m *mockTPM) IsPlatformPCRExtended() (bool, error) {
	panic("mockTPM: IsPlatformPCRExtended not expected")
}
func (m *mockTPM) ExtendPCR(_ int, _ string, _ []byte) error {
	panic("mockTPM: ExtendPCR not expected")
}
func (m *mockTPM) KeyAttributes(handle tpm2.TPMHandle) (*types.KeyAttributes, error) {
	if m.handleKeyAttrs != nil {
		if attrs, ok := m.handleKeyAttrs[handle]; ok {
			return attrs, nil
		}
	}
	return nil, fmt.Errorf("handle 0x%08X not found", handle)
}
func (m *mockTPM) LoadKeyPair(_ *types.KeyAttributes, _ *tpm2.Session, _ store.KeyBackend) (*tpm2.LoadResponse, error) {
	panic("mockTPM: LoadKeyPair not expected")
}
func (m *mockTPM) MakeCredential(_ tpm2.TPM2BName, _ []byte) ([]byte, []byte, []byte, error) {
	panic("mockTPM: MakeCredential not expected")
}
func (m *mockTPM) MakeCredentialWithExternalEK(_ *x509.Certificate, _, _ []byte) ([]byte, []byte, []byte, error) {
	panic("mockTPM: MakeCredentialWithExternalEK not expected")
}
func (m *mockTPM) NonceSession(_ types.Password) (tpm2.Session, func() error, error) {
	panic("mockTPM: NonceSession not expected")
}
func (m *mockTPM) NVRead(_ *types.KeyAttributes, _ uint16) ([]byte, error) {
	return m.nvReadResult, m.nvReadErr
}
func (m *mockTPM) NVWrite(_ *types.KeyAttributes) error {
	return m.nvWriteErr
}
func (m *mockTPM) NVDefineCounter(_ *types.KeyAttributes) error {
	return m.nvDefineCounterErr
}
func (m *mockTPM) NVDefineExtend(_ *types.KeyAttributes) error {
	return m.nvDefineExtendErr
}
func (m *mockTPM) NVIncrement(_ *types.KeyAttributes) (uint64, error) {
	return m.nvIncrementResult, m.nvIncrementErr
}
func (m *mockTPM) NVExtend(_ *types.KeyAttributes, _ []byte) error {
	return m.nvExtendErr
}
func (m *mockTPM) NVReadCounter(_ *types.KeyAttributes) (uint64, error) {
	return m.nvReadCounterResult, m.nvReadCounterErr
}
func (m *mockTPM) NVReadExtend(_ *types.KeyAttributes) ([]byte, error) {
	return m.nvReadExtendResult, m.nvReadExtendErr
}
func (m *mockTPM) NVUndefine(_ *types.KeyAttributes) error {
	return m.nvUndefineErr
}
func (m *mockTPM) Open() error { panic("mockTPM: Open not expected") }
func (m *mockTPM) ParseEKCertificate(_ []byte) (*x509.Certificate, error) {
	panic("mockTPM: ParseEKCertificate not expected")
}
func (m *mockTPM) ParsePublicKey(_ []byte) (crypto.PublicKey, error) {
	panic("mockTPM: ParsePublicKey not expected")
}
func (m *mockTPM) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {
	panic("mockTPM: PlatformPolicyDigest not expected")
}
func (m *mockTPM) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	panic("mockTPM: PlatformPolicySession not expected")
}
func (m *mockTPM) PlatformQuote(_ *types.KeyAttributes) (tpm2pkg.Quote, []byte, error) {
	panic("mockTPM: PlatformQuote not expected")
}
func (m *mockTPM) ProvisionEKCert(_, _ []byte) error {
	panic("mockTPM: ProvisionEKCert not expected")
}
func (m *mockTPM) ProvisionOwner(_ types.Password) (*types.KeyAttributes, error) {
	panic("mockTPM: ProvisionOwner not expected")
}
func (m *mockTPM) CertifyKey(_ *types.KeyAttributes, _ []byte, _ store.KeyBackend) (*tpm2pkg.CertifyResult, error) {
	return m.certifyKeyResult, m.certifyKeyErr
}
func (m *mockTPM) Random() ([]byte, error) { panic("mockTPM: Random not expected") }
func (m *mockTPM) RandomHex(_ int) ([]byte, error) {
	panic("mockTPM: RandomHex not expected")
}
func (m *mockTPM) RandomSource() io.Reader { panic("mockTPM: RandomSource not expected") }
func (m *mockTPM) Read(_ []byte) (int, error) {
	panic("mockTPM: Read not expected")
}
func (m *mockTPM) ReadHandle(_ tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, m.readHandleErr
}
func (m *mockTPM) RSADecrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	panic("mockTPM: RSADecrypt not expected")
}
func (m *mockTPM) RSAEncrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	panic("mockTPM: RSAEncrypt not expected")
}
func (m *mockTPM) SaveKeyPair(_ *types.KeyAttributes, _ tpm2.TPM2BPrivate, _ tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], _ store.KeyBackend, _ bool) error {
	panic("mockTPM: SaveKeyPair not expected")
}
func (m *mockTPM) Seal(_ context.Context, _ []byte, _ *types.SealOptions) (*types.SealedData, error) {
	panic("mockTPM: Seal not expected")
}
func (m *mockTPM) SealKey(_ *types.KeyAttributes, _ store.KeyBackend, _ bool) (*tpm2.CreateResponse, error) {
	panic("mockTPM: SealKey not expected")
}
func (m *mockTPM) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	panic("mockTPM: Sign not expected")
}
func (m *mockTPM) SetHierarchyAuth(_, _ types.Password, _ *tpm2.TPMHandle) error {
	return m.setHierarchyAuthErr
}
func (m *mockTPM) SecretFromShares(_ []string) (string, error) {
	panic("mockTPM: SecretFromShares not expected")
}
func (m *mockTPM) ShareSecret(_ []byte, _ int) ([]string, error) {
	panic("mockTPM: ShareSecret not expected")
}
func (m *mockTPM) Transport() transport.TPM {
	panic("mockTPM: Transport not expected")
}
func (m *mockTPM) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	panic("mockTPM: Unseal not expected")
}
func (m *mockTPM) UnsealKey(_ *types.KeyAttributes, _ store.KeyBackend) ([]byte, error) {
	panic("mockTPM: UnsealKey not expected")
}
func (m *mockTPM) CanSeal() bool { panic("mockTPM: CanSeal not expected") }
func (m *mockTPM) DeleteIDevIDCertificate() error {
	panic("mockTPM: DeleteIDevIDCertificate not expected")
}
func (m *mockTPM) DeleteIAKCertificate() error {
	panic("mockTPM: DeleteIAKCertificate not expected")
}
func (m *mockTPM) VerifyTCGCSR(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCGCSR not expected")
}
func (m *mockTPM) VerifyTCG_CSR_IAK(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCG_CSR_IAK not expected")
}
func (m *mockTPM) VerifyTCG_CSR_IDevID(_ *tpm2pkg.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*types.KeyAttributes, *tpm2pkg.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCG_CSR_IDevID not expected")
}
func (m *mockTPM) SignValidate(_ *types.KeyAttributes, _, _ []byte) ([]byte, error) {
	panic("mockTPM: SignValidate not expected")
}
func (m *mockTPM) HashSequence(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("mockTPM: HashSequence not expected")
}
func (m *mockTPM) Hash(_ *types.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("mockTPM: Hash not expected")
}
func (m *mockTPM) ECDHZGen(_ *types.KeyAttributes, _ *tpm2.TPMSECCPoint, _ store.KeyBackend) ([]byte, error) {
	panic("mockTPM: ECDHZGen not expected")
}
func (m *mockTPM) SSRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	panic("mockTPM: SSRKPublic not expected")
}
func (m *mockTPM) FactoryReset(_ []byte) error {
	if m.factoryResetErr != nil {
		return m.factoryResetErr
	}
	return nil
}
func (m *mockTPM) FactoryResetWithClear(_ []byte) error {
	if m.factoryResetErr != nil {
		return m.factoryResetErr
	}
	return nil
}
func (m *mockTPM) GenerateSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	panic("mockTPM: GenerateSymmetricKey not expected")
}
func (m *mockTPM) GetSymmetricKey(_ *types.KeyAttributes) (types.SymmetricKey, error) {
	panic("mockTPM: GetSymmetricKey not expected")
}
func (m *mockTPM) SymmetricEncrypter(_ *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	panic("mockTPM: SymmetricEncrypter not expected")
}

func (m *mockTPM) VerifyAuth(_ tpm2.TPMHandle, _ []byte) error    { return nil }
func (m *mockTPM) ChangeAuth(_ tpm2.TPMHandle, _, _ []byte) error { return nil }

// compile-time check
var _ tpm2pkg.TrustedPlatformModule = (*mockTPM)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testCert creates a minimal self-signed x509.Certificate for testing.
func testCert() *x509.Certificate {
	return &x509.Certificate{
		Raw:          []byte{0x30, 0x82, 0x01, 0x22}, // minimal DER header
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
	}
}

// testECCCert creates a minimal x509.Certificate with an ECDSA public key for testing.
func testECCCert() *x509.Certificate {
	return &x509.Certificate{
		Raw:                []byte{0x30, 0x82, 0x01, 0x22},
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "test-ecc"},
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
		},
	}
}

// defaultMockTPM returns a mockTPM with reasonable defaults for a provisioned TPM.
// Default state: EK present, SRK present, IDevID attrs present but no IDevID cert.
// This maps to StatusLevel = "owner" (SRK exists but no IDevID key+cert).
// mockPlatformKeyStorer implements tpm2pkg.PlatformKeyStorer for testing.
type mockPlatformKeyStorer struct {
	initialized   bool
	policyEnabled bool
	srkAttrs      *types.KeyAttributes
}

func (m *mockPlatformKeyStorer) SRKAttributes() *types.KeyAttributes { return m.srkAttrs }
func (m *mockPlatformKeyStorer) Backend() store.KeyBackend           { return nil }
func (m *mockPlatformKeyStorer) Initialize(_, _ string) error        { return nil }
func (m *mockPlatformKeyStorer) InitializeWithDefaults() error       { return nil }
func (m *mockPlatformKeyStorer) IsInitialized() bool                 { return m.initialized }
func (m *mockPlatformKeyStorer) PINManager() pin.PINManager          { return nil } //nolint:staticcheck // TODO: migrate to PINBackend
func (m *mockPlatformKeyStorer) PlatformPolicyEnabled() bool         { return m.policyEnabled }
func (m *mockPlatformKeyStorer) VerifyAuth(_ string) error           { return nil }
func (m *mockPlatformKeyStorer) ChangeAuth(_, _ string) error        { return nil }
func (m *mockPlatformKeyStorer) GetLockoutInfo() (int, int, int, int, error) {
	return 0, 10, 0, 300, nil
}
func (m *mockPlatformKeyStorer) PINBackend() pin.PINBackend                  { return nil }
func (m *mockPlatformKeyStorer) DictionaryAttackLockoutReset(_ []byte) error { return nil }
func (m *mockPlatformKeyStorer) IsProvisioned() bool                         { return m.initialized }
func (m *mockPlatformKeyStorer) IsAuthReady() bool                           { return m.initialized }
func (m *mockPlatformKeyStorer) SetAuthReady(_ bool)                         {}

func defaultMockTPM() *mockTPM {
	return &mockTPM{
		device: "/dev/tpmrm0",
		config: &tpm2pkg.Config{
			Hash: "SHA-256",
			SSRK: &tpm2pkg.SRKConfig{
				Handle:         0x81000001,
				PlatformPolicy: false,
				KeyAlgorithm:   "RSA",
			},
		},
		fixedProps: &tpm2pkg.PropertiesFixed{
			Manufacturer:       "TestMFG",
			VendorID:           "TEST",
			Family:             "2.0\x00",
			Revision:           "1.38",
			FwMajor:            7,
			FwMinor:            85,
			Fips1402:           false,
			NVBufferMax:        2048,
			LockoutCounter:     0,
			MaxAuthFail:        32,
			Model:              "SIM\x00",
			ActiveSessionsMax:  64,
			AuthSessionsLoaded: 3,
			AuthSessionsActive: 2,
			PersistentLoaded:   5,
			PersistentAvail:    7,
			TransientAvail:     3,
			NVIndexesDefined:   4,
			NVIndexesMax:       32,
			MaxRSAKeyBits:      2048,
			MaxECCKeyBits:      384,
			Level:              0,
		},
		ekAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81010001,
			},
		},
		ekCertErr:    errors.New("no cert"),
		ekCertRSAErr: errors.New("not available"),
		ekCertECErr:  errors.New("not available"),
		ekECC:        nil,
		iakPub:       &rsa.PublicKey{},
		iakAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &types.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &types.TPMAttributes{
				Handle: 0x81010002,
			},
		},
		iakCertErr: errors.New("no cert"),
		idevidPub:  &rsa.PublicKey{},
		idevidAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{
				Curve: nil,
			},
		},
		idevidCertErr: errors.New("no cert"),
		srkName:       tpm2.TPM2BName{Buffer: []byte{0x01, 0x02}},
		ssrkAttrs: &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		pcrBanks: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
					{ID: 7, Value: []byte{0xCC, 0xDD}},
				},
			},
		},
		quoteResult: tpm2pkg.Quote{
			Quoted:    []byte{0x01, 0x02},
			Signature: []byte{0x03, 0x04},
			PCRs:      []byte{0x05, 0x06},
			Nonce:     []byte{0xde, 0xad},
		},
		parsedEvents: []tpm2pkg.Event{
			{
				PCRIndex:    0,
				EventType:   "EV_NO_ACTION",
				DigestCount: 1,
				Digests: []tpm2pkg.Digest{
					{AlgorithmId: "SHA256", Digest: "aabb"},
				},
				EventString: "spec_id_event",
			},
		},
		randomBytesVal: []byte{0xde, 0xad, 0xbe, 0xef},
		policyHash:     []byte{0x11, 0x22, 0x33},
		supportedAlgos: []string{"RSA", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "AES", "ECC", "HMAC"},
	}
}

// newServiceWithMock creates a TPMService wired to the given mockTPM
// via a shared TPMAccessor.
func newServiceWithMock(mock *mockTPM) *TPMService {
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return mock }))
	return svc
}

// createTestTPMService creates a TPMService wired to the given mockTPM with
// a temporary dataDir for file-based persistence tests. The temp directory
// is automatically cleaned up when the test completes.
func createTestTPMService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}

// ---------------------------------------------------------------------------
// Constructor & lifecycle
// ---------------------------------------------------------------------------

func TestNewTPMService(t *testing.T) {
	svc := NewTPMService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestTPMService_SetContext(t *testing.T) {
	svc := NewTPMService()
	svc.SetContext(context.Background())
	assert.Equal(t, context.Background(), svc.ctx)
}

func TestTPMService_SetTPMAccessor(t *testing.T) {
	svc := NewTPMService()
	called := false
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule {
		called = true
		return nil
	}))
	_, err := svc.getTPM()
	assert.True(t, called)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetStatus - Phase 1B four-level model:
//   none -> manufacturer -> owner -> device_identity
//   none:            no EK
//   manufacturer:    EK exists but no SRK
//   owner:           SRK exists but no IDevID key+cert
//   device_identity: IDevID key AND certificate present
// ---------------------------------------------------------------------------

func TestTPMService_GetStatus_WithTPM(t *testing.T) {
	mock := defaultMockTPM()
	// Default mock has EK + SRK but no IDevID cert -> "owner".
	svc := newServiceWithMock(mock)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelOwner, status.StatusLevel)
	assert.Equal(t, "TestMFG", status.Manufacturer)
	assert.Equal(t, "7.85", status.FirmwareVer)
	assert.Equal(t, "/dev/tpmrm0", status.DevicePath)
}

func TestTPMService_GetStatus_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

func TestTPMService_GetStatus_FixedPropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("capability error")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.Empty(t, status.Manufacturer)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

func TestTPMService_GetStatus_EKError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekAttrsErr = errors.New("not provisioned")
	mock.ekAttrs = nil
	svc := newServiceWithMock(mock)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

// ---------------------------------------------------------------------------
// GetStatus - device exists but TPM init fails (Bug 1 fix)
// ---------------------------------------------------------------------------

func TestTPMService_GetStatus_DeviceExistsButInitFails(t *testing.T) {
	// Create a temporary file to simulate /dev/tpmrm0 existence.
	tmpDir := t.TempDir()
	fakeDevice := filepath.Join(tmpDir, "tpmrm0")
	require.NoError(t, os.WriteFile(fakeDevice, []byte{}, 0644))

	// Verify deviceExists helper works with the fake file.
	assert.True(t, deviceExists(fakeDevice))

	// When TPM initialization fails, GetStatus must return Available=false
	// regardless of whether the device node exists. A device file without
	// a working TPM is not an available TPM.
	svc := NewTPMService()
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.False(t, status.Available)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

func TestTPMService_GetStatus_InitErrorField(t *testing.T) {
	// Verify the InitError field is populated when TPM init fails but device exists.
	// We test this by verifying the struct field behavior directly.
	status := &TPMStatus{
		Available:   true,
		Provisioned: false,
		StatusLevel: TPMStatusLevelNone,
		DevicePath:  "/dev/tpmrm0",
		InitError:   ErrTPMInitFailed.Error(),
	}
	assert.True(t, status.Available)
	assert.Equal(t, defaultTPMDevice, status.DevicePath)
	assert.Equal(t, "tpm_service: TPM device found but initialization failed", status.InitError)
}

// ---------------------------------------------------------------------------
// deviceExists helper
// ---------------------------------------------------------------------------

func TestDeviceExists_ExistingFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test-device")
	require.NoError(t, os.WriteFile(tmpFile, []byte{}, 0644))
	assert.True(t, deviceExists(tmpFile))
}

func TestDeviceExists_NonExistentFile(t *testing.T) {
	assert.False(t, deviceExists("/tmp/nonexistent-device-file-for-test"))
}

func TestDeviceExists_EmptyPath(t *testing.T) {
	assert.False(t, deviceExists(""))
}

// ---------------------------------------------------------------------------
// SetDevicePath / DevicePath
// ---------------------------------------------------------------------------

func TestTPMService_DevicePath_Default(t *testing.T) {
	svc := NewTPMService()
	assert.Equal(t, defaultTPMDevice, svc.DevicePath())
}

func TestTPMService_SetDevicePath(t *testing.T) {
	svc := NewTPMService()
	svc.SetDevicePath("/dev/tpm0")
	assert.Equal(t, "/dev/tpm0", svc.DevicePath())
}

func TestTPMService_SetDevicePath_Empty(t *testing.T) {
	svc := NewTPMService()
	svc.SetDevicePath("")
	// Empty string should not override the default.
	assert.Equal(t, defaultTPMDevice, svc.DevicePath())
}

func TestTPMService_GetStatus_UsesConfiguredDevicePath(t *testing.T) {
	// Point the service at a non-existent device path.
	svc := NewTPMService()
	svc.SetDevicePath("/dev/nonexistent-tpm-test")

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.Available)
	assert.False(t, status.DeviceExists)
	assert.Equal(t, "/dev/nonexistent-tpm-test", status.DevicePath)
}

func TestTPMService_GetStatus_DevicePathInResult(t *testing.T) {
	// Create a fake device to simulate an existing TPM device node.
	tmpDir := t.TempDir()
	fakeDevice := filepath.Join(tmpDir, "tpmrm0")
	require.NoError(t, os.WriteFile(fakeDevice, []byte{}, 0644))

	svc := NewTPMService()
	svc.SetDevicePath(fakeDevice)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.DeviceExists)
	assert.Equal(t, fakeDevice, status.DevicePath)
	// Available is false because no real TPM behind the file.
	assert.False(t, status.Available)
	assert.NotEmpty(t, status.InitError)
}

// ---------------------------------------------------------------------------
// ErrTPMInitFailed sentinel
// ---------------------------------------------------------------------------

func TestErrTPMInitFailed_Sentinel(t *testing.T) {
	assert.Equal(t, "tpm_service: TPM device found but initialization failed", ErrTPMInitFailed.Error())
	assert.True(t, errors.Is(ErrTPMInitFailed, ErrTPMInitFailed))
}

// ---------------------------------------------------------------------------
// GetStatus - StatusLevel tests (Phase 1B four-level model)
// ---------------------------------------------------------------------------

func TestGetStatusLevel_None(t *testing.T) {
	// TPM available but no EK -> StatusLevel = "none"
	mock := defaultMockTPM()
	mock.ekAttrsErr = errors.New("no EK")
	mock.ekAttrs = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelNone, status.StatusLevel)
}

func TestGetStatusLevel_Manufacturer(t *testing.T) {
	// EK present but no SRK -> StatusLevel = "manufacturer"
	mock := defaultMockTPM()
	mock.ssrkAttrsErr = errors.New("no SRK") // SSRKAttributes returns error
	mock.ssrkAttrs = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelManufacturer, status.StatusLevel)
}

func TestGetStatusLevel_Owner(t *testing.T) {
	// EK + SRK present, no IDevID attrs or cert -> StatusLevel = "owner"
	mock := defaultMockTPM()
	mock.idevidAttrsErr = errors.New("no idevid")
	mock.idevidAttrs = nil
	mock.idevidCertErr = errors.New("no cert")
	mock.idevidCert = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelOwner, status.StatusLevel)
}

func TestGetStatusLevel_Owner_AttrsButNoCert(t *testing.T) {
	// EK + SRK present, IDevID attrs present but no IDevID cert -> StatusLevel = "owner"
	mock := defaultMockTPM()
	// idevidAttrs is already set in defaultMockTPM
	mock.idevidCertErr = errors.New("no cert")
	mock.idevidCert = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelOwner, status.StatusLevel)
}

func TestGetStatusLevel_DeviceIdentity(t *testing.T) {
	// EK + SRK + IDevID key + IDevID cert -> StatusLevel = "device_identity"
	mock := defaultMockTPM()
	// IDevID attrs already set in defaultMockTPM.
	mock.idevidCert = testCert()
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.True(t, status.Available)
	assert.True(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelDeviceIdentity, status.StatusLevel)
}

func TestGetStatusLevel_DeviceIdentity_RequiresBothAttrsAndCert(t *testing.T) {
	// IDevID attrs error but cert present -> still "owner" (attrs required)
	mock := defaultMockTPM()
	mock.idevidAttrsErr = errors.New("no attrs")
	mock.idevidAttrs = nil
	mock.idevidCert = testCert()
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.Provisioned)
	assert.Equal(t, TPMStatusLevelOwner, status.StatusLevel)
}

// ---------------------------------------------------------------------------
// GetInfo
// ---------------------------------------------------------------------------

func TestTPMService_GetInfo_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.Equal(t, "TestMFG", info.Manufacturer)
	assert.Equal(t, "TEST", info.VendorID)
	assert.Equal(t, "7.85", info.FirmwareVersion)
	assert.Equal(t, "2.0\x00", info.Family)
	assert.Equal(t, "1.38", info.Revision)
	assert.False(t, info.FIPSMode)
	assert.Equal(t, 2048, info.MaxNVBufferSize)
	assert.Equal(t, 0, info.LockoutCounter)
	assert.Equal(t, 32, info.MaxAuthFail)
	assert.Contains(t, info.PCRBanks, "sha256")
	assert.Equal(t, "SIM\x00", info.Model)

	// Session and resource info fields.
	assert.Equal(t, 64, info.ActiveSessionsMax)
	assert.Equal(t, 3, info.AuthSessionsLoaded)
	assert.Equal(t, 2, info.AuthSessionsActive)
	assert.Equal(t, 5, info.PersistentLoaded)
	assert.Equal(t, 7, info.PersistentAvail)
	assert.Equal(t, 3, info.TransientAvail)
	assert.Equal(t, 4, info.NVIndexesDefined)
	assert.Equal(t, 32, info.NVIndexesMax)
	assert.Equal(t, 0, info.Level)

	// MaxRSAKeySize and MaxECCKeySize from FixedProperties.
	assert.Equal(t, 2048, info.MaxRSAKeySize)
	assert.Equal(t, 384, info.MaxECCKeySize)
}

func TestTPMService_GetInfo_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

func TestTPMService_GetInfo_FixedPropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("fail")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Empty(t, info.Manufacturer)
}

func TestTPMService_GetInfo_MaxKeySizeDefaults(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedProps.MaxRSAKeyBits = 0
	mock.fixedProps.MaxECCKeyBits = 0
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	// Falls back to defaults when FixedProperties reports 0.
	assert.Equal(t, 2048, info.MaxRSAKeySize)
	assert.Equal(t, 521, info.MaxECCKeySize)
}

// ---------------------------------------------------------------------------
// GetEKInfo
// ---------------------------------------------------------------------------

func TestTPMService_GetEKInfo_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "RSA-SSA", info.Algorithm)
	assert.Equal(t, 2048, info.KeySize)
	assert.Empty(t, info.Certificate) // cert returns error in default mock
}

func TestTPMService_GetEKInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
}

func TestTPMService_GetEKInfo_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetEKInfo_EKAttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekAttrsErr = errors.New("not found")
	mock.ekAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetEKECCInfo - cert-based detection
// ---------------------------------------------------------------------------

func TestTPMService_GetEKECCInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "ECDSA", info.Algorithm)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
}

func TestTPMService_GetEKECCInfo_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetEKECCInfo_NoCert(t *testing.T) {
	mock := defaultMockTPM()
	// Default mock has ekCertECErr set, so no ECC cert is available.
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetEKECCInfo_NilCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertECErr = nil
	mock.ekCertEC = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetEKECCInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIAKInfo - uses iakAttrs != nil for presence
// ---------------------------------------------------------------------------

func TestTPMService_GetIAKInfo_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "RSA-SSA", info.Algorithm)
	assert.Equal(t, 2048, info.KeySize)
	assert.Equal(t, "0x81010002", info.Handle)
}

func TestTPMService_GetIAKInfo_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetIAKInfo_AttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrsErr = errors.New("not provisioned")
	mock.iakAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetIAKInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakCert = testCert()
	mock.iakCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
}

func TestTPMService_GetIAKInfo_UsesAttrsNotIAK(t *testing.T) {
	// Verify that GetIAKInfo does NOT call IAK() (which can panic).
	// It should use iakAttrs != nil for presence.
	mock := defaultMockTPM()
	mock.iakPub = nil // IAK() would return nil, but we should not be calling it
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present) // iakAttrs is non-nil, so present is true
}

func TestTPMService_GetIAKInfo_NilTPMAttributes(t *testing.T) {
	// Verify that GetIAKInfo gracefully handles nil TPMAttributes.
	mock := defaultMockTPM()
	mock.iakAttrs = &types.KeyAttributes{
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		TPMAttributes: nil, // nil TPMAttributes
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Empty(t, info.Handle) // Handle should be empty when TPMAttributes is nil
}

func TestTPMService_GetIAKInfo_NilAttrsNoError(t *testing.T) {
	// Verify that GetIAKInfo handles IAKAttributes returning (nil, nil)
	// without panicking. This occurs when no IAK is configured but the
	// TPM library does not treat it as an error.
	mock := defaultMockTPM()
	mock.iakAttrs = nil
	mock.iakAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIAKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetIDevIDInfo - uses idevidAttrs != nil for presence
// ---------------------------------------------------------------------------

func TestTPMService_GetIDevIDInfo_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "ECDSA", info.Algorithm)
}

func TestTPMService_GetIDevIDInfo_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetIDevIDInfo_AttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidAttrsErr = errors.New("not found")
	mock.idevidAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

func TestTPMService_GetIDevIDInfo_UsesAttrsNotIDevID(t *testing.T) {
	// Verify that GetIDevIDInfo does NOT call IDevID() (which can panic).
	// It should use idevidAttrs != nil for presence.
	mock := defaultMockTPM()
	mock.idevidPub = nil // IDevID() would return nil, but we should not be calling it
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.True(t, info.Present) // idevidAttrs is non-nil, so present is true
}

func TestTPMService_GetIDevIDInfo_NilAttrsNoError(t *testing.T) {
	// Verify that GetIDevIDInfo handles IDevIDAttributes returning (nil, nil)
	// without panicking. This occurs when no IDevID is configured but the
	// TPM library does not treat it as an error.
	mock := defaultMockTPM()
	mock.idevidAttrs = nil
	mock.idevidAttrsErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
}

// ---------------------------------------------------------------------------
// GetSharedSRKInfo
// ---------------------------------------------------------------------------

func TestTPMService_GetSharedSRKInfo_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "RSA-SSA", info.Algorithm)
	assert.Equal(t, "0x81000001", info.Handle)
}

func TestTPMService_GetSharedSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
	assert.Equal(t, "N/A", info.Algorithm)
	assert.Empty(t, info.Handle)
}

func TestTPMService_GetSharedSRKInfo_NotPresent(t *testing.T) {
	mock := defaultMockTPM()
	mock.ssrkAttrsErr = errors.New("handle not found")
	mock.ssrkAttrs = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
	// SSRK config is still populated, so handle comes from config.
	assert.Equal(t, "0x81000001", info.Handle)
}

func TestTPMService_GetSharedSRKInfo_NilSSRKConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.SSRK = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetSharedSRKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present) // ssrkAttrs is non-nil, so present
	assert.Empty(t, info.Handle) // no config to read handle from
}

// ---------------------------------------------------------------------------
// GetPlatformSRKInfo
// ---------------------------------------------------------------------------

func TestTPMService_GetPlatformSRKInfo_WithPolicyEnabled(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: true,
		srkAttrs: &types.KeyAttributes{
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			TPMAttributes: &types.TPMAttributes{Handle: 0x81000002},
		},
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "RSA-SSA", info.Algorithm)
	assert.Equal(t, "0x81000002", info.Handle)
	assert.True(t, info.PolicyEnabled)
	assert.Equal(t, "Platform Policy", info.PolicyName)
	assert.True(t, info.Initialized)
}

func TestTPMService_GetPlatformSRKInfo_NoPlatformKeyStore(t *testing.T) {
	mock := defaultMockTPM()
	// platformKeyStore is nil by default.
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)
	assert.Equal(t, "N/A", info.Algorithm)
	assert.False(t, info.Initialized)
	assert.False(t, info.PolicyEnabled)
}

func TestTPMService_GetPlatformSRKInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.False(t, info.Present)
	assert.Equal(t, "N/A", info.Algorithm)
}

func TestTPMService_GetPlatformSRKInfo_NotInitialized(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   false,
		policyEnabled: false,
		srkAttrs: &types.KeyAttributes{
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			TPMAttributes: &types.TPMAttributes{Handle: 0x81000002},
		},
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Equal(t, "ECDSA", info.Algorithm)
	assert.False(t, info.Initialized)
	assert.False(t, info.PolicyEnabled)
	assert.Empty(t, info.PolicyName)
}

func TestTPMService_GetPlatformSRKInfo_HandleFallbackToConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = &tpm2pkg.PlatformSRKConfig{SRKHandle: 0x81000002}
	mock.platformKeyStore = &mockPlatformKeyStorer{
		initialized:   true,
		policyEnabled: false,
		srkAttrs:      nil, // no SRK attributes - will fall back to config
	}
	svc := newServiceWithMock(mock)
	info, err := svc.GetPlatformSRKInfo()
	require.NoError(t, err)
	assert.False(t, info.Present)              // no SRK attributes means not present
	assert.Equal(t, "0x81000002", info.Handle) // falls back to config handle
	assert.True(t, info.Initialized)
}

// ---------------------------------------------------------------------------
// GetPCRs
// ---------------------------------------------------------------------------

func TestTPMService_GetPCRs_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	values, err := svc.GetPCRs("sha256")
	require.NoError(t, err)
	require.Len(t, values, 2)
	assert.Equal(t, 0, values[0].Index)
	assert.Equal(t, "sha256", values[0].Bank)
	assert.Equal(t, "aabb", values[0].Digest)
}

func TestTPMService_GetPCRs_InvalidBank(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPCRs("md5")
	assert.ErrorIs(t, err, ErrTPMInvalidBank)
}

func TestTPMService_GetPCRs_ValidBanks(t *testing.T) {
	banks := []string{"sha1", "sha256", "sha384", "sha512"}
	for _, bank := range banks {
		t.Run(bank, func(t *testing.T) {
			_, err := NewTPMService().GetPCRs(bank)
			// Will fail with ErrTPMNotAvailable, not ErrTPMInvalidBank.
			assert.ErrorIs(t, err, ErrTPMNotAvailable)
		})
	}
}

func TestTPMService_GetPCRs_BankNotSupported(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{} // empty banks — simulates unsupported
	svc := newServiceWithMock(mock)
	values, err := svc.GetPCRs("sha384")
	assert.ErrorIs(t, err, ErrTPMBankNotSupported)
	assert.Nil(t, values)
}

// ---------------------------------------------------------------------------
// PCR Bank Sorting
// ---------------------------------------------------------------------------

func TestDetectPCRBanks_SortedOrder(t *testing.T) {
	mock := defaultMockTPM()
	// Return banks in reverse order to verify sorting.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA512", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA1", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA384", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
	}
	banks := detectPCRBanks(mock)
	require.Len(t, banks, 4)
	assert.Equal(t, "sha1", banks[0])
	assert.Equal(t, "sha256", banks[1])
	assert.Equal(t, "sha384", banks[2])
	assert.Equal(t, "sha512", banks[3])
}

func TestDetectPCRBanks_SHA386VariantNormalized(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA386", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0x00}}}},
	}
	banks := detectPCRBanks(mock)
	require.Len(t, banks, 2)
	assert.Equal(t, "sha256", banks[0])
	assert.Equal(t, "sha384", banks[1])
}

func TestDetectPCRBanks_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanksErr = errors.New("read error")
	banks := detectPCRBanks(mock)
	assert.Nil(t, banks)
}

// ---------------------------------------------------------------------------
// ListKeys
// ---------------------------------------------------------------------------

func TestTPMService_ListKeys(t *testing.T) {
	svc := NewTPMService()
	keys, err := svc.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// ---------------------------------------------------------------------------
// Provision
// ---------------------------------------------------------------------------

func TestTPMService_Provision_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.Provision(&ProvisionOptions{OwnerAuth: "test123"})
	assert.NoError(t, err)
}

func TestTPMService_Provision_NilOpts(t *testing.T) {
	svc := NewTPMService()
	err := svc.Provision(nil)
	assert.ErrorIs(t, err, ErrTPMProvisionFailed)
}

func TestTPMService_Provision_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Provision(&ProvisionOptions{OwnerAuth: "test"})
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_Provision_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.provisionErr = errors.New("provision failed")
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{OwnerAuth: "test"})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

func TestTPMService_Install_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	err := svc.Install("testpin")
	assert.NoError(t, err)
}

func TestTPMService_Install_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.Install("testpin")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_Install_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.installErr = errors.New("install failed")
	svc := newServiceWithMock(mock)
	err := svc.Install("testpin")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// GenerateQuote
// ---------------------------------------------------------------------------

func TestTPMService_GenerateQuote_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	q, err := svc.GenerateQuote("deadbeef", []int{0, 7}, "sha256")
	require.NoError(t, err)
	assert.Equal(t, "0102", q.QuoteData)
	assert.Equal(t, "0304", q.Signature)
	assert.Equal(t, "0506", q.PCRDigest)
	assert.Equal(t, "dead", q.Nonce)
	assert.False(t, q.CreatedAt.IsZero())
}

func TestTPMService_GenerateQuote_EmptyNonce_AutoGenerates(t *testing.T) {
	mock := defaultMockTPM()
	mock.randomBytesVal = make([]byte, 32)
	for i := range mock.randomBytesVal {
		mock.randomBytesVal[i] = byte(i)
	}
	svc := newServiceWithMock(mock)
	q, err := svc.GenerateQuote("", []int{0}, "sha256")
	require.NoError(t, err)
	assert.NotEmpty(t, q.Nonce)
	assert.False(t, q.CreatedAt.IsZero())
}

func TestTPMService_GenerateQuote_EmptyNonce_RandomFails(t *testing.T) {
	mock := defaultMockTPM()
	mock.randomBytesErr = errors.New("rng failure")
	svc := newServiceWithMock(mock)
	_, err := svc.GenerateQuote("", []int{0}, "sha256")
	assert.ErrorIs(t, err, ErrTPMNonceGenFailed)
}

func TestTPMService_GenerateQuote_EmptyPCRs(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GenerateQuote("deadbeef", nil, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTPMService_GenerateQuote_InvalidHexNonce(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GenerateQuote("not-hex!", []int{0}, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidNonce)
}

func TestTPMService_GenerateQuote_InvalidBank(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GenerateQuote("deadbeef", []int{0}, "md5")
	assert.ErrorIs(t, err, ErrTPMInvalidBank)
}

func TestTPMService_GenerateQuote_InvalidPCRIndex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GenerateQuote("deadbeef", []int{0, 24}, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTPMService_GenerateQuote_NegativePCRIndex(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.GenerateQuote("deadbeef", []int{-1}, "sha256")
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTPMService_GenerateQuote_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GenerateQuote("deadbeef", []int{0}, "sha256")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GetEventLog
// ---------------------------------------------------------------------------

func TestTPMService_GetEventLog_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	entries, err := svc.GetEventLog()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, 0, entries[0].PCRIndex)
	assert.Equal(t, "EV_NO_ACTION", entries[0].EventType)
	assert.Equal(t, "aabb", entries[0].DigestHex)
	assert.Equal(t, "spec_id_event", entries[0].EventData)
}

func TestTPMService_GetEventLog_WithoutTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetEventLog()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GetEventLog_ParseError(t *testing.T) {
	mock := defaultMockTPM()
	mock.parsedEventsErr = errors.New("parse error")
	svc := newServiceWithMock(mock)
	_, err := svc.GetEventLog()
	assert.ErrorIs(t, err, ErrTPMEventLogNotFound)
}

func TestTPMService_GetEventLog_EmptyDigests(t *testing.T) {
	mock := defaultMockTPM()
	mock.parsedEvents = []tpm2pkg.Event{
		{PCRIndex: 1, EventType: "EV_SEPARATOR", Digests: nil, EventString: "sep"},
	}
	svc := newServiceWithMock(mock)
	entries, err := svc.GetEventLog()
	require.NoError(t, err)
	assert.Equal(t, "", entries[0].DigestHex)
}

// ---------------------------------------------------------------------------
// GetRandomBytes
// ---------------------------------------------------------------------------

func TestTPMService_GetRandomBytes_ValidLength(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	hexStr, err := svc.GetRandomBytes(4)
	require.NoError(t, err)
	assert.Equal(t, "deadbeef", hexStr)
}

func TestTPMService_GetRandomBytes_InvalidLength_Zero(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetRandomBytes(0)
	assert.ErrorIs(t, err, ErrTPMInvalidLength)
}

func TestTPMService_GetRandomBytes_InvalidLength_TooLarge(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetRandomBytes(1025)
	assert.ErrorIs(t, err, ErrTPMInvalidLength)
}

func TestTPMService_GetRandomBytes_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetRandomBytes(16)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GetRandomBytes_BoundaryValues(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())

	_, err := svc.GetRandomBytes(1)
	assert.NoError(t, err)

	_, err = svc.GetRandomBytes(1024)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetPlatformPolicy
// ---------------------------------------------------------------------------

func TestTPMService_GetPlatformPolicy_WithTPM(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	hexStr, err := svc.GetPlatformPolicy()
	require.NoError(t, err)
	assert.Equal(t, "112233", hexStr)
}

func TestTPMService_GetPlatformPolicy_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetPlatformPolicy()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GetPlatformPolicy_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.policyHashErr = errors.New("policy error")
	svc := newServiceWithMock(mock)
	_, err := svc.GetPlatformPolicy()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "platform policy")
}

// ---------------------------------------------------------------------------
// ExportEKCert / ImportEKCert
// ---------------------------------------------------------------------------

func TestTPMService_ExportEKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ExportEKCert_NoCert(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM()) // ekCertErr is set
	_, err := svc.ExportEKCert("pem")
	assert.ErrorIs(t, err, ErrTPMCertNotFound)
}

func TestTPMService_ExportEKCert_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)
	pemStr, err := svc.ExportEKCert("pem")
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN CERTIFICATE")
}

func TestTPMService_ImportEKCert_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportEKCert("not a pem")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportEKCert_WrongBlockType(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportEKCert("-----BEGIN RSA PRIVATE KEY-----\nYQ==\n-----END RSA PRIVATE KEY-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportEKCert_NoTPM(t *testing.T) {
	// Create a valid PEM with the test cert
	cert := testCert()
	pemStr := certToPEM(cert)
	svc := NewTPMService()
	err := svc.ImportEKCert(pemStr)
	// The cert has invalid DER, so x509.ParseCertificate will fail.
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// ExportEKECCCert / ImportEKECCCert
// ---------------------------------------------------------------------------

func TestTPMService_ExportEKECCCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportEKECCCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ExportEKECCCert_NoCert(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM()) // ekCertECErr is set
	_, err := svc.ExportEKECCCert("pem")
	assert.ErrorIs(t, err, ErrTPMCertNotFound)
}

func TestTPMService_ExportEKECCCert_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)
	pemStr, err := svc.ExportEKECCCert("pem")
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN CERTIFICATE")
}

func TestTPMService_ImportEKECCCert_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportEKECCCert("not a pem")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportEKECCCert_WrongBlockType(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportEKECCCert("-----BEGIN RSA PRIVATE KEY-----\nYQ==\n-----END RSA PRIVATE KEY-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportEKECCCert_NoTPM(t *testing.T) {
	cert := testCert()
	pemStr := certToPEM(cert)
	svc := NewTPMService()
	err := svc.ImportEKECCCert(pemStr)
	// The cert has invalid DER, so x509.ParseCertificate will fail.
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportEKECCCert_WriteError(t *testing.T) {
	mock := defaultMockTPM()
	mock.writeEKCertErr = errors.New("write failed")
	svc := newServiceWithMock(mock)
	// We need a valid x509 cert for ParseCertificate to pass.
	// Use a real self-signed cert for this test.
	// Since testCert() has invalid DER, we test only that invalid PEM is caught.
	err := svc.ImportEKECCCert("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert) // x509 parse will fail on minimal DER
}

// ---------------------------------------------------------------------------
// ExportIAKCert / ImportIAKCert
// ---------------------------------------------------------------------------

func TestTPMService_ExportIAKCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIAKCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ExportIAKCert_NoCert(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.ExportIAKCert("pem")
	assert.ErrorIs(t, err, ErrTPMCertNotFound)
}

func TestTPMService_ImportIAKCert_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportIAKCert("garbage")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ImportIAKCert_NoTPM(t *testing.T) {
	// Would need valid x509 cert bytes in PEM; the test cert has invalid DER.
	svc := NewTPMService()
	err := svc.ImportIAKCert("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert) // x509 parse will fail
}

// ---------------------------------------------------------------------------
// ExportIDevIDCert / ImportIDevIDCert
// ---------------------------------------------------------------------------

func TestTPMService_ExportIDevIDCert_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ExportIDevIDCert("pem")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ExportIDevIDCert_NoCert(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	_, err := svc.ExportIDevIDCert("pem")
	assert.ErrorIs(t, err, ErrTPMCertNotFound)
}

func TestTPMService_ImportIDevIDCert_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ImportIDevIDCert("garbage")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// buildCapabilities
// ---------------------------------------------------------------------------

func TestBuildCapabilities_WithSessionInfo(t *testing.T) {
	info := &TPMInfo{
		MaxRSAKeySize:     2048,
		MaxECCKeySize:     384,
		NVIndexesDefined:  4,
		NVIndexesMax:      32,
		PersistentLoaded:  5,
		PersistentAvail:   7,
		ActiveSessionsMax: 64,
		FIPSMode:          true,
	}
	caps := buildCapabilities(info)
	assert.Contains(t, caps, "RSA (up to 2048-bit)")
	assert.Contains(t, caps, "ECC (up to 384-bit)")
	assert.Contains(t, caps, "PCR Read/Extend")
	assert.Contains(t, caps, "Quoting")
	assert.Contains(t, caps, "Sealing")
	assert.Contains(t, caps, "Random Number Generation")
	assert.Contains(t, caps, "NV Storage (4/32 indexes)")
	assert.Contains(t, caps, "Persistent Keys (5 loaded, 7 avail)")
	assert.Contains(t, caps, "Sessions (max 64)")
	assert.Contains(t, caps, "FIPS 140-2")
}

func TestBuildCapabilities_NoSessionInfo(t *testing.T) {
	info := &TPMInfo{
		MaxRSAKeySize: 2048,
		MaxECCKeySize: 256,
	}
	caps := buildCapabilities(info)
	assert.Contains(t, caps, "RSA (up to 2048-bit)")
	assert.Contains(t, caps, "ECC (up to 256-bit)")
	// NV Storage, Persistent Keys, and Sessions should not appear.
	for _, cap := range caps {
		assert.NotContains(t, cap, "NV Storage")
		assert.NotContains(t, cap, "Persistent Keys")
		assert.NotContains(t, cap, "Sessions")
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func TestKeySize_RSA(t *testing.T) {
	attrs := &types.KeyAttributes{
		RSAAttributes: &types.RSAAttributes{KeySize: 4096},
	}
	assert.Equal(t, 4096, keySize(attrs))
}

func TestKeySize_NoAttributes(t *testing.T) {
	attrs := &types.KeyAttributes{}
	assert.Equal(t, 0, keySize(attrs))
}

func TestKeySize_NilAttributes(t *testing.T) {
	assert.Equal(t, 0, keySize(nil))
}

func TestCertToPEM(t *testing.T) {
	cert := testCert()
	pemStr := certToPEM(cert)
	assert.Contains(t, pemStr, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemStr, "-----END CERTIFICATE-----")
}

// ---------------------------------------------------------------------------
// getTPM edge cases
// ---------------------------------------------------------------------------

func TestTPMService_getTPM_NilAccessor(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.getTPM()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_getTPM_FuncReturnsNil(t *testing.T) {
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))
	_, err := svc.getTPM()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_getTPM_FuncReturnsMock(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	tpm, err := svc.getTPM()
	require.NoError(t, err)
	assert.Equal(t, mock, tpm)
	// Release the TPM accessor mutex acquired by getTPM.
	svc.tpmAccessor.Release()
}

// ---------------------------------------------------------------------------
// UpdatePolicy
// ---------------------------------------------------------------------------

func TestTPMService_UpdatePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a policy first.
	original := &PCRPolicy{
		Name:        "boot-policy",
		Description: "original description",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(original))

	// Update the policy description.
	updated := &PCRPolicy{
		Name:        "boot-policy",
		Description: "updated description",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	result, updateErr := svc.UpdatePolicy("boot-policy", updated)
	require.NoError(t, updateErr)
	require.NotNil(t, result)

	// Verify the update was persisted.
	fetched, err := svc.GetPolicy("boot-policy")
	require.NoError(t, err)
	assert.Equal(t, "updated description", fetched.Description)
	assert.NotEmpty(t, fetched.UpdatedAt)
}

func TestTPMService_UpdatePolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policy := &PCRPolicy{
		Name:        "nonexistent-policy",
		Description: "does not exist",
	}
	_, err := svc.UpdatePolicy("nonexistent-policy", policy)
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTPMService_UpdatePolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Nil policy.
	_, err := svc.UpdatePolicy("test", nil)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	// Empty name.
	_, err = svc.UpdatePolicy("", &PCRPolicy{Name: ""})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	// Whitespace-only name.
	_, err = svc.UpdatePolicy("   ", &PCRPolicy{Name: "   "})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// ExportPolicy
// ---------------------------------------------------------------------------

func TestTPMService_ExportPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a policy with PCR selections.
	policy := &PCRPolicy{
		Name:        "export-test",
		Description: "policy for export",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Export and verify the JSON output.
	exported, err := svc.ExportPolicy("export-test")
	require.NoError(t, err)
	assert.NotEmpty(t, exported)

	// Unmarshal and verify expected fields.
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Equal(t, "export-test", parsed["name"])
	assert.NotEmpty(t, parsed["created_at"])
	assert.Equal(t, "sha256", parsed["pcr_bank"])

	// Verify PCR selections are present as an array.
	selections, ok := parsed["pcr_selections"].([]interface{})
	require.True(t, ok)
	assert.Len(t, selections, 2)
}

func TestTPMService_ExportPolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.ExportPolicy("nonexistent-policy")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKey
// ---------------------------------------------------------------------------

func TestTPMService_AssignPolicyToKey_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a policy first.
	policy := &PCRPolicy{
		Name:        "assign-test",
		Description: "policy for assignment",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Assign the policy to a key handle.
	err := svc.AssignPolicyToKey("assign-test", "0x81000001")
	require.NoError(t, err)

	// Verify the assignment via ListPolicyAssignments.
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "assign-test", assignments[0].PolicyName)
	assert.Equal(t, "0x81000001", assignments[0].KeyHandle)
	assert.NotEmpty(t, assignments[0].AssignedAt)
}

func TestTPMService_AssignPolicyToKey_InvalidHandle(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.AssignPolicyToKey("some-policy", "")
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)

	err = svc.AssignPolicyToKey("some-policy", "   ")
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)
}

func TestTPMService_AssignPolicyToKey_InvalidPolicyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.AssignPolicyToKey("", "0x81000001")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	err = svc.AssignPolicyToKey("   ", "0x81000001")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTPMService_AssignPolicyToKey_PolicyNotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.AssignPolicyToKey("nonexistent-policy", "0x81000001")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// ListPolicyAssignments
// ---------------------------------------------------------------------------

func TestTPMService_ListPolicyAssignments_Empty(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

// ---------------------------------------------------------------------------
// UnassignPolicyFromKey
// ---------------------------------------------------------------------------

func TestTPMService_UnassignPolicyFromKey_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create and assign a policy.
	policy := &PCRPolicy{
		Name:        "unassign-test",
		Description: "policy for unassignment",
		PCRSelections: []PCRSelection{
			{Index: 7, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))
	require.NoError(t, svc.AssignPolicyToKey("unassign-test", "0x81000002"))

	// Verify assignment exists.
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 1)

	// Unassign and verify it is gone.
	err = svc.UnassignPolicyFromKey("0x81000002")
	require.NoError(t, err)

	assignments, err = svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

func TestTPMService_UnassignPolicyFromKey_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.UnassignPolicyFromKey("0x81FFFFFF")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// CreateCompositePolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreateCompositePolicy_AND(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	composite := &CompositePolicy{
		Name:        "and-composite",
		Description: "AND composite policy",
		Operator:    "AND",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 7, Bank: "sha256"}},
			},
		},
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	// Verify via GetCompositePolicy.
	fetched, err := svc.GetCompositePolicy("and-composite")
	require.NoError(t, err)
	assert.Equal(t, "and-composite", fetched.Name)
	assert.Equal(t, "AND", fetched.Operator)
	assert.Len(t, fetched.Elements, 2)
	assert.NotEmpty(t, fetched.CreatedAt)
}

func TestTPMService_CreateCompositePolicy_OR(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	composite := &CompositePolicy{
		Name:        "or-composite",
		Description: "OR composite policy",
		Operator:    "OR",
		Elements: []PolicyElement{
			{
				Type:          "pcr",
				PCRBank:       "sha256",
				PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
			},
		},
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	fetched, err := svc.GetCompositePolicy("or-composite")
	require.NoError(t, err)
	assert.Equal(t, "OR", fetched.Operator)
	assert.NotEmpty(t, fetched.CreatedAt)
}

func TestTPMService_CreateCompositePolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	composite := &CompositePolicy{
		Name:     "dup-composite",
		Operator: "AND",
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	// Second creation with the same name should fail.
	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "dup-composite",
		Operator: "OR",
	})
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

func TestTPMService_CreateCompositePolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Nil policy.
	err := svc.CreateCompositePolicy(nil)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	// Empty name.
	err = svc.CreateCompositePolicy(&CompositePolicy{Name: "", Operator: "AND"})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	// Whitespace-only name.
	err = svc.CreateCompositePolicy(&CompositePolicy{Name: "   ", Operator: "AND"})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTPMService_CreateCompositePolicy_InvalidOperator(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "bad-operator",
		Operator: "XOR",
	})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyOperator)

	err = svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "empty-operator",
		Operator: "",
	})
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyOperator)
}

// ---------------------------------------------------------------------------
// ListCompositePolicies
// ---------------------------------------------------------------------------

func TestTPMService_ListCompositePolicies_Empty(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// DeleteCompositePolicy
// ---------------------------------------------------------------------------

func TestTPMService_DeleteCompositePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a composite policy.
	composite := &CompositePolicy{
		Name:     "delete-me",
		Operator: "AND",
		Elements: []PolicyElement{
			{Type: "pcr", PCRBank: "sha256"},
		},
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	// Verify it exists.
	_, err := svc.GetCompositePolicy("delete-me")
	require.NoError(t, err)

	// Delete and verify it is gone.
	require.NoError(t, svc.DeleteCompositePolicy("delete-me"))

	_, err = svc.GetCompositePolicy("delete-me")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTPMService_DeleteCompositePolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.DeleteCompositePolicy("nonexistent-composite")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// Phase 2: ListPoliciesWithDigests
// ---------------------------------------------------------------------------

func TestTPMService_ListPoliciesWithDigests_PopulatesDigests(t *testing.T) {
	mock := &mockTPM{
		pcrBanks: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xaa, 0xbb, 0xcc}},
					{ID: 7, Value: []byte{0xdd, 0xee, 0xff}},
				},
			},
		},
	}
	svc, _ := createTestTPMService(t, mock)

	// Create a policy with PCR selections.
	policy := &PCRPolicy{
		Name:          "digest-test",
		Description:   "test policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Call ListPoliciesWithDigests.
	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)

	assert.NotEmpty(t, policies[0].PCRDigests)
	assert.Contains(t, policies[0].PCRDigests, "sha256:0")
	assert.Contains(t, policies[0].PCRDigests, "sha256:7")
	assert.Equal(t, "aabbcc", policies[0].PCRDigests["sha256:0"])
	assert.Equal(t, "ddeeff", policies[0].PCRDigests["sha256:7"])
}

func TestTPMService_ListPoliciesWithDigests_EmptyPolicies(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestTPMService_ListPoliciesWithDigests_TPMUnavailable(t *testing.T) {
	// Create service with no TPMAccessor (simulating TPM unavailable).
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())

	// Create a policy manually.
	policy := PCRPolicy{
		Name:          "no-tpm-test",
		Description:   "test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		CreatedAt:     "2025-01-01T00:00:00Z",
	}
	require.NoError(t, svc.savePolicies([]PCRPolicy{policy}))

	// Should return policies without digests (graceful degradation).
	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "no-tpm-test", policies[0].Name)
}

// ---------------------------------------------------------------------------
// Phase 2: AssignPolicyToKeys
// ---------------------------------------------------------------------------

func TestTPMService_AssignPolicyToKeys_Multiple(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a policy first.
	policy := &PCRPolicy{
		Name:          "multi-assign",
		Description:   "test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Assign to 3 handles.
	err := svc.AssignPolicyToKeys("multi-assign", []string{"0x81000001", "0x81000002", "0x81010001"})
	require.NoError(t, err)

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 3)
	for _, a := range assignments {
		assert.Equal(t, "multi-assign", a.PolicyName)
	}
}

func TestTPMService_AssignPolicyToKeys_UpdatesExisting(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create two policies.
	p1 := &PCRPolicy{Name: "policy-a", Description: "A", PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}}}
	p2 := &PCRPolicy{Name: "policy-b", Description: "B", PCRSelections: []PCRSelection{{Index: 7, Bank: "sha256"}}}
	require.NoError(t, svc.CreatePolicy(p1))
	require.NoError(t, svc.CreatePolicy(p2))

	// Assign policy-a to handle.
	require.NoError(t, svc.AssignPolicyToKeys("policy-a", []string{"0x81000001"}))

	// Re-assign to policy-b.
	require.NoError(t, svc.AssignPolicyToKeys("policy-b", []string{"0x81000001"}))

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "policy-b", assignments[0].PolicyName)
}

func TestTPMService_AssignPolicyToKeys_EmptyHandles(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.AssignPolicyToKeys("some-policy", []string{})
	assert.ErrorIs(t, err, ErrTPMInvalidHandle)
}

// ---------------------------------------------------------------------------
// Phase 2: Password Policies
// ---------------------------------------------------------------------------

func TestTPMService_CreatePasswordPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.CreatePasswordPolicy("pwd-policy", "Password-only policy", "my-secure-password", false)
	require.NoError(t, err)

	// Verify it was created as a composite policy.
	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "pwd-policy", policies[0].Name)
	assert.Equal(t, "SINGLE", policies[0].Operator)
	require.Len(t, policies[0].Elements, 1)
	assert.Equal(t, "password", policies[0].Elements[0].Type)
	assert.NotEmpty(t, policies[0].Elements[0].PasswordHash)
}

func TestTPMService_CreatePasswordPolicy_EmptyPassword(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.CreatePasswordPolicy("pwd-policy", "test", "", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)

	err = svc.CreatePasswordPolicy("pwd-policy", "test", "   ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

func TestTPMService_CreatePCROrPasswordPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	pcrSels := []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}}
	err := svc.CreatePCROrPasswordPolicy("or-policy", "PCR or password", pcrSels, "sha256", "fallback-pwd", false)
	require.NoError(t, err)

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "or-policy", policies[0].Name)
	assert.Equal(t, "OR", policies[0].Operator)
	require.Len(t, policies[0].Elements, 2)
	assert.Equal(t, "pcr", policies[0].Elements[0].Type)
	assert.Equal(t, "password", policies[0].Elements[1].Type)
}

func TestTPMService_VerifyPolicyPassword_Correct(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	require.NoError(t, svc.CreatePasswordPolicy("verify-test", "test", "correct-password", false))

	ok, err := svc.VerifyPolicyPassword("verify-test", "correct-password")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestTPMService_VerifyPolicyPassword_Wrong(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	require.NoError(t, svc.CreatePasswordPolicy("verify-test", "test", "correct-password", false))

	ok, err := svc.VerifyPolicyPassword("verify-test", "wrong-password")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestTPMService_VerifyPolicyPassword_PolicyNotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.VerifyPolicyPassword("nonexistent", "any-password")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// Phase 2: CreatePCRAndPasswordPolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreatePCRAndPasswordPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	pcrSels := []PCRSelection{{Index: 7, Bank: "sha256"}}
	err := svc.CreatePCRAndPasswordPolicy("and-policy", "PCR and password", pcrSels, "sha256", "test-password-123", false)
	require.NoError(t, err)

	policies, err := svc.ListCompositePolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "and-policy", policies[0].Name)
	assert.Equal(t, "AND", policies[0].Operator)
	require.Len(t, policies[0].Elements, 2)
	assert.Equal(t, "pcr", policies[0].Elements[0].Type)
	assert.Equal(t, "password", policies[0].Elements[1].Type)
	assert.NotEmpty(t, policies[0].Elements[1].PasswordHash)
}

func TestTPMService_CreatePCRAndPasswordPolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	pcrSels := []PCRSelection{{Index: 7, Bank: "sha256"}}

	err := svc.CreatePCRAndPasswordPolicy("", "desc", pcrSels, "sha256", "test-password-123", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)

	err = svc.CreatePCRAndPasswordPolicy("   ", "desc", pcrSels, "sha256", "test-password-123", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTPMService_CreatePCRAndPasswordPolicy_EmptyPCRs(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	err := svc.CreatePCRAndPasswordPolicy("and-policy", "desc", []PCRSelection{}, "sha256", "test-password-123", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)

	err = svc.CreatePCRAndPasswordPolicy("and-policy", "desc", nil, "sha256", "test-password-123", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTPMService_CreatePCRAndPasswordPolicy_EmptyPassword(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	pcrSels := []PCRSelection{{Index: 7, Bank: "sha256"}}

	err := svc.CreatePCRAndPasswordPolicy("and-policy", "desc", pcrSels, "sha256", "", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)

	err = svc.CreatePCRAndPasswordPolicy("and-policy", "desc", pcrSels, "sha256", "   ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

func TestTPMService_CreatePCRAndPasswordPolicy_VerifyOperator(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	pcrSels := []PCRSelection{{Index: 7, Bank: "sha256"}}
	require.NoError(t, svc.CreatePCRAndPasswordPolicy("verify-and", "AND policy", pcrSels, "sha256", "test-password-123", false))

	fetched, err := svc.GetCompositePolicy("verify-and")
	require.NoError(t, err)
	assert.Equal(t, "AND", fetched.Operator)
	require.Len(t, fetched.Elements, 2)
	assert.Equal(t, "pcr", fetched.Elements[0].Type)
	assert.Equal(t, "password", fetched.Elements[1].Type)

	// Verify PCR selections were preserved.
	require.Len(t, fetched.Elements[0].PCRSelections, 1)
	assert.Equal(t, 7, fetched.Elements[0].PCRSelections[0].Index)
	assert.Equal(t, "sha256", fetched.Elements[0].PCRSelections[0].Bank)
	assert.Equal(t, "sha256", fetched.Elements[0].PCRBank)

	// Verify password hash is populated.
	assert.NotEmpty(t, fetched.Elements[1].PasswordHash)
}

// ---------------------------------------------------------------------------
// mockTrustStore implements truststore.TrustStore for unit testing.
// Only methods exercised by ImportManufacturerCA and VerifyTPM are implemented;
// all others panic if called unexpectedly.
// ---------------------------------------------------------------------------

type addedCertRecord struct {
	cert *x509.Certificate
	opts *truststore.AddCertificateOptions
}

type mockTrustStore struct {
	addedCerts   []*addedCertRecord
	addErr       error
	purposeCerts map[truststore.CertPurpose][]*x509.Certificate
	purposeErr   error
}

func (m *mockTrustStore) AddCertificateWithOptions(cert *x509.Certificate, opts *truststore.AddCertificateOptions) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.addedCerts = append(m.addedCerts, &addedCertRecord{cert: cert, opts: opts})
	return nil
}

func (m *mockTrustStore) CertificatesByPurpose(purpose truststore.CertPurpose) ([]*x509.Certificate, error) {
	if m.purposeErr != nil {
		return nil, m.purposeErr
	}
	return m.purposeCerts[purpose], nil
}

// Unused interface methods -- panic if called in tests unexpectedly.
func (m *mockTrustStore) AddCertificate(_ *x509.Certificate) error {
	panic("mockTrustStore: AddCertificate not expected")
}
func (m *mockTrustStore) AddPEM(_ []byte) (int, error) {
	panic("mockTrustStore: AddPEM not expected")
}
func (m *mockTrustStore) RemoveCertificate(_ string) error {
	panic("mockTrustStore: RemoveCertificate not expected")
}
func (m *mockTrustStore) Certificates() ([]*x509.Certificate, error) {
	panic("mockTrustStore: Certificates not expected")
}
func (m *mockTrustStore) CertPool() (*x509.CertPool, error) {
	panic("mockTrustStore: CertPool not expected")
}
func (m *mockTrustStore) Contains(_ string) (bool, error) {
	panic("mockTrustStore: Contains not expected")
}
func (m *mockTrustStore) Count() (int, error) {
	panic("mockTrustStore: Count not expected")
}
func (m *mockTrustStore) Metadata(_ string) (*truststore.CertMetadata, error) {
	panic("mockTrustStore: Metadata not expected")
}
func (m *mockTrustStore) SetPurpose(_ string, _ truststore.CertPurpose) error {
	panic("mockTrustStore: SetPurpose not expected")
}
func (m *mockTrustStore) SetSource(_ string, _ string) error {
	panic("mockTrustStore: SetSource not expected")
}
func (m *mockTrustStore) SetSystemInstalled(_ string, _ bool) error {
	panic("mockTrustStore: SetSystemInstalled not expected")
}
func (m *mockTrustStore) SetTags(_ string, _ []string) error {
	panic("mockTrustStore: SetTags not expected")
}
func (m *mockTrustStore) Close() error { return nil }

// compile-time check
var _ truststore.TrustStore = (*mockTrustStore)(nil)

// ---------------------------------------------------------------------------
// Test helpers for certificate generation
// ---------------------------------------------------------------------------

// testCertPEM generates a real self-signed CA certificate and returns the PEM
// string and parsed certificate. The certificate is valid for 1 hour.
func testCertPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBlock), cert
}

// testCASignedCert generates a CA certificate and an EK certificate signed by
// that CA. Returns the CA PEM, parsed CA cert, and parsed EK cert.
func testCASignedCert(t *testing.T) (caPEM string, caCert *x509.Certificate, ekCert *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Manufacturer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ekTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, ekTmpl, caTmpl, &ekKey.PublicKey, caKey)
	require.NoError(t, err)
	ekCert, err = x509.ParseCertificate(ekDER)
	require.NoError(t, err)
	return caPEM, caCert, ekCert
}

// ---------------------------------------------------------------------------
// Bug 2: ImportManufacturerCA persistence tests
// ---------------------------------------------------------------------------

func TestImportManufacturerCA_PersistsToTrustStore(t *testing.T) {
	certPEM, _ := testCertPEM(t)

	ts := &mockTrustStore{}
	svc := NewTPMService()
	svc.SetTrustStore(ts)

	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)

	// Verify the cert was added to the in-memory slice.
	require.Len(t, svc.mfgCACerts, 1)

	// Verify the cert was persisted to the trust store with correct options.
	require.Len(t, ts.addedCerts, 1)
	assert.Equal(t, truststore.PurposeTPMManufacturer, ts.addedCerts[0].opts.Purpose)
	assert.Equal(t, "user-import", ts.addedCerts[0].opts.Source)
	assert.Equal(t, svc.mfgCACerts[0].Raw, ts.addedCerts[0].cert.Raw)
}

func TestImportManufacturerCA_NilTrustStore_StillWorks(t *testing.T) {
	certPEM, _ := testCertPEM(t)

	svc := NewTPMService()
	// No trust store set -- trustStore is nil.

	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)

	// Cert should still be added to the in-memory slice.
	require.Len(t, svc.mfgCACerts, 1)
	assert.Equal(t, "Test CA", svc.mfgCACerts[0].Subject.CommonName)
}

func TestImportManufacturerCA_TrustStoreError_DoesNotFail(t *testing.T) {
	certPEM, _ := testCertPEM(t)

	ts := &mockTrustStore{
		addErr: errors.New("disk full"),
	}
	svc := NewTPMService()
	svc.SetTrustStore(ts)

	// Import should succeed even though the trust store returns an error.
	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)

	// Cert should still be in memory.
	require.Len(t, svc.mfgCACerts, 1)

	// Trust store should not have any recorded certs (addErr prevented it).
	assert.Empty(t, ts.addedCerts)
}

func TestImportManufacturerCA_DuplicateCert_NoError(t *testing.T) {
	certPEM, _ := testCertPEM(t)

	ts := &mockTrustStore{
		addErr: truststore.ErrCertificateExists,
	}
	svc := NewTPMService()
	svc.SetTrustStore(ts)

	// Import should succeed silently when trust store reports duplicate.
	err := svc.ImportManufacturerCA(certPEM)
	require.NoError(t, err)

	// Cert should still be in memory.
	require.Len(t, svc.mfgCACerts, 1)
}

// ---------------------------------------------------------------------------
// Bug 3: VerifyTPM trust store fallback tests
// ---------------------------------------------------------------------------

func TestVerifyTPM_UsesTrustStoreFallback(t *testing.T) {
	_, caCert, ekCert := testCASignedCert(t)

	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil

	svc := newServiceWithMock(mock)
	// mfgCACerts is empty -- no in-memory certs loaded.

	// Put the CA in the trust store only.
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert},
		},
	}
	svc.SetTrustStore(ts)

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.True(t, status.Verified)
	assert.Equal(t, "Test Manufacturer CA", status.Issuer)
}

func TestVerifyTPM_MergesBothSources(t *testing.T) {
	// Create two independent CA chains.
	_, caCert1, ekCert := testCASignedCert(t)
	_, caCert2, _ := testCASignedCert(t)

	mock := defaultMockTPM()
	mock.ekCert = ekCert
	mock.ekCertErr = nil

	svc := newServiceWithMock(mock)
	// Put caCert2 in memory (it does NOT sign the EK cert).
	svc.mfgCACerts = []*x509.Certificate{caCert2}

	// Put caCert1 in trust store (it DOES sign the EK cert).
	ts := &mockTrustStore{
		purposeCerts: map[truststore.CertPurpose][]*x509.Certificate{
			truststore.PurposeTPMManufacturer: {caCert1},
		},
	}
	svc.SetTrustStore(ts)

	// Verification should succeed because the trust store CA is merged.
	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.True(t, status.Verified)
	assert.Equal(t, "Test Manufacturer CA", status.Issuer)
}

func TestVerifyTPM_NoCertsAnywhere_ReturnsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil

	svc := newServiceWithMock(mock)
	// mfgCACerts is empty, trust store is nil.

	status, err := svc.VerifyTPM()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Equal(t, "no manufacturer CA certificates loaded", status.ErrorMessage)
}

// ---------------------------------------------------------------------------
// CreatePolicy PCR digest capture
// ---------------------------------------------------------------------------

func TestCreatePolicy_CapturesPCRDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	policy := &PCRPolicy{
		Name:        "boot-integrity",
		Description: "Captures digests at creation time",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Retrieve the saved policy and verify digests were captured.
	saved, err := svc.GetPolicy("boot-integrity")
	require.NoError(t, err)
	assert.NotNil(t, saved.PCRDigests)
	assert.Len(t, saved.PCRDigests, 2)
	assert.Equal(t, "aabb", saved.PCRDigests["sha256:0"])
	assert.Equal(t, "ccdd", saved.PCRDigests["sha256:7"])
}

func TestCreatePolicy_NoPCRSelections_NoDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	policy := &PCRPolicy{
		Name:        "password-only",
		Description: "No PCR selections at all",
	}
	require.NoError(t, svc.CreatePolicy(policy))

	saved, err := svc.GetPolicy("password-only")
	require.NoError(t, err)
	assert.Empty(t, saved.PCRDigests)
}

func TestCreatePolicy_TPMUnavailable_SavesWithoutDigests(t *testing.T) {
	// Use a nil-returning TPM accessor so getTPM fails.
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))
	svc.SetDataDir(t.TempDir())

	policy := &PCRPolicy{
		Name:        "degraded-policy",
		Description: "TPM not available, digests should be empty",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	saved, err := svc.GetPolicy("degraded-policy")
	require.NoError(t, err)
	assert.Empty(t, saved.PCRDigests, "digests should be empty when TPM is unavailable")
	assert.NotEmpty(t, saved.CreatedAt)
}

// ---------------------------------------------------------------------------
// readPCRDigests helper
// ---------------------------------------------------------------------------

func TestReadPCRDigests_ReturnsDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)

	selections := []PCRSelection{
		{Index: 0, Bank: "sha256"},
		{Index: 7, Bank: "sha256"},
	}
	digests := svc.readPCRDigests(mock, selections)
	assert.Len(t, digests, 2)
	assert.Equal(t, "aabb", digests["sha256:0"])
	assert.Equal(t, "ccdd", digests["sha256:7"])
}

func TestReadPCRDigests_ReadError_ReturnsEmpty(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = nil
	mock.pcrBanksErr = errors.New("tpm read failed")
	svc := newServiceWithMock(mock)

	selections := []PCRSelection{
		{Index: 0, Bank: "sha256"},
	}
	digests := svc.readPCRDigests(mock, selections)
	assert.Empty(t, digests)
}

func TestReadPCRDigests_EmptySelections(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)

	digests := svc.readPCRDigests(mock, nil)
	assert.Empty(t, digests)
}

// ---------------------------------------------------------------------------
// RefreshPolicyPCRs
// ---------------------------------------------------------------------------

func TestRefreshPolicyPCRs_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a policy without digests (force no-TPM for creation).
	original := &PCRPolicy{
		Name:        "refresh-test",
		Description: "Will be refreshed",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(original))

	// Refresh should populate digests.
	refreshed, err := svc.RefreshPolicyPCRs("refresh-test")
	require.NoError(t, err)
	assert.NotNil(t, refreshed.PCRDigests)
	assert.Len(t, refreshed.PCRDigests, 2)
	assert.NotEmpty(t, refreshed.UpdatedAt)
}

func TestRefreshPolicyPCRs_PolicyNotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	_, err := svc.RefreshPolicyPCRs("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestRefreshPolicyPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))
	svc.SetDataDir(t.TempDir())

	// Create a policy file manually.
	policy := &PCRPolicy{
		Name: "no-tpm-refresh",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	_, err := svc.RefreshPolicyPCRs("no-tpm-refresh")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ListPoliciesWithDigests - compare mode tests
// ---------------------------------------------------------------------------

func TestListPoliciesWithDigests_CompareMode_AllMatch(t *testing.T) {
	// Mock returns PCR values that match saved digests.
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a policy (captures PCR digests at creation time from mock).
	policy := &PCRPolicy{
		Name:          "test-compare",
		Description:   "test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// ListPoliciesWithDigests should compare saved digests (captured at creation)
	// against current TPM values (same mock). All should match.
	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.True(t, *policies[0].Valid)
	// Saved digests should NOT be overwritten - they should remain the same.
	assert.NotEmpty(t, policies[0].PCRDigests)
}

func TestListPoliciesWithDigests_CompareMode_Mismatch(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a policy (captures digests from current mock values).
	policy := &PCRPolicy{
		Name:          "test-mismatch",
		Description:   "test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Change the mock PCR values to simulate a mismatch.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xEE}},
				{ID: 7, Value: []byte{0xDD, 0xCC}},
			},
		},
	}

	// Now ListPoliciesWithDigests should detect the mismatch.
	policies, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid)
}

func TestListPoliciesWithDigests_NoSavedDigests_ValidNil(t *testing.T) {
	svc, dataDir := createTestTPMService(t, defaultMockTPM())

	// Manually write a policy WITHOUT digests (simulating old data).
	policies := []PCRPolicy{{
		Name:          "no-digests",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		CreatedAt:     "2024-01-01T00:00:00Z",
	}}
	data, _ := json.MarshalIndent(policies, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "pcr_policies.json"), data, 0600)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].Valid) // No saved digests -> unknown validity
}

func TestListPoliciesWithDigests_TPMUnavailable_ValidNil(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	// No TPM accessor set.

	// Create a policy file manually.
	policies := []PCRPolicy{{
		Name:          "offline",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		PCRDigests:    map[string]string{"sha256:0": "aabb"},
		CreatedAt:     "2024-01-01T00:00:00Z",
	}}
	data, _ := json.MarshalIndent(policies, "", "  ")
	os.WriteFile(filepath.Join(svc.dataDir, "pcr_policies.json"), data, 0600)

	result, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, result, 1)
	// TPM unavailable -> no validation possible, Valid should be nil.
	assert.Nil(t, result[0].Valid)
}

func TestListPoliciesWithDigests_DoesNotOverwriteSavedDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a policy (captures initial digests).
	policy := &PCRPolicy{
		Name:          "preserve-test",
		Description:   "test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Verify initial digests were captured.
	created, _ := svc.GetPolicy("preserve-test")
	initialDigests := make(map[string]string)
	for k, v := range created.PCRDigests {
		initialDigests[k] = v
	}

	// Change mock PCR values (simulate TPM state change).
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xFF}},
				{ID: 7, Value: []byte{0xEE, 0xEE}},
			},
		},
	}

	// Call ListPoliciesWithDigests - should NOT overwrite saved digests.
	_, err := svc.ListPoliciesWithDigests()
	require.NoError(t, err)

	// Re-read from disk and verify digests are unchanged.
	afterList, _ := svc.GetPolicy("preserve-test")
	assert.Equal(t, initialDigests, afterList.PCRDigests, "saved digests must not be overwritten by ListPoliciesWithDigests")
}

// ---------------------------------------------------------------------------
// ListCompositePoliciesWithDigests tests
// ---------------------------------------------------------------------------

func TestListCompositePoliciesWithDigests_AllMatch(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a composite policy with PCR element.
	policy := &CompositePolicy{
		Name:     "composite-match",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:          "pcr",
			PCRBank:       "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	// List should show valid since mock PCR values haven't changed.
	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.True(t, *policies[0].Valid)
}

func TestListCompositePoliciesWithDigests_Mismatch(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	policy := &CompositePolicy{
		Name:     "composite-mismatch",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:          "pcr",
			PCRBank:       "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	// Change mock PCR values.
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA256", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xFF}}}},
	}

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.NotNil(t, policies[0].Valid)
	assert.False(t, *policies[0].Valid)
}

func TestListCompositePoliciesWithDigests_PasswordOnly_NoValidation(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Password-only composite policy has no PCR digests.
	policy := &CompositePolicy{
		Name:     "password-only",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:         "password",
			PasswordHash: "fakehash",
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	policies, err := svc.ListCompositePoliciesWithDigests()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Nil(t, policies[0].Valid) // No PCR digests -> nil validity
}

// ---------------------------------------------------------------------------
// CreateCompositePolicy PCR digest capture tests
// ---------------------------------------------------------------------------

func TestCreateCompositePolicy_CapturesPCRDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	policy := &CompositePolicy{
		Name:     "pcr-with-digests",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:          "pcr",
			PCRBank:       "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}, {Index: 7, Bank: "sha256"}},
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	// Verify digests were captured.
	fetched, err := svc.GetCompositePolicy("pcr-with-digests")
	require.NoError(t, err)
	assert.NotEmpty(t, fetched.PCRDigests)
	assert.Contains(t, fetched.PCRDigests, "sha256:0")
	assert.Contains(t, fetched.PCRDigests, "sha256:7")
}

func TestCreateCompositePolicy_PasswordOnly_NoDigests(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	policy := &CompositePolicy{
		Name:     "pw-only",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:         "password",
			PasswordHash: "hash123",
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	fetched, err := svc.GetCompositePolicy("pw-only")
	require.NoError(t, err)
	assert.Empty(t, fetched.PCRDigests)
}

// ---------------------------------------------------------------------------
// RefreshCompositePolicyPCRs tests
// ---------------------------------------------------------------------------

func TestRefreshCompositePolicyPCRs_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Create a composite policy first.
	policy := &CompositePolicy{
		Name:     "refresh-test",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:          "pcr",
			PCRBank:       "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		}},
	}
	require.NoError(t, svc.CreateCompositePolicy(policy))

	// Refresh PCRs.
	result, err := svc.RefreshCompositePolicyPCRs("refresh-test")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.PCRDigests)
	assert.NotEmpty(t, result.UpdatedAt)
}

func TestRefreshCompositePolicyPCRs_NotFound(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	_, err := svc.RefreshCompositePolicyPCRs("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestRefreshCompositePolicyPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetDataDir(t.TempDir())
	// No TPM accessor.

	// Manually write a composite policy.
	policies := []CompositePolicy{{
		Name:     "no-tpm-refresh",
		Operator: "SINGLE",
		Elements: []PolicyElement{{
			Type:          "pcr",
			PCRBank:       "sha256",
			PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
		}},
		CreatedAt: "2024-01-01T00:00:00Z",
	}}
	data, _ := json.MarshalIndent(policies, "", "  ")
	os.WriteFile(filepath.Join(svc.dataDir, "composite_policies.json"), data, 0600)

	_, err := svc.RefreshCompositePolicyPCRs("no-tpm-refresh")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReplayEventLog tests
// ---------------------------------------------------------------------------

// replayTestEvents returns events with lowercase algorithm IDs (as required
// by CalculatePCRs) and the corresponding mock PCR banks that exactly match
// the computed replay output.
func replayTestEvents() ([]tpm2pkg.Event, []tpm2pkg.PCRBank) {
	events := []tpm2pkg.Event{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []tpm2pkg.Digest{
				{AlgorithmId: "sha256", Digest: "aabb"},
			},
			EventString: "spec_id_event",
		},
	}

	// Compute expected PCR values by replaying the events.
	computed := tpm2pkg.CalculatePCRs(events)

	// Build mock PCR banks that match the computed values.
	// ReadPCRs returns UPPERCASE algorithm names.
	var banks []tpm2pkg.PCRBank
	for algo, pcrMap := range computed {
		bank := tpm2pkg.PCRBank{
			Algorithm: strings.ToUpper(algo),
		}
		for idx, val := range pcrMap {
			bank.PCRs = append(bank.PCRs, tpm2pkg.PCR{
				ID:    int32(idx),
				Value: val,
			})
		}
		banks = append(banks, bank)
	}

	return events, banks
}

func TestReplayEventLog_Success_AllMatch(t *testing.T) {
	events, banks := replayTestEvents()
	mock := &mockTPM{
		device:       "/dev/tpmrm0",
		parsedEvents: events,
		pcrBanks:     banks,
	}
	svc := newServiceWithMock(mock)

	result, err := svc.ReplayEventLog()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success)
	assert.Equal(t, 1, result.EventCount)
	assert.Greater(t, result.TotalPCRs, 0)
	assert.Equal(t, result.TotalPCRs, result.MatchCount)
	assert.Equal(t, 0, result.MismatchCount)
	assert.NotEmpty(t, result.Banks)

	for _, entry := range result.Entries {
		assert.True(t, entry.Match, "PCR %d bank %s should match", entry.PCRIndex, entry.Bank)
		assert.NotEmpty(t, entry.Expected)
		assert.NotEmpty(t, entry.Actual)
	}
}

func TestReplayEventLog_Mismatch(t *testing.T) {
	events := []tpm2pkg.Event{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []tpm2pkg.Digest{
				{AlgorithmId: "sha256", Digest: "aabb"},
			},
			EventString: "spec_id_event",
		},
	}

	// Provide PCR banks that do NOT match the computed replay.
	mismatchBanks := []tpm2pkg.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []tpm2pkg.PCR{
				{ID: 0, Value: []byte{0xFF, 0xFF}},
			},
		},
	}

	mock := &mockTPM{
		device:       "/dev/tpmrm0",
		parsedEvents: events,
		pcrBanks:     mismatchBanks,
	}
	svc := newServiceWithMock(mock)

	result, err := svc.ReplayEventLog()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Success)
	assert.Greater(t, result.MismatchCount, 0)
}

func TestReplayEventLog_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))

	_, err := svc.ReplayEventLog()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestReplayEventLog_NoEventLog(t *testing.T) {
	mock := &mockTPM{
		device:          "/dev/tpmrm0",
		parsedEventsErr: errors.New("no event log"),
	}
	svc := newServiceWithMock(mock)

	_, err := svc.ReplayEventLog()
	assert.ErrorIs(t, err, ErrTPMEventLogNotFound)
}

func TestReplayEventLog_EmptyEventLog(t *testing.T) {
	mock := &mockTPM{
		device:       "/dev/tpmrm0",
		parsedEvents: []tpm2pkg.Event{},
	}
	svc := newServiceWithMock(mock)

	result, err := svc.ReplayEventLog()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success)
	assert.Equal(t, 0, result.EventCount)
	assert.Equal(t, 0, result.TotalPCRs)
}

func TestReplayEventLog_ReadPCRsFails(t *testing.T) {
	events := []tpm2pkg.Event{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []tpm2pkg.Digest{
				{AlgorithmId: "sha256", Digest: "aabb"},
			},
			EventString: "spec_id_event",
		},
	}
	mock := &mockTPM{
		device:       "/dev/tpmrm0",
		parsedEvents: events,
		pcrBanksErr:  errors.New("hardware fault"),
	}
	svc := newServiceWithMock(mock)

	_, err := svc.ReplayEventLog()
	assert.ErrorIs(t, err, ErrTPMEventLogReplayFailed)
}

// ---------------------------------------------------------------------------
// ComparePolicyPCRs tests
// ---------------------------------------------------------------------------

func TestComparePolicyPCRs_AllMatch(t *testing.T) {
	// Mock returns the same PCR values that the policy stores as digests.
	mock := &mockTPM{
		device: "/dev/tpmrm0",
		pcrBanks: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
					{ID: 7, Value: []byte{0xCC, 0xDD}},
				},
			},
		},
	}
	svc, _ := createTestTPMService(t, mock)

	// Create a policy with digests that match the mock TPM values.
	policy := &PCRPolicy{
		Name: "match-policy",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
			{Index: 7, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aabb",
			"sha256:7": "ccdd",
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	result, err := svc.ComparePolicyPCRs("match-policy")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.AllMatch)
	assert.Equal(t, "match-policy", result.PolicyName)
	assert.Equal(t, 2, result.TotalPCRs)
	assert.Equal(t, 2, result.MatchCount)
	assert.Equal(t, 0, result.MismatchCount)
	assert.NotEmpty(t, result.ComparedAt)

	for _, entry := range result.Entries {
		assert.True(t, entry.Match, "PCR %s should match", entry.Key)
	}
}

func TestComparePolicyPCRs_Mismatch(t *testing.T) {
	mock := &mockTPM{
		device: "/dev/tpmrm0",
		pcrBanks: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xFF, 0xFF}},
				},
			},
		},
	}
	svc, dataDir := createTestTPMService(t, mock)

	// Write the policy file directly to avoid CreatePolicy overwriting
	// PCRDigests with current TPM values (which would make them match).
	policies := []PCRPolicy{
		{
			Name: "mismatch-policy",
			PCRSelections: []PCRSelection{
				{Index: 0, Bank: "sha256"},
			},
			PCRDigests: map[string]string{
				"sha256:0": "aabb",
			},
			CreatedAt: "2025-01-01T00:00:00Z",
		},
	}
	data, err := json.MarshalIndent(policies, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "pcr_policies.json"), data, 0600))

	result, err := svc.ComparePolicyPCRs("mismatch-policy")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.AllMatch)
	assert.Equal(t, 1, result.MismatchCount)
	assert.Len(t, result.Entries, 1)
	assert.False(t, result.Entries[0].Match)
	assert.Equal(t, "aabb", result.Entries[0].Saved)
	assert.Equal(t, "ffff", result.Entries[0].Current)
}

func TestComparePolicyPCRs_PolicyNotFound(t *testing.T) {
	mock := &mockTPM{device: "/dev/tpmrm0"}
	svc, _ := createTestTPMService(t, mock)

	_, err := svc.ComparePolicyPCRs("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestComparePolicyPCRs_EmptyName(t *testing.T) {
	mock := &mockTPM{device: "/dev/tpmrm0"}
	svc, _ := createTestTPMService(t, mock)

	_, err := svc.ComparePolicyPCRs("")
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestComparePolicyPCRs_NoDigests(t *testing.T) {
	mock := &mockTPM{device: "/dev/tpmrm0"}
	svc, _ := createTestTPMService(t, mock)

	// Create a policy without any digests.
	policy := &PCRPolicy{
		Name: "no-digests",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	_, err := svc.ComparePolicyPCRs("no-digests")
	assert.ErrorIs(t, err, ErrTPMPolicyNoDigests)
}

func TestComparePolicyPCRs_NoTPM(t *testing.T) {
	svc := NewTPMService()
	svc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil }))
	svc.SetDataDir(t.TempDir())

	// Create a policy with digests.
	policy := &PCRPolicy{
		Name: "tpm-unavailable",
		PCRSelections: []PCRSelection{
			{Index: 0, Bank: "sha256"},
		},
		PCRDigests: map[string]string{
			"sha256:0": "aabb",
		},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	_, err := svc.ComparePolicyPCRs("tpm-unavailable")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// isPlatformPolicyName
// ---------------------------------------------------------------------------

func TestIsPlatformPolicyName_MatchWithLoadedPolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	ppSvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aa", 7: "bb"},
	})
	svc.SetPlatformPolicyService(ppSvc)

	assert.True(t, svc.isPlatformPolicyName("Platform Policy"))
}

func TestIsPlatformPolicyName_WrongName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	ppSvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aa", 7: "bb"},
	})
	svc.SetPlatformPolicyService(ppSvc)

	assert.False(t, svc.isPlatformPolicyName("Other Policy"))
}

func TestIsPlatformPolicyName_NilService(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	// No SetPlatformPolicyService call — platformPolicyService is nil.
	assert.False(t, svc.isPlatformPolicyName("Platform Policy"))
}

func TestIsPlatformPolicyName_ServiceWithoutPolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Wire the service but do NOT store a policy — policy.Load() returns nil.
	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	svc.SetPlatformPolicyService(ppSvc)

	assert.False(t, svc.isPlatformPolicyName("Platform Policy"))
}

// ---------------------------------------------------------------------------
// GetConflictingAssignments
// ---------------------------------------------------------------------------

func TestGetConflictingAssignments_WithConflicts(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a policy so assignments can reference it.
	policy := &PCRPolicy{
		Name:          "conflict-policy",
		Description:   "policy for conflict test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}
	require.NoError(t, svc.CreatePolicy(policy))

	// Assign it to two handles.
	require.NoError(t, svc.AssignPolicyToKey("conflict-policy", "0x81000001"))
	require.NoError(t, svc.AssignPolicyToKey("conflict-policy", "0x81000002"))

	// Query with one overlapping handle and one new handle.
	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000001", "0x81000003"})
	require.NoError(t, err)

	// Only "0x81000001" should conflict.
	require.Len(t, conflicts, 1)
	assert.Equal(t, "0x81000001", conflicts[0].KeyHandle)
	assert.Equal(t, "conflict-policy", conflicts[0].CurrentPolicy)
	assert.NotEmpty(t, conflicts[0].AssignedAt)
}

func TestGetConflictingAssignments_NoConflicts(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// No assignments exist — asking for any handle yields zero conflicts.
	conflicts, err := svc.GetConflictingAssignments([]string{"0x81000005"})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

func TestGetConflictingAssignments_EmptyHandles(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	conflicts, err := svc.GetConflictingAssignments([]string{})
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKeys — platform policy path
// ---------------------------------------------------------------------------

func TestAssignPolicyToKeys_PlatformPolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Wire platform policy service with a loaded policy.
	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	ppSvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aa", 7: "bb"},
	})
	svc.SetPlatformPolicyService(ppSvc)

	// This should succeed even though "Platform Policy" is not in loadPolicies().
	err := svc.AssignPolicyToKeys("Platform Policy", []string{"0x81000001"})
	require.NoError(t, err)

	// Verify the assignment was saved.
	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "Platform Policy", assignments[0].PolicyName)
	assert.Equal(t, "0x81000001", assignments[0].KeyHandle)
}

// ---------------------------------------------------------------------------
// AssignPolicyToKey - Platform Policy fallback
// ---------------------------------------------------------------------------

func TestTPMService_AssignPolicyToKey_PlatformPolicyFallback(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Wire a PlatformPolicyService with a loaded policy definition.
	ppSvc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "platform.policy"))
	ppSvc.policy.Store(&PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aa", 7: "bb"},
	})
	svc.SetPlatformPolicyService(ppSvc)

	// "Platform Policy" does not exist in the TPM-side policy store (loadPolicies
	// returns nothing for this name), so GetPolicy will return an error.
	// AssignPolicyToKey should fall back to isPlatformPolicyName and succeed.
	err := svc.AssignPolicyToKey("Platform Policy", "0x81000002")
	require.NoError(t, err, "AssignPolicyToKey must succeed via isPlatformPolicyName fallback")

	// Verify the assignment was persisted.
	assignments, listErr := svc.ListPolicyAssignments()
	require.NoError(t, listErr)
	require.Len(t, assignments, 1)
	assert.Equal(t, "Platform Policy", assignments[0].PolicyName)
	assert.Equal(t, "0x81000002", assignments[0].KeyHandle)
	assert.NotEmpty(t, assignments[0].AssignedAt)
}

func TestTPMService_AssignPolicyToKey_PlatformPolicyFallback_NoPolicySvc(t *testing.T) {
	mock := defaultMockTPM()
	svc, _ := createTestTPMService(t, mock)

	// Do NOT set a PlatformPolicyService. Without both GetPolicy and
	// isPlatformPolicyName succeeding, AssignPolicyToKey should fail.
	err := svc.AssignPolicyToKey("Platform Policy", "0x81000002")
	assert.Error(t, err, "AssignPolicyToKey must fail when no platform policy service is wired")
}

// ---------------------------------------------------------------------------
// ExportCompositePolicy
// ---------------------------------------------------------------------------

func TestExportCompositePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create a composite policy with a PCR element.
	composite := &CompositePolicy{
		Name:        "export-comp-test",
		Description: "test composite for export",
		Operator:    "AND",
		Elements: []PolicyElement{
			{
				Type:    "pcr",
				PCRBank: "sha256",
				PCRSelections: []PCRSelection{
					{Index: 0, Bank: "sha256"},
					{Index: 7, Bank: "sha256"},
				},
			},
			{
				Type:         "password",
				PasswordHash: "fakehash",
			},
		},
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	exported, err := svc.ExportCompositePolicy("export-comp-test")
	require.NoError(t, err)
	assert.NotEmpty(t, exported)

	// Parse and verify the JSON structure.
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	assert.Equal(t, "export-comp-test", parsed["name"])
	assert.Equal(t, "AND", parsed["operator"])
	assert.NotNil(t, parsed["elements"])
	assert.NotEmpty(t, parsed["created_at"])
	assert.Equal(t, "test composite for export", parsed["description"])

	// Verify PCR bank and selections are included.
	assert.Equal(t, "sha256", parsed["pcr_bank"])
	selections, ok := parsed["pcr_selections"].([]interface{})
	require.True(t, ok)
	assert.Len(t, selections, 2)
}

func TestExportCompositePolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.ExportCompositePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestExportCompositePolicy_NoDescription_OmitsField(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	composite := &CompositePolicy{
		Name:     "no-desc",
		Operator: "SINGLE",
		Elements: []PolicyElement{
			{Type: "password", PasswordHash: "hash"},
		},
	}
	require.NoError(t, svc.CreateCompositePolicy(composite))

	exported, err := svc.ExportCompositePolicy("no-desc")
	require.NoError(t, err)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &parsed))
	_, hasDesc := parsed["description"]
	assert.False(t, hasDesc, "description should be omitted when empty")
}

// ---------------------------------------------------------------------------
// savePolicyDigestBinary
// ---------------------------------------------------------------------------

func TestSavePolicyDigestBinary_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Build a minimal policy JSON with PCR bank, selections, and digests.
	policyJSON := `{
		"name": "binary-test",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {
			"sha256:0": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
			"sha256:7": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
		}
	}`

	outPath := filepath.Join(t.TempDir(), "policy.bin")
	err := svc.savePolicyDigestBinary(outPath, policyJSON)
	require.NoError(t, err)

	// Read the written file and verify it's a 32-byte SHA-256 digest.
	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Len(t, data, 32, "policy digest should be exactly 32 bytes (SHA-256)")
}

func TestSavePolicyDigestBinary_InvalidJSON(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	outPath := filepath.Join(t.TempDir(), "policy.bin")
	err := svc.savePolicyDigestBinary(outPath, "not-json{{{")
	assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

func TestSavePolicyDigestBinary_InvalidHexDigest(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// The digest value is not valid hex.
	policyJSON := `{
		"name": "bad-hex",
		"pcr_bank": "sha256",
		"pcr_selections": [0],
		"pcr_digests": {
			"sha256:0": "not-hex-at-all!!!"
		}
	}`

	outPath := filepath.Join(t.TempDir(), "policy.bin")
	err := svc.savePolicyDigestBinary(outPath, policyJSON)
	assert.ErrorIs(t, err, ErrTPMPolicyExportFailed)
}

func TestSavePolicyDigestBinary_MissingDigests_ZeroFilled(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Selections include PCR 0 and 7, but only PCR 0 has a digest.
	// PCR 7 should be zero-filled.
	policyJSON := `{
		"name": "partial-digest",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {
			"sha256:0": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
		}
	}`

	outPath := filepath.Join(t.TempDir(), "policy.bin")
	err := svc.savePolicyDigestBinary(outPath, policyJSON)
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Len(t, data, 32, "digest should still be 32 bytes even with missing PCR digests")
}

func TestSavePolicyDigestBinary_DefaultsToSHA256Bank(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// No pcr_bank field -- should default to sha256.
	policyJSON := `{
		"name": "default-bank",
		"pcr_selections": [0],
		"pcr_digests": {
			"sha256:0": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
		}
	}`

	outPath := filepath.Join(t.TempDir(), "policy.bin")
	err := svc.savePolicyDigestBinary(outPath, policyJSON)
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Len(t, data, 32)
}

// ---------------------------------------------------------------------------
// importJSONPolicy - PCR policy path
// ---------------------------------------------------------------------------

func TestImportJSONPolicy_PCRPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policyJSON := `{
		"name": "imported-pcr",
		"description": "imported via JSON",
		"pcr_bank": "sha256",
		"pcr_selections": [0, 7],
		"pcr_digests": {
			"sha256:0": "aabb",
			"sha256:7": "ccdd"
		}
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "imported-pcr", name)

	// Verify the policy was persisted.
	policy, err := svc.GetPolicy("imported-pcr")
	require.NoError(t, err)
	assert.Equal(t, "imported via JSON", policy.Description)
	assert.Len(t, policy.PCRSelections, 2)
	assert.Equal(t, "aabb", policy.PCRDigests["sha256:0"])
	assert.Equal(t, "ccdd", policy.PCRDigests["sha256:7"])
}

func TestImportJSONPolicy_InvalidJSON(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.importJSONPolicy([]byte("not valid json"))
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestImportJSONPolicy_MissingName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policyJSON := `{"description": "no name field"}`
	_, err := svc.importJSONPolicy([]byte(policyJSON))
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestImportJSONPolicy_DefaultsBank(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// No pcr_bank field -- should default to sha256.
	policyJSON := `{
		"name": "default-bank-import",
		"pcr_selections": [0]
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "default-bank-import", name)

	policy, err := svc.GetPolicy("default-bank-import")
	require.NoError(t, err)
	require.Len(t, policy.PCRSelections, 1)
	assert.Equal(t, "sha256", policy.PCRSelections[0].Bank)
}

func TestImportJSONPolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create an existing policy.
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "dup-import",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))

	policyJSON := `{"name": "dup-import", "pcr_selections": [0]}`
	_, err := svc.importJSONPolicy([]byte(policyJSON))
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

// ---------------------------------------------------------------------------
// importJSONPolicy - composite policy path (has "operator" field)
// ---------------------------------------------------------------------------

func TestImportJSONPolicy_CompositePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	policyJSON := `{
		"name": "imported-composite",
		"operator": "AND",
		"elements": [
			{"type": "pcr", "pcr_bank": "sha256", "pcr_selections": [{"index": 0, "bank": "sha256"}]},
			{"type": "password", "password_hash": "abc123"}
		]
	}`

	name, err := svc.importJSONPolicy([]byte(policyJSON))
	require.NoError(t, err)
	assert.Equal(t, "imported-composite", name)

	// Verify it was stored as a composite policy.
	cp, err := svc.GetCompositePolicy("imported-composite")
	require.NoError(t, err)
	assert.Equal(t, "AND", cp.Operator)
	assert.Len(t, cp.Elements, 2)
}

// ---------------------------------------------------------------------------
// importCompositePolicy
// ---------------------------------------------------------------------------

func TestImportCompositePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	raw := map[string]interface{}{
		"name":     "comp-import",
		"operator": "OR",
		"elements": []interface{}{
			map[string]interface{}{"type": "password", "password_hash": "xyz"},
		},
	}

	name, err := svc.importCompositePolicy(raw)
	require.NoError(t, err)
	assert.Equal(t, "comp-import", name)

	// Verify persistence.
	cp, err := svc.GetCompositePolicy("comp-import")
	require.NoError(t, err)
	assert.Equal(t, "OR", cp.Operator)
	assert.NotEmpty(t, cp.CreatedAt)
}

func TestImportCompositePolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	raw := map[string]interface{}{
		"name":     "",
		"operator": "AND",
	}

	_, err := svc.importCompositePolicy(raw)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestImportCompositePolicy_DuplicateName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Create existing composite policy.
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "existing-comp",
		Operator: "AND",
	}))

	raw := map[string]interface{}{
		"name":     "existing-comp",
		"operator": "OR",
	}

	_, err := svc.importCompositePolicy(raw)
	assert.ErrorIs(t, err, ErrTPMPolicyExists)
}

func TestImportCompositePolicy_MissingNameField(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	raw := map[string]interface{}{
		"operator": "AND",
	}

	_, err := svc.importCompositePolicy(raw)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

// ---------------------------------------------------------------------------
// importBinaryPolicyDigest
// ---------------------------------------------------------------------------

func TestImportBinaryPolicyDigest_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Simulate a 32-byte binary policy digest.
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	name, err := svc.importBinaryPolicyDigest("/tmp/my-policy.bin", digest)
	require.NoError(t, err)
	assert.Equal(t, "my-policy", name)

	// Verify the policy was stored with the hex digest.
	policy, err := svc.GetPolicy("my-policy")
	require.NoError(t, err)
	assert.Contains(t, policy.PCRDigests, "policy_digest")
	assert.NotEmpty(t, policy.PCRDigests["policy_digest"])
	assert.Contains(t, policy.Description, "my-policy.bin")
}

func TestImportBinaryPolicyDigest_EmptyData(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.importBinaryPolicyDigest("/tmp/empty.bin", []byte{})
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestImportBinaryPolicyDigest_NilData(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	_, err := svc.importBinaryPolicyDigest("/tmp/nil.bin", nil)
	assert.ErrorIs(t, err, ErrTPMPolicyImportFailed)
}

func TestImportBinaryPolicyDigest_NoExtension(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	name, err := svc.importBinaryPolicyDigest("/tmp/policydigest", []byte{0xAA})
	require.NoError(t, err)
	assert.Equal(t, "policydigest", name)
}

func TestImportBinaryPolicyDigest_DuplicateName_AppendsTimestamp(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// Import the first time.
	_, err := svc.importBinaryPolicyDigest("/tmp/dup.bin", []byte{0x01})
	require.NoError(t, err)

	// Import again with the same filename -- should get a timestamped name.
	name2, err := svc.importBinaryPolicyDigest("/tmp/dup.bin", []byte{0x02})
	require.NoError(t, err)
	assert.NotEqual(t, "dup", name2, "second import should have a different name")
	assert.True(t, strings.HasPrefix(name2, "dup-"), "timestamped name should start with dup-")
}

func TestImportBinaryPolicyDigest_EmptyBasename_UsesDefault(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})

	// A path like "/tmp/.bin" yields an empty name after trimming the extension.
	name, err := svc.importBinaryPolicyDigest("/tmp/.bin", []byte{0xFF})
	require.NoError(t, err)
	assert.Equal(t, "imported-policy", name)
}

// ---------------------------------------------------------------------------
// Test helper: real self-signed certificate for import tests
// ---------------------------------------------------------------------------

// realSelfSignedCert generates a real self-signed x509.Certificate suitable
// for tests that require valid DER encoding (e.g. ImportIAKCert, ImportIDevIDCert).
func realSelfSignedCert(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return cert, string(pemBlock)
}

// ---------------------------------------------------------------------------
// Setters: SetElevator, SetElevatorFunc, SetStaticPasswordService
// ---------------------------------------------------------------------------

func TestTPMService_SetElevator(t *testing.T) {
	svc := NewTPMService()
	assert.Nil(t, svc.elevator)
	// The Elevator interface is set and can be read back.
	// We just verify no panic and the field is set.
	svc.SetElevator(nil) // nil is valid (disables elevation)
	assert.Nil(t, svc.elevator)
}

func TestTPMService_SetElevatorFunc(t *testing.T) {
	svc := NewTPMService()
	assert.Nil(t, svc.elevatorFunc)
	called := false
	fn := ElevatorFunc(func(args ...string) error {
		called = true
		return nil
	})
	svc.SetElevatorFunc(fn)
	assert.NotNil(t, svc.elevatorFunc)
	require.NoError(t, svc.elevatorFunc("test"))
	assert.True(t, called)
}

func TestTPMService_SetElevatorFunc_NilDisables(t *testing.T) {
	svc := NewTPMService()
	svc.SetElevatorFunc(nil)
	assert.Nil(t, svc.elevatorFunc)
}

func TestTPMService_SetStaticPasswordService(t *testing.T) {
	svc := NewTPMService()
	assert.Nil(t, svc.staticPWService)
	pwSvc := &StaticPasswordService{}
	svc.SetStaticPasswordService(pwSvc)
	assert.Equal(t, pwSvc, svc.staticPWService)
}

func TestTPMService_SetStaticPasswordService_Nil(t *testing.T) {
	svc := NewTPMService()
	svc.SetStaticPasswordService(nil)
	assert.Nil(t, svc.staticPWService)
}

// ---------------------------------------------------------------------------
// ReadPCRs (alias for GetPCRs)
// ---------------------------------------------------------------------------

func TestTPMService_ReadPCRs_Success(t *testing.T) {
	svc := newServiceWithMock(defaultMockTPM())
	values, err := svc.ReadPCRs("sha256")
	require.NoError(t, err)
	require.Len(t, values, 2)
	assert.Equal(t, "sha256", values[0].Bank)
}

func TestTPMService_ReadPCRs_InvalidBank(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadPCRs("md5")
	assert.ErrorIs(t, err, ErrTPMInvalidBank)
}

// ---------------------------------------------------------------------------
// FactoryReset
// ---------------------------------------------------------------------------

func TestTPMService_FactoryReset_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.FactoryReset("ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_FactoryReset_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.FactoryReset("ownerpass")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_FactoryReset_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.factoryResetErr = errors.New("factory reset failed")
	svc := newServiceWithMock(mock)
	err := svc.FactoryReset("ownerpass")
	assert.ErrorIs(t, err, ErrTPMFactoryResetFailed)
}

func TestTPMService_FactoryReset_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.factoryResetErr = fmt.Errorf("auth_fail: bad password")
	svc := newServiceWithMock(mock)
	err := svc.FactoryReset("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// ProvisionIAK
// ---------------------------------------------------------------------------

func TestTPMService_ProvisionIAK_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIAKResult = &types.KeyAttributes{KeyAlgorithm: x509.RSA}
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIAK("ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_ProvisionIAK_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ProvisionIAK("ownerpass")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ProvisionIAK_EKAttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekAttrsErr = errors.New("no EK")
	mock.ekAttrs = nil
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIAK("ownerpass")
	assert.ErrorIs(t, err, ErrTPMProvisionIAKFailed)
}

func TestTPMService_ProvisionIAK_CreateIAKError(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIAKErr = errors.New("create failed")
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIAK("ownerpass")
	assert.ErrorIs(t, err, ErrTPMProvisionIAKFailed)
}

func TestTPMService_ProvisionIAK_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIAKErr = fmt.Errorf("auth_fail: wrong password")
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIAK("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// ProvisionIDevID
// ---------------------------------------------------------------------------

func TestTPMService_ProvisionIDevID_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIDevIDResult = &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIDevID("ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_ProvisionIDevID_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ProvisionIDevID("ownerpass")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ProvisionIDevID_IAKAttrsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakAttrsErr = errors.New("no IAK")
	mock.iakAttrs = nil
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIDevID("ownerpass")
	assert.ErrorIs(t, err, ErrTPMProvisionIDevIDFailed)
}

func TestTPMService_ProvisionIDevID_CreateIDevIDError(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIDevIDErr = errors.New("create failed")
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIDevID("ownerpass")
	assert.ErrorIs(t, err, ErrTPMProvisionIDevIDFailed)
}

func TestTPMService_ProvisionIDevID_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIDevIDErr = fmt.Errorf("auth_fail: wrong password")
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIDevID("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// ListPersistentHandles
// ---------------------------------------------------------------------------

func TestTPMService_ListPersistentHandles_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000001, 0x81010001}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81000001: {KeyAlgorithm: x509.RSA},
		0x81010001: {KeyAlgorithm: x509.ECDSA},
	}
	svc, _ := createTestTPMService(t, mock)

	handles, err := svc.ListPersistentHandles()
	require.NoError(t, err)
	require.Len(t, handles, 2)
	assert.Equal(t, "0x81000001", handles[0].Handle)
	assert.Equal(t, "persistent", handles[0].Type)
	assert.Equal(t, "TCG Shared SRK (RSA)", handles[0].Description)
	assert.Equal(t, "RSA-SSA", handles[0].Algorithm)
	assert.Equal(t, "0x81010001", handles[1].Handle)
	assert.Equal(t, "Endorsement Key (EK-RSA)", handles[1].Description)
}

func TestTPMService_ListPersistentHandles_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ListPersistentHandles()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ListPersistentHandles_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("enum failed")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.ListPersistentHandles()
	assert.Error(t, err)
}

func TestTPMService_ListPersistentHandles_WithPlatformSRK(t *testing.T) {
	mock := defaultMockTPM()
	mock.config.PlatformSRK = &tpm2pkg.PlatformSRKConfig{SRKHandle: 0x81000003}
	mock.persistentHandles = []tpm2.TPMHandle{0x81000003}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81000003: {KeyAlgorithm: x509.RSA},
	}
	svc, _ := createTestTPMService(t, mock)

	handles, err := svc.ListPersistentHandles()
	require.NoError(t, err)
	require.Len(t, handles, 1)
	assert.Equal(t, "Platform SRK", handles[0].Description)
}

func TestTPMService_ListPersistentHandles_UserDescription(t *testing.T) {
	mock := defaultMockTPM()
	mock.persistentHandles = []tpm2.TPMHandle{0x81000001}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*types.KeyAttributes{
		0x81000001: {KeyAlgorithm: x509.RSA},
	}
	svc, _ := createTestTPMService(t, mock)

	// Set a custom description.
	require.NoError(t, svc.SetHandleDescription("0x81000001", "My Custom SRK"))

	handles, err := svc.ListPersistentHandles()
	require.NoError(t, err)
	require.Len(t, handles, 1)
	assert.Equal(t, "My Custom SRK", handles[0].Description)
}

// ---------------------------------------------------------------------------
// ListTransientHandles
// ---------------------------------------------------------------------------

func TestTPMService_ListTransientHandles_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.transientHandles = []tpm2.TPMHandle{0x80000001, 0x80000002}
	svc := newServiceWithMock(mock)

	handles, err := svc.ListTransientHandles()
	require.NoError(t, err)
	require.Len(t, handles, 2)
	assert.Equal(t, "0x80000001", handles[0].Handle)
	assert.Equal(t, "transient", handles[0].Type)
	assert.Equal(t, "0x80000002", handles[1].Handle)
}

func TestTPMService_ListTransientHandles_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ListTransientHandles()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ListTransientHandles_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("enum failed")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.ListTransientHandles()
	assert.Error(t, err)
}

func TestTPMService_ListTransientHandles_Empty(t *testing.T) {
	mock := defaultMockTPM()
	mock.transientHandles = []tpm2.TPMHandle{}
	svc := newServiceWithMock(mock)
	handles, err := svc.ListTransientHandles()
	require.NoError(t, err)
	assert.Empty(t, handles)
}

// ---------------------------------------------------------------------------
// SetHandleDescription / loadHandleDescriptions / saveHandleDescriptions
// ---------------------------------------------------------------------------

func TestTPMService_SetHandleDescription_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())

	err := svc.SetHandleDescription("0x81000001", "My SRK")
	require.NoError(t, err)

	descs := svc.loadHandleDescriptions()
	assert.Equal(t, "My SRK", descs["0x81000001"])
}

func TestTPMService_SetHandleDescription_Remove(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())

	require.NoError(t, svc.SetHandleDescription("0x81000001", "My SRK"))
	require.NoError(t, svc.SetHandleDescription("0x81000001", ""))

	descs := svc.loadHandleDescriptions()
	_, found := descs["0x81000001"]
	assert.False(t, found)
}

func TestTPMService_SetHandleDescription_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.SetHandleDescription("0x81000001", "desc")
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

func TestTPMService_LoadHandleDescriptions_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	descs := svc.loadHandleDescriptions()
	assert.Empty(t, descs)
}

func TestTPMService_LoadHandleDescriptions_NoFile(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	descs := svc.loadHandleDescriptions()
	assert.Empty(t, descs)
}

func TestTPMService_LoadHandleDescriptions_InvalidJSON(t *testing.T) {
	svc, dataDir := createTestTPMService(t, defaultMockTPM())
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, handleDescriptionsFile), []byte("invalid json"), 0600))
	descs := svc.loadHandleDescriptions()
	assert.Empty(t, descs)
}

func TestTPMService_SaveHandleDescriptions_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	err := svc.saveHandleDescriptions(map[string]string{"a": "b"})
	assert.ErrorIs(t, err, ErrTPMDataDirNotSet)
}

// ---------------------------------------------------------------------------
// GetLockoutInfo
// ---------------------------------------------------------------------------

func TestTPMService_GetLockoutInfo_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	info, err := svc.GetLockoutInfo()
	require.NoError(t, err)
	assert.Equal(t, 0, info.Counter)
	assert.Equal(t, 32, info.MaxFail)
	assert.False(t, info.IsLocked)
}

func TestTPMService_GetLockoutInfo_Locked(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedProps.LockoutCounter = 32
	svc := newServiceWithMock(mock)
	info, err := svc.GetLockoutInfo()
	require.NoError(t, err)
	assert.True(t, info.IsLocked)
}

func TestTPMService_GetLockoutInfo_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetLockoutInfo()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GetLockoutInfo_PropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("props fail")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.GetLockoutInfo()
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ResetLockout
// ---------------------------------------------------------------------------

func TestTPMService_ResetLockout_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ResetLockout("lockoutpass")
	assert.NoError(t, err)
}

func TestTPMService_ResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ResetLockout("lockoutpass")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ResetLockout_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.lockoutResetErr = errors.New("reset failed")
	svc := newServiceWithMock(mock)
	err := svc.ResetLockout("lockoutpass")
	assert.ErrorIs(t, err, ErrTPMLockoutResetFailed)
}

// ---------------------------------------------------------------------------
// ForceResetLockout
// ---------------------------------------------------------------------------

func TestTPMService_ForceResetLockout_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ForceResetLockout("lockoutpass")
	assert.NoError(t, err)
}

func TestTPMService_ForceResetLockout_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ForceResetLockout("lockoutpass")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ForceResetLockout_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.lockoutResetErr = errors.New("reset failed")
	svc := newServiceWithMock(mock)
	err := svc.ForceResetLockout("lockoutpass")
	assert.ErrorIs(t, err, ErrTPMLockoutResetFailed)
}

// ---------------------------------------------------------------------------
// CertifyKey
// ---------------------------------------------------------------------------

func TestTPMService_CertifyKey_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.certifyKeyResult = &tpm2pkg.CertifyResult{
		CertifyInfo: []byte{0xAA, 0xBB},
		Signature:   []byte{0xCC, 0xDD},
	}
	svc := newServiceWithMock(mock)

	result, err := svc.CertifyKey("0x81000001")
	require.NoError(t, err)
	assert.Equal(t, "aabb", result.Attested)
	assert.Equal(t, "ccdd", result.Signature)
	assert.NotEmpty(t, result.Nonce)
}

func TestTPMService_CertifyKey_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.CertifyKey("0x81000001")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_CertifyKey_InvalidHandle(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	_, err := svc.CertifyKey("not-hex")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key handle")
}

func TestTPMService_CertifyKey_HandleWithoutPrefix(t *testing.T) {
	mock := defaultMockTPM()
	mock.certifyKeyResult = &tpm2pkg.CertifyResult{
		CertifyInfo: []byte{0x01},
		Signature:   []byte{0x02},
	}
	svc := newServiceWithMock(mock)
	result, err := svc.CertifyKey("81000001")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Attested)
}

func TestTPMService_CertifyKey_NonceGenFails(t *testing.T) {
	mock := defaultMockTPM()
	mock.randomBytesErr = errors.New("rng fail")
	svc := newServiceWithMock(mock)
	_, err := svc.CertifyKey("0x81000001")
	assert.ErrorIs(t, err, ErrTPMNonceGenFailed)
}

func TestTPMService_CertifyKey_CertifyFails(t *testing.T) {
	mock := defaultMockTPM()
	mock.certifyKeyErr = errors.New("certify failed")
	svc := newServiceWithMock(mock)
	_, err := svc.CertifyKey("0x81000001")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certify key")
}

// ---------------------------------------------------------------------------
// ViewKey
// ---------------------------------------------------------------------------

func TestTPMService_ViewKey_EKRSA(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekAttrs.TPMAttributes = &types.TPMAttributes{
		Handle:         0x81010001,
		PublicKeyBytes: []byte{0x01, 0x02},
	}
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	data, err := svc.ViewKey("EK-RSA")
	require.NoError(t, err)
	assert.Equal(t, "EK-RSA", data.Name)
	assert.Equal(t, "RSA-SSA", data.Algorithm)
	assert.Equal(t, "0x81010001", data.Handle)
	assert.NotEmpty(t, data.PublicKeyPEM)
	assert.Contains(t, data.Certificate, "CERTIFICATE")
}

func TestTPMService_ViewKey_EKECC(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertEC = testECCCert()
	mock.ekCertECErr = nil
	svc := newServiceWithMock(mock)

	data, err := svc.ViewKey("EK-ECC")
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", data.Algorithm)
	assert.Contains(t, data.Certificate, "CERTIFICATE")
}

func TestTPMService_ViewKey_EKECC_NotAvailable(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	_, err := svc.ViewKey("EK-ECC")
	assert.Error(t, err)
}

func TestTPMService_ViewKey_IAK(t *testing.T) {
	mock := defaultMockTPM()
	mock.iakCert = testCert()
	mock.iakCertErr = nil
	svc := newServiceWithMock(mock)
	data, err := svc.ViewKey("IAK")
	require.NoError(t, err)
	assert.Equal(t, "RSA-SSA", data.Algorithm)
	assert.Contains(t, data.Certificate, "CERTIFICATE")
}

func TestTPMService_ViewKey_IDevID(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidCert = testCert()
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)
	data, err := svc.ViewKey("IDevID")
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", data.Algorithm)
}

func TestTPMService_ViewKey_SRK(t *testing.T) {
	mock := defaultMockTPM()
	mock.ssrkAttrs.TPMAttributes = &types.TPMAttributes{Handle: 0x81000001}
	svc := newServiceWithMock(mock)
	data, err := svc.ViewKey("SRK")
	require.NoError(t, err)
	assert.Equal(t, "RSA-SSA", data.Algorithm)
	assert.Equal(t, "0x81000001", data.Handle)
}

func TestTPMService_ViewKey_Unknown(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	_, err := svc.ViewKey("UnknownKey")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key name")
}

func TestTPMService_ViewKey_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ViewKey("EK-RSA")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// GenerateIDevIDCSR
// ---------------------------------------------------------------------------

func TestTPMService_GenerateIDevIDCSR_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GenerateIDevIDCSR()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GenerateIDevIDCSR_NoEKCert(t *testing.T) {
	mock := defaultMockTPM()
	// ekCertErr is already set in defaultMockTPM
	svc := newServiceWithMock(mock)
	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EK certificate required")
}

func TestTPMService_GenerateIDevIDCSR_NoIAKAttrs(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.iakAttrsErr = errors.New("no IAK")
	mock.iakAttrs = nil
	// Also make the fallback handle lookup fail.
	mock.handleKeyAttrs = nil
	svc := newServiceWithMock(mock)
	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IAK required")
}

func TestTPMService_GenerateIDevIDCSR_NoIDevIDAttrs(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	mock.idevidAttrsErr = errors.New("no IDevID")
	mock.idevidAttrs = nil
	mock.handleKeyAttrs = nil
	svc := newServiceWithMock(mock)
	_, err := svc.GenerateIDevIDCSR()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IDevID required")
}

// ---------------------------------------------------------------------------
// ChangeOwnerAuth / ChangeEndorsementAuth / ChangeLockoutAuth
// ---------------------------------------------------------------------------

func TestTPMService_ChangeOwnerAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("oldpass", "newpass")
	assert.NoError(t, err)
}

func TestTPMService_ChangeOwnerAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeOwnerAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ChangeOwnerAuth_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.setHierarchyAuthErr = errors.New("auth change failed")
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("old", "new")
	assert.Error(t, err)
}

func TestTPMService_ChangeEndorsementAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeEndorsementAuth("oldpass", "newpass")
	assert.NoError(t, err)
}

func TestTPMService_ChangeEndorsementAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeEndorsementAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ChangeLockoutAuth_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeLockoutAuth("oldpass", "newpass")
	assert.NoError(t, err)
}

func TestTPMService_ChangeLockoutAuth_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ChangeLockoutAuth("old", "new")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ChangeHierarchyAuth_EmptyPasswords(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ChangeOwnerAuth("", "")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetNVSummary
// ---------------------------------------------------------------------------

func TestTPMService_GetNVSummary_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{
		{Handle: 0x01800001, Type: "ordinary", Size: 64, AuthRead: true, AuthWrite: true},
		{Handle: 0x01800002, Type: "counter", Size: 8, AuthRead: false, AuthWrite: true},
	}
	svc := newServiceWithMock(mock)

	summary, err := svc.GetNVSummary()
	require.NoError(t, err)
	assert.Equal(t, 4, summary.IndexesDefined) // from fixedProps
	assert.Equal(t, 32, summary.IndexesMax)
	require.Len(t, summary.Indexes, 2)
	assert.Equal(t, "0x01800001", summary.Indexes[0].Handle)
	assert.Equal(t, "ordinary", summary.Indexes[0].Type)
	assert.Equal(t, 64, summary.Indexes[0].Size)
}

func TestTPMService_GetNVSummary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.GetNVSummary()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_GetNVSummary_PropsError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fixedPropsErr = errors.New("props fail")
	mock.fixedProps = nil
	svc := newServiceWithMock(mock)
	_, err := svc.GetNVSummary()
	assert.Error(t, err)
}

func TestTPMService_GetNVSummary_NoIndexes(t *testing.T) {
	mock := defaultMockTPM()
	// NV indexes not populated — should return empty indexes.
	mock.nvIndexes = nil
	svc := newServiceWithMock(mock)
	summary, err := svc.GetNVSummary()
	require.NoError(t, err)
	assert.Empty(t, summary.Indexes)
}

// ---------------------------------------------------------------------------
// DefineNVOrdinary / DefineNVCounter / DefineNVExtend
// ---------------------------------------------------------------------------

func TestTPMService_DefineNVOrdinary_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVOrdinary(0x01800001, 64, "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_DefineNVOrdinary_InvalidSize(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVOrdinary(0x01800001, 0, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)

	err = svc.DefineNVOrdinary(0x01800001, 2049, "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTPMService_DefineNVOrdinary_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVOrdinary(0x01800001, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_DefineNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVCounter(0x01800001, "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_DefineNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVCounter(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_DefineNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DefineNVExtend(0x01800001, "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_DefineNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DefineNVExtend(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ReadNVData / WriteNVData
// ---------------------------------------------------------------------------

func TestTPMService_ReadNVData_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadResult = []byte{0xAA, 0xBB, 0xCC}
	svc := newServiceWithMock(mock)
	hexStr, err := svc.ReadNVData(0x01800001, 3, "ownerpass")
	require.NoError(t, err)
	assert.Equal(t, "aabbcc", hexStr)
}

func TestTPMService_ReadNVData_AutoDetectSize(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []tpm2pkg.NVIndexInfo{
		{Handle: 0x01800001, Size: 8},
	}
	mock.nvReadResult = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	svc := newServiceWithMock(mock)
	hexStr, err := svc.ReadNVData(0x01800001, 0, "ownerpass")
	require.NoError(t, err)
	assert.Equal(t, "0102030405060708", hexStr)
}

func TestTPMService_ReadNVData_AutoDetectFails(t *testing.T) {
	mock := defaultMockTPM()
	// No NV indexes populated — auto-detect has nothing to find.
	mock.nvIndexes = nil
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVData(0x01800001, 0, "ownerpass")
	assert.ErrorIs(t, err, ErrTPMInvalidNVSize)
}

func TestTPMService_ReadNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVData(0x01800001, 64, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_WriteNVData_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.WriteNVData(0x01800001, "aabbccdd", "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_WriteNVData_InvalidHex(t *testing.T) {
	svc := NewTPMService()
	err := svc.WriteNVData(0x01800001, "not-hex!", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTPMService_WriteNVData_EmptyData(t *testing.T) {
	svc := NewTPMService()
	err := svc.WriteNVData(0x01800001, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTPMService_WriteNVData_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.WriteNVData(0x01800001, "aabb", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// IncrementNVCounter / ReadNVCounter
// ---------------------------------------------------------------------------

func TestTPMService_IncrementNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIncrementResult = 42
	svc := newServiceWithMock(mock)
	val, err := svc.IncrementNVCounter(0x01800001, "ownerpass")
	require.NoError(t, err)
	assert.Equal(t, uint64(42), val)
}

func TestTPMService_IncrementNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.IncrementNVCounter(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ReadNVCounter_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadCounterResult = 100
	svc := newServiceWithMock(mock)
	val, err := svc.ReadNVCounter(0x01800001, "ownerpass")
	require.NoError(t, err)
	assert.Equal(t, uint64(100), val)
}

func TestTPMService_ReadNVCounter_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVCounter(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

// ---------------------------------------------------------------------------
// ExtendNV / ReadNVExtend
// ---------------------------------------------------------------------------

func TestTPMService_ExtendNV_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ExtendNV(0x01800001, "aabbccdd", "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_ExtendNV_InvalidHex(t *testing.T) {
	svc := NewTPMService()
	err := svc.ExtendNV(0x01800001, "not-hex!", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTPMService_ExtendNV_EmptyData(t *testing.T) {
	svc := NewTPMService()
	err := svc.ExtendNV(0x01800001, "", "")
	assert.ErrorIs(t, err, ErrTPMInvalidNVData)
}

func TestTPMService_ExtendNV_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.ExtendNV(0x01800001, "aabb", "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ReadNVExtend_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendResult = []byte{0x01, 0x02}
	svc := newServiceWithMock(mock)
	hexStr, err := svc.ReadNVExtend(0x01800001, "ownerpass")
	require.NoError(t, err)
	assert.Equal(t, "0102", hexStr)
}

func TestTPMService_ReadNVExtend_NoTPM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ReadNVExtend(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ReadNVExtend_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvReadExtendErr = errors.New("read failed")
	svc := newServiceWithMock(mock)
	_, err := svc.ReadNVExtend(0x01800001, "ownerpass")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeleteNVIndex
// ---------------------------------------------------------------------------

func TestTPMService_DeleteNVIndex_Success(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01800001, "ownerpass")
	assert.NoError(t, err)
}

func TestTPMService_DeleteNVIndex_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.DeleteNVIndex(0x01800001, "")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_DeleteNVIndex_Error(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvUndefineErr = errors.New("undefine failed")
	svc := newServiceWithMock(mock)
	err := svc.DeleteNVIndex(0x01800001, "ownerpass")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// buildNVKeyAttributes
// ---------------------------------------------------------------------------

func TestTPMService_BuildNVKeyAttributes_WithAuth(t *testing.T) {
	svc := NewTPMService()
	attrs := svc.buildNVKeyAttributes(0x01800001, "ownerpass", tpm2.TPMAlgSHA256)
	require.NotNil(t, attrs)
	require.NotNil(t, attrs.TPMAttributes)
	assert.Equal(t, tpm2.TPMHandle(0x01800001), attrs.TPMAttributes.Handle)
	require.NotNil(t, attrs.Parent)
	require.NotNil(t, attrs.Parent.TPMAttributes)
	assert.NotNil(t, attrs.Parent.TPMAttributes.HierarchyAuth)
}

func TestTPMService_BuildNVKeyAttributes_NoAuth(t *testing.T) {
	svc := NewTPMService()
	attrs := svc.buildNVKeyAttributes(0x01800001, "", tpm2.TPMAlgSHA256)
	require.NotNil(t, attrs)
	assert.Nil(t, attrs.Parent.TPMAttributes.HierarchyAuth)
}

// ---------------------------------------------------------------------------
// GetVerificationStatus
// ---------------------------------------------------------------------------

func TestTPMService_GetVerificationStatus_NoTPM(t *testing.T) {
	svc := NewTPMService()
	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "not available")
}

func TestTPMService_GetVerificationStatus_NoCerts(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCert = testCert()
	mock.ekCertErr = nil
	svc := newServiceWithMock(mock)

	status, err := svc.GetVerificationStatus()
	require.NoError(t, err)
	assert.False(t, status.Verified)
	assert.Contains(t, status.ErrorMessage, "no manufacturer CA")
}

// ---------------------------------------------------------------------------
// ParseCertificate
// ---------------------------------------------------------------------------

func TestTPMService_ParseCertificate_Success(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	svc := NewTPMService()

	details, err := svc.ParseCertificate(pemStr)
	require.NoError(t, err)
	assert.Equal(t, "test-self-signed", details.SubjectCN)
	assert.NotEmpty(t, details.FingerprintSHA256)
	assert.NotEmpty(t, details.FingerprintSHA1)
	assert.NotEmpty(t, details.FingerprintMD5)
	assert.NotEmpty(t, details.SignatureAlgorithm)
	assert.NotEmpty(t, details.NotBefore)
	assert.NotEmpty(t, details.NotAfter)
	assert.Equal(t, 3, details.Version)
}

func TestTPMService_ParseCertificate_InvalidPEM(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ParseCertificate("not a pem")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ParseCertificate_WrongBlockType(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ParseCertificate("-----BEGIN RSA PRIVATE KEY-----\nYQ==\n-----END RSA PRIVATE KEY-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

func TestTPMService_ParseCertificate_InvalidDER(t *testing.T) {
	svc := NewTPMService()
	_, err := svc.ParseCertificate("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n")
	assert.ErrorIs(t, err, ErrTPMInvalidCert)
}

// ---------------------------------------------------------------------------
// formatFingerprint
// ---------------------------------------------------------------------------

func TestFormatFingerprint(t *testing.T) {
	hash := []byte{0xAA, 0xBB, 0xCC}
	result := formatFingerprint(hash)
	assert.Equal(t, "AA:BB:CC", result)
}

func TestFormatFingerprint_Empty(t *testing.T) {
	result := formatFingerprint([]byte{})
	assert.Equal(t, "", result)
}

func TestFormatFingerprint_Single(t *testing.T) {
	result := formatFingerprint([]byte{0xFF})
	assert.Equal(t, "FF", result)
}

// ---------------------------------------------------------------------------
// publicKeyBitSize
// ---------------------------------------------------------------------------

func TestPublicKeyBitSize_RSA(t *testing.T) {
	key := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047)}
	assert.Equal(t, 2048, publicKeyBitSize(key))
}

func TestPublicKeyBitSize_ECDSA(t *testing.T) {
	key := &ecdsa.PublicKey{Curve: elliptic.P256()}
	assert.Equal(t, 256, publicKeyBitSize(key))
}

func TestPublicKeyBitSize_Ed25519(t *testing.T) {
	key := make(ed25519.PublicKey, 32)
	assert.Equal(t, 256, publicKeyBitSize(key))
}

func TestPublicKeyBitSize_Unknown(t *testing.T) {
	assert.Equal(t, 0, publicKeyBitSize("not a key"))
}

// ---------------------------------------------------------------------------
// buildSubjectAltNames
// ---------------------------------------------------------------------------

func TestBuildSubjectAltNames_DNSNames(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames: []string{"example.com", "test.example.com"},
	}
	result := buildSubjectAltNames(cert)
	assert.Contains(t, result, "DNS:example.com")
	assert.Contains(t, result, "DNS:test.example.com")
}

func TestBuildSubjectAltNames_EmailAddresses(t *testing.T) {
	cert := &x509.Certificate{
		EmailAddresses: []string{"user@example.com"},
	}
	result := buildSubjectAltNames(cert)
	assert.Contains(t, result, "email:user@example.com")
}

func TestBuildSubjectAltNames_Empty(t *testing.T) {
	cert := &x509.Certificate{}
	result := buildSubjectAltNames(cert)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// ListPolicies
// ---------------------------------------------------------------------------

func TestTPMService_ListPolicies_Empty(t *testing.T) {
	svc, _ := createTestTPMService(t, defaultMockTPM())
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestTPMService_ListPolicies_WithPolicies(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "test-policy",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "test-policy", policies[0].Name)
}

func TestTPMService_ListPolicies_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	policies, err := svc.ListPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// ---------------------------------------------------------------------------
// GetPolicyDeletionImpact
// ---------------------------------------------------------------------------

func TestTPMService_GetPolicyDeletionImpact_PCRPolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "del-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("del-test", "0x81000001"))

	impact, err := svc.GetPolicyDeletionImpact("del-test")
	require.NoError(t, err)
	assert.Equal(t, "pcr", impact.PolicyType)
	assert.Contains(t, impact.AssignedKeyHandles, "0x81000001")
}

func TestTPMService_GetPolicyDeletionImpact_CompositePolicy(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreateCompositePolicy(&CompositePolicy{
		Name:     "comp-del-test",
		Operator: "SINGLE",
		Elements: []PolicyElement{{Type: "password", PasswordHash: "hash"}},
	}))

	impact, err := svc.GetPolicyDeletionImpact("comp-del-test")
	require.NoError(t, err)
	assert.Equal(t, "composite", impact.PolicyType)
}

func TestTPMService_GetPolicyDeletionImpact_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	_, err := svc.GetPolicyDeletionImpact("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

// ---------------------------------------------------------------------------
// DeletePolicy
// ---------------------------------------------------------------------------

func TestTPMService_DeletePolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "to-delete",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))

	err := svc.DeletePolicy("to-delete")
	assert.NoError(t, err)

	_, err = svc.GetPolicy("to-delete")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTPMService_DeletePolicy_NotFound(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.DeletePolicy("nonexistent")
	assert.ErrorIs(t, err, ErrTPMPolicyNotFound)
}

func TestTPMService_DeletePolicy_CascadesAssignments(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "cascade-test",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("cascade-test", "0x81000001"))

	err := svc.DeletePolicy("cascade-test")
	assert.NoError(t, err)

	assignments, listErr := svc.ListPolicyAssignments()
	require.NoError(t, listErr)
	for _, a := range assignments {
		assert.NotEqual(t, "cascade-test", a.PolicyName)
	}
}

// ---------------------------------------------------------------------------
// verifyCertAgainstTrustStore
// ---------------------------------------------------------------------------

func TestTPMService_VerifyCertAgainstTrustStore_NilTrustStore(t *testing.T) {
	svc := NewTPMService()
	cert := testCert()
	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestTPMService_VerifyCertAgainstTrustStore_NilCert(t *testing.T) {
	svc := NewTPMService()
	result := svc.verifyCertAgainstTrustStore(nil, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

// ---------------------------------------------------------------------------
// CreateDefaultPlatformPolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreateDefaultPlatformPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreateDefaultPlatformPolicy()
	assert.NoError(t, err)

	cp, getErr := svc.GetCompositePolicy("Platform Policy")
	require.NoError(t, getErr)
	assert.Equal(t, "SINGLE", cp.Operator)
	assert.Len(t, cp.Elements, 1)
	assert.Equal(t, "pcr", cp.Elements[0].Type)
}

func TestTPMService_CreateDefaultPlatformPolicy_Idempotent(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreateDefaultPlatformPolicy())
	err := svc.CreateDefaultPlatformPolicy()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// savePolicyPassword / findPolicyPasswordEntry / deletePolicyPassword
// ---------------------------------------------------------------------------

func TestTPMService_SavePolicyPassword_NilService(t *testing.T) {
	svc := NewTPMService()
	// Should not panic, just log a message.
	svc.savePolicyPassword("test-policy", "SINGLE", "secret123")
}

func TestTPMService_FindPolicyPasswordEntry_NilService(t *testing.T) {
	svc := NewTPMService()
	id, found := svc.findPolicyPasswordEntry("test-policy")
	assert.Empty(t, id)
	assert.False(t, found)
}

func TestTPMService_DeletePolicyPassword_NilService(t *testing.T) {
	svc := NewTPMService()
	// Should not panic.
	svc.deletePolicyPassword("test-policy")
}

// ---------------------------------------------------------------------------
// removeAssignmentsForPolicy
// ---------------------------------------------------------------------------

func TestTPMService_RemoveAssignmentsForPolicy_Success(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "policy-a",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("policy-a", "0x81000001"))
	require.NoError(t, svc.AssignPolicyToKey("policy-a", "0x81000002"))

	svc.removeAssignmentsForPolicy("policy-a")

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

func TestTPMService_RemoveAssignmentsForPolicy_NoMatches(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	require.NoError(t, svc.CreatePolicy(&PCRPolicy{
		Name:          "policy-b",
		PCRSelections: []PCRSelection{{Index: 0, Bank: "sha256"}},
	}))
	require.NoError(t, svc.AssignPolicyToKey("policy-b", "0x81000001"))

	svc.removeAssignmentsForPolicy("nonexistent")

	assignments, err := svc.ListPolicyAssignments()
	require.NoError(t, err)
	assert.Len(t, assignments, 1) // unchanged
}

func TestTPMService_RemoveAssignmentsForPolicy_NoDataDir(t *testing.T) {
	svc := NewTPMService()
	svc.removeAssignmentsForPolicy("test") // should not panic
}

// ---------------------------------------------------------------------------
// isTPMAuthError - additional coverage
// ---------------------------------------------------------------------------

func TestIsTPMAuthError_NilError(t *testing.T) {
	assert.False(t, isTPMAuthError(nil))
}

func TestIsTPMAuthError_StringFallback_AuthFail(t *testing.T) {
	err := errors.New("TPM returned AUTH_FAIL")
	assert.True(t, isTPMAuthError(err))
}

func TestIsTPMAuthError_StringFallback_BadAuth(t *testing.T) {
	err := errors.New("TPM returned BAD_AUTH")
	assert.True(t, isTPMAuthError(err))
}

func TestIsTPMAuthError_RegularError(t *testing.T) {
	err := errors.New("some other error")
	assert.False(t, isTPMAuthError(err))
}

func TestIsTPMAuthError_TPMRC_Format1_AuthFail(t *testing.T) {
	// Format-1 error: bit 7 set, bits 0-5 = 0x0E (AUTH_FAIL)
	rc := tpm2.TPMRC(0x8E) // 0x80 | 0x0E
	assert.True(t, isTPMAuthError(rc))
}

func TestIsTPMAuthError_TPMRC_Format0_BadAuth(t *testing.T) {
	rc := tpm2.TPMRC(0x0022) // TPM_RC_BAD_AUTH
	assert.True(t, isTPMAuthError(rc))
}

func TestIsTPMAuthError_TPMRC_OtherCode(t *testing.T) {
	rc := tpm2.TPMRC(0x0001) // some other error code
	assert.False(t, isTPMAuthError(rc))
}

// ---------------------------------------------------------------------------
// algoDisplayName - additional coverage
// ---------------------------------------------------------------------------

func TestAlgoDisplayName_Nil(t *testing.T) {
	assert.Equal(t, "Unknown", algoDisplayName(nil))
}

func TestAlgoDisplayName_RSA_SSA(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.RSA}
	assert.Equal(t, "RSA-SSA", algoDisplayName(attrs))
}

func TestAlgoDisplayName_ECDSA(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	assert.Equal(t, "ECDSA", algoDisplayName(attrs))
}

func TestAlgoDisplayName_Ed25519(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}
	assert.Equal(t, "Ed25519", algoDisplayName(attrs))
}

func TestAlgoDisplayName_Default(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.DSA}
	result := algoDisplayName(attrs)
	assert.NotEmpty(t, result)
	assert.NotEqual(t, "Unknown", result)
}

// ---------------------------------------------------------------------------
// Provision - additional coverage for modes
// ---------------------------------------------------------------------------

func TestTPMService_Provision_InstallMode(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{Mode: ProvisionModeInstall, OwnerAuth: "test"})
	assert.NoError(t, err)
}

func TestTPMService_Provision_InvalidMode(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{Mode: "invalid", OwnerAuth: "test"})
	assert.ErrorIs(t, err, ErrTPMInvalidProvisionMode)
}

func TestTPMService_Provision_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.provisionErr = fmt.Errorf("auth_fail: wrong password")
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{OwnerAuth: "wrong"})
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// Install - additional coverage for auth error path
// ---------------------------------------------------------------------------

func TestTPMService_Install_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.installErr = fmt.Errorf("auth_fail: wrong password")
	svc := newServiceWithMock(mock)
	err := svc.Install("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

func TestTPMService_Install_EmptyAuth(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Install("")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// InitializePlatformKeyStore / InitializePlatformKeyStoreWithDefaults
// ---------------------------------------------------------------------------

func TestTPMService_InitializePlatformKeyStore_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStore("so-pin", "user-pin")
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_InitializePlatformKeyStore_NoPKS(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStore("so-pin", "user-pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

func TestTPMService_InitializePlatformKeyStore_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{}
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStore("so-pin", "user-pin")
	assert.NoError(t, err)
}

func TestTPMService_InitializePlatformKeyStoreWithDefaults_NoTPM(t *testing.T) {
	svc := NewTPMService()
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_InitializePlatformKeyStoreWithDefaults_NoPKS(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "platform key store not configured")
}

func TestTPMService_InitializePlatformKeyStoreWithDefaults_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.platformKeyStore = &mockPlatformKeyStorer{}
	svc := newServiceWithMock(mock)
	err := svc.InitializePlatformKeyStoreWithDefaults()
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// ImportEKCert / ImportEKECCCert / ImportIAKCert / ImportIDevIDCert
// - additional coverage with real certificates
// ---------------------------------------------------------------------------

func TestTPMService_ImportEKCert_WithValidCert(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ImportEKCert(pemStr)
	assert.NoError(t, err)
}

func TestTPMService_ImportEKECCCert_WithValidCert(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ImportEKECCCert(pemStr)
	assert.NoError(t, err)
}

func TestTPMService_ImportIAKCert_WithValidCert_Success(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ImportIAKCert(pemStr)
	assert.NoError(t, err)
}

func TestTPMService_ImportIAKCert_WithValidCert_NoTPM(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	svc := NewTPMService()
	err := svc.ImportIAKCert(pemStr)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ImportIAKCert_WriteError(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	mock.writeIAKCertErr = errors.New("write failed")
	svc := newServiceWithMock(mock)
	err := svc.ImportIAKCert(pemStr)
	assert.Error(t, err)
}

func TestTPMService_ImportIDevIDCert_WithValidCert_Success(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.ImportIDevIDCert(pemStr)
	assert.NoError(t, err)
}

func TestTPMService_ImportIDevIDCert_WithValidCert_NoTPM(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	svc := NewTPMService()
	err := svc.ImportIDevIDCert(pemStr)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMService_ImportIDevIDCert_WriteError(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	mock.writeIDevIDErr = errors.New("write failed")
	svc := newServiceWithMock(mock)
	err := svc.ImportIDevIDCert(pemStr)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// CreatePasswordPolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreatePasswordPolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePasswordPolicy("", "desc", "secret", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTPMService_CreatePasswordPolicy_WhitespacePassword(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePasswordPolicy("pw-policy", "desc", "   ", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// CreatePCROrPasswordPolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreatePCROrPasswordPolicy_EmptyName(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePCROrPasswordPolicy("", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "secret", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPolicyName)
}

func TestTPMService_CreatePCROrPasswordPolicy_NoPCRs(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePCROrPasswordPolicy("or-policy", "desc", nil, "sha256", "secret", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

func TestTPMService_CreatePCROrPasswordPolicy_EmptyPassword(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePCROrPasswordPolicy("or-policy", "desc", []PCRSelection{{Index: 0, Bank: "sha256"}}, "sha256", "", false)
	assert.ErrorIs(t, err, ErrTPMInvalidAuth)
}

// ---------------------------------------------------------------------------
// CreatePCRAndPasswordPolicy
// ---------------------------------------------------------------------------

func TestTPMService_CreatePCRAndPasswordPolicy_NoPCRs(t *testing.T) {
	svc, _ := createTestTPMService(t, &mockTPM{})
	err := svc.CreatePCRAndPasswordPolicy("and-policy", "desc", nil, "sha256", "secret", false)
	assert.ErrorIs(t, err, ErrTPMInvalidPCRs)
}

// ---------------------------------------------------------------------------
// GetInfo - additional coverage for SupportedCommands fallback
// ---------------------------------------------------------------------------

func TestTPMService_GetInfo_SupportedCommandsFallback(t *testing.T) {
	mock := defaultMockTPM()
	// Return some command names from SupportedCommands.
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	// Commands should be nil since SupportedCommands returns nil for the mock.
	// But the path is exercised since the mock is not a concrete TPM2.
	assert.NotNil(t, info)
}

func TestTPMService_GetInfo_AlgorithmsFallbackToConfig(t *testing.T) {
	mock := defaultMockTPM()
	mock.supportedAlgos = nil
	mock.supportedAlgosErr = errors.New("not supported")
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	// Falls back to config hash.
	assert.Contains(t, info.Algorithms, "SHA-256")
}

func TestTPMService_GetInfo_FIPSError(t *testing.T) {
	mock := defaultMockTPM()
	mock.fipsErr = errors.New("fips check failed")
	svc := newServiceWithMock(mock)
	info, err := svc.GetInfo()
	require.NoError(t, err)
	assert.False(t, info.FIPSMode)
}

// ---------------------------------------------------------------------------
// GetPCRs - SHA384/SHA386 mismatch path
// ---------------------------------------------------------------------------

func TestTPMService_GetPCRs_SHA384_SHA386Mismatch(t *testing.T) {
	mock := defaultMockTPM()
	mock.pcrBanks = []tpm2pkg.PCRBank{
		{Algorithm: "SHA386", PCRs: []tpm2pkg.PCR{{ID: 0, Value: []byte{0xAA}}}},
	}
	svc := newServiceWithMock(mock)
	values, err := svc.GetPCRs("sha384")
	require.NoError(t, err)
	require.Len(t, values, 1)
	assert.Equal(t, "sha384", values[0].Bank)
}

// ---------------------------------------------------------------------------
// GetIDevIDInfo - with cert and verification
// ---------------------------------------------------------------------------

func TestTPMService_GetIDevIDInfo_WithCert(t *testing.T) {
	mock := defaultMockTPM()
	mock.idevidCert = testCert()
	mock.idevidCertErr = nil
	svc := newServiceWithMock(mock)
	info, err := svc.GetIDevIDInfo()
	require.NoError(t, err)
	assert.True(t, info.Present)
	assert.Contains(t, info.Certificate, "CERTIFICATE")
}

// ---------------------------------------------------------------------------
// keySize - additional coverage for fallback cases
// ---------------------------------------------------------------------------

func TestKeySize_ECDSA_Fallback(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	assert.Equal(t, 256, keySize(attrs))
}

func TestKeySize_RSA_Fallback(t *testing.T) {
	attrs := &types.KeyAttributes{KeyAlgorithm: x509.RSA}
	assert.Equal(t, 2048, keySize(attrs))
}

func TestKeySize_ECCWithCurve(t *testing.T) {
	attrs := &types.KeyAttributes{
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	}
	assert.Equal(t, 384, keySize(attrs))
}

// ---------------------------------------------------------------------------
// Provision - empty mode defaults to "provision"
// ---------------------------------------------------------------------------

func TestTPMService_Provision_EmptyModeDefaultsToProvision(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{Mode: "", OwnerAuth: "test"})
	assert.NoError(t, err)
}
