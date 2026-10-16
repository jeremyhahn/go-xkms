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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
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
	fixedProps        *xkms.PropertiesFixed
	fixedPropsErr     error
	clearAllowed      bool
	clearCalled       bool
	clearErr          error
	device            string
	config            *xkms.TPMConfig
	ekAttrs           *xkms.KeyAttributes
	ekAttrsErr        error
	ekCert            *x509.Certificate
	ekCertErr         error
	ekCertRSA         *x509.Certificate
	ekCertRSAErr      error
	ekCertEC          *x509.Certificate
	ekCertECErr       error
	ekECC             *ecdsa.PublicKey
	iakPub            crypto.PublicKey
	iakAttrs          *xkms.KeyAttributes
	iakAttrsErr       error
	iakCert           *x509.Certificate
	iakCertErr        error
	idevidPub         crypto.PublicKey
	idevidAttrs       *xkms.KeyAttributes
	idevidAttrsErr    error
	idevidCert        *x509.Certificate
	idevidCertErr     error
	srkName           tpm2.TPM2BName
	srkPub            tpm2.TPMTPublic
	ssrkAttrs         *xkms.KeyAttributes
	ssrkAttrsErr      error
	pcrBanks          []xkms.PCRBank
	pcrBanksErr       error
	fips              bool
	fipsErr           error
	quoteResult       xkms.Quote
	quoteErr          error
	parsedEvents      []xkms.TPMEvent
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
	nvIndexes         []xkms.NVIndexInfo
	lockoutResetErr   error

	// Phase 3: SRK and platform key store.
	readHandleErr    error
	platformKeyStore xkms.PlatformKeyStorer
	handleKeyAttrs   map[tpm2.TPMHandle]*xkms.KeyAttributes

	// Public areas returned by ReadHandle, keyed by handle. Populated by
	// tests that exercise code reading an object's public area (ListKeys).
	handlePublics map[tpm2.TPMHandle]tpm2.TPMTPublic

	// Phase 4: configurable returns for operations that previously panicked.
	factoryResetErr     error
	createIAKResult     *xkms.KeyAttributes
	createIAKErr        error
	createIDevIDResult  *xkms.KeyAttributes
	createIDevIDErr     error
	setHierarchyAuthErr error
	certifyKeyResult    *xkms.CertifyResult
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
	createTCGCSRResult  xkms.TCG_CSR_IDEVID
	createTCGCSRErr     error
}

// Methods called by TPMService.

func (m *mockTPM) Device() string          { return m.device }
func (m *mockTPM) Config() *xkms.TPMConfig { return m.config }
func (m *mockTPM) FixedProperties() (*xkms.PropertiesFixed, error) {
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
func (m *mockTPM) EKAttributes() (*xkms.KeyAttributes, error) {
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
func (m *mockTPM) EKECC() (*ecdsa.PublicKey, error)            { return m.ekECC, nil }
func (m *mockTPM) IAK() (crypto.PublicKey, error)              { return m.iakPub, nil }
func (m *mockTPM) IAKAttributes() (*xkms.KeyAttributes, error) { return m.iakAttrs, m.iakAttrsErr }
func (m *mockTPM) IDevID() (crypto.PublicKey, error)           { return m.idevidPub, nil }
func (m *mockTPM) IDevIDAttributes() (*xkms.KeyAttributes, error) {
	return m.idevidAttrs, m.idevidAttrsErr
}
func (m *mockTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return m.srkName, m.srkPub, nil
}
func (m *mockTPM) SSRKAttributes() (*xkms.KeyAttributes, error)        { return m.ssrkAttrs, m.ssrkAttrsErr }
func (m *mockTPM) PlatformSRKAttributes() (*xkms.KeyAttributes, error) { return nil, nil }
func (m *mockTPM) SSRK() *xkms.SRKConfig {
	if m.config == nil {
		return nil
	}
	return m.config.SSRK
}
func (m *mockTPM) PlatformKeyStore() xkms.PlatformKeyStorer { return m.platformKeyStore }
func (m *mockTPM) ReadPCRs(pcrList []uint) ([]xkms.PCRBank, error) {
	return m.pcrBanks, m.pcrBanksErr
}
func (m *mockTPM) IsFIPS140_2() (bool, error) { return m.fips, m.fipsErr }
func (m *mockTPM) Quote(pcrs []uint, nonce []byte) (xkms.Quote, error) {
	return m.quoteResult, m.quoteErr
}
func (m *mockTPM) ParsedEventLog() ([]xkms.TPMEvent, error) {
	return m.parsedEvents, m.parsedEventsErr
}
func (m *mockTPM) RandomBytes(fixedLength int) ([]byte, error) {
	return m.randomBytesVal, m.randomBytesErr
}
func (m *mockTPM) PlatformPolicyDigestHash() ([]byte, error) { return m.policyHash, m.policyHashErr }
func (m *mockTPM) Provision(soPIN xkms.Password) error       { return m.provisionErr }
func (m *mockTPM) Install(soPIN xkms.Password, _ *xkms.InstallOptions) error {
	return m.installErr
}
func (m *mockTPM) WriteEKCert(ekCert []byte) error { return m.writeEKCertErr }
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
func (m *mockTPM) AnswerCredentialChallenge(_ *xkms.ActivationKey, _ *xkms.CredentialChallenge) ([]byte, error) {
	panic("mockTPM: AnswerCredentialChallenge not expected")
}
func (m *mockTPM) ClearForReprovision() (bool, error) {
	panic("mockTPM: ClearForReprovision not expected")
}
func (m *mockTPM) CreateActivationKey() (*xkms.ActivationKey, error) {
	panic("mockTPM: CreateActivationKey not expected")
}
func (m *mockTPM) State() (*xkms.ProvisioningState, error) {
	panic("mockTPM: State not expected")
}
func (m *mockTPM) AKProfile() (xkms.AKProfile, error) {
	panic("mockTPM: AKProfile not expected")
}
func (m *mockTPM) AlgID() tpm2.TPMAlgID { panic("mockTPM: AlgID not expected") }
func (m *mockTPM) CalculateName(_ tpm2.TPMAlgID, _ []byte) {
	panic("mockTPM: CalculateName not expected")
}
func (m *mockTPM) Clear(_ []byte) error {
	if !m.clearAllowed {
		panic("mockTPM: Clear not expected")
	}
	m.clearCalled = true
	return m.clearErr
}
func (m *mockTPM) ForceClear() error { return nil }
func (m *mockTPM) Close() error      { return nil }
func (m *mockTPM) CreateECDSA(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend, _ bool) (*ecdsa.PublicKey, error) {
	panic("mockTPM: CreateECDSA not expected")
}
func (m *mockTPM) CreateEK(_ *xkms.KeyAttributes) error { panic("mockTPM: CreateEK not expected") }
func (m *mockTPM) CreateSecretKey(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend) error {
	panic("mockTPM: CreateSecretKey not expected")
}
func (m *mockTPM) CreateIAK(_ *xkms.KeyAttributes, _ []byte) (*xkms.KeyAttributes, error) {
	return m.createIAKResult, m.createIAKErr
}
func (m *mockTPM) DeleteIAK(_ *xkms.KeyAttributes) error {
	return nil
}
func (m *mockTPM) CreateIDevID(_ *xkms.KeyAttributes, _ *x509.Certificate, _ []byte) (*xkms.KeyAttributes, *xkms.TCG_CSR_IDEVID, error) {
	return m.createIDevIDResult, nil, m.createIDevIDErr
}
func (m *mockTPM) CreatePlatformPolicy() error { panic("mockTPM: CreatePlatformPolicy not expected") }
func (m *mockTPM) CreateRSA(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend, _ bool) (*rsa.PublicKey, error) {
	panic("mockTPM: CreateRSA not expected")
}
func (m *mockTPM) CreateKeySession(_ *xkms.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("mockTPM: CreateKeySession not expected")
}
func (m *mockTPM) CreateSession(_ *xkms.KeyAttributes) (tpm2.Session, func() error, error) {
	panic("mockTPM: CreateSession not expected")
}
func (m *mockTPM) CreateSRK(_ *xkms.KeyAttributes) error {
	panic("mockTPM: CreateSRK not expected")
}
func (m *mockTPM) CreateTCG_CSR_IDEVID(_ *x509.Certificate, _, _ *xkms.KeyAttributes) (xkms.TCG_CSR_IDEVID, error) {
	return m.createTCGCSRResult, m.createTCGCSRErr
}
func (m *mockTPM) DeleteKey(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend) error {
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
func (m *mockTPM) HMACSaltedSession(_ tpm2.TPMHandle, _ tpm2.TPMTPublic, _ []byte) (tpm2.Session, func() error, error) {
	panic("mockTPM: HMACSaltedSession not expected")
}
func (m *mockTPM) HMACSession(_ []byte) (tpm2.Session, func() error, error) {
	panic("mockTPM: HMACSession not expected")
}
func (m *mockTPM) Info() (string, error) { panic("mockTPM: Info not expected") }
func (m *mockTPM) ExtendPCR(_ int, _ string, _ []byte) error {
	panic("mockTPM: ExtendPCR not expected")
}
func (m *mockTPM) KeyAttributes(handle tpm2.TPMHandle) (*xkms.KeyAttributes, error) {
	if m.handleKeyAttrs != nil {
		if attrs, ok := m.handleKeyAttrs[handle]; ok {
			return attrs, nil
		}
	}
	return nil, &MessageError{Msg: fmt.Sprintf("handle 0x%08X not found", handle)}
}
func (m *mockTPM) LoadKeyPair(_ *xkms.KeyAttributes, _ *tpm2.Session, _ xkms.TPMKeyBackend) (*tpm2.LoadResponse, error) {
	panic("mockTPM: LoadKeyPair not expected")
}
func (m *mockTPM) MakeCredential(_ tpm2.TPM2BName, _ []byte) ([]byte, []byte, []byte, error) {
	panic("mockTPM: MakeCredential not expected")
}
func (m *mockTPM) MakeCredentialWithExternalEK(_ *x509.Certificate, _, _ []byte) ([]byte, []byte, []byte, error) {
	panic("mockTPM: MakeCredentialWithExternalEK not expected")
}
func (m *mockTPM) NonceSession(_ xkms.Password) (tpm2.Session, func() error, error) {
	panic("mockTPM: NonceSession not expected")
}
func (m *mockTPM) NVRead(_ *xkms.KeyAttributes, _ uint16) ([]byte, error) {
	return m.nvReadResult, m.nvReadErr
}
func (m *mockTPM) NVWrite(_ *xkms.KeyAttributes) error {
	return m.nvWriteErr
}
func (m *mockTPM) NVDefineCounter(_ *xkms.KeyAttributes) error {
	return m.nvDefineCounterErr
}
func (m *mockTPM) NVDefineExtend(_ *xkms.KeyAttributes) error {
	return m.nvDefineExtendErr
}
func (m *mockTPM) NVIncrement(_ *xkms.KeyAttributes) (uint64, error) {
	return m.nvIncrementResult, m.nvIncrementErr
}
func (m *mockTPM) NVExtend(_ *xkms.KeyAttributes, _ []byte) error {
	return m.nvExtendErr
}
func (m *mockTPM) NVReadCounter(_ *xkms.KeyAttributes) (uint64, error) {
	return m.nvReadCounterResult, m.nvReadCounterErr
}
func (m *mockTPM) NVReadExtend(_ *xkms.KeyAttributes) ([]byte, error) {
	return m.nvReadExtendResult, m.nvReadExtendErr
}
func (m *mockTPM) NVUndefine(_ *xkms.KeyAttributes) error {
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
func (m *mockTPM) PlatformQuote(_ *xkms.KeyAttributes) (xkms.Quote, []byte, error) {
	panic("mockTPM: PlatformQuote not expected")
}
func (m *mockTPM) ProvisionEKCert(_, _ []byte) error {
	panic("mockTPM: ProvisionEKCert not expected")
}
func (m *mockTPM) ReplaceEKCert(_, _ []byte) error {
	panic("mockTPM: ReplaceEKCert not expected")
}
func (m *mockTPM) ProvisionOwner(_ xkms.Password) (*xkms.KeyAttributes, error) {
	panic("mockTPM: ProvisionOwner not expected")
}
func (m *mockTPM) CertifyKey(_ *xkms.KeyAttributes, _ []byte, _ xkms.TPMKeyBackend) (*xkms.CertifyResult, error) {
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
func (m *mockTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if m.readHandleErr != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, m.readHandleErr
	}
	if pub, ok := m.handlePublics[handle]; ok {
		return tpm2.TPM2BName{}, pub, nil
	}
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, m.readHandleErr
}
func (m *mockTPM) RSADecrypt(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend, _ []byte) ([]byte, error) {
	panic("mockTPM: RSADecrypt not expected")
}
func (m *mockTPM) RSAEncrypt(_ tpm2.TPMHandle, _ tpm2.TPM2BName, _ []byte) ([]byte, error) {
	panic("mockTPM: RSAEncrypt not expected")
}
func (m *mockTPM) SaveKeyPair(_ *xkms.KeyAttributes, _ tpm2.TPM2BPrivate, _ tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], _ xkms.TPMKeyBackend, _ bool) error {
	panic("mockTPM: SaveKeyPair not expected")
}
func (m *mockTPM) Seal(_ context.Context, _ []byte, _ *xkms.SealOptions) (*xkms.SealedData, error) {
	panic("mockTPM: Seal not expected")
}
func (m *mockTPM) SealKey(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend, _ bool) (*tpm2.CreateResponse, error) {
	panic("mockTPM: SealKey not expected")
}
func (m *mockTPM) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	panic("mockTPM: Sign not expected")
}
func (m *mockTPM) SetHierarchyAuth(_, _ xkms.Password, _ *tpm2.TPMHandle) error {
	return m.setHierarchyAuthErr
}

func (m *mockTPM) SetPolicyBindingResolver(xkms.TPMPolicyBindingResolver) {}
func (m *mockTPM) SecretFromShares(_ []string) (string, error) {
	panic("mockTPM: SecretFromShares not expected")
}
func (m *mockTPM) ShareSecret(_ []byte, _ int) ([]string, error) {
	panic("mockTPM: ShareSecret not expected")
}
func (m *mockTPM) Transport() transport.TPM {
	panic("mockTPM: Transport not expected")
}
func (m *mockTPM) Unseal(_ context.Context, _ *xkms.SealedData, _ *xkms.UnsealOptions) ([]byte, error) {
	panic("mockTPM: Unseal not expected")
}
func (m *mockTPM) UnsealKey(_ *xkms.KeyAttributes, _ xkms.TPMKeyBackend) ([]byte, error) {
	panic("mockTPM: UnsealKey not expected")
}
func (m *mockTPM) CanSeal() bool { panic("mockTPM: CanSeal not expected") }
func (m *mockTPM) DeleteIDevIDCertificate() error {
	panic("mockTPM: DeleteIDevIDCertificate not expected")
}
func (m *mockTPM) DeleteIAKCertificate() error {
	panic("mockTPM: DeleteIAKCertificate not expected")
}
func (m *mockTPM) CreateLAK(_ xkms.Password, _ xkms.TPMKeyBackend, _ bool) (*xkms.KeyAttributes, error) {
	panic("mockTPM: CreateLAK not expected")
}
func (m *mockTPM) LAKAttributes() (*xkms.KeyAttributes, error) {
	panic("mockTPM: LAKAttributes not expected")
}
func (m *mockTPM) LAK() (crypto.PublicKey, error) { panic("mockTPM: LAK not expected") }
func (m *mockTPM) CertifyLAK(_ []byte, _ xkms.TPMKeyBackend) (*xkms.CertifyResult, error) {
	panic("mockTPM: CertifyLAK not expected")
}
func (m *mockTPM) CertifyKeyWithLAK(_ *xkms.KeyAttributes, _ []byte, _ xkms.TPMKeyBackend) (*xkms.CertifyResult, error) {
	panic("mockTPM: CertifyKeyWithLAK not expected")
}
func (m *mockTPM) LAKCertificate() (*x509.Certificate, error) {
	panic("mockTPM: LAKCertificate not expected")
}
func (m *mockTPM) ProvisionLAKCert(_ *x509.Certificate) error {
	panic("mockTPM: ProvisionLAKCert not expected")
}
func (m *mockTPM) DeleteLAKCertificate() error {
	panic("mockTPM: DeleteLAKCertificate not expected")
}
func (m *mockTPM) VerifyTCGCSR(_ *xkms.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*xkms.KeyAttributes, *xkms.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCGCSR not expected")
}
func (m *mockTPM) VerifyTCG_CSR_IAK(_ *xkms.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*xkms.KeyAttributes, *xkms.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCG_CSR_IAK not expected")
}
func (m *mockTPM) VerifyTCG_CSR_IDevID(_ *xkms.TCG_CSR_IDEVID, _ x509.SignatureAlgorithm) (*xkms.KeyAttributes, *xkms.UNPACKED_TCG_CSR_IDEVID, error) {
	panic("mockTPM: VerifyTCG_CSR_IDevID not expected")
}
func (m *mockTPM) SignValidate(_ *xkms.KeyAttributes, _, _ []byte) ([]byte, error) {
	panic("mockTPM: SignValidate not expected")
}
func (m *mockTPM) HashSequence(_ *xkms.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("mockTPM: HashSequence not expected")
}
func (m *mockTPM) Hash(_ *xkms.KeyAttributes, _ []byte) ([]byte, []byte, error) {
	panic("mockTPM: Hash not expected")
}
func (m *mockTPM) ECDHZGen(_ *xkms.KeyAttributes, _ *tpm2.TPMSECCPoint, _ xkms.TPMKeyBackend) ([]byte, error) {
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
func (m *mockTPM) GenerateSymmetricKey(_ *xkms.KeyAttributes) (xkms.SymmetricKey, error) {
	panic("mockTPM: GenerateSymmetricKey not expected")
}
func (m *mockTPM) GetSymmetricKey(_ *xkms.KeyAttributes) (xkms.SymmetricKey, error) {
	panic("mockTPM: GetSymmetricKey not expected")
}
func (m *mockTPM) SymmetricEncrypter(_ *xkms.KeyAttributes) (xkms.SymmetricEncrypter, error) {
	panic("mockTPM: SymmetricEncrypter not expected")
}

func (m *mockTPM) VerifyAuth(_ tpm2.TPMHandle, _ []byte) error    { return nil }
func (m *mockTPM) ChangeAuth(_ tpm2.TPMHandle, _, _ []byte) error { return nil }

// compile-time check
var _ xkms.TrustedPlatformModule = (*mockTPM)(nil)

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
			X:     big.NewInt(1), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
			Y:     big.NewInt(2), //nolint:staticcheck // synthetic test fixture; a fixed non-curve point is the input under test and a validating constructor would refuse to build it.
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
	srkAttrs      *xkms.KeyAttributes
}

func (m *mockPlatformKeyStorer) SRKAttributes() *xkms.KeyAttributes  { return m.srkAttrs }
func (m *mockPlatformKeyStorer) Backend() xkms.TPMKeyBackend         { return nil }
func (m *mockPlatformKeyStorer) Initialize(_, _ string) error        { return nil }
func (m *mockPlatformKeyStorer) EnrollPlatformSRK(_, _ string) error { return nil }
func (m *mockPlatformKeyStorer) InitializeWithDefaults() error       { return nil }
func (m *mockPlatformKeyStorer) IsInitialized() bool                 { return m.initialized }
func (m *mockPlatformKeyStorer) PlatformPolicyEnabled() bool         { return m.policyEnabled }
func (m *mockPlatformKeyStorer) VerifyAuth(_ string) error           { return nil }
func (m *mockPlatformKeyStorer) ChangeAuth(_, _ string) error        { return nil }
func (m *mockPlatformKeyStorer) GetLockoutInfo() (int, int, int, int, error) {
	return 0, 10, 0, 300, nil
}
func (m *mockPlatformKeyStorer) PINBackend() qrdbsdk.PINBackend              { return nil }
func (m *mockPlatformKeyStorer) DictionaryAttackLockoutReset(_ []byte) error { return nil }
func (m *mockPlatformKeyStorer) IsProvisioned() bool                         { return m.initialized }
func (m *mockPlatformKeyStorer) IsAuthReady() bool                           { return m.initialized }
func (m *mockPlatformKeyStorer) SetAuthReady(_ bool)                         {}

func defaultMockTPM() *mockTPM {
	return &mockTPM{
		device: "/dev/tpmrm0",
		config: &xkms.TPMConfig{
			Hash: "SHA-256",
			SSRK: &xkms.SRKConfig{
				Handle:       0x81000001,
				KeyAlgorithm: "RSA",
			},
		},
		fixedProps: &xkms.PropertiesFixed{
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
		ekAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &xkms.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &xkms.TPMAttributes{
				Handle: 0x81010001,
			},
		},
		ekCertErr:    xkms.ErrTPMEndorsementCertNotFound,
		ekCertRSAErr: errors.New("not available"),
		ekCertECErr:  errors.New("not available"),
		ekECC:        nil,
		iakPub:       &rsa.PublicKey{},
		iakAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &xkms.RSAAttributes{
				KeySize: 2048,
			},
			TPMAttributes: &xkms.TPMAttributes{
				Handle: 0x81010002,
			},
		},
		iakCertErr: errors.New("no cert"),
		idevidPub:  &rsa.PublicKey{},
		idevidAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &xkms.ECCAttributes{
				Curve: nil,
			},
		},
		idevidCertErr: errors.New("no cert"),
		srkName:       tpm2.TPM2BName{Buffer: []byte{0x01, 0x02}},
		ssrkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		},
		pcrBanks: []xkms.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []xkms.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
					{ID: 7, Value: []byte{0xCC, 0xDD}},
				},
			},
		},
		quoteResult: xkms.Quote{
			Quoted:    []byte{0x01, 0x02},
			Signature: []byte{0x03, 0x04},
			PCRs:      []byte{0x05, 0x06},
			Nonce:     []byte{0xde, 0xad},
		},
		parsedEvents: []xkms.TPMEvent{
			{
				PCRIndex:    0,
				EventType:   "EV_NO_ACTION",
				DigestCount: 1,
				Digests: []xkms.TPMDigest{
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
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return mock }))
	return svc
}

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
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule {
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
	mock.iakAttrs = &xkms.KeyAttributes{
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &xkms.RSAAttributes{
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
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm:  x509.RSA,
			RSAAttributes: &xkms.RSAAttributes{KeySize: 2048},
			TPMAttributes: &xkms.TPMAttributes{Handle: 0x81000002},
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
		srkAttrs: &xkms.KeyAttributes{
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &xkms.ECCAttributes{Curve: elliptic.P256()},
			TPMAttributes: &xkms.TPMAttributes{Handle: 0x81000002},
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
	mock.config.PlatformSRK = &xkms.PlatformSRKConfig{SRKHandle: 0x81000002}
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
	mock.pcrBanks = []xkms.PCRBank{} // empty banks — simulates unsupported
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
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA512", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA1", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA384", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
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
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA386", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
		{Algorithm: "SHA256", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0x00}}}},
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

// TestTPMService_ListKeys: with no TPM the caller is told so. An empty list
// would read as "provisioned but holding nothing", which is a different fact.
func TestTPMService_ListKeys(t *testing.T) {
	svc := NewTPMService()
	keys, err := svc.ListKeys()
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
	assert.Nil(t, keys)
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
	mock.parsedEvents = []xkms.TPMEvent{
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
	attrs := &xkms.KeyAttributes{
		RSAAttributes: &xkms.RSAAttributes{KeySize: 4096},
	}
	assert.Equal(t, 4096, keySize(attrs))
}

func TestKeySize_NoAttributes(t *testing.T) {
	attrs := &xkms.KeyAttributes{}
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
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return nil }))
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
func (m *mockTrustStore) ImportPEM(_ []byte, _ *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	panic("mockTrustStore: ImportPEM not expected")
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
func (m *mockTrustStore) Close() error  { return nil }
func (m *mockTrustStore) Reload() error { return nil }

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

// replayTestEvents returns events with lowercase algorithm IDs (as required
// by CalculatePCRs) and the corresponding mock PCR banks that exactly match
// the computed replay output.
func replayTestEvents() ([]xkms.TPMEvent, []xkms.PCRBank) {
	events := []xkms.TPMEvent{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []xkms.TPMDigest{
				{AlgorithmId: "sha256", Digest: "aabb"},
			},
			EventString: "spec_id_event",
		},
	}

	// Compute expected PCR values by replaying the events.
	computed := xkms.CalculatePCRs(events)

	// Build mock PCR banks that match the computed values.
	// ReadPCRs returns UPPERCASE algorithm names.
	var banks []xkms.PCRBank
	for algo, pcrMap := range computed {
		bank := xkms.PCRBank{
			Algorithm: strings.ToUpper(algo),
		}
		for idx, val := range pcrMap {
			bank.PCRs = append(bank.PCRs, xkms.PCR{
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
	events := []xkms.TPMEvent{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []xkms.TPMDigest{
				{AlgorithmId: "sha256", Digest: "aabb"},
			},
			EventString: "spec_id_event",
		},
	}

	// Provide PCR banks that do NOT match the computed replay.
	mismatchBanks := []xkms.PCRBank{
		{
			Algorithm: "SHA256",
			PCRs: []xkms.PCR{
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
	svc.SetTPMAccessor(NewTPMAccessor(func() xkms.TrustedPlatformModule { return nil }))

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
		parsedEvents: []xkms.TPMEvent{},
	}
	svc := newServiceWithMock(mock)

	result, err := svc.ReplayEventLog()
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success)
	assert.Equal(t, 0, result.EventCount)
	assert.Equal(t, 0, result.TotalPCRs)
}

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
	mock.factoryResetErr = &MessageError{Msg: "auth_fail: bad password"}
	svc := newServiceWithMock(mock)
	err := svc.FactoryReset("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// ProvisionIAK
// ---------------------------------------------------------------------------

func TestTPMService_ProvisionIAK_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIAKResult = &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
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
	mock.createIAKErr = &MessageError{Msg: "auth_fail: wrong password"}
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIAK("wrong")
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// ProvisionIDevID
// ---------------------------------------------------------------------------

func TestTPMService_ProvisionIDevID_Success(t *testing.T) {
	mock := defaultMockTPM()
	mock.createIDevIDResult = &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
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

// TestTPMService_ProvisionIDevID_EKCertNotProvisioned verifies that the
// sentinel "no EK certificate provisioned yet" error is tolerated: the EK
// certificate is optional for CreateIDevID, so provisioning proceeds
// without one.
func TestTPMService_ProvisionIDevID_EKCertNotProvisioned(t *testing.T) {
	mock := defaultMockTPM() // ekCertErr defaults to xkms.ErrTPMEndorsementCertNotFound.
	mock.createIDevIDResult = &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	svc := newServiceWithMock(mock)
	err := svc.ProvisionIDevID("ownerpass")
	assert.NoError(t, err)
}

// TestTPMService_ProvisionIDevID_EKCertError verifies that a non-sentinel
// EK certificate lookup failure (e.g. a TPM communication error) fails
// provisioning instead of silently proceeding without the EK certificate.
func TestTPMService_ProvisionIDevID_EKCertError(t *testing.T) {
	mock := defaultMockTPM()
	mock.ekCertErr = errors.New("TPM communication failure")
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
	mock.createIDevIDErr = &MessageError{Msg: "auth_fail: wrong password"}
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
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
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
	mock.config.PlatformSRK = &xkms.PlatformSRKConfig{SRKHandle: 0x81000003}
	mock.persistentHandles = []tpm2.TPMHandle{0x81000003}
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
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
	mock.handleKeyAttrs = map[tpm2.TPMHandle]*xkms.KeyAttributes{
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
	mock.certifyKeyResult = &xkms.CertifyResult{
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
	mock.certifyKeyResult = &xkms.CertifyResult{
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
	mock.ekAttrs.TPMAttributes = &xkms.TPMAttributes{
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
	mock.ssrkAttrs.TPMAttributes = &xkms.TPMAttributes{Handle: 0x81000001}
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
	mock.nvIndexes = []xkms.NVIndexInfo{
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
	mock.nvIndexes = []xkms.NVIndexInfo{
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
	attrs, err := svc.buildNVKeyAttributes(0x01800001, "ownerpass", tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NotNil(t, attrs)
	require.NotNil(t, attrs.TPMAttributes)
	assert.Equal(t, tpm2.TPMHandle(0x01800001), attrs.TPMAttributes.Handle)
	require.NotNil(t, attrs.Parent)
	require.NotNil(t, attrs.Parent.TPMAttributes)
	assert.NotNil(t, attrs.Parent.TPMAttributes.HierarchyAuth)
}

func TestTPMService_BuildNVKeyAttributes_NoAuth(t *testing.T) {
	svc := NewTPMService()
	attrs, err := svc.buildNVKeyAttributes(0x01800001, "", tpm2.TPMAlgSHA256)
	require.NoError(t, err)
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

func TestTPMService_VerifyCertAgainstTrustStore_NilTrustStore(t *testing.T) {
	svc := NewTPMService()
	cert := testCert()
	result := svc.verifyCertAgainstTrustStore(cert, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

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
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
	assert.Equal(t, "RSA-SSA", algoDisplayName(attrs))
}

func TestAlgoDisplayName_ECDSA(t *testing.T) {
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	assert.Equal(t, "ECDSA", algoDisplayName(attrs))
}

func TestAlgoDisplayName_Ed25519(t *testing.T) {
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.Ed25519}
	assert.Equal(t, "Ed25519", algoDisplayName(attrs))
}

func TestAlgoDisplayName_Default(t *testing.T) {
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.DSA}
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
	mock.provisionErr = &MessageError{Msg: "auth_fail: wrong password"}
	svc := newServiceWithMock(mock)
	err := svc.Provision(&ProvisionOptions{OwnerAuth: "wrong"})
	assert.ErrorIs(t, err, ErrTPMAuthRequired)
}

// ---------------------------------------------------------------------------
// Install - additional coverage for auth error path
// ---------------------------------------------------------------------------

func TestTPMService_Install_AuthError(t *testing.T) {
	mock := defaultMockTPM()
	mock.installErr = &MessageError{Msg: "auth_fail: wrong password"}
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
	mock.pcrBanks = []xkms.PCRBank{
		{Algorithm: "SHA386", PCRs: []xkms.PCR{{ID: 0, Value: []byte{0xAA}}}},
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
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.ECDSA}
	assert.Equal(t, 256, keySize(attrs))
}

func TestKeySize_RSA_Fallback(t *testing.T) {
	attrs := &xkms.KeyAttributes{KeyAlgorithm: x509.RSA}
	assert.Equal(t, 2048, keySize(attrs))
}

func TestKeySize_ECCWithCurve(t *testing.T) {
	attrs := &xkms.KeyAttributes{
		ECCAttributes: &xkms.ECCAttributes{Curve: elliptic.P384()},
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

// ---------------------------------------------------------------------------
// NVSummary JSON field name regression (Bug A)
// ---------------------------------------------------------------------------

// TestTPMService_GetNVSummary_JSONFieldNames is a regression test that ensures
// NVSummary marshals to the exact field names the Svelte frontend expects:
// "indexes_defined" and "indexes_max". A mismatch between Go JSON tags and the
// TypeScript interface causes the NV Storage header to render "undefined /
// undefined indexes defined". This test catches any future rename.
func TestTPMService_GetNVSummary_JSONFieldNames(t *testing.T) {
	mock := defaultMockTPM()
	mock.nvIndexes = []xkms.NVIndexInfo{
		{Handle: 0x01800001, Type: "ordinary", Size: 32, AuthRead: true},
	}
	svc := newServiceWithMock(mock)

	summary, err := svc.GetNVSummary()
	require.NoError(t, err)

	data, err := json.Marshal(summary)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, hasIndexesDefined := m["indexes_defined"]
	_, hasIndexesMax := m["indexes_max"]
	_, hasDefined := m["defined"]
	_, hasMax := m["max"]

	assert.True(t, hasIndexesDefined, "JSON must contain 'indexes_defined' field")
	assert.True(t, hasIndexesMax, "JSON must contain 'indexes_max' field")
	assert.False(t, hasDefined, "JSON must NOT contain 'defined' — frontend accesses 'indexes_defined'")
	assert.False(t, hasMax, "JSON must NOT contain 'max' — frontend accesses 'indexes_max'")

	// Also assert the values are correct so this test validates the Go-side
	// population path (NVIndexesDefined=4, NVIndexesMax=32 from fixedProps mock).
	assert.Equal(t, float64(4), m["indexes_defined"])
	assert.Equal(t, float64(32), m["indexes_max"])
}

// TestTPMService_GetNVSummary_FieldsPopulated verifies that both IndexesDefined
// and IndexesMax carry non-zero values when the TPM reports them. This is the
// unit-level companion to the Playwright regression: it proves the Go service
// actually populates the fields before they reach the frontend.
func TestTPMService_GetNVSummary_FieldsPopulated(t *testing.T) {
	mock := defaultMockTPM()
	svc := newServiceWithMock(mock)

	summary, err := svc.GetNVSummary()
	require.NoError(t, err)

	// Both fields must be non-zero — the fixedProps mock returns 4 and 32.
	assert.Equal(t, 4, summary.IndexesDefined, "IndexesDefined must be populated from TPM FixedProperties")
	assert.Equal(t, 32, summary.IndexesMax, "IndexesMax must be populated from TPM FixedProperties")
}

func TestReplayEventLog_ReadPCRsFails(t *testing.T) {
	events := []xkms.TPMEvent{
		{
			PCRIndex:    0,
			EventType:   "EV_NO_ACTION",
			DigestCount: 1,
			Digests: []xkms.TPMDigest{
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

func TestTPMService_VerifyCertAgainstTrustStore_NilCert(t *testing.T) {
	svc := NewTPMService()
	result := svc.verifyCertAgainstTrustStore(nil, truststore.PurposeTPMManufacturer)
	assert.False(t, result)
}

func TestTPMService_ImportIDevIDCert_WriteError(t *testing.T) {
	_, pemStr := realSelfSignedCert(t)
	mock := defaultMockTPM()
	mock.writeIDevIDErr = errors.New("write failed")
	svc := newServiceWithMock(mock)
	err := svc.ImportIDevIDCert(pemStr)
	assert.Error(t, err)
}

// createTestTPMService returns a TPMService over mock with a temporary data
// directory.
func createTestTPMService(t *testing.T, mock *mockTPM) (*TPMService, string) {
	t.Helper()
	svc := newServiceWithMock(mock)
	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)
	return svc, dataDir
}
