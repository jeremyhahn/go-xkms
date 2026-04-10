package tpm2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility

	// #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"github.com/jeremyhahn/go-quicraft/pkg/crypto/shamir"
	kbackend "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SimulatorInterface abstracts the TPM simulator for conditional compilation
type SimulatorInterface interface {
	Close() error
	Transport() transport.TPM
	ReadWriter() io.ReadWriter
}

// simulatorOpener opens the TPM simulator for unit testing
var simulatorOpener func() (SimulatorInterface, error)

type TrustedPlatformModule interface {
	ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error)
	AKProfile() (AKProfile, error)
	AlgID() tpm2.TPMAlgID
	CalculateName(algID tpm2.TPMAlgID, publicArea []byte)
	Clear(lockoutAuth []byte) error
	Close() error
	FactoryReset(ownerAuth []byte) error
	// FactoryResetWithClear is FactoryReset preceded by a destructive
	// TPM2_Clear via the LOCKOUT hierarchy with empty auth. Callers MUST
	// gate this behind explicit operator opt-in — it resets owner /
	// endorsement / lockout hierarchy auths and wipes all persistent
	// objects in those hierarchies. Manufacturer EK certificates in the
	// Platform hierarchy are preserved. See FactoryReset doc comment for
	// when to use which.
	FactoryResetWithClear(ownerAuth []byte) error
	ForceClear() error
	Config() *Config
	CreateECDSA(
		keyAttrs *types.KeyAttributes,
		backend store.KeyBackend,
		overwrite bool) (*ecdsa.PublicKey, error)
	CreateEK(keyAttrs *types.KeyAttributes) error
	CreateSecretKey(
		keyAttrs *types.KeyAttributes,
		backend store.KeyBackend) error
	CreateIAK(ekAttrs *types.KeyAttributes, qualifyingData []byte) (*types.KeyAttributes, error)
	CreateIDevID(akAttrs *types.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*types.KeyAttributes, *TCG_CSR_IDEVID, error)
	CreatePlatformPolicy() error
	CreateRSA(
		keyAttrs *types.KeyAttributes,
		backend store.KeyBackend,
		overwrite bool) (*rsa.PublicKey, error)
	CreateKeySession(
		keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error)
	CreateSession(
		keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error)
	CreateSRK(keyAttrs *types.KeyAttributes) error
	CreateTCG_CSR_IDEVID(
		ekCert *x509.Certificate,
		akAttrs *types.KeyAttributes,
		idevidAttrs *types.KeyAttributes) (TCG_CSR_IDEVID, error)
	DeleteKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) error
	Device() string
	EK() (crypto.PublicKey, error)
	EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error)
	EKAttributes() (*types.KeyAttributes, error)
	EKCertificate() (*x509.Certificate, error)
	EKCertificateRSA() (*x509.Certificate, error)
	EKCertificateEC() (*x509.Certificate, error)
	EKECC() (*ecdsa.PublicKey, error)
	EKRSA() (*rsa.PublicKey, error)
	EventLog() ([]byte, error)
	FixedProperties() (*PropertiesFixed, error)
	Flush(handle tpm2.TPMHandle)
	GoldenMeasurements() ([]byte, error)
	HMAC(auth []byte) tpm2.Session
	HMACSaltedSession(
		handle tpm2.TPMHandle,
		pub tpm2.TPMTPublic,
		auth []byte) (s tpm2.Session, close func() error, err error)
	HMACSession(auth []byte) (s tpm2.Session, close func() error, err error)
	IAK() (crypto.PublicKey, error)
	IAKAttributes() (*types.KeyAttributes, error)
	IDevID() (crypto.PublicKey, error)
	IDevIDAttributes() (*types.KeyAttributes, error)
	Info() (string, error)
	IsFIPS140_2() (bool, error)
	IsPlatformPCRExtended() (bool, error)
	ExtendPCR(pcrIndex int, hashAlg string, data []byte) error
	Install(soPIN types.Password, opts *InstallOptions) error
	KeyAttributes(handle tpm2.TPMHandle) (*types.KeyAttributes, error)
	LoadKeyPair(
		keyAttrs *types.KeyAttributes,
		session *tpm2.Session,
		backend store.KeyBackend) (*tpm2.LoadResponse, error)
	MakeCredential(
		akName tpm2.TPM2BName,
		secret []byte) ([]byte, []byte, []byte, error)
	MakeCredentialWithExternalEK(
		ekCert *x509.Certificate,
		iakPubBytes []byte,
		secret []byte) ([]byte, []byte, []byte, error)
	NonceSession(secret types.Password) (tpm2.Session, func() error, error)
	NVRead(keyAttrs *types.KeyAttributes, dataSize uint16) ([]byte, error)
	NVWrite(keyAttrs *types.KeyAttributes) error
	NVDefineCounter(keyAttrs *types.KeyAttributes) error
	NVDefineExtend(keyAttrs *types.KeyAttributes) error
	NVIncrement(keyAttrs *types.KeyAttributes) (uint64, error)
	NVExtend(keyAttrs *types.KeyAttributes, data []byte) error
	NVReadCounter(keyAttrs *types.KeyAttributes) (uint64, error)
	NVReadExtend(keyAttrs *types.KeyAttributes) ([]byte, error)
	NVUndefine(keyAttrs *types.KeyAttributes) error
	Open() error
	ParseEKCertificate(ekCert []byte) (*x509.Certificate, error)
	ParsedEventLog() ([]Event, error)
	ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error)
	PlatformPolicyDigestHash() ([]byte, error)
	PlatformPolicyDigest() (tpm2.TPM2BDigest, error)
	PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error)
	PlatformQuote(keyAttrs *types.KeyAttributes) (Quote, []byte, error)
	Provision(soPIN types.Password) error
	ProvisionEKCert(hierarchyAuth, ekCert []byte) error
	ProvisionOwner(hierarchyAuth types.Password) (*types.KeyAttributes, error)
	Quote(pcrs []uint, nonce []byte) (Quote, error)
	CertifyKey(keyAttrs *types.KeyAttributes, nonce []byte, backend store.KeyBackend) (*CertifyResult, error)
	Random() ([]byte, error)
	RandomBytes(fixedLength int) ([]byte, error)
	RandomHex(fixedLength int) ([]byte, error)
	RandomSource() io.Reader
	Read(data []byte) (n int, err error)
	ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error)
	ReadPCRs(pcrList []uint) ([]PCRBank, error)
	RSADecrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, blob []byte) ([]byte, error)
	RSAEncrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, message []byte) ([]byte, error)
	SaveKeyPair(
		keyAttrs *types.KeyAttributes,
		outPrivate tpm2.TPM2BPrivate,
		outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic],
		backend store.KeyBackend,
		overwrite bool) error
	// Seal implements types.Sealer - seals data using the TPM
	Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error)
	// SealKey creates a sealed keyed hash key (legacy API)
	SealKey(
		keyAttrs *types.KeyAttributes,
		backend store.KeyBackend,
		overwrite bool) (*tpm2.CreateResponse, error)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	SetHierarchyAuth(oldSecret, newSecret types.Password, hierarchy *tpm2.TPMHandle) error

	// VerifyAuth verifies the auth value on a persistent key at the given handle.
	// The TPM validates the auth by executing a lightweight command (Create)
	// with the provided authValue as the session auth.
	VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error

	// ChangeAuth changes the auth value on a persistent primary key.
	// For primary keys, recreates with same template (deterministic key material)
	// and new auth, then evicts and re-persists at the same handle.
	ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error
	SecretFromShares(shares []string) (string, error)
	ShareSecret(secret []byte, shares int) ([]string, error)
	SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error)
	SSRKAttributes() (*types.KeyAttributes, error)
	PlatformSRKAttributes() (*types.KeyAttributes, error)
	// SSRK returns the Storage Root Key configuration.
	SSRK() *SRKConfig
	// PlatformKeyStore returns the platform key store, or nil if not configured.
	PlatformKeyStore() PlatformKeyStorer
	SupportedAlgorithms() ([]string, error)
	SupportedCommands() ([]string, error)
	SupportedECCCurves() ([]string, error)
	Transport() transport.TPM
	// Unseal implements types.Sealer - unseals data from the TPM
	Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error)
	// UnsealKey unseals a keyed hash key (legacy API)
	UnsealKey(keyAttrs *types.KeyAttributes, backend store.KeyBackend) ([]byte, error)
	// CanSeal implements types.Sealer - returns true if sealing is supported
	CanSeal() bool
	WriteEKCert(ekCert []byte) error

	// IDevID/IAK Certificate management
	IDevIDCertificate() (*x509.Certificate, error)
	ProvisionIDevIDCert(cert *x509.Certificate) error
	DeleteIDevIDCertificate() error
	IAKCertificate() (*x509.Certificate, error)
	ProvisionIAKCert(cert *x509.Certificate) error
	DeleteIAKCertificate() error

	VerifyTCGCSR(
		csr *TCG_CSR_IDEVID,
		sigAlgo x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error)
	VerifyTCG_CSR_IAK(
		csr *TCG_CSR_IDEVID,
		sigAlgo x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error)
	VerifyTCG_CSR_IDevID(
		csr *TCG_CSR_IDEVID,
		signatureAlgorithm x509.SignatureAlgorithm) (*types.KeyAttributes, *UNPACKED_TCG_CSR_IDEVID, error)
	SignValidate(
		keyAttrs *types.KeyAttributes,
		digest, validationDigest []byte) ([]byte, error)
	HashSequence(
		keyAttrs *types.KeyAttributes,
		data []byte) ([]byte, []byte, error)
	Hash(
		keyAttrs *types.KeyAttributes,
		data []byte) ([]byte, []byte, error)

	// ECDHZGen performs ECDH key agreement using TPM2_ECDH_ZGen command.
	// It computes the shared secret Z = [privateKey]Q where Q is the peer's public key.
	// The result is the X coordinate of the shared point as per NIST SP 800-56A.
	// Per TCG TPM 2.0 specification Part 3, section 14.5.
	ECDHZGen(
		keyAttrs *types.KeyAttributes,
		peerPublicKey *tpm2.TPMSECCPoint,
		backend store.KeyBackend) ([]byte, error)

	// Dictionary attack lockout management
	// DictionaryAttackLockoutReset resets the DA lockout counter using the lockout hierarchy auth.
	DictionaryAttackLockoutReset(lockoutAuth []byte) error

	// Symmetric key operations
	GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error)
	GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error)
	SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error)
}

type Params struct {
	Backend      store.KeyBackend
	BlobStore    store.BlobStorer
	CertStore    store.CertificateStorer
	Config       *Config
	DebugSecrets bool
	FQDN         string
	Logger       *slog.Logger
	SignerStore  store.SignerStorer
	Tracker      types.AEADSafetyTracker // Optional: AEAD safety tracker for symmetric encryption
	Transport    transport.TPM           // Optional: custom transport for testing
}

type TPM2 struct {
	algID        tpm2.TPMAlgID
	backend      store.KeyBackend
	blobStore    store.BlobStorer
	certStore    store.CertificateStorer
	config       *Config
	debugSecrets bool
	device       *os.File
	ekAttrs      *types.KeyAttributes
	ekECCPubKey  *ecdsa.PublicKey
	ekRSAPubKey  *rsa.PublicKey
	fqdn         string
	// hash         crypto.Hash
	iakAttrs         *types.KeyAttributes
	idevidAttrs      *types.KeyAttributes
	logger           *slog.Logger
	policyDigest     tpm2.TPM2BDigest
	platformKeyStore PlatformKeyStorer
	platformSRKAttrs *types.KeyAttributes
	random           io.Reader
	signerStore      store.SignerStorer
	simulator        SimulatorInterface
	ssrkAttrs        *types.KeyAttributes
	tracker          types.AEADSafetyTracker
	transport        transport.TPM
	TrustedPlatformModule
}

// Creates a new TPM2 instance by opening a socket to a
// Trusted Platform Module (TPM). When this function
// returns the TPM is ready for use.
func NewTPM2(params *Params) (TrustedPlatformModule, error) {

	// Ensure Config is not nil
	if params.Config == nil {
		cfg := DefaultConfig // Copy default config
		params.Config = &cfg
	}

	// Set default device if not specified
	if params.Config.Device == "" {
		params.Config.Device = DefaultConfig.Device
	}

	// Ensure EK config is set with defaults
	if params.Config.EK == nil {
		params.Config.EK = DefaultConfig.EK
	}

	if params.Config.EK.KeyAlgorithm == "" {
		if params.Config.EK.RSAConfig != nil {
			params.Config.EK.KeyAlgorithm = x509.RSA.String()
		} else if params.Config.EK.ECCConfig != nil {
			params.Config.EK.KeyAlgorithm = x509.ECDSA.String()
		} else {
			// Use default EK config if no algorithm specified
			params.Config.EK = DefaultConfig.EK
		}
	}

	// Set default Hash if not specified
	if params.Config.Hash == "" {
		params.Config.Hash = DefaultConfig.Hash
	}

	// Ensure PlatformSRK config is set with defaults
	if params.Config.PlatformSRK == nil {
		params.Config.PlatformSRK = DefaultConfig.PlatformSRK
	}

	// Create default logger if none provided
	if params.Logger == nil {
		params.Logger = slog.Default()
	}

	var sim SimulatorInterface
	var tpmTransport transport.TPM
	var device *os.File
	var err error

	// Use custom transport if provided (for testing)
	if params.Transport != nil {
		params.Logger.Info("Using custom TPM transport")
		tpmTransport = params.Transport
	} else if params.Config.UseSimulator {
		params.Logger.Info(infoOpeningSimulator)
		sim, err = simulatorOpener()
		if err != nil {
			params.Logger.Error("failed to open simulator", slog.String("error", err.Error()))
			return nil, err
		}
		tpmTransport = sim.Transport()
	} else if params.Config.Device != "" {
		params.Logger.Info(infoOpeningDevice, slog.String("device", params.Config.Device))
		if strings.HasSuffix(params.Config.Device, ".sock") {
			tpmTransport, err = linuxudstpm.Open(params.Config.Device)
			if err != nil {
				params.Logger.Error("failed to open unix socket", slog.String("error", err.Error()))
				return nil, err
			}
		} else {
			device, err = os.OpenFile(params.Config.Device, os.O_RDWR, 0)
			if err != nil {
				params.Logger.Error("failed to open device", slog.String("error", err.Error()))
				return nil, ErrOpeningDevice
			}
			tpmTransport = transport.FromReadWriter(device)
		}
	}

	hash, ok := store.AvailableHashes()[params.Config.Hash]
	if !ok {
		return nil, store.ErrInvalidHashFunction
	}

	algID, err := ParseCryptoHashAlgID(hash)
	if err != nil {
		return nil, err
	}

	// Initialize AEAD tracker
	tracker := params.Tracker
	if tracker == nil {
		// Check if config has a tracker
		if params.Config.Tracker != nil {
			tracker = params.Config.Tracker
		} else {
			tracker = kbackend.NewMemoryAEADTracker()
		}
	}

	tpm := &TPM2{
		algID:        algID,
		logger:       params.Logger,
		backend:      params.Backend,
		blobStore:    params.BlobStore,
		certStore:    params.CertStore,
		signerStore:  params.SignerStore,
		debugSecrets: params.DebugSecrets,
		config:       params.Config,
		device:       device,
		fqdn:         params.FQDN,
		// hash:         hash,
		simulator: sim,
		tracker:   tracker,
		transport: tpmTransport}

	if params.Config.UseEntropy {
		tpm.random = tpm
	} else {
		tpm.random = rand.Reader
	}

	// Check if the TPM is initialized by attempting to read the EK.
	// First, try the persistent EK handle (created during provisioning).
	// If that fails, fall back to checking for manufacturer EK certificate in NV RAM.
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(params.Config.EK.Handle),
	}.Execute(tpm.transport)
	if err != nil {
		// Persistent EK handle doesn't exist — always fall back to checking for
		// manufacturer EK certificate in NV RAM. TPMs return varying response codes
		// (TPM_RC_VALUE 0x184, TPM_RC_HANDLE 0x18b, or other format-1 codes) depending
		// on firmware, so we do not match specific TPMRC values.
		tpm.logger.Debug("persistent EK not found, checking NV RAM for manufacturer certificate",
			slog.String("ekHandle", fmt.Sprintf("0x%08X", params.Config.EK.Handle)),
			slog.String("readPublicError", err.Error()))

		_, nvErr := tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(params.Config.EK.CertHandle),
		}.Execute(tpm.transport)

		if nvErr != nil {
			// Neither persistent EK nor manufacturer certificate exists
			tpm.logger.Debug("TPM not initialized: no persistent EK and no manufacturer EK certificate",
				slog.String("ekHandle", fmt.Sprintf("0x%08X", params.Config.EK.Handle)),
				slog.String("certHandle", fmt.Sprintf("0x%08X", params.Config.EK.CertHandle)))
			return tpm, ErrNotInitialized
		}

		// Manufacturer EK certificate exists in NV RAM — TPM can be used for read operations
		// but provisioning is still needed to create the persistent EK key
		tpm.logger.Debug("Manufacturer EK certificate found in NV RAM",
			slog.String("certHandle", fmt.Sprintf("0x%08X", params.Config.EK.CertHandle)))
	}

	return tpm, nil
}

// Opens a new logical connection with the underlying TPM
// using an instance of this TPM2 object that's already been
// instantiated.
func (tpm *TPM2) Open() error {

	var t transport.TPM
	var err error

	if tpm.config.UseSimulator {

		tpm.logger.Info(infoOpeningSimulator)
		sim, err := simulatorOpener()
		if err != nil {
			tpm.logger.Error("failed to open simulator", slog.String("error", err.Error()))
			return err
		}
		tpm.simulator = sim
		t = sim.Transport()
	} else if tpm.config.Device != "" {
		// tpm.logger.Info(infoOpeningDevice, slog.String("device", tpm.config.Device))
		// f, err := os.OpenFile(tpm.config.Device, os.O_RDWR, 0)
		// if err != nil {
		// 	tpm.logger.Error(err.Error())
		// 	return ErrOpeningDevice
		// }
		// tpm.device = f
		// t = transport.FromReadWriter(f)
		if strings.HasSuffix(tpm.config.Device, ".sock") {
			t, err = linuxudstpm.Open(tpm.config.Device)
			if err != nil {
				tpm.logger.Error("failed to open unix socket", slog.String("error", err.Error()))
				return err
			}
		} else {
			f, err := os.OpenFile(tpm.config.Device, os.O_RDWR, 0)
			if err != nil {
				tpm.logger.Error("failed to open device", slog.String("error", err.Error()))
				return ErrOpeningDevice
			}
			tpm.device = f
			t = transport.FromReadWriter(f)
		}
	} else {
		return errors.New("invalid TPM transport configuration")
	}

	tpm.transport = t
	return nil
}

// OpenUnixSocketTransport opens a connection to a TPM via Unix domain socket.
// This is typically used for connecting to swtpm instances. The returned transport
// should be closed when no longer needed.
func OpenUnixSocketTransport(socketPath string) (transport.TPM, error) {
	return linuxudstpm.Open(socketPath)
}

// Parses a tpm2.TPM2BPublic byte array and returns the crypto.PublicKey
func (tpm *TPM2) ParsePublicKey(tpm2BPublic []byte) (crypto.PublicKey, error) {

	loadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHNull,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](tpm2BPublic),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}
	defer tpm.Flush(loadRsp.ObjectHandle)

	pubArea, err := tpm2.ReadPublic{
		ObjectHandle: loadRsp.ObjectHandle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to read public key", slog.String("error", err.Error()))
		return nil, err
	}

	pub, err := pubArea.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	if pub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, err
		}
		return rsaPub, nil

	} else if pub.Type == tpm2.TPMAlgECC {

		eccDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, err
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, err
		}

		curve, err := eccDetail.CurveID.Curve()
		if err != nil {
			return nil, err
		}

		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		return eccPub, nil
	}

	return nil, store.ErrInvalidKeyAlgorithm
}

// Returns the configured TPM_ALG_ID (per TCG algorithm registry).
// See definition in Part 2: Structures, section 6.3.
func (tpm *TPM2) AlgID() tpm2.TPMAlgID {
	return tpm.algID
}

// PlatformPolicyDigest computes a PolicyOR digest that combines two policy
// branches: a PCR-based branch (PolicyPCR) and a password-based branch
// (PolicyAuthValue). This digest is used as the AuthPolicy when creating
// TPM objects with compound policy, enabling both automatic PCR-based
// unlock and manual PIN-based fallback.
//
// The computation follows the TPM 2.0 specification (Part 3, Section 23.6):
//  1. Compute Branch 1 digest: trial PolicyPCR
//  2. Compute Branch 2 digest: trial PolicyAuthValue
//  3. Compute PolicyOR over both branch digests
func (tpm *TPM2) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: %v", ErrPlatformPolicyDigestCompute, err)
	}

	pcrDigest, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: %v", ErrPlatformPolicyDigestCompute, err)
	}

	// Branch 1: PolicyPCR digest (computed via trial/calculator)
	pcrCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: %v", ErrPlatformPolicyDigestCompute, err)
	}

	pcrCmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrDigest,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      hashAlgID,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			}},
		},
	}
	if err := pcrCmd.Update(pcrCalc); err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: PolicyPCR trial: %v", ErrPlatformPolicyDigestCompute, err)
	}
	branch1Digest := pcrCalc.Hash().Digest

	// Branch 2: PolicyAuthValue digest (computed via trial/calculator)
	authCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: %v", ErrPlatformPolicyDigestCompute, err)
	}

	authCmd := tpm2.PolicyAuthValue{}
	if err := authCmd.Update(authCalc); err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: PolicyAuthValue trial: %v", ErrPlatformPolicyDigestCompute, err)
	}
	branch2Digest := authCalc.Hash().Digest

	tpm.logger.Debug("tpm: PlatformPolicyDigest - branch digests",
		slog.String("pcr_branch", fmt.Sprintf("%x", branch1Digest)),
		slog.String("auth_branch", fmt.Sprintf("%x", branch2Digest)))

	// Compute PolicyOR over both branches
	orCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: %v", ErrPlatformPolicyDigestCompute, err)
	}

	orCmd := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				{Buffer: branch1Digest},
				{Buffer: branch2Digest},
			},
		},
	}
	if err := orCmd.Update(orCalc); err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("%w: PolicyOR trial: %v", ErrPlatformPolicyDigestCompute, err)
	}
	compoundDigest := orCalc.Hash().Digest

	tpm.logger.Info("tpm: PlatformPolicyDigest computed",
		slog.String("digest", fmt.Sprintf("%x", compoundDigest)))

	return tpm2.TPM2BDigest{Buffer: compoundDigest}, nil
}

// Returns the TPM device path
func (tpm *TPM2) Device() string {
	return tpm.config.Device
}

// Returns the underlying transport.TPM used to facilitate
// the logical connection to the TPM.
func (tpm *TPM2) Transport() transport.TPM {
	return tpm.transport
}

// getActiveTransientHandles queries the TPM for currently loaded transient handles
func (tpm *TPM2) getActiveTransientHandles() []tpm2.TPMHandle {
	if tpm.transport == nil {
		return nil
	}

	// Query TPM for transient handles (starting from 0x80000000)
	response, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(0x80000000), // Transient handle range start
		PropertyCount: 16,                 // Query up to 16 handles
	}.Execute(tpm.transport)
	if err != nil {
		// If we can't query capabilities, return empty list
		tpm.logger.Debug("unable to query active handles", slog.String("error", err.Error()))
		return nil
	}

	handles, err := response.CapabilityData.Data.Handles()
	if err != nil {
		tpm.logger.Debug("unable to parse handle list", slog.String("error", err.Error()))
		return nil
	}

	return handles.Handle
}

// flushSilent flushes a handle without logging errors (for cleanup operations)
// flushSilent flushes a handle without logging errors (for cleanup operations)
func (tpm *TPM2) flushSilent(handle tpm2.TPMHandle) {
	tpm.logger.Debug("flushing handle", slog.String("handle", fmt.Sprintf("0x%x", handle)))
	_, err := tpm2.FlushContext{FlushHandle: handle}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Debug("failed to flush handle",
			slog.String("handle", fmt.Sprintf("0x%x", handle)),
			slog.String("error", err.Error()))
	}
}
func (tpm *TPM2) Close() error {
	tpm.logger.Info(infoClosingConnection)

	if tpm.transport != nil {
		activeHandles := tpm.getActiveTransientHandles()
		for _, handle := range activeHandles {
			tpm.flushSilent(handle)
		}
	}

	if tpm.device != nil {
		if err := tpm.device.Close(); err != nil {
			tpm.logger.Error("failed to close device", slog.String("error", err.Error()))
		}
		tpm.device = nil
		tpm.transport = nil
	}
	if tpm.simulator != nil {
		if err := tpm.simulator.Close(); err != nil {
			tpm.logger.Error("failed to close simulator", slog.String("error", err.Error()))
		}
		tpm.simulator = nil
	}
	return nil
}

// Returns the TPM configuration per the platform configuration file
func (tpm *TPM2) Config() *Config {
	return tpm.config
}

// SSRK returns the Storage Root Key configuration from the TPM config.
func (tpm *TPM2) SSRK() *SRKConfig {
	if tpm.config == nil {
		return nil
	}
	return tpm.config.SSRK
}

// PlatformKeyStore returns the platform key store, or nil if not configured.
func (tpm *TPM2) PlatformKeyStore() PlatformKeyStorer {
	return tpm.platformKeyStore
}

// SetPlatformKeyStore sets the platform key store on the TPM instance.
func (tpm *TPM2) SetPlatformKeyStore(pks PlatformKeyStorer) {
	tpm.platformKeyStore = pks
}

// Takes ownership of the TPM by setting the Owner, Endorsement and
// Lockout hierarchy authorization passwords, as described in TCG
// TPM 2.0 Part 1 - Architecture - Section 13.8.1 - Taking Ownership
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
//
// If the optional hierarchy is provided, only the authorization password for
// the specified hierarchy will be set. If not provided, all hierarchies will
// be set to the same authorization store.
func (tpm *TPM2) SetHierarchyAuth(oldPasswd, newPasswd types.Password, hierarchy *tpm2.TPMHandle) error {
	if tpm.transport == nil {
		return errors.New("TPM transport not initialized")
	}
	if hierarchy != nil {
		var sHierarchy string
		switch *hierarchy {
		case tpm2.TPMRHLockout:
			sHierarchy = "Lockout"
		case tpm2.TPMRHEndorsement:
			sHierarchy = "Endorsement"
		case tpm2.TPMRHOwner:
			sHierarchy = "Owner"
		}
		tpm.logger.Debug("setting hierarchy authorization password", slog.String("hierarchy", sHierarchy))
	} else {
		tpm.logger.Debug("setting hierarchy authorization passwords")
	}
	var oldPassword, newPassword []byte
	if oldPasswd != nil {
		oldPassword = oldPasswd.Bytes()
	}
	if newPasswd != nil {
		newPassword = newPasswd.Bytes()
	}
	if tpm.debugSecrets {
		tpm.logger.Debug("hierarchy passwords",
			slog.String("old", string(oldPassword)),
			slog.String("new", string(newPassword)))
	}
	var hierarchies []tpm2.TPMHandle
	if hierarchy != nil {
		hierarchies = []tpm2.TPMHandle{
			*hierarchy,
		}
	} else {
		hierarchies = []tpm2.TPMHandle{
			tpm2.TPMRHEndorsement,
			tpm2.TPMRHLockout,
			tpm2.TPMRHOwner,
			// tpm2.TPMRHPlatform,
		}
	}
	for _, hierarchy := range hierarchies {
		_, err := tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{
				Handle: hierarchy,
				Auth:   tpm2.PasswordAuth(oldPassword),
			},
			NewAuth: tpm2.TPM2BAuth{
				Buffer: newPassword,
			},
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to change hierarchy auth", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}

// Retrieve the Endorsement Key Certificate. If the EK cert-handle is 0, the EK certificate
// is managed using an internal certificate store. If an EK cert-handle is defined, the
// certificate is retrieved from TPM NVRAM. If the certificate is not found in NVRAM, an
// attempt is made to download the certificate from the Manufacturer's EK cert service.
// If the configured certificate location fails, it falls back to checking both RSA and EC
// standard NV indices.
func (tpm *TPM2) EKCertificate() (*x509.Certificate, error) {

	tpm.logger.Debug("retrieving EK certificate")

	policyDigest, err := tpm.PlatformPolicyDigest()
	if err != nil {
		return nil, err
	}
	ekAttrs, err := EKAttributesFromConfig(*tpm.config.EK, &policyDigest, tpm.config.IDevID)
	if err != nil {
		return nil, err
	}

	if tpm.config.EK.CertHandle == 0 {
		if tpm.certStore == nil {
			return nil, ErrEndorsementCertNotFound
		}
		ekCert, err := tpm.certStore.Get(ekAttrs)
		if err != nil {
			if err == store.ErrCertNotFound {
				return nil, ErrEndorsementCertNotFound
			}
			return nil, err
		}
		return ekCert, nil
	}

	// Build list of NV indices to try (configured first, then standard locations)
	var indicesToTry []tpm2.TPMHandle

	// Add configured/attribute-based index first
	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.CertHandle != 0 {
		indicesToTry = append(indicesToTry, ekAttrs.TPMAttributes.CertHandle)
	} else if tpm.config.EK.CertHandle > 0 {
		indicesToTry = append(indicesToTry, tpm2.TPMHandle(tpm.config.EK.CertHandle))
	}

	// Add standard RSA and EC locations as fallbacks (avoiding duplicates)
	rsaIndex := tpm2.TPMHandle(ekCertIndexRSA2048)
	ecIndex := tpm2.TPMHandle(ekCertIndexECCP256)

	if len(indicesToTry) == 0 || indicesToTry[0] != rsaIndex {
		indicesToTry = append(indicesToTry, rsaIndex)
	}
	if len(indicesToTry) < 2 || (indicesToTry[0] != ecIndex && indicesToTry[1] != ecIndex) {
		indicesToTry = append(indicesToTry, ecIndex)
	}

	// Try each NV index until we find a valid certificate
	var lastErr error
	for _, ekCertIndex := range indicesToTry {
		cert, err := tpm.readEKCertFromNV(ekCertIndex)
		if err == nil {
			return cert, nil
		}
		lastErr = err
		tpm.logger.Debug("EK certificate not found at index, trying next",
			slog.String("index", fmt.Sprintf("0x%08X", ekCertIndex)),
			slog.String("error", err.Error()))
	}

	// Try certificate store fallback
	if tpm.certStore != nil {
		tpm.logger.Debug("NVRAM read failed, trying certificate store fallback")
		if ekCert, certErr := tpm.certStore.Get(ekAttrs); certErr == nil {
			return ekCert, nil
		}
	}

	// As a last resort, try downloading from the manufacturer EK certificate service
	cert, err := tpm.downloadEKCertFromManufacturer(indicesToTry[0])
	if err == nil {
		return cert, nil
	}

	// If all attempts failed, return the last error
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrEndorsementCertNotFound
}

// readEKCertFromNV reads an EK certificate from the specified NV RAM index.
// Returns the parsed certificate or an error if the certificate cannot be read.
func (tpm *TPM2) readEKCertFromNV(ekCertIndex tpm2.TPMHandle) (*x509.Certificate, error) {
	// Step 1: Read NV public area to get Name and DataSize
	nvPub, err := tpm2.NVReadPublic{
		NVIndex: ekCertIndex,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, fmt.Errorf("failed to read NV public at 0x%08X: %w", ekCertIndex, err)
	}

	// Get the NV public contents
	nvPublic, err := nvPub.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get NV public contents: %w", err)
	}

	// Check if the area is readable
	if nvPublic.DataSize == 0 {
		return nil, fmt.Errorf("NV area at 0x%08X has zero size", ekCertIndex)
	}

	// Step 2: Read NV data in chunks (TPM has max buffer size, typically 1024 bytes)
	// Use the NV index's own handle for auth (authread attribute)
	const maxNVBufferSize = 512 // Conservative chunk size for compatibility
	totalSize := nvPublic.DataSize
	certData := make([]byte, 0, totalSize)

	for offset := uint16(0); offset < totalSize; {
		chunkSize := totalSize - offset
		if chunkSize > maxNVBufferSize {
			chunkSize = maxNVBufferSize
		}

		response, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: ekCertIndex, // Use NV index handle for authread
				Name:   nvPub.NVName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.AuthHandle{
				Handle: ekCertIndex,
				Name:   nvPub.NVName,
				Auth:   tpm2.PasswordAuth(nil),
			},
			Size:   chunkSize,
			Offset: offset,
		}.Execute(tpm.transport)

		if err != nil {
			return nil, fmt.Errorf("failed to read NV chunk at offset %d: %w", offset, err)
		}

		certData = append(certData, response.Data.Buffer...)
		offset += chunkSize
	}

	tpm.logger.Debug("read NVRAM EK certificate",
		slog.String("index", fmt.Sprintf("0x%08X", ekCertIndex)),
		slog.Int("size", len(certData)))

	// Try to parse as PEM first, then DER
	cert, err := store.DecodePEM(certData)
	if err != nil {
		tpm.logger.Debug("not PEM encoded, trying DER", slog.String("error", err.Error()))
		return x509.ParseCertificate(certData)
	}

	return x509.ParseCertificate(cert.Bytes)
}

// EKCertificateRSA returns the RSA EK certificate from NV RAM at index 0x01C00002.
func (tpm *TPM2) EKCertificateRSA() (*x509.Certificate, error) {
	return tpm.readEKCertFromNV(tpm2.TPMHandle(ekCertIndexRSA2048))
}

// EKCertificateEC returns the EC EK certificate from NV RAM at index 0x01C0000A.
func (tpm *TPM2) EKCertificateEC() (*x509.Certificate, error) {
	return tpm.readEKCertFromNV(tpm2.TPMHandle(ekCertIndexECCP256))
}

// Signs the requested data using the key attributes
// provided by SignerOpts. Supports RSA and ECDSA.
func (tpm *TPM2) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) (signature []byte, err error) {

	ksSignerOpts, ok := opts.(*store.SignerOpts)
	if !ok {
		return nil, store.ErrInvalidSignerOpts
	}

	var session tpm2.Session
	var closer func() error

	keyAttrs := ksSignerOpts.KeyAttributes

	// Default to the platform backend
	backend := tpm.backend

	// Use backend provided by signer opts
	if ksSignerOpts.Backend != nil {
		backend = ksSignerOpts.Backend
	}

	// Create parent session to load the key
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		if closer != nil {
			if err := closer(); err != nil {
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	var handle tpm2.TPMHandle

	validation := tpm2.TPMTTKHashCheck{
		Tag: tpm2.TPMSTHashCheck,
	}

	if keyAttrs.KeyType == types.KeyTypeAttestation ||
		keyAttrs.KeyType == types.KeyTypeIDevID {

		digest, validationDigest, _ := tpm.Hash(keyAttrs, digest)

		// TPMT_TK_HASHCHECK -- This ticket is used to indicate that
		// a digest of external data is safe to sign using a restricted
		// signing key. A restricted signing key may only sign a digest
		// that was produced by the TPM. If the digest was produced from
		// externally provided data, there needs to be an indication that the
		// data did not start with the same first octets as are used for data
		// that is generated within the TPM. This prevents "forgeries" of
		// attestation data. This ticket is used to provide the evidence that
		// the data used in the digest was checked by the TPM and is safe to
		// sign. Assuming that the external data is "safe", this type of ticket
		// is produced by TPM2_Hash() or TPM2_SequenceComplete() and used by
		// TPM2_Sign().
		validation = tpm2.TPMTTKHashCheck{
			Hierarchy: tpm2.TPMRHEndorsement,
			Digest: tpm2.TPM2BDigest{
				Buffer: validationDigest,
			},
			Tag: tpm2.TPMSTHashCheck,
		}

		handle = keyAttrs.TPMAttributes.Handle

		pub, err := tpm2.ReadPublic{
			ObjectHandle: handle,
		}.Execute(tpm.Transport())
		if err != nil {
			tpm.logger.Error("failed to read public key", slog.String("error", err.Error()))
			return nil, err
		}

		outPub, err := pub.OutPublic.Contents()
		if err != nil {
			tpm.logger.Error("failed to get public contents", slog.String("error", err.Error()))
			return nil, err
		}

		var algo tpm2.TPMIAlgHash
		if opts == nil {
			algo = tpm2.TPMAlgSHA256
		} else {
			if opts.HashFunc() == crypto.SHA256 {
				algo = tpm2.TPMAlgSHA256
			} else if opts.HashFunc() == crypto.SHA384 {
				algo = tpm2.TPMAlgSHA384
			} else if opts.HashFunc() == crypto.SHA512 {
				algo = tpm2.TPMAlgSHA512
			} else {
				tpm.logger.Error("invalid hash function",
					slog.String("error", store.ErrInvalidHashFunction.Error()),
					slog.String("hash", opts.HashFunc().String()))
				return nil, store.ErrInvalidHashFunction
			}
		}

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: algo,
					}),
			},
			Validation: validation,
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}
		var rsaSig *tpm2.TPMSSignatureRSA
		if opts.(*store.SignerOpts).PSSOptions != nil {
			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		return rsaSig.Sig.Buffer, nil

	} else {

		// Load the keyed hash from saved context file and priv, pub keys
		key, err := tpm.LoadKeyPair(keyAttrs, &session, backend)
		if err != nil {
			tpm.logger.Error("failed to load key pair", slog.String("error", err.Error()))
			return nil, err
		}
		defer tpm.Flush(key.ObjectHandle)
		handle = key.ObjectHandle
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.Transport())
	if err != nil {
		tpm.logger.Error("failed to read public key", slog.String("error", err.Error()))
		return nil, err
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public contents", slog.String("error", err.Error()))
		return nil, err
	}

	var algo tpm2.TPMIAlgHash
	if opts == nil {
		algo = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			algo = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			algo = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			algo = tpm2.TPMAlgSHA512
		} else {
			tpm.logger.Error("invalid hash function",
				slog.String("error", store.ErrInvalidHashFunction.Error()),
				slog.String("hash", opts.HashFunc().String()))
			return nil, store.ErrInvalidHashFunction
		}
	}

	// Create key session to sign with
	session2, closer2, err2 := tpm.CreateKeySession(keyAttrs)
	if err2 != nil {
		tpm.logger.Error("failed to create key session", slog.String("error", err2.Error()))
		return nil, err2
	}
	defer func() {
		if err := closer2(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	if outPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   session2,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: algo,
					}),
			},
			Validation: validation,
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to sign with RSA", slog.String("error", err.Error()))
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if store.IsRSAPSS(keyAttrs.SignatureAlgorithm) ||
			opts.(*store.SignerOpts).PSSOptions != nil {

			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}

			pubKey, err := tpm.ParsePublicKey(pub.OutPublic.Bytes())
			if err != nil {
				return nil, err
			}
			err = rsa.VerifyPSS(
				pubKey.(*rsa.PublicKey),
				crypto.SHA256,
				digest,
				rsaSig.Sig.Buffer,
				&rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				})
			if err != nil {
				return nil, err
			}
			fips140_2, err := tpm.IsFIPS140_2()
			if err != nil {
				return nil, err
			}
			if !fips140_2 {
				// TPM's that aren't FIPS 140-2 compliant don't sign
				// RSA-PSS using a salt length the same size as the
				// hash length, which is incompatible with TLS v1.3
				// and non-compliant with FIPS 140-2.
				//
				// The Golang crypto/rsa/pss.go doesn't expose a public
				// API to perform PSS padding, so punting on synthesizing
				// the functionality on behalf of incompatible TPMs for now.
				return nil, ErrRSAPSSNotSupported
			}

		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		return rsaSig.Sig.Buffer, nil

	} else if outPub.Type == tpm2.TPMAlgECC {

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   session2,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: algo,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.Transport())
		if err != nil {
			return nil, err
		}

		sig, err := signResponse.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}
		return asn1.Marshal(asn1Struct)
	}

	return nil, store.ErrUnsupportedKeyAlgorithm
}

// Performs a TPM2_Hash on the requested data. If the length is greater
// than 1024 bytes, the data is hashed using HashSequence commands.
func (tpm *TPM2) Hash(
	keyAttrs *types.KeyAttributes,
	data []byte) ([]byte, []byte, error) {

	if keyAttrs == nil || keyAttrs.TPMAttributes == nil {
		return nil, nil, ErrInvalidKeyAttributes
	}

	if len(data) > 1024 {
		return tpm.HashSequence(keyAttrs, data)
	}
	h, err := tpm2.Hash{
		Hierarchy: tpm2.TPMRHEndorsement,
		HashAlg:   keyAttrs.TPMAttributes.HashAlg,
		Data: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	return h.OutHash.Buffer, h.Validation.Digest.Buffer, nil
}

// Performs a hash sequence using TPM2_HashSequenceStart,
// TPM2_SequenceUpdate, TPM2_SequenceComplete under the
// Endorsement Hierarchy, using the Hierarchy Authorization
// provided in the key attributes Parent field.
func (tpm *TPM2) HashSequence(
	keyAttrs *types.KeyAttributes,
	data []byte) ([]byte, []byte, error) {

	// var auth []byte
	var err error
	var maxDigestBuffer = 1024

	// if keyAttrs.Password != nil {
	// 	auth, err = keyAttrs.Password.Bytes()
	// 	if err != nil {
	// 		return nil, nil, err
	// 	}
	// }

	// Try to get hierarchy auth from parent, then self, then use empty auth
	var hierarchyAuth []byte
	if keyAttrs.Parent != nil && keyAttrs.Parent.TPMAttributes != nil && keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	} else if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.TPMAttributes.HierarchyAuth.Bytes()
	} else {
		// Use empty auth for hash sequence
		hierarchyAuth = []byte{}
	}

	auth := hierarchyAuth

	hashSequenceStart := tpm2.HashSequenceStart{
		Auth: tpm2.TPM2BAuth{
			Buffer: auth,
		},
		HashAlg: keyAttrs.TPMAttributes.HashAlg,
	}
	rspHSS, err := hashSequenceStart.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	authHandle := tpm2.AuthHandle{
		Handle: rspHSS.SequenceHandle,
		Name: tpm2.TPM2BName{
			Buffer: auth,
		},
		Auth: tpm2.PasswordAuth(hierarchyAuth),
	}

	for len(data) > maxDigestBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxDigestBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(tpm.transport)
		if err != nil {
			return nil, nil, err
		}

		data = data[maxDigestBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHEndorsement,
	}

	rspSC, err := sequenceComplete.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}
	digest := rspSC.Result.Buffer

	return digest, rspSC.Validation.Digest.Buffer, nil
}

// Performs a sequential hash on the provided data using the
// hash algorithm and authorization defined by akAttrs. This
// operation uses the Handle, HashAlg, Name, SignatureAlgorithm
// and Password provided by akAttrs.
func (tpm *TPM2) SignValidate(
	keyAttrs *types.KeyAttributes,
	digest, validationDigest []byte) ([]byte, error) {

	if keyAttrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	var akAuth []byte

	if keyAttrs.Password != nil {
		akAuth = keyAttrs.Password.Bytes()
	}

	// Sign the digest
	var hashSig []byte
	if keyAttrs.TPMAttributes == nil || keyAttrs.TPMAttributes.Public.Type == 0 {
		return nil, errors.New("TPMAttributes.Public is required for SignValidate")
	}
	if keyAttrs.TPMAttributes.HashAlg == 0 {
		return nil, errors.New("TPMAttributes.HashAlg is required for SignValidate")
	}
	public := keyAttrs.TPMAttributes.Public
	if public.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		// rsaDetails, err := keyAttrs.TPMAttributes.Public.Parameters.RSADetail()
		rsaDetails, err := public.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: keyAttrs.TPMAttributes.Handle,
				Name:   keyAttrs.TPMAttributes.Name,
				Auth:   tpm2.PasswordAuth(akAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rsaDetails.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(
					rsaDetails.Scheme.Scheme, &tpm2.TPMSSchemeHash{
						HashAlg: keyAttrs.TPMAttributes.HashAlg,
					}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: validationDigest,
				},
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to sign with RSA", slog.String("error", err.Error()))
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if store.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = signResponse.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}

			// loadRsp, err := tpm2.LoadExternal{
			// 	Hierarchy: tpm2.TPMRHEndorsement,
			// 	// InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](tcgContent.AttestPub),
			// 	// InPublic: akAttrs.TPMAttributes.BPublic,
			// 	InPublic: tpm2.New2B(keyAttrs.TPMAttributes.Public),
			// 	// InPublic: tpm2.New2B(*iakPub),
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	return nil, err
			// }
			// defer tpm.Flush(loadRsp.ObjectHandle)

			// _, err = tpm2.VerifySignature{
			// 	KeyHandle: loadRsp.ObjectHandle,
			// 	Digest: tpm2.TPM2BDigest{
			// 		Buffer: digest,
			// 	},
			// 	Signature: tpm2.TPMTSignature{
			// 		SigAlg: tpm2.TPMAlgRSASSA,
			// 		Signature: tpm2.NewTPMUSignature[*tpm2.TPMSSignatureRSA](
			// 			tpm2.TPMAlgRSASSA,
			// 			&tpm2.TPMSSignatureRSA{
			// 				Hash: keyAttrs.TPMAttributes.HashAlg,
			// 				Sig: tpm2.TPM2BPublicKeyRSA{
			// 					Buffer: rsaSig.Sig.Buffer,
			// 				},
			// 			},
			// 		),
			// 	},
			// }.Execute(tpm.transport)
			// if err != nil {
			// 	return nil, err
			// }

		}
		hashSig = rsaSig.Sig.Buffer

	} else if public.Type == tpm2.TPMAlgECC {

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: keyAttrs.TPMAttributes.Handle,
				Name:   keyAttrs.TPMAttributes.Name,
				Auth:   tpm2.PasswordAuth(akAuth),
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: keyAttrs.TPMAttributes.HashAlg,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: validationDigest,
				},
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}

		sig, err := signResponse.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, err
		}
		hashSig = asn1Sig
	}

	return hashSig, nil
}

// Retrieves the raw event log from /sys/kernel/security/tpm*/binary_bios_measurements
func (tpm *TPM2) EventLog() ([]byte, error) {
	measurementLogPath := fmt.Sprintf(
		binaryMeasurementsFileNameTemplate,
		tpm.tpmDeviceName())
	cleanPath := filepath.Clean(measurementLogPath)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("measurement log path must be absolute: %s", measurementLogPath)
	}
	bytes, err := os.ReadFile(cleanPath)
	if err != nil {
		// Log at debug level - this is expected in simulator environments
		// where binary_bios_measurements doesn't exist
		tpm.logger.Debug("failed to read event log", slog.String("error", err.Error()))
		return nil, err
	}
	return bytes, nil
}

// Returns a parsed event log from /sys/kernel/security/tpm*/binary_bios_measurements
func (tpm *TPM2) ParsedEventLog() ([]Event, error) {
	measurementLogPath := fmt.Sprintf(
		binaryMeasurementsFileNameTemplate,
		tpm.tpmDeviceName())
	return ParseEventLog(measurementLogPath)
}

// Returns the name and public area for the provided handle
func (tpm *TPM2) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	ek, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	pub, err := ek.OutPublic.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, err
	}
	return ek.Name, *pub, nil
}

// Reads Platform Configuration Register (PCR) values across all
// supported banks with the corresponding PCR ID. This method supports SHA1,
// SHA256, SHA386, and SHA512. If one of the banks are not supported, the
// function stops processing and returns the banks that were successfully
// parsed without an error.
func (tpm *TPM2) ReadPCRs(pcrList []uint) ([]PCRBank, error) {

	tpm.logger.Debug("reading PCR values across all supported banks")

	maxPCR := uint(23)
	banks := make([]PCRBank, 0)

	supportedBanks := make(map[string]tpm2.TPMAlgID, 4)
	supportedBanks["SHA1"] = tpm2.TPMAlgSHA1
	supportedBanks["SHA256"] = tpm2.TPMAlgSHA256
	supportedBanks["SHA384"] = tpm2.TPMAlgSHA384
	supportedBanks["SHA512"] = tpm2.TPMAlgSHA512

	for name, algo := range supportedBanks {

		tpm.logger.Debug(name)

		bank := PCRBank{
			Algorithm: name,
			PCRs:      make([]PCR, 0),
		}
		bankUnsupported := false
		for _, pcr := range pcrList {
			if pcr > maxPCR {
				tpm.logger.Error("invalid PCR index",
					slog.String("bank", strings.ToLower(name)),
					slog.Uint64("pcr", uint64(pcr)))
				return nil, ErrInvalidPCRIndex
			}
			pcrRead := tpm2.PCRRead{
				PCRSelectionIn: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{
						{
							Hash:      algo,
							PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
						},
					},
				},
			}
			response, err := pcrRead.Execute(tpm.transport)
			if err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, ErrHashAlgorithmNotSupported.Error()) ||
					strings.Contains(errMsg, "hash algorithm not supported or not appropriate") {
					tpm.logger.Warn("PCR bank not supported, skipping",
						slog.String("bank", name),
						slog.String("error", errMsg))
					bankUnsupported = true
					break
				}
				tpm.logger.Error("error reading PCR",
					slog.String("bank", name),
					slog.Uint64("pcr", uint64(pcr)),
					slog.String("error", errMsg))
				bankUnsupported = true
				break
			}
			if response == nil {
				continue
			}
			if len(response.PCRValues.Digests) == 0 {
				continue
			}
			buf := response.PCRValues.Digests[0].Buffer
			bank.PCRs = append(bank.PCRs, PCR{
				ID:    int32(pcr), // Use actual PCR index, not iteration index
				Value: buf,        // Store raw bytes, not double-encoded
			})
			tpm.logger.Debug("PCR value",
				slog.Int("pcr", int(pcr)),
				slog.String("value", fmt.Sprintf("%x", buf)))
		}
		if !bankUnsupported && len(bank.PCRs) > 0 {
			banks = append(banks, bank)
		}
	}

	return banks, nil
}

// Flushes a handle from TPM memory
func (tpm *TPM2) Flush(handle tpm2.TPMHandle) {
	tpm.logger.Debug("flushing handle", slog.String("handle", fmt.Sprintf("0x%x", handle)))
	_, err := tpm2.FlushContext{FlushHandle: handle}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to flush handle", slog.String("error", err.Error()))
	}
}

// Thanks, Google:
// https://github.com/google/go-attestation/blob/master/attest/tpm.go#L263
func intelEKURL(ekPub *rsa.PublicKey) string {
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	return intelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

// Downloads the EK certificate from the manufactuers EK cert service
func (tpm *TPM2) downloadEKCertFromManufacturer(ekCertIndex tpm2.TPMHandle) (*x509.Certificate, error) {

	attrs, err := tpm.KeyAttributes(tpm2.TPMHandle(ekIndex))
	if err != nil {
		return nil, err
	}

	ekPub := attrs.TPMAttributes.Public

	if ekPub.Type != tpm2.TPMAlgRSA {
		return nil, errors.New("ECC EK certificates unsupported at this time")
	}

	rsaDetail, err := ekPub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
		return nil, err
	}
	rsaUnique, err := ekPub.Unique.RSA()
	if err != nil {
		tpm.logger.Error("failed to get RSA unique", slog.String("error", err.Error()))
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error("failed to create RSA public key", slog.String("error", err.Error()))
		return nil, err
	}

	ekURL := intelEKURL(rsaPub)
	tpm.logger.Info("downloading EK certificate", slog.String("url", ekURL))

	// Validate URL before making HTTP request
	parsedURL, err := url.Parse(ekURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS URLs are allowed, got: %s", parsedURL.Scheme)
	}
	resp, err := /* #nosec G107 */ http.Get(ekURL) // URL validated above
	if err != nil {
		tpm.logger.Error("failed to download EK certificate", slog.String("error", err.Error()))
		return nil, err
	}

	if resp.StatusCode != 200 {
		body := new(strings.Builder)
		_, err := io.Copy(body, resp.Body)
		if err != nil {
			tpm.logger.Error("failed to read response body", slog.String("error", err.Error()))
			return nil, err
		}
		tpm.logger.Error("error downloading EK certificate",
			slog.Int("status_code", resp.StatusCode),
			slog.String("body", body.String()))
		return nil, ErrEndorsementCertNotFound
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, resp.Body); err != nil {
		tpm.logger.Error("failed to read response body", slog.String("error", err.Error()))
		return nil, err
	}

	result := make(map[string]interface{})
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		return nil, err
	}

	certificate, ok := result["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to parse certificate from EK certificate service")
	}

	cert, err := x509.ParseCertificate([]byte(certificate))
	if err != nil {
		tpm.logger.Error("failed to parse certificate", slog.String("error", err.Error()))
		return nil, ErrEndorsementCertNotFound
	}

	return cert, nil
}

func (tpm *TPM2) tpmDeviceName() string {
	filename := filepath.Base(tpm.config.Device)
	return strings.ReplaceAll(filename, "tpmrm", "tpm")
}

// Calculates the key name of the provided public area using the specified algorithm
func CalculateName(algID tpm2.TPMAlgID, publicArea []byte) ([]byte, error) {
	var hash []byte
	switch algID {
	case tpm2.TPMAlgSHA1:
		// #nosec G401 -- SHA-1 required for TPM 2.0 specification compatibility
		h := sha1.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA256:
		h := sha256.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA3384:
		h := sha512.New384()
		h.Write(publicArea)
		hash = h.Sum(nil)
	case tpm2.TPMAlgSHA512:
		h := sha512.New()
		h.Write(publicArea)
		hash = h.Sum(nil)
	default:
		return nil, fmt.Errorf("unsupported algorithm ID: %d", algID)
	}

	name := make([]byte, 2+len(hash)) // 2 bytes for Algorithm ID + hash length
	binary.BigEndian.PutUint16(name, uint16(algID))
	copy(name[2:], hash) // Copy the hash into the name after the Algorithm ID

	return name, nil
}

// ShareSecret splits a secret into N shares using Shamir's Secret Sharing.
// The threshold is set to 2/3 of total shares (minimum 2).
// Each share is returned as a JSON-serialized string.
func (tpm *TPM2) ShareSecret(secret []byte, shares int) ([]string, error) {
	if shares < 2 {
		return nil, fmt.Errorf("shares must be at least 2, got %d", shares)
	}

	// Calculate threshold as 2/3 of total shares, minimum 2
	threshold := (shares * 2) / 3
	if threshold < 2 {
		threshold = 2
	}

	// Split the secret using Shamir's Secret Sharing
	shareObjs, err := shamir.Split(secret, threshold, shares)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}

	// Convert Share objects to JSON strings
	result := make([]string, len(shareObjs))
	for i, share := range shareObjs {
		jsonBytes, err := json.Marshal(share)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal share %d: %w", i, err)
		}
		result[i] = string(jsonBytes)
	}

	return result, nil
}

// SecretFromShares reconstructs a secret from Shamir shares.
// Each share must be a JSON-serialized Share object.
func (tpm *TPM2) SecretFromShares(shares []string) (string, error) {
	if len(shares) == 0 {
		return "", fmt.Errorf("no shares provided")
	}

	// Convert JSON strings back to Share objects
	shareObjs := make([]*shamir.Share, len(shares))
	for i, shareStr := range shares {
		var share shamir.Share
		if err := json.Unmarshal([]byte(shareStr), &share); err != nil {
			return "", fmt.Errorf("failed to unmarshal share %d: %w", i, err)
		}
		shareObjs[i] = &share
	}

	// Combine the shares to reconstruct the secret
	secret, err := shamir.Combine(shareObjs)
	if err != nil {
		return "", fmt.Errorf("failed to combine shares: %w", err)
	}

	return string(secret), nil
}
