package tpm2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 required for TPM 2.0 specification compatibility

	"github.com/jeremyhahn/go-xkms/pkg/errs"

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
	"sync/atomic"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	tcptpm "github.com/google/go-tpm/tpm2/transport/tcp"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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
	// deviceCaps caches the algorithm and curve sets this TPM reports. The
	// answer cannot change while the device is open, and the pointer is
	// published atomically so concurrent callers share one snapshot without a
	// lock on the hot path.
	deviceCaps atomic.Pointer[DeviceCapabilities]
	// rsaKeyBits caches the RSA modulus sizes this TPM accepts. They are not
	// reported by any capability property, so they are learned by offering each
	// defined size to TPM2_TestParms.
	rsaKeyBits  atomic.Pointer[[]int]
	device      *os.File
	ekAttrs     *types.KeyAttributes
	ekECCPubKey *ecdsa.PublicKey
	ekRSAPubKey *rsa.PublicKey
	fqdn        string
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
		switch {
		case params.Config.EK.RSAConfig != nil:
			params.Config.EK.KeyAlgorithm = x509.RSA.String()
		case params.Config.EK.ECCConfig != nil:
			params.Config.EK.KeyAlgorithm = x509.ECDSA.String()
		default:
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
	switch {
	case params.Transport != nil:
		params.Logger.Info("Using custom TPM transport")
		tpmTransport = params.Transport
	case params.Config.CommandAddress != "":
		// External TPM over TCP (e.g. swtpm socket). CommandAddress carries the
		// "host:port" of the TPM command channel; PlatformAddress carries the
		// control channel (command port+1 by convention). This path is used when
		// connecting to a software TPM like swtpm in CI or integration tests.
		platAddr := params.Config.PlatformAddress
		if platAddr == "" {
			// Derive platform address from command address by incrementing the port.
			// swtpm convention: command=2321, platform(ctrl)=2322.
			if host, port, splitErr := splitHostPort(params.Config.CommandAddress); splitErr == nil {
				platAddr = fmt.Sprintf("%s:%d", host, port+1)
			} else {
				platAddr = params.Config.CommandAddress
			}
		}
		params.Logger.Info(infoOpeningPlatformAddress,
			slog.String("command", params.Config.CommandAddress),
			slog.String("platform", platAddr))
		tpmTransport, err = tcptpm.Open(tcptpm.Config{
			CommandAddress:  params.Config.CommandAddress,
			PlatformAddress: platAddr,
		})
		if err != nil {
			params.Logger.Error("failed to open TCP TPM", slog.String("error", err.Error()))
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("open TCP TPM at %s", params.Config.CommandAddress), Err: err}
		}
	case params.Config.UseSimulator:
		params.Logger.Info(infoOpeningSimulator)
		sim, err = simulatorOpener()
		if err != nil {
			params.Logger.Error("failed to open simulator", slog.String("error", err.Error()))
			return nil, err
		}
		tpmTransport = sim.Transport()
	case params.Config.Device != "":
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

	switch {
	case tpm.config.UseSimulator:
		tpm.logger.Info(infoOpeningSimulator)
		sim, err := simulatorOpener()
		if err != nil {
			tpm.logger.Error("failed to open simulator", slog.String("error", err.Error()))
			return err
		}
		tpm.simulator = sim
		t = sim.Transport()
	case tpm.config.Device != "":
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
	default:
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

// OpenTCPTransport opens a connection to a TPM over TCP (e.g. swtpm).
// commandAddress is "host:port" for the TPM command channel.
// platformAddress is "host:port" for the TPM platform (control) channel;
// when empty it defaults to commandAddress with port incremented by one.
func OpenTCPTransport(commandAddress, platformAddress string) (transport.TPM, error) {
	if platformAddress == "" {
		if host, port, err := splitHostPort(commandAddress); err == nil {
			platformAddress = fmt.Sprintf("%s:%d", host, port+1)
		} else {
			platformAddress = commandAddress
		}
	}
	return tcptpm.Open(tcptpm.Config{
		CommandAddress:  commandAddress,
		PlatformAddress: platformAddress,
	})
}

// splitHostPort splits a "host:port" string into its components, returning
// an error when the address is malformed or the port is not numeric.
func splitHostPort(addr string) (host string, port int, err error) {
	h, p, splitErr := strings.Cut(addr, ":")
	if !splitErr {
		return "", 0, &errs.Message{Msg: fmt.Sprintf("tpm2: malformed address %q (no colon)", addr)}
	}
	var portN int
	if _, scanErr := fmt.Sscanf(p, "%d", &portN); scanErr != nil {
		return "", 0, &errs.Wrapped{Msg: fmt.Sprintf("tpm2: non-numeric port in %q", addr), Err: scanErr}
	}
	return h, portN, nil
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

		return eccPublicKey(pub)
	}

	return nil, store.ErrInvalidKeyAlgorithm
}

// Returns the configured TPM_ALG_ID (per TCG algorithm registry).
// See definition in Part 2: Structures, section 6.3.
func (tpm *TPM2) AlgID() tpm2.TPMAlgID {
	return tpm.algID
}

// platformPolicyPCRSelection returns the TPML_PCR_SELECTION used by every
// branch of the platform policy: the single platform PCR in the platform PCR
// bank (TCG TPM 2.0 Part 2, Section 10.6.2).
func platformPolicyPCRSelection(hashAlgID tpm2.TPMAlgID, pcr uint) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      hashAlgID,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
		}},
	}
}

// platformPolicyBranchDigests computes the two branch digests of the platform
// policy with trial policy calculators: branch 1 is TPM2_PolicyPCR over the
// supplied PCR selection and PCR digest, branch 2 is TPM2_PolicyAuthValue.
//
// pcrDigest is a parameter rather than a live PCR read so a caller can rebuild
// the branch digests a given object was created with. Every producer of a
// platform policy digest -- object creation, the trial digest and the live
// policy session -- routes through this one function, so the branches cannot
// drift apart.
func platformPolicyBranchDigests(
	hashAlgID tpm2.TPMAlgID,
	pcr uint,
	pcrDigest []byte) (branch1, branch2 []byte, err error) {

	pcrCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}
	pcrCmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrDigest,
		},
		Pcrs: platformPolicyPCRSelection(hashAlgID, pcr),
	}
	if err := pcrCmd.Update(pcrCalc); err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("PolicyPCR trial: %v", err)}
	}

	authCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}
	authCmd := tpm2.PolicyAuthValue{}
	if err := authCmd.Update(authCalc); err != nil {
		return nil, nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("PolicyAuthValue trial: %v", err)}
	}

	return pcrCalc.Hash().Digest, authCalc.Hash().Digest, nil
}

// platformPolicyORDigest computes the TPM2_PolicyOR digest over both platform
// policy branches (TCG TPM 2.0 Part 3, Section 23.6). The result is the value
// attached to an object as its AuthPolicy, and the value a policy session must
// reach before the TPM will honour it.
func platformPolicyORDigest(hashAlgID tpm2.TPMAlgID, branch1, branch2 []byte) ([]byte, error) {

	orCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}

	orCmd := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				{Buffer: branch1},
				{Buffer: branch2},
			},
		},
	}
	if err := orCmd.Update(orCalc); err != nil {
		return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("PolicyOR trial: %v", err)}
	}

	return orCalc.Hash().Digest, nil
}

// capturePlatformPolicyPin reads the live platform PCR and records it, together
// with the PCR selection it was read from, as the pin for an object about to be
// created under the platform policy. The pin is what later lets the
// PolicyAuthValue (PIN) branch rebuild the object's PolicyPCR branch digest
// without consulting live PCRs.
func (tpm *TPM2) capturePlatformPolicyPin() (*store.PlatformPolicyPin, error) {

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}

	pcrDigest, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return nil, &errs.Detail{Err: ErrPlatformPolicyDigestCompute, Detail: fmt.Sprintf("%v", err)}
	}

	return &store.PlatformPolicyPin{
		PCRBank:   uint16(hashAlgID),
		PCRIndex:  uint32(tpm.config.PlatformPCR),
		PCRDigest: pcrDigest,
	}, nil
}

// platformPolicyDigestFromPin computes the platform policy AuthPolicy digest
// from a pin instead of from live PCRs. Called with a freshly captured pin it
// produces exactly the value PlatformPolicyDigest produces; called with a
// stored pin it reproduces the value an existing object was created with.
func platformPolicyDigestFromPin(pin *store.PlatformPolicyPin) (tpm2.TPM2BDigest, error) {

	if pin == nil {
		return tpm2.TPM2BDigest{}, &errs.Detail{
			Err:    ErrPlatformPolicyDigestCompute,
			Detail: "nil platform policy pin",
		}
	}

	hashAlgID := tpm2.TPMAlgID(pin.PCRBank)

	branch1, branch2, err := platformPolicyBranchDigests(
		hashAlgID, uint(pin.PCRIndex), pin.PCRDigest)
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}

	compoundDigest, err := platformPolicyORDigest(hashAlgID, branch1, branch2)
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}

	return tpm2.TPM2BDigest{Buffer: compoundDigest}, nil
}

// primaryPolicyPinAttrs returns the key attributes under which a persistent
// primary key's platform policy pin is recorded.
//
// A primary key has no blobs in the key store -- it is identified by the
// handle it was persisted to -- and several of them share the configured CN,
// because they are all built from the same SRK configuration and differ only
// by handle. The handle is therefore folded into the record name so their pins
// cannot overwrite one another.
//
// Only platform-policy primaries record a pin, so in practice this names the
// Platform SRK's record. The shared SRK carries no platform policy and writes
// no record; the qualification exists so that no two platform-bound primaries
// -- present or future -- can collide.
//
// Returns nil when the key carries no TPM attributes, which is also the
// condition under which no pin was ever recorded for it.
func primaryPolicyPinAttrs(attrs *types.KeyAttributes) *types.KeyAttributes {
	if attrs == nil || attrs.TPMAttributes == nil {
		return nil
	}
	pinAttrs := *attrs
	pinAttrs.CN = fmt.Sprintf("%s-%08x", attrs.CN, uint32(attrs.TPMAttributes.Handle))
	return &pinAttrs
}

// recordPrimaryPolicyPin persists a persistent primary key's platform policy
// pin to the platform key backend under its handle-qualified name, overwriting
// any record left by a previous key at the same handle.
//
// Overwriting is the correct behaviour and the reason a stale record is never
// a hazard: a pin is only ever read back for a key that uses the platform
// policy, and every creation of such a key writes its own pin first.
//
// The primary key backend is deliberate. A primary key has no blobs in any
// caller's key store -- it is platform state, identified by the handle it was
// persisted to -- so its pin has exactly one writer and one reader.
func (tpm *TPM2) recordPrimaryPolicyPin(
	keyAttrs *types.KeyAttributes,
	pin *store.PlatformPolicyPin) error {

	pinAttrs := primaryPolicyPinAttrs(keyAttrs)
	if pinAttrs == nil {
		return &errs.Detail{
			Err:    ErrPlatformPolicyDigestCompute,
			Detail: "cannot record a platform policy pin without TPM key attributes",
		}
	}

	if tpm.backend == nil {
		tpm.logger.Warn("tpm: no key backend configured to record the platform policy pin; "+
			"the password branch of this key will not survive a platform change",
			slog.String("cn", pinAttrs.CN))
		return nil
	}

	record, err := pin.MarshalBinary()
	if err != nil {
		return err
	}

	if err := tpm.backend.Save(
		pinAttrs, record, store.FSEXT_PLATFORM_POLICY, true); err != nil {

		return err
	}

	tpm.logger.Debug("tpm: platform policy pin recorded",
		slog.String("cn", pinAttrs.CN),
		slog.String("pcr_digest", fmt.Sprintf("%x", pin.PCRDigest)))

	return nil
}

// recordKeyPolicyPin persists a child key's platform policy pin beside that
// key's public and private areas, under the key's own name.
//
// Unlike a primary key, a child key already owns a name in the key store -- the
// one its blobs are written under -- so its pin shares exactly the blobs'
// collision domain and needs no further qualification: two keys that could
// overwrite one another's pin would already be overwriting one another's
// blobs. It also follows the blobs' lifetime, including deletion.
//
// backend may be nil, in which case the platform backend is used, and
// overwrite carries the caller's own overwrite policy so the record cannot
// replace a record the blobs themselves were not allowed to replace.
func (tpm *TPM2) recordKeyPolicyPin(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	pin *store.PlatformPolicyPin,
	overwrite bool) error {

	if backend == nil {
		backend = tpm.backend
	}
	if backend == nil {
		tpm.logger.Warn("tpm: no key backend configured to record the platform policy pin; "+
			"the password branch of this key will not survive a platform change",
			slog.String("cn", keyAttrs.CN))
		return nil
	}

	record, err := pin.MarshalBinary()
	if err != nil {
		return err
	}

	if err := backend.Save(
		keyAttrs, record, store.FSEXT_PLATFORM_POLICY, overwrite); err != nil {

		return err
	}

	tpm.logger.Debug("tpm: platform policy pin recorded",
		slog.String("cn", keyAttrs.CN),
		slog.String("pcr_digest", fmt.Sprintf("%x", pin.PCRDigest)))

	return nil
}

// PlatformPolicyDigest computes a PolicyOR digest that combines two policy
// branches: a PCR-based branch (PolicyPCR) and a password-based branch
// (PolicyAuthValue). This digest is used as the AuthPolicy when creating
// TPM objects with compound policy, enabling both automatic PCR-based
// unlock and manual PIN-based fallback.
//
// The computation follows the TPM 2.0 specification (Part 3, Section 23.6):
//  1. Compute Branch 1 digest: trial PolicyPCR over the live platform PCR
//  2. Compute Branch 2 digest: trial PolicyAuthValue
//  3. Compute PolicyOR over both branch digests
//
// The digest is derived from the platform PCR as it reads right now, so an
// object created with it is bound to the current platform state. Callers that
// also need to know which PCR state a created object was bound to (sealed
// objects, so their PIN branch survives a platform change) capture the pin
// with capturePlatformPolicyPin and use platformPolicyDigestFromPin instead;
// both paths compute the same digest.
func (tpm *TPM2) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {

	pin, err := tpm.capturePlatformPolicyPin()
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}

	digest, err := platformPolicyDigestFromPin(pin)
	if err != nil {
		return tpm2.TPM2BDigest{}, err
	}

	tpm.logger.Info("tpm: PlatformPolicyDigest computed",
		slog.String("digest", fmt.Sprintf("%x", digest.Buffer)))

	return digest, nil
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
		return ErrInstallTransportNotInitialized
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
			// Reinstall recovery: if the empty-auth attempt failed with
			// TPM_RC_BAD_AUTH, a prior platformd run on this TPM set the
			// hierarchy auth to the current soPIN. A fresh install never
			// gets to clear the TPM (the installer doesn't PPI-clear, and
			// TPM2_Clear fails inside platformd because DA protects it).
			// So retry once using newPassword as the old auth — this
			// covers the common case where a platform is reinstalled
			// with the same soPIN and the TPM still has the prior
			// provisioning. It's a no-op if already under the right auth
			// (HierarchyChangeAuth with old==new is idempotent).
			if len(oldPassword) == 0 && len(newPassword) > 0 && isTPMBadAuth(err) {
				tpm.logger.Warn("hierarchy auth already set with soPIN; retrying with soPIN as old-auth (reinstall recovery)",
					slog.String("first_error", err.Error()))
				_, retryErr := tpm2.HierarchyChangeAuth{
					AuthHandle: tpm2.AuthHandle{
						Handle: hierarchy,
						Auth:   tpm2.PasswordAuth(newPassword),
					},
					NewAuth: tpm2.TPM2BAuth{
						Buffer: newPassword,
					},
				}.Execute(tpm.transport)
				if retryErr == nil {
					tpm.logger.Info("hierarchy auth confirmed (reinstall recovery)")
					continue
				}
				tpm.logger.Error("failed to change hierarchy auth after soPIN retry", slog.String("error", retryErr.Error()))
				return retryErr
			}
			tpm.logger.Error("failed to change hierarchy auth", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}

// isTPMBadAuth reports whether err is a TPM_RC_BAD_AUTH failure. We only
// match on the string because the go-tpm error wrapping doesn't expose a
// stable typed code at this call site. Accepting the literal prefix is
// safe — TPM_RC_BAD_AUTH is the canonical form emitted by go-tpm.
func isTPMBadAuth(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "TPM_RC_BAD_AUTH") ||
		strings.Contains(msg, "authorization failure without DA implications")
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

	// If all attempts failed, surface the canonical "not found" sentinel
	// so callers can reliably detect a missing EK certificate with
	// errors.Is(err, ErrEndorsementCertNotFound), regardless of which
	// underlying fallback (NV RAM, certificate store, manufacturer
	// download) was attempted last. The last low-level error is wrapped
	// for diagnostics rather than returned bare, since a raw TPM RC (e.g.
	// TPM_RC_HANDLE from a NV index that was never defined) is an
	// implementation detail, not a distinct error condition callers
	// should need to match on.
	if lastErr != nil {
		return nil, &errs.Detail{Err: ErrEndorsementCertNotFound, Detail: fmt.Sprintf("%v", lastErr)}
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
		return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to read NV public at 0x%08X", ekCertIndex), Err: err}
	}

	// Get the NV public contents
	nvPublic, err := nvPub.NVPublic.Contents()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get NV public contents", Err: err}
	}

	// Check if the area is readable
	if nvPublic.DataSize == 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("NV area at 0x%08X has zero size", ekCertIndex)}
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
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to read NV chunk at offset %d", offset), Err: err}
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

	// signAuth is the authorization the TPM2_Sign command runs under. Each
	// branch below answers it for the key shape it handles; a branch that
	// leaves it nil gets the key session created for a stored key pair.
	var signAuth tpm2.Session

	validation := tpm2.TPMTTKHashCheck{
		Tag: tpm2.TPMSTHashCheck,
	}

	// Only an attestation key takes the ticketed path.
	//
	// A restricted signing key may sign nothing but a digest the TPM itself
	// produced, so signing external data with one means hashing it inside the
	// TPM first and presenting the TPMT_TK_HASHCHECK that TPM2_Hash returns
	// (TCG TPM 2.0 Library Part 3, section 12.1). That is correct for the IAK,
	// the AK and the LAK, which TCG "TPM 2.0 Keys for Device Identity and
	// Attestation" v1.10 r9 defines as Restricted.
	//
	// The IDevID key is the deliberate opposite: the same document creates it
	// Unrestricted precisely so a device can sign arbitrary data -- a TLS
	// CertificateVerify above all -- with its device identity, and marks the
	// two classes differently in their certificates (tcg-cap-verifiedTPMFixed
	// versus tcg-cap-verifiedTPMRestricted) "to prevent the possibility of
	// spoofing." This package agrees everywhere else: the IDevID templates in
	// types.go leave Restricted CLEAR, and VerifyTCG_CSR_IDevID rejects an
	// enrolling IDevID whose public area says otherwise.
	//
	// Routing the IDevID through the restricted case hashed the caller's digest
	// a second time, so the signature was over H(digest) and could not be
	// verified by anyone computing over digest. The IDevID case signs the
	// caller's digest directly, like any other unrestricted key.
	switch keyAttrs.KeyType {

	case types.KeyTypeAttestation:

		digest, validationDigest, err := tpm.Hash(keyAttrs, digest)
		if err != nil {
			tpm.logger.Error("failed to hash data for restricted signing key",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN))
			return nil, err
		}

		// TPM2_Hash answers with a NULL ticket -- an empty digest under the
		// NULL hierarchy -- when the data it hashed begins with
		// TPM_GENERATED_VALUE, which is how the TPM refuses to certify data
		// shaped like its own attestation structures as safe for a restricted
		// key (TCG TPM 2.0 Library Part 3, section 16.1). Sending that on as
		// though it were an endorsement-hierarchy ticket asks the TPM to
		// validate a ticket it never issued, and it answers TPM_RC_TICKET
		// naming a command parameter. Refuse here instead, saying what the TPM
		// declined to do.
		if len(validationDigest) == 0 {
			tpm.logger.Error("TPM refused to certify the data as safe for a restricted signing key",
				slog.String("cn", keyAttrs.CN))
			return nil, ErrRestrictedSignRefused
		}

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

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		// An attestation or IDevID key is RSA here, and TPM2_Sign builds the
		// PKCS#1 v1.5 DigestInfo for it, so the digest algorithm has to be
		// named. These keys are restricted and therefore always name a scheme
		// of their own, which the resolution below both honours and enforces.
		// See rsaSchemeHash and rsaSignScheme.
		algo, err := rsaSchemeHash(requestedSignHash(opts), rsaDetails.Scheme, len(digest))
		if err != nil {
			tpm.logger.Error("failed to resolve signature scheme hash",
				slog.String("error", err.Error()),
				slog.String("hash", requestedSignHash(opts).String()))
			return nil, err
		}

		schemeAlg, err := rsaSignScheme(rsaDetails.Scheme, isPSSRequest(keyAttrs, ksSignerOpts))
		if err != nil {
			tpm.logger.Error("failed to resolve signature scheme",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN))
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
				Scheme: schemeAlg,
				Details: tpm2.NewTPMUSigScheme(
					schemeAlg, &tpm2.TPMSSchemeHash{
						HashAlg: algo,
					}),
			},
			Validation: validation,
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}

		// The signature is unpacked as the shape that was asked of the TPM,
		// which is the only shape it can be.
		var rsaSig *tpm2.TPMSSignatureRSA
		if schemeAlg == tpm2.TPMAlgRSAPSS {
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

	case types.KeyTypeIDevID:

		// An IDevID (or LDevID) is a primary key made persistent by
		// CreateIDevID, so there is no key pair to load: it is addressed by the
		// persistent handle its configuration names. Everything after this
		// point -- the scheme resolution, the NULL hash-check ticket already in
		// validation, the signature unpacking -- is the ordinary unrestricted
		// signing path, which is exactly what an unrestricted key needs.
		if keyAttrs.TPMAttributes == nil {
			return nil, ErrInvalidKeyAttributes
		}
		handle = keyAttrs.TPMAttributes.Handle

		// signAuth is left nil on purpose: the USER role of an IDevID is
		// answered by createKeySession below, which presents the authValue
		// when one is set and otherwise, for a platform-bound IDevID, the
		// delegated session through the key's Policy NV Index (TCG "TPM 2.0
		// Keys for Device Identity and Attestation" v1.00 r12, sections 7.2.4
		// and 7.3). Choosing here would duplicate that rule.

	default:

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

	// The hash algorithm for the TPMT_SIG_SCHEME is resolved inside each key
	// type's branch below. It cannot be resolved here because hash "NONE"
	// (crypto.Hash(0) -- the caller has already produced the digest) has a
	// different answer per key type: for ECDSA it is the key's own scheme hash,
	// which the TPM requires inScheme to match, while for RSA it cannot be
	// honoured at all. See eccSchemeHash and rsaSchemeHash.
	requestedHash := requestedSignHash(opts)

	// Create key session to sign with, unless the branch above already answered
	// the authorization. The backend is threaded through so the key's platform
	// policy pin is read from the same store its blobs came from, which is what
	// lets a PIN-carrying signing key still sign after the platform
	// measurements change.
	if signAuth == nil {
		session2, closer2, err2 := tpm.createKeySession(keyAttrs, backend)
		if err2 != nil {
			tpm.logger.Error("failed to create key session", slog.String("error", err2.Error()))
			return nil, err2
		}
		defer func() {
			if err := closer2(); err != nil {
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}()
		signAuth = session2
	}

	if outPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		rsaDetails, err := outPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		algo, err := rsaSchemeHash(requestedHash, rsaDetails.Scheme, len(digest))
		if err != nil {
			tpm.logger.Error("failed to resolve RSA signature scheme hash",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN),
				slog.String("hash", requestedHash.String()))
			return nil, err
		}

		// The padding scheme comes from the key when the key fixes one, and
		// from the request when it does not. A key created with TPM_ALG_NULL
		// can produce both PKCS#1 v1.5 and PSS signatures, which is what lets
		// one RSA key serve a certificate signed v1.5 and a TLS 1.3 handshake
		// that requires PSS.
		schemeAlg, err := rsaSignScheme(rsaDetails.Scheme, isPSSRequest(keyAttrs, ksSignerOpts))
		if err != nil {
			tpm.logger.Error("failed to resolve RSA signature scheme",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN))
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   signAuth,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: schemeAlg,
				Details: tpm2.NewTPMUSigScheme(
					schemeAlg, &tpm2.TPMSSchemeHash{
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
		if schemeAlg == tpm2.TPMAlgRSAPSS {

			rsaSig, err = signResponse.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}

			pubKey, err := tpm.ParsePublicKey(pub.OutPublic.Bytes())
			if err != nil {
				return nil, err
			}

			// The salt-length check below is performed under the digest the
			// caller actually asked for. It used to be hardcoded to SHA-256,
			// which made every PSS signature over a SHA-384 or SHA-512 digest
			// fail this check rather than the TPM's.
			err = rsa.VerifyPSS(
				pubKey.(*rsa.PublicKey),
				requestedHash,
				digest,
				rsaSig.Sig.Buffer,
				&rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       requestedHash,
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

		eccDetails, err := outPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Error("failed to get ECC details", slog.String("error", err.Error()))
			return nil, err
		}

		algo, err := eccSchemeHash(requestedHash, eccDetails.Scheme, len(digest))
		if err != nil {
			tpm.logger.Error("failed to resolve ECDSA signature scheme hash",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN),
				slog.String("hash", requestedHash.String()))
			return nil, err
		}

		signResponse, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: handle,
				Name:   pub.Name,
				Auth:   signAuth,
			},
			Digest: tpm2.TPM2BDigest{
				Buffer: digest,
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

	var err error
	var maxDigestBuffer = 1024

	// Try to get hierarchy auth from parent, then self, then use empty auth
	var hierarchyAuth []byte
	switch {
	case keyAttrs.Parent != nil && keyAttrs.Parent.TPMAttributes != nil && keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil:
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	case keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.HierarchyAuth != nil:
		hierarchyAuth = keyAttrs.TPMAttributes.HierarchyAuth.Bytes()
	default:
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

	// TPM2_HashSequenceStart allocates an object slot to hold the sequence
	// context (TCG TPM 2.0 Library Part 3, section 17.3). TPM2_SequenceComplete
	// releases that slot, but only when it succeeds -- so a failure in any
	// TPM2_SequenceUpdate, or in TPM2_SequenceComplete itself, strands the slot
	// for the life of the connection. Signing an attestation payload larger than
	// one TPM2B_MAX_BUFFER is what reaches this path, and a handful of failures
	// there is enough to exhaust a real TPM's object memory.
	sequenceCompleted := false
	defer func() {
		if !sequenceCompleted {
			tpm.Flush(rspHSS.SequenceHandle)
		}
	}()

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
	sequenceCompleted = true
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

		rsaDetails, err := public.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA details", slog.String("error", err.Error()))
			return nil, err
		}

		// The padding scheme comes from the key when the key fixes one, and
		// from the key's configured signature algorithm when it does not.
		// Copying the key's scheme field into inScheme verbatim was wrong for
		// exactly one shape, and it is the shape TCG "TPM 2.0 Keys for Device
		// Identity and Attestation" v1.00 r12, Template H-1 requires of an
		// IDevID: a key whose scheme is TPM_ALG_NULL names no scheme to copy,
		// and TPM2_Sign refuses a TPM_ALG_NULL inScheme on such a key with
		// TPM_RC_SCHEME -- for a key that constrains nothing, the command has
		// to say what to sign with (TCG TPM 2.0 Library Part 3, section 12.1).
		// rsaSignScheme is the same resolution the crypto.Signer path uses.
		schemeAlg, err := rsaSignScheme(rsaDetails.Scheme, store.IsRSAPSS(keyAttrs.SignatureAlgorithm))
		if err != nil {
			tpm.logger.Error("failed to resolve RSA signature scheme",
				slog.String("error", err.Error()),
				slog.String("cn", keyAttrs.CN))
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
				Scheme: schemeAlg,
				Details: tpm2.NewTPMUSigScheme(
					schemeAlg, &tpm2.TPMSSchemeHash{
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

		// The signature is unpacked as the shape that was asked of the TPM,
		// which is the only shape it can be. Deriving the two separately is
		// how a signature gets requested as one shape and read as another.
		var rsaSig *tpm2.TPMSSignatureRSA
		if schemeAlg == tpm2.TPMAlgRSAPSS {
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
		return nil, &errs.Message{Msg: fmt.Sprintf("measurement log path must be absolute: %s", measurementLogPath)}
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

	// Ordered, not a map. Ranging over a map randomizes the order of the
	// returned banks on every call, so any caller indexing the result --
	// banks[0] to mean "the SHA-1 bank", say -- reads a different bank run to
	// run. That already cost this package a disabled test whose failure was
	// misattributed to test isolation. Callers should still match on
	// PCRBank.Algorithm, but the order is now at least stable and predictable.
	supportedBanks := []struct {
		name string
		algo tpm2.TPMAlgID
	}{
		{"SHA1", tpm2.TPMAlgSHA1},
		{"SHA256", tpm2.TPMAlgSHA256},
		{"SHA384", tpm2.TPMAlgSHA384},
		{"SHA512", tpm2.TPMAlgSHA512},
	}

	for _, supported := range supportedBanks {
		name, algo := supported.name, supported.algo

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

// downloadEKCertFromManufacturer downloads the EK certificate from the
// manufacturer's EK cert service.
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
		return nil, &errs.Wrapped{Msg: "invalid URL", Err: err}
	}
	if parsedURL.Scheme != "https" {
		return nil, &errs.Message{Msg: fmt.Sprintf("only HTTPS URLs are allowed, got: %s", parsedURL.Scheme)}
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
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported algorithm ID: %d", algID)}
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
		return nil, &errs.Message{Msg: fmt.Sprintf("shares must be at least 2, got %d", shares)}
	}

	// Calculate threshold as 2/3 of total shares, minimum 2
	threshold := (shares * 2) / 3
	if threshold < 2 {
		threshold = 2
	}

	// Split the secret using Shamir's Secret Sharing
	shareObjs, err := qrdbsdk.ShamirSplit(secret, threshold, shares)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to split secret", Err: err}
	}

	// Convert Share objects to JSON strings
	result := make([]string, len(shareObjs))
	for i, share := range shareObjs {
		jsonBytes, err := json.Marshal(share)
		if err != nil {
			return nil, &errs.Wrapped{Msg: fmt.Sprintf("failed to marshal share %d", i), Err: err}
		}
		result[i] = string(jsonBytes)
	}

	return result, nil
}

// SecretFromShares reconstructs a secret from Shamir shares.
// Each share must be a JSON-serialized Share object.
func (tpm *TPM2) SecretFromShares(shares []string) (string, error) {
	if len(shares) == 0 {
		return "", &errs.Message{Msg: "no shares provided"}
	}

	// Convert JSON strings back to Share objects
	shareObjs := make([]*qrdbsdk.ShamirShare, len(shares))
	for i, shareStr := range shares {
		var share qrdbsdk.ShamirShare
		if err := json.Unmarshal([]byte(shareStr), &share); err != nil {
			return "", &errs.Wrapped{Msg: fmt.Sprintf("failed to unmarshal share %d", i), Err: err}
		}
		shareObjs[i] = &share
	}

	// Combine the shares to reconstruct the secret
	secret, err := qrdbsdk.ShamirCombine(shareObjs)
	if err != nil {
		return "", &errs.Wrapped{Msg: "failed to combine shares", Err: err}
	}

	return string(secret), nil
}
