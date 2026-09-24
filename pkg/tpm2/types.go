package tpm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

type EnrollmentStrategy string

// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
const (
	tpmPtManufacturer = 0x00000100 + 5  // PT_FIXED + offset of 5
	tpmPtVendorString = 0x00000100 + 6  // PT_FIXED + offset of 6
	tpmPtFwVersion1   = 0x00000100 + 11 // PT_FIXED + offset of 11

	// Defined in TCG TPM 2.0 Provisioning Guidance - Section 7.8 - NV Memory
	// Table 2: Reserved Handles for TPM Provisioning Fundamental Elements
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ekIndex         = 0x81010001
	ekCertIndex     = 0x01C00002
	srkIndexRSA2048 = 0x81000001
	srkIndexECCP256 = 0x81000002
	idevIDKey       = 0x81020000
	idevIDCert      = 0x01C90000
	iakKey          = 0x81020001
	iakCert         = 0x01C90001

	// TCG TPM 2.0 Keys for Device Identity and Attestation
	// Section 7.3.2 - IDevID/IAK Policy NV Indices for Recoverable Keys
	// Section 7.3.3 - IDevID/IAK Unique String
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
	idevIDNVIndex = 0x01C90020
	iakNVIndex    = 0x01C90021

	ekCertIndexRSA2048 = 0x01C00002
	ekCertIndexECCP256 = 0x01C0000a
	ekCertIndexECCP384 = 0x01C00016
	ekCertIndexECCP521 = 0x01C00018

	// Defined in "Registry of reserved TPM 2.0 handles and localities".
	// These constants are used in test files.

	nvramPlatformIndex    = 0x01400001 //nolint:unused // used in tests
	nvramEndorsementIndex = 0x01C00001 //nolint:unused // used in tests
	nvramOwnerIndex       = 0x01800001 //nolint:unused // used in tests

	// NV index ranges for counter and extend testing
	nvramCounterIndex = 0x01800010 //nolint:unused // used in tests
	nvramExtendIndex  = 0x01800020 //nolint:unused // used in tests

	// nvramChunkIndex is used to test chunked NVRead/NVWrite paths for
	// indices larger than TPM_PT_NV_BUFFER_MAX.
	nvramChunkIndex = 0x01800030 //nolint:unused // used in tests

	// Trusted Platform EK and SRK stored under the Platform Hierarchy
	// Registry of Reserved TPM 2.0 Handles and Localities, Section 2.3.1 - Key Handle Assignments
	tpEKIndex   = 0x81800001
	tpSRKIndex  = 0x81000002
	tpSealIndex = 0x81000003

	manufacturerIntel          = "Intel"
	intelEKCertServiceURL      = "https://ekop.intel.com/ekcertservice/"
	infoOpeningSimulator       = "tpm: opening TPM simulator"
	infoOpeningDevice          = "tpm: opening Linux TPM 2.0 Device"
	infoOpeningPlatformAddress = "tpm: opening TPM 2.0 TCP connection"
	infoClosingConnection      = "tpm: closing TPM 2.0"

	EnrollmentStrategyIAK                    = EnrollmentStrategy("IAK")
	EnrollmentStrategyIAK_IDEVID_SINGLE_PASS = EnrollmentStrategy("IAK_IDEVID_SINGLE_PASS")

	// EnrollmentStrategyUnknown is what ParseIdentityProvisioningStrategy
	// returns for a configured value it does not recognize. It matches no
	// branch in any strategy switch, so the caller falls through to
	// ErrInvalidEnrollmentStrategy and the enrollment fails closed instead of
	// silently running a different device-identity ceremony.
	EnrollmentStrategyUnknown = EnrollmentStrategy("UNKNOWN")

	binaryMeasurementsFileNameTemplate = "/sys/kernel/security/%s/binary_bios_measurements"
)

var (
	// debugPCR and debugPCRBank are used in test files.
	debugPCR     = uint(16)      //nolint:unused // used in tests
	debugPCRBank = PCRBankSHA256 //nolint:unused // used in tests

	ErrPlatformPasswordUnavailable = errors.New("tpm: failed to retrieve platform password")
	ErrCertStoreNotInitialized     = errors.New("tpm: certificate store not initialized")
	ErrInvalidAKAttributes         = errors.New("tpm: invalid AK attributes")
	ErrInvalidEKCertFormat         = errors.New("tpm: invalid endorsement certificate format")
	ErrInvalidEKAttributes         = errors.New("tpm: invalid EK attributes")
	ErrInvalidEKCert               = errors.New("tpm: failed to verify endorsement key certificate")
	ErrDeviceAlreadyOpen           = errors.New("tpm: device already open")
	ErrOpeningDevice               = errors.New("tpm: error opening device")
	ErrInvalidSessionType          = errors.New("tpm: invalid session type")
	ErrInvalidSRKAuth              = errors.New("tpm: invalid storage root key auth")
	ErrInvalidActivationCredential = errors.New("tpm: invalid activation credential")
	ErrHashAlgorithmNotSupported   = errors.New("tpm: hash algorithm not supported")
	ErrInvalidKeyAttributes        = errors.New("tpm: invalid key attributes")
	ErrInvalidPolicyDigest         = errors.New("tpm: invalid policy digest")
	ErrInvalidHandle               = errors.New("tpm: invalid entity handle")
	ErrUnexpectedRandomBytes       = errors.New("tpm: unexpected number of random bytes read")
	ErrInvalidRandomBytesLength    = errors.New("tpm: invalid random bytes length")
	ErrInvalidPCRIndex             = errors.New("tpm: invalid PCR index")
	ErrInvalidNonce                = errors.New("tpm: invalid nonce")
	ErrNotInitialized              = errors.New("tpm: not initialized")

	// ErrKeyRetrievalFailed indicates GetSymmetricKey could not determine
	// whether a symmetric key exists because the underlying key store
	// (store.KeyBackend) returned an error other than "not found" -- a
	// transient I/O failure, permission error, or corrupt blob. Callers
	// must not treat this as backend.ErrKeyNotFound: doing so risks
	// silently generating a replacement for a key that merely failed to
	// read. Mirrors pkg/backend/tpm2.ErrKeyRetrievalFailed.
	ErrKeyRetrievalFailed = errors.New("tpm: symmetric key retrieval failed")

	ErrNotConfigured                   = errors.New("tpm: IDevID not configured")
	ErrEndorsementCertNotFound         = errors.New("tpm: endorsement certificate not found")
	ErrInvalidPlatformSRKConfiguration = errors.New("tpm: invalid platform SRK configuration")
	ErrInvalidHashFunction             = errors.New("tpm: invalid hash function")
	ErrInvalidSessionAuthorization     = errors.New("tpm: invalid session authorization")
	ErrUnsupportedCertifyScheme        = errors.New("tpm: attestation key signing scheme is not supported for certification")
	ErrMissingMeasurementLog           = errors.New("tpm: binary measurement log not found")
	ErrInvalidTPMTransport             = errors.New("tpm: invalid TPM transport configuration")
	ErrSignValidatePublicRequired      = errors.New("tpm: TPMAttributes.Public is required for SignValidate")
	ErrSignValidateHashAlgRequired     = errors.New("tpm: TPMAttributes.HashAlg is required for SignValidate")
	ErrECCEKCertUnsupported            = errors.New("tpm: ECC EK certificates unsupported at this time")
	ErrEKCertServiceParseFailed        = errors.New("tpm: failed to parse certificate from EK certificate service")
	ErrRSAPSSNotSupported              = errors.New("tpm: RSA-PSS / FIPS 140-2 not supported by this TPM")

	// ErrRawRSASignUnsupported reports that a TPM cannot produce a PKCS#1 v1.5
	// signature over a caller-supplied DigestInfo -- the operation PKCS#11 calls
	// raw CKM_RSA_PKCS and Go spells crypto.Hash(0).
	//
	// This is a property of the TPM 2.0 command set, not a gap in this package.
	// TPM2_Sign does not pad the caller's bytes: for an RSASSA scheme it builds
	// the DigestInfo itself from the OID of the scheme's hash algorithm and
	// requires the supplied digest to be exactly that algorithm's digest size
	// (TCG TPM 2.0 Library Part 3, section 12.1, encoded by Part 4's
	// RSASSA_Encode). Handing it a complete 51-byte SHA-256 DigestInfo is
	// answered with TPM_RC_SIZE; handing it a bare 32-byte digest would succeed
	// but produce a signature over a DigestInfo the caller did not build, which
	// is a different signature from the one that was asked for.
	//
	// The only command that performs the bare private-key exponentiation is
	// TPM2_RSA_Decrypt with a TPM_ALG_NULL scheme (Part 3, section 14.3), and it
	// requires the key to have the decrypt attribute SET. The signing keys this
	// package creates have it CLEAR, so the TPM answers TPM_RC_ATTRIBUTES.
	// Setting it to route raw signing through TPM2_RSA_Decrypt would turn every
	// signing key into a raw private-key-operation oracle -- a signature forgery
	// primitive -- so it is deliberately not done.
	//
	// A caller that needs PKCS#1 v1.5 from a TPM key must name the digest
	// algorithm, which lets the TPM build the DigestInfo; a caller that needs the
	// digest signed verbatim must use a backend that can, such as software or
	// PKCS#11.
	ErrRawRSASignUnsupported = errors.New("tpm: raw RSA PKCS#1 v1.5 signing is not supported by this token: TPM2_Sign builds its own DigestInfo, and TPM2_RSA_Decrypt is not permitted on a sign-only key")

	// ErrSchemeHashUnresolved reports that the hash algorithm for a TPM2_Sign
	// TPMT_SIG_SCHEME could not be determined.
	//
	// It is returned when the caller asked for hash "NONE" (crypto.Hash(0),
	// meaning the digest is already built) and neither source of an answer is
	// available: the key's public area names no scheme hash of its own -- it was
	// created with TPM_ALG_NULL -- and the digest's length matches no digest
	// algorithm this package supports, so the TPM would reject every possible
	// choice with TPM_RC_SIZE. It is also returned for a malformed public area
	// whose scheme names an algorithm but no hash.
	ErrSchemeHashUnresolved = errors.New("tpm: cannot resolve the signature scheme hash for hash \"NONE\": the key names no scheme hash and the digest length matches no supported digest algorithm")

	// ErrSignSchemeMismatch reports that a key's public area fixes a signature
	// scheme that cannot satisfy the request.
	//
	// A key created with a scheme other than TPM_ALG_NULL can only be signed
	// with under exactly that scheme, hash algorithm included: TPM2_Sign
	// requires inScheme to be TPM_ALG_NULL or to match the key, and answers
	// anything else with TPM_RC_SCHEME (TCG TPM 2.0 Library Part 3, section
	// 12.1). Keys created before this package moved to TPM_ALG_NULL templates
	// have this shape, so a request for a digest other than the one they were
	// created with is reported here, naming the constraint, instead of letting a
	// bare TPM response code reach the caller.
	ErrSignSchemeMismatch = errors.New("tpm: the key's public area fixes a signature scheme that does not match the requested one; a key created with a fixed scheme can only sign under that scheme")

	// ErrDigestLengthMismatch reports that the digest handed to TPM2_Sign is not
	// the length the signature scheme's hash algorithm produces.
	//
	// TPM2_Sign signs the digest it is given and requires it to be exactly the
	// size of the hash named in inScheme, answering anything else with
	// TPM_RC_SIZE (TCG TPM 2.0 Library Part 3, section 12.1). Reporting it here
	// tells the caller which length was expected; the TPM's own response code
	// names only a command parameter number.
	ErrDigestLengthMismatch = errors.New("tpm: the digest is not the length the signature scheme's hash algorithm produces")

	// ErrAlgorithmNotSupported reports that the TPM does not implement a
	// requested algorithm, as reported by TPM2_GetCapability with TPM_CAP_ALGS.
	// See AlgorithmNotSupportedError for the detail.
	ErrAlgorithmNotSupported = errors.New("tpm: algorithm not implemented by this TPM")

	// ErrSchemeNotImplemented reports that a scheme is legal in TPM 2.0 but is
	// not one this package can operate a key with. See
	// SchemeNotImplementedError.
	ErrSchemeNotImplemented = errors.New("tpm: signature scheme not implemented by this package")

	// ErrSchemeHashRequired reports that a key template named a signature or
	// encryption scheme without the hash algorithm that scheme requires
	// (TCG TPM 2.0 Library Part 2, section 11.2.1.2).
	ErrSchemeHashRequired = errors.New("tpm: a key template that names a scheme must also name the scheme's hash algorithm")

	// ErrSchemeHashUnexpected reports that a key template named a scheme hash
	// while leaving the scheme itself TPM_ALG_NULL. A scheme-less key fixes no
	// hash, so the two cannot both be present.
	ErrSchemeHashUnexpected = errors.New("tpm: a key template with a TPM_ALG_NULL scheme must not name a scheme hash")

	// ErrAdminWithPolicyNoAuthPolicy reports that a key template claims
	// policy-only administration while naming no policy to enforce.
	//
	// With adminWithPolicy SET, the TPM authorizes ADMIN-role commands only
	// through a policy session satisfying the object's authPolicy, and
	// refuses the auth value with TPM_RC_AUTH_TYPE (TCG TPM 2.0 Library
	// Part 1, section 19.6). An empty authPolicy is satisfiable by no
	// session, because a session's policy digest starts at zero and can
	// never equal a zero-length value. The pair therefore makes the ADMIN
	// role -- TPM2_Certify among it -- permanently unavailable on the
	// created object, and because the attribute is part of the template a
	// primary key is derived from, the key cannot be recreated without it
	// either. Creating such an object is refused rather than performed.
	ErrAdminWithPolicyNoAuthPolicy = errors.New("tpm: a key template that sets adminWithPolicy must also name an authPolicy; the admin role would be permanently unauthorizable")

	// ErrDevIDPolicyUnsupported reports a key kind or hash algorithm for which
	// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12 defines
	// no recoverable-key template or Policy NV Index (sections 7.3.2, 7.3.4).
	// Computing a policy for it would produce a digest nothing can check.
	ErrDevIDPolicyUnsupported = errors.New("tpm: no TCG IDevID/IAK policy template exists for this key kind and hash algorithm")

	// ErrDevIDPolicyDigestCompute reports a failure inside the trial-policy
	// computation of an IDevID/IAK Key Policy or Policy NV Index Name
	// (section 7.3.6).
	ErrDevIDPolicyDigestCompute = errors.New("tpm: failed to compute the TCG IDevID/IAK key policy digest")

	// ErrDevIDPolicySession reports a failure while building the policy
	// session that authorizes the ADMIN role of an IDevID/IAK key, or the
	// delegated USER role through its Policy NV Index.
	ErrDevIDPolicySession = errors.New("tpm: failed to build the TCG IDevID/IAK policy session")

	// ErrDevIDPolicyNVIndex reports that the reserved Policy NV Index for an
	// IDevID/IAK key exists with a public area other than NV Policy Template
	// I-0/I-1..I-3 (section 7.3.5), so its Name -- and therefore the
	// PolicyDelegationNV branch of every key policy derived from it (section
	// 7.3.6.4) -- does not match the specification's Table 18. Nothing written
	// to such an index can delegate anything; it is refused instead.
	ErrDevIDPolicyNVIndex = errors.New("tpm: the TCG IDevID/IAK Policy NV Index does not match the specification's template")

	// ErrDevIDDelegation reports a TPM refusal while defining the Policy NV
	// Index under Owner authorization or writing a Delegation Policy into it
	// as the Privacy Administrator (sections 7.2.4, 7.3.5).
	ErrDevIDDelegation = errors.New("tpm: failed to define or write the TCG IDevID/IAK Delegation Policy NV index")

	// ErrDevIDCNUnresolved reports that neither an explicit cn nor a device
	// model and serial number were available to name an IDevID or IAK. The
	// name is refused rather than defaulted because the key stores key on it.
	ErrDevIDCNUnresolved = errors.New("tpm: an IDevID/IAK common name requires either cn or both a device model and serial number")

	// ErrDevIDTemplateNonConformant reports an IDevID or IAK template whose
	// TPMA_OBJECT, authPolicy, unique, scheme, symmetric or exponent departs
	// from TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
	// Templates H-0 through H-4 (sections 7.3.4.1-7.3.4.5). Every one of those
	// fields is an input to a primary key's derivation, so a non-conformant
	// key cannot be repaired after creation; it is refused before
	// TPM2_CreatePrimary instead.
	ErrDevIDTemplateNonConformant = errors.New("tpm: the IDevID/IAK template does not conform to TCG Template H-0")

	// ErrDevIDProvisionEKCert reports that device identity provisioning could
	// not obtain the endorsement key certificate. The TCG-CSR-IDEVID carries
	// the EK certificate (TCG "TPM 2.0 Keys for Device Identity and
	// Attestation" v1.00 r12, section 6.1.2 step 2b and section 6.2.2 step
	// 4b) and the CA verifies it before issuing; without it the ceremony
	// cannot complete, so provisioning refuses rather than continuing without
	// an identity.
	ErrDevIDProvisionEKCert = errors.New("tpm: device identity provisioning requires the endorsement key certificate")

	// ErrDevIDProvisionIAK reports that the Initial Attestation Key could not
	// be created during provisioning (section 6.1.2 step 1).
	ErrDevIDProvisionIAK = errors.New("tpm: failed to provision the initial attestation key")

	// ErrDevIDProvisionIDevID reports that the Initial Device Identity key
	// could not be created during provisioning (section 6.2.2 step 2). A
	// device without an IDevID has no identity; provisioning fails closed
	// instead of logging and continuing.
	ErrDevIDProvisionIDevID = errors.New("tpm: failed to provision the initial device identity key")

	// ErrDevIDProvisionLookup reports that provisioning could not determine
	// whether an IDevID or IAK already exists at its persistent handle. Only
	// TPM_RC_HANDLE means "absent, create it"; every other answer is a fault
	// that must not be mistaken for a provisioned key.
	ErrDevIDProvisionLookup = errors.New("tpm: failed to determine whether a device identity key exists")

	// ErrTCGCSRAttestation reports that the platform attestation carried in
	// the TCG-CSR-IDEVID prodCaData field (section 13.1) could not be
	// produced. A quote the TPM refused is a fault; the CSR is not emitted
	// with the attestation silently missing.
	ErrTCGCSRAttestation = errors.New("tpm: failed to produce the platform attestation carried by the TCG-CSR-IDEVID")

	// ErrTCGCSRPad reports that the random pad bytes the TCG-CSR-IDEVID
	// structure ends with (section 13.1: "padSz bytes of random data") could
	// not be read from the TPM's random number generator.
	ErrTCGCSRPad = errors.New("tpm: failed to generate the TCG-CSR-IDEVID pad")

	// ErrDevIDUniqueString reports that the unique field of an IDevID or IAK
	// template is not the string TCG "TPM 2.0 Keys for Device Identity and
	// Attestation" v1.00 r12, section 7.3.1 Table 2 requires of the key's
	// purpose -- 'IDEVID' or 'IAK', optionally followed by a per-device string
	// of printable ASCII, never NUL terminated.
	ErrDevIDUniqueString = errors.New("tpm: the IDevID/IAK unique string is not the one TCG section 7.3.1 Table 2 requires")

	// ErrDevIDUniqueStringTooLong reports a combined unique string larger than
	// the unique field of the chosen crypto suite, which section 7.3.1 forbids:
	// "The combined string size MUST NOT be larger than the allowed unique size
	// for the crypto suite selected."
	ErrDevIDUniqueStringTooLong = errors.New("tpm: the IDevID/IAK unique string is larger than the crypto suite's unique field")

	// ErrDevIDTemplateSuiteUnsupported reports a crypto suite for which the
	// specification defines no Recoverable IDevID/IAK key template: a hash
	// algorithm with no reserved Policy NV Index (section 7.3.2), or a scheme
	// Templates H-1 through H-4 do not allow for the key's purpose.
	ErrDevIDTemplateSuiteUnsupported = errors.New("tpm: no TCG IDevID/IAK key template exists for this crypto suite")

	// ErrRestrictedSchemeRequired reports that a restricted signing key was
	// requested without a scheme. A restricted signing key must name one: it may
	// only sign data the TPM produced, and the scheme is part of what the
	// verifier relies on (TCG TPM 2.0 Library Part 1, section 25.2.3).
	ErrRestrictedSchemeRequired = errors.New("tpm: a restricted signing key must name a signature scheme; TPM_ALG_NULL is not permitted")

	// ErrRestrictedSignRefused reports that the TPM declined to certify the
	// data handed to a restricted signing key as safe to sign.
	//
	// A restricted signing key may only sign a digest the TPM produced, so
	// signing external data with one requires the TPMT_TK_HASHCHECK that
	// TPM2_Hash returns. TPM2_Hash withholds that ticket -- answering with a
	// NULL ticket -- when the data begins with TPM_GENERATED_VALUE, which is
	// how the TPM refuses to lend a restricted key to forging something shaped
	// like its own attestation output (TCG TPM 2.0 Library Part 3, section
	// 16.1). Passing that NULL ticket on as an endorsement-hierarchy ticket
	// would earn a bare TPM_RC_TICKET naming a parameter number; this reports
	// the refusal itself.
	ErrRestrictedSignRefused = errors.New("tpm: the TPM refused to certify this data as safe to sign with a restricted key; data shaped like TPM-generated attestation output cannot be signed by an attestation key")

	ErrInvalidEnrollmentStrategy      = errors.New("tpm: invalid enrollment strategy")
	ErrInvalidCryptoHashAlgID         = errors.New("tpm: crypto.Hash doesn't map to a supported TPMAlgID")
	ErrCurveNotSupported              = errors.New("tpm: ECC curve not supported by TPM")
	ErrInvalidKeySize                 = errors.New("tpm: invalid key size")
	ErrInvalidNVExtendData            = errors.New("tpm: invalid NV extend data - data cannot be nil or empty")
	ErrIAKNotProvisioned              = errors.New("tpm: IAK not provisioned")
	ErrTransportNotInitialized        = errors.New("tpm: transport not initialized")
	ErrInstallTransportNotInitialized = errors.New("tpm: TPM transport not initialized")
	ErrLockoutResetFailed             = errors.New("tpm: dictionary attack lockout reset failed")
	ErrEKNotInitialized               = errors.New("tpm: endorsement key not initialized")
	ErrEKPublicRead                   = errors.New("tpm: failed to read endorsement key public area")
	ErrEKRSAParse                     = errors.New("tpm: failed to parse RSA endorsement key")
	ErrEKECCParse                     = errors.New("tpm: failed to parse ECC endorsement key")
	ErrSRKPublicRead                  = errors.New("tpm: failed to read storage root key public area")
	ErrIAKNotInitialized              = errors.New("tpm: initial attestation key not initialized")
	ErrIAKPublicParse                 = errors.New("tpm: failed to parse IAK public key")
	ErrIDevIDNotInitialized           = errors.New("tpm: initial device identifier not initialized")
	ErrIDevIDPublicParse              = errors.New("tpm: failed to parse IDevID public key")
	ErrGoldenMeasurements             = errors.New("tpm: failed to compute golden measurements")
	ErrPolicyDigest                   = errors.New("tpm: failed to compute platform policy digest")
	ErrIAKConfigFailed                = errors.New("tpm: failed to create IAK attributes from config")
	ErrCSRFieldTooLarge               = errors.New("tpm: CSR field exceeds maximum size")
	ErrNVSecretTooLarge               = errors.New("tpm: NV secret data exceeds maximum size")
	ErrNVReadNotAuthorized            = errors.New("tpm: NV index has no readable attribute (AuthRead or OwnerRead) matching the provided credentials")
	ErrNVCertEmpty                    = errors.New("tpm: certificate DER is empty")
	ErrNVCertTooLarge                 = errors.New("tpm: certificate exceeds the maximum NV index data size (TPM_PT_NV_INDEX_MAX)")
	ErrNVIndexMaxUnavailable          = errors.New("tpm: TPM reported a maximum NV index data size of zero")
	ErrInvalidHierarchy               = errors.New("tpm: invalid hierarchy")
	ErrFactoryReset                   = errors.New("tpm: factory reset failed")
	ErrForceClear                     = errors.New("tpm: force clear via PPI failed")
	ErrEKConfigNil                    = errors.New("tpm: EK config is nil")
	ErrIAKConfigNil                   = errors.New("tpm: IAK config is nil")
	ErrIDevIDConfigNil                = errors.New("tpm: IDevID config is nil")
	ErrSSRKConfigNil                  = errors.New("tpm: SSRK config is nil")

	// Handle enumeration errors
	ErrListPersistentHandles = errors.New("tpm: list persistent handles")
	ErrListTransientHandles  = errors.New("tpm: list transient handles")
	ErrListNVIndexes         = errors.New("tpm: list NV indexes")

	// Sealer errors
	ErrSealFailed                = errors.New("tpm: seal operation failed")
	ErrUnsealFailed              = errors.New("tpm: unseal operation failed")
	ErrNilSealedData             = errors.New("tpm: sealed data is required")
	ErrSealedDataBackendMismatch = errors.New("tpm: sealed data was not created by TPM2 backend")
	ErrNoStorageBackend          = errors.New("tpm: no storage backend available for sealed data")
	ErrInvalidSealBackend        = errors.New("tpm: opts.Backend must implement store.KeyBackend")
	ErrSSRKNotAvailable          = errors.New("tpm: SSRK not available, TPM may not be provisioned")

	// TPM_RC errors
	ErrCommandNotSupported = tpm2.TPMRC(0xb0143)

	// RSASSATemplate is the general-purpose RSA signing key template.
	//
	// Its TPMT_RSA_SCHEME is TPM_ALG_NULL, which leaves both the padding scheme
	// and the digest algorithm to be chosen per operation: TPM2_Sign takes the
	// scheme from inScheme when the key names none, and requires inScheme to
	// match exactly when the key does name one (TCG TPM 2.0 Library Part 2,
	// section 12.2.3.5; Part 3, section 12.1). Naming RSASSA/SHA-256 here made
	// every key created from this template able to sign under SHA-256 and
	// nothing else -- a request for SHA-384 or SHA-512 came back TPM_RC_SCHEME
	// even though the TPM is perfectly able to perform it -- and it also barred
	// the RSA-PSS signatures TLS 1.3 requires of the same key.
	//
	// A scheme of TPM_ALG_NULL is only permitted on an unrestricted key (Part 1,
	// section 25.2.3), which is why the restricted attestation templates below
	// keep their fixed schemes.
	RSASSATemplate = mustKeyTemplate(KeyTemplateSpec{
		Algorithm: x509.RSA,
		KeyBits:   DefaultRSAKeyBits,
		NameAlg:   tpm2.TPMAlgSHA256,
	})

	// RSAPSSTemplate pins a key to RSA-PSS over SHA-256.
	//
	// It keeps a fixed scheme deliberately, and is the one asymmetric signing
	// template that does. RSASSATemplate above is the general-purpose key: with
	// TPM_ALG_NULL it can produce both PKCS#1 v1.5 and PSS signatures under any
	// digest the TPM implements. This template is for the caller that wants the
	// device itself to refuse anything but PSS/SHA-256, which is a property only
	// the key's public area can carry -- TPMT_RSA_SCHEME has no way to say
	// "RSA-PSS under any digest" (TCG TPM 2.0 Library Part 2, section 12.2.3.5).
	// Keys created from it therefore sign under SHA-256 and no other digest, by
	// design rather than by accident.
	RSAPSSTemplate = mustKeyTemplate(KeyTemplateSpec{
		Algorithm:  x509.RSA,
		KeyBits:    DefaultRSAKeyBits,
		NameAlg:    tpm2.TPMAlgSHA256,
		Scheme:     tpm2.TPMAlgRSAPSS,
		SchemeHash: tpm2.TPMAlgSHA256,
	})

	// ECCP256Template is the general-purpose ECC P-256 signing key template.
	//
	// Like RSASSATemplate its scheme is TPM_ALG_NULL, so the digest is chosen
	// per operation. For ECDSA the scheme's hash never enters the signature
	// computation -- Part 4's CryptEccSign consumes the digest directly,
	// truncated to the order of the curve -- so a P-256 key naming ECDSA/SHA-256
	// was refusing SHA-384 and SHA-512 digests it is entirely capable of
	// signing, purely because inScheme has to match the key (Part 3, section
	// 12.1).
	ECCP256Template = mustKeyTemplate(KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P256(),
		NameAlg:   tpm2.TPMAlgSHA256,
	})

	// ECC P384 Template
	ECCP384Template = mustKeyTemplate(KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P384(),
		NameAlg:   tpm2.TPMAlgSHA384,
	})

	// ECC P521 Template
	ECCP521Template = mustKeyTemplate(KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P521(),
		NameAlg:   tpm2.TPMAlgSHA512,
	})

	// The Recoverable IDevID and IAK key templates of TCG "TPM 2.0 Keys for
	// Device Identity and Attestation" v1.00 r12, section 7.3.4.
	//
	// Each is Template H-0 (section 7.3.4.1) over the crypto suite named by
	// its H-x table: H-1 RSA 2048 (section 7.3.4.2), H-2 ECC NIST P256
	// (7.3.4.3), H-3 ECC NIST P384 (7.3.4.4), H-4 ECC NIST P521 (7.3.4.5).
	// H-5 ECC SM2 P256 (7.3.4.6) is not implemented; devid_template.go says
	// why. The IAK is Restricted and the IDevID is not, which is the whole
	// point of having two keys (sections 4.1 and 4.2): an IAK may sign only
	// what the TPM produced, an IDevID signs whatever its owner hands it.
	//
	// They are built by DevIDTemplateSpec so that this file and the creation
	// paths in key.go cannot drift apart: before these were derived, CreateIAK
	// carried its own inline copies, and #455's adminWithPolicy reached the
	// inline ones only. Every field is a derivation input, so two spellings of
	// "the AK template" are two different keys.
	//
	// AuthPolicy is deliberately absent here: it is the IDevID/IAK Key Policy
	// for the template's nameAlg (section 7.3.6.6), it is computed by
	// DevIDKeyPolicyDigest, and the creation path assigns it immediately
	// before TPM2_CreatePrimary. assertDevIDTemplateConformant refuses a
	// template that still has it empty.
	//
	// The unique field carries the required string of section 7.3.1 Table 2 --
	// 'IAK' or 'IDEVID', unpadded and not NUL terminated. A deployment adding
	// the optional per-device string builds its template through
	// DevIDTemplateSpec rather than using these; the string is a derivation
	// input, so the two keys differ.

	// RSASSAAKTemplate is Template H-1 for an IAK signing PKCS#1 v1.5.
	RSASSAAKTemplate = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeyAttestation,
		Algorithm: x509.RSA,
		Scheme:    tpm2.TPMAlgRSASSA,
	})

	// RSAPSSAKTemplate is Template H-1 for an IAK signing RSA-PSS.
	RSAPSSAKTemplate = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeyAttestation,
		Algorithm: x509.RSA,
		Scheme:    tpm2.TPMAlgRSAPSS,
	})

	// ECCAKP256Template is Template H-2 for an IAK.
	ECCAKP256Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeyAttestation,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P256(),
	})

	// ECCAKP384Template is Template H-3 for an IAK.
	ECCAKP384Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeyAttestation,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P384(),
	})

	// ECCAKP521Template is Template H-4 for an IAK.
	ECCAKP521Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeyAttestation,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P521(),
	})

	// RSASSAIDevIDTemplate is Template H-1 for an IDevID.
	//
	// Its scheme is TPM_ALG_NULL, as H-1 requires of a signing DevID, so the
	// padding and digest are chosen per TPM2_Sign command. That is what lets
	// one device identity key serve a certificate signed PKCS#1 v1.5 and the
	// RSA-PSS a TLS 1.3 handshake requires. The name kept the SSA suffix
	// because a deployment configured for PKCS#1 v1.5 still selects it.
	RSASSAIDevIDTemplate = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.RSA,
	})

	// RSAPSSIDevIDTemplate is Template H-1 for an IDevID whose configuration
	// names RSA-PSS. It is identical to RSASSAIDevIDTemplate -- H-1 gives a
	// signing DevID no scheme to differ in -- and both names are kept so the
	// selection in CreateIDevID still reads as the choice it makes.
	RSAPSSIDevIDTemplate = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.RSA,
	})

	// ECCIDevIDP256Template is Template H-2 for an IDevID.
	ECCIDevIDP256Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P256(),
	})

	// ECCIDevIDP384Template is Template H-3 for an IDevID.
	ECCIDevIDP384Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P384(),
	})

	// ECCIDevIDP521Template is Template H-4 for an IDevID.
	ECCIDevIDP521Template = mustDevIDTemplate(DevIDTemplateSpec{
		Kind:      DevIDKeySigning,
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P521(),
	})

	// AES Templates

	AES128CFBTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
				},
			},
		),
	}

	AES256CFBTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgSymCipher,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgSymCipher,
			&tpm2.TPMSSymCipherParms{
				Sym: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
				},
			},
		),
	}

	// Keyed hash / HMAC Template
	KeyedHashTemplate = tpm2.TPMTPublic{
		Type:       tpm2.TPMAlgKeyedHash,
		NameAlg:    tpm2.TPMAlgSHA256,
		AuthPolicy: tpm2.TPM2BDigest{},
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}
)

// type EK struct {
// 	// Public key of the EK.
// 	Public crypto.PublicKey

// 	// Certificate is the EK certificate for TPMs that provide it.
// 	Certificate *x509.Certificate

// 	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
// 	// Public key. Clients or servers can perform an HTTP GET to this URL, and
// 	// use ParseEKCertificate on the response body.
// 	CertificateURL string

// 	// The EK persistent handle.
// 	handle tpmutil.Handle
// }

type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

func (id TCGVendorID) String() string {
	return vendors[id]
}

// Structure constants of the TCG-CSR-IDEVID, from TCG "TPM 2.0 Keys for
// Device Identity and Attestation" v1.00 r12, section 13.1.
const (
	// TCGCSRIDevIDStructVer is TCG_CSR_IDEVID.structVer for version 1.0 of the
	// structure: "Version 1.0 = 0x01000100". The first byte, 0x01, identifies
	// an IDevID CSR; an LDevID CSR (section 13.2) carries 0x02 there.
	TCGCSRIDevIDStructVer uint32 = 0x01000100

	// TCGIDevIDContentStructVer is TCG_IDEVID_CONTENT.structVer for version
	// 1.0 of the content structure: "Version 1.0 = 0x00000100".
	TCGIDevIDContentStructVer uint32 = 0x00000100

	// TCGCSRAlignment is the byte multiple the padded TCG_IDEVID_CONTENT
	// structure is brought to: "padSz bytes of random data here to make the
	// structure size a multiple of 16 bytes".
	TCGCSRAlignment = 16
)

// TPM 2.0 Keys for Device Identity and Attestation -
// Section 13.1 - TCG-CSR-IDEVID
type TCG_CSR_IDEVID struct {
	StructVer   [4]byte
	Contents    [4]byte
	SigSz       [4]byte
	CsrContents TCG_IDEVID_CONTENT
	Signature   []byte
}

// Marshal serializes the TCG_CSR_IDEVID to a binary byte array.
func (csr TCG_CSR_IDEVID) Marshal() ([]byte, error) {
	return PackIDevIDCSR(&csr)
}

type TCG_IDEVID_CONTENT struct {
	StructVer                 [4]byte
	HashAlgoId                [4]byte
	HashSz                    [4]byte
	ProdModelSz               [4]byte
	ProdSerialSz              [4]byte
	ProdCaDataSz              [4]byte
	BootEvntLogSz             [4]byte
	EkCertSZ                  [4]byte
	AttestPubSZ               [4]byte
	AtCreateTktSZ             [4]byte
	AtCertifyInfoSZ           [4]byte
	AtCertifyInfoSignatureSZ  [4]byte
	SigningPubSZ              [4]byte
	SgnCertifyInfoSZ          [4]byte
	SgnCertifyInfoSignatureSZ [4]byte
	PadSz                     [4]byte
	ProdModel                 []byte
	ProdSerial                []byte
	ProdCaData                []byte
	BootEvntLog               []byte
	EkCert                    []byte
	AttestPub                 []byte
	AtCreateTkt               []byte
	AtCertifyInfo             []byte
	AtCertifyInfoSig          []byte
	SigningPub                []byte
	SgnCertifyInfo            []byte
	SgnCertifyInfoSig         []byte
	Pad                       []byte
}

// Represents an unpacked TCG-CSR-IDEVID. All binary
// fields are unmarshalled to their native Golang types,
// including size fields which the TCG spec requires
// encoded as 4 bytes big endian.
// // https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
type UNPACKED_TCG_CSR_IDEVID struct {
	StructVer   uint32
	Contents    uint32
	SigSz       uint32
	CsrContents UNPACKED_TCG_IDEVID_CONTENT
	RawBytes    []byte
	Signature   []byte
}

type UNPACKED_TCG_IDEVID_CONTENT struct {
	StructVer                 uint32
	HashAlgoId                uint32
	HashSz                    uint32
	ProdModelSz               uint32
	ProdSerialSz              uint32
	ProdCaDataSz              uint32
	BootEvntLogSz             uint32
	EkCertSZ                  uint32
	AttestPubSZ               uint32
	AtCreateTktSZ             uint32
	AtCertifyInfoSZ           uint32
	AtCertifyInfoSignatureSZ  uint32
	SigningPubSZ              uint32
	SgnCertifyInfoSZ          uint32
	SgnCertifyInfoSignatureSZ uint32
	PadSz                     uint32
	ProdModel                 []byte
	ProdSerial                []byte
	ProdCaData                []byte
	BootEvntLog               []byte
	EkCert                    []byte
	AttestPub                 []byte
	AtCreateTkt               []byte
	AtCertifyInfo             []byte
	AtCertifyInfoSig          []byte
	SigningPub                []byte
	SgnCertifyInfo            []byte
	SgnCertifyInfoSig         []byte
	Pad                       []byte
}

// Represents an unpacked TCG-CSR-LDEVID. All binary
// fields are unmarshalled to their native Golang types,
// including size fields which the TCG spec requires
// encoded as 4 bytes big endian.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
type UNPACKED_TCG_CSR_LDEVID struct {
	StructVer   uint32
	Contents    uint32
	SigSz       uint32
	CsrContents UNPACKED_TCG_IDEVID_CONTENT
	Signature   []byte
}

type UNPACKED_TCG_LDEVID_CONTENT struct {
	StructVer                uint32
	HashAlgoId               uint32
	HashSz                   uint32
	EkCertSZ                 uint32
	IakCertSZ                uint32
	PlatCertSZ               uint32
	PubkeySZ                 uint32
	AtCertifyInfoSZ          uint32
	AtCertifyInfoSignatureSZ uint32
	PadSz                    uint32
	EkCert                   []byte
	IakCert                  []byte
	PlatCert                 []byte
	Pubkey                   []byte
	AtCertifyInfo            []byte
	AtCertifyInfoSig         []byte
}

type TCG_CSR_LDEVID struct {
	StructVer   [4]byte
	Contents    [4]byte
	SigSz       [4]byte
	CsrContents TCG_LDEVID_CONTENT
	Signature   []byte
}

type TCG_LDEVID_CONTENT struct {
	StructVer                [4]byte
	HashAlgoId               [4]byte
	HashSz                   [4]byte
	EkCertSZ                 [4]byte
	IakCertSZ                [4]byte
	PlatCertSZ               [4]byte
	PubkeySZ                 [4]byte
	AtCertifyInfoSZ          [4]byte
	AtCertifyInfoSignatureSZ [4]byte
	PadSz                    [4]byte
	EkCert                   []byte
	IakCert                  []byte
	PlatCert                 []byte
	Pubkey                   []byte
	AtCertifyInfo            []byte
	AtCertifyInfoSig         []byte
}

type AKProfile struct {
	EKPub              []byte
	AKPub              []byte
	AKName             tpm2.TPM2BName
	SignatureAlgorithm x509.SignatureAlgorithm
}

type Quote struct {
	Quoted    []byte
	Signature []byte
	Nonce     []byte
	PCRs      []byte
	EventLog  []byte
}

type PCRBank struct {
	Algorithm string
	PCRs      []PCR
}

type PCR struct {
	ID    int32
	Value []byte
}

// NVIndexInfo describes an NV index defined on the TPM.
type NVIndexInfo struct {
	Handle    tpm2.TPMHandle
	Type      string // "ordinary", "counter", "extend"
	Size      uint16
	AuthRead  bool
	AuthWrite bool
}

func HierarchyName(hierarchy tpm2.TPMHandle) (string, error) {
	switch hierarchy {

	case tpm2.TPMRHPlatform:
		return "PLATFORM", nil

	case tpm2.TPMRHOwner:
		return "OWNER", nil

	case tpm2.TPMRHEndorsement:
		return "ENDORSEMENT", nil

	case tpm2.TPMRHNull:
		return "NULL", nil
	}

	return "", ErrInvalidHierarchy
}

// ParseHash converts a string representation of a hash algorithm to crypto.Hash
func ParseHash(hash string) crypto.Hash {
	switch strings.ToUpper(hash) {
	case crypto.SHA1.String():
		return crypto.SHA1
	case crypto.SHA256.String():
		return crypto.SHA256
	case crypto.SHA384.String():
		return crypto.SHA384
	case crypto.SHA512.String():
		return crypto.SHA512
	}
	return 0
}

func ParseHashAlgFromString(hash string) (tpm2.TPMIAlgHash, error) {
	switch strings.ToUpper(hash) {
	case crypto.SHA1.String():
		return tpm2.TPMAlgSHA1, nil
	case crypto.SHA256.String():
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384.String():
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512.String():
		return tpm2.TPMAlgSHA512, nil
	}
	return 0, ErrInvalidHashFunction
}

func ParseHashAlg(hash crypto.Hash) (tpm2.TPMIAlgHash, error) {
	switch hash {
	case crypto.SHA1:
		return tpm2.TPMAlgSHA1, nil
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	}
	return 0, ErrInvalidHashFunction
}

func ParseHashSize(hash crypto.Hash) (uint32, error) {
	switch hash {
	case crypto.SHA1:
		return 20, nil
	case crypto.SHA256:
		return 32, nil
	case crypto.SHA384:
		return 48, nil
	case crypto.SHA512:
		return 64, nil
	}
	return 0, ErrInvalidHashFunction
}
