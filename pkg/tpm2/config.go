package tpm2

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"gopkg.in/yaml.v3"
)

type PCRBankAlgo string

var (
	PCRBankSHA1   = "sha1"
	PCRBankSHA256 = "sha256"
	PCRBankSHA384 = "sha384"
	PCRBankSHA512 = "sha512"

	pcrBankAlgIDMap = map[string]tpm2.TPMAlgID{
		PCRBankSHA1:   tpm2.TPMAlgSHA1,
		PCRBankSHA256: tpm2.TPMAlgSHA256,
		PCRBankSHA384: tpm2.TPMAlgSHA384,
		PCRBankSHA512: tpm2.TPMAlgSHA512,
	}

	cryptoHashAlgIDMap = map[string]tpm2.TPMAlgID{
		"SHA-1":    tpm2.TPMAlgSHA1,
		"SHA-256":  tpm2.TPMAlgSHA256,
		"SHA-384":  tpm2.TPMAlgSHA384,
		"SHA-512":  tpm2.TPMAlgSHA512,
		"SHA3-256": tpm2.TPMAlgSHA3256,
		"SHA3-384": tpm2.TPMAlgSHA3384,
		"SHA3-512": tpm2.TPMAlgSHA3512,
	}

	pcrBankCryptoHashMap = map[string]crypto.Hash{
		PCRBankSHA1:   crypto.SHA1,
		PCRBankSHA256: crypto.SHA256,
		PCRBankSHA384: crypto.SHA3_384,
		PCRBankSHA512: crypto.SHA512,
	}
)

func (pcrBankAlgo PCRBankAlgo) String() string {
	return string(pcrBankAlgo)
}

// ErrSSRKPlatformPolicy reports a configuration that asks for a platform
// policy on the Shared SRK. The Shared SRK never carries one; platform binding
// belongs to the Platform SRK. See SRKConfig for why.
var ErrSSRKPlatformPolicy = errors.New(
	"tpm2: the shared SRK cannot carry a platform policy")

// SSRKPlatformPolicyError is the typed error returned when an ssrk
// configuration section asks for a platform policy. Format and Key name the
// serialization and the offending key so the operator can find it.
type SSRKPlatformPolicyError struct {
	Format string
	Key    string
}

func (e *SSRKPlatformPolicyError) Error() string {
	return fmt.Sprintf(
		"%s (%s key %q): platform binding belongs on the platform SRK; "+
			"set platform-srk.platform-policy instead and remove the key from the ssrk section",
		ErrSSRKPlatformPolicy.Error(), e.Format, e.Key)
}

// Unwrap reports ErrSSRKPlatformPolicy so callers can match with errors.Is.
func (e *SSRKPlatformPolicyError) Unwrap() error { return ErrSSRKPlatformPolicy }

var (
	ErrInvalidHierarchyType = errors.New("tpm2: invalid hierarchy type")
	ErrInvalidPCRBankType   = errors.New("tpm2: invalid PCR bank")

	DefaultConfig = Config{
		EncryptSession:               false,
		UseEntropy:                   false,
		Device:                       "/dev/tpmrm0",
		UseSimulator:                 true,
		Hash:                         "SHA-256",
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Debug:         true,
			Handle:        0x81010001,
			HierarchyAuth: types.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		// FileIntegrity is deprecated - leave empty and use GoldenPCRs with PCR 10 (IMA) instead
		FileIntegrity: []string{},
		// GoldenPCRs - leave empty to use defaults: [0, 7, 9, 10]
		//   PCR 0: BIOS/UEFI firmware, PCR 7: Secure Boot, PCR 9: cmdline, PCR 10: IMA
		GoldenPCRs: []uint{},
		IAK: &IAKConfig{
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       0x81020001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		IDevID: &IDevIDConfig{
			CertHandle:   0x01C90000,
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       0x81020000,
			KeyAlgorithm: x509.RSA.String(),
			Model:        "edge",
			Serial:       "001",
			// Manufacturer, Version: empty by default
			// When empty, SMBIOS/DMI discovery will be used as fallback
			// Password:           types.DEFAULT_PASSWORD,
			Pad:                true,
			PlatformPolicy:     true,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformSRK: &PlatformSRKConfig{
			SRKAuth:        "platform",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
		PlatformPCR:     16,
		PlatformPCRBank: PCRBankSHA256,
		SSRK: &SRKConfig{
			Debug:  true,
			Handle: 0x81000001,
			// HierarchyAuth: types.DEFAULT_PASSWORD,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
	}
)

type Config struct {
	CommandAddress string    `yaml:"command-address,omitempty" json:"command_address" mapstructure:"command-address"`
	Device         string    `yaml:"device,omitempty" json:"device" mapstructure:"device"`
	EncryptSession bool      `yaml:"encrypt-sessions" json:"encrypt_sessions" mapstructure:"encrypt-sessions"`
	EK             *EKConfig `yaml:"ek" json:"ek" mapstructure:"ek"`
	// FileIntegrity is DEPRECATED. Use Linux IMA (PCR 10) instead by adding 10 to GoldenPCRs.
	// This custom file integrity monitoring computes a hash of specified directories
	// and includes it in the golden measurements. Linux IMA provides the same functionality
	// with hardware-backed measurements stored in PCR 10.
	FileIntegrity []string `yaml:"file-integrity" json:"file_integrity" mapstructure:"file-integrity"`
	// GoldenPCRs specifies which PCRs to include in the golden integrity measurement.
	// Leave empty to use defaults: [0, 7, 9, 10]
	//   PCR 0: BIOS/UEFI firmware measurements
	//   PCR 7: Secure Boot state
	//   PCR 9: Kernel command line
	//   PCR 10: Linux IMA (file integrity measurements)
	// To customize, specify an explicit list, e.g., [0, 7, 9, 10, 14]
	GoldenPCRs                   []uint                  `yaml:"golden-pcrs" json:"golden_pcrs" mapstructure:"golden-pcrs"`
	Hash                         string                  `yaml:"hash" json:"hash" mapstructure:"hash"`
	IAK                          *IAKConfig              `yaml:"iak" json:"iak" mapstructure:"iak"`
	IdentityProvisioningStrategy string                  `yaml:"identity-provisioning" json:"identity_provisioning" mapstructure:"identity-provisioning"`
	IDevID                       *IDevIDConfig           `yaml:"idevid" json:"idevid" mapstructure:"idevid"`
	PlatformSRK                  *PlatformSRKConfig      `yaml:"platform-srk" json:"platform_srk" mapstructure:"platform-srk"`
	LockoutAuth                  string                  `yaml:"lockout-auth,omitempty" json:"lockout-auth" mapstructure:"lockout-auth"`
	PlatformAddress              string                  `yaml:"platform-address,omitempty" json:"platform_address" mapstructure:"platform-address"`
	PlatformPCR                  uint                    `yaml:"platform-pcr" json:"platform_pcr" mapstructure:"platform-pcr"`
	PlatformPCRBank              string                  `yaml:"platform-pcr-bank" json:"platform_pcr_bank" mapstructure:"platform-pcr-bank"`
	SSRK                         *SRKConfig              `yaml:"ssrk" json:"ssrk" mapstructure:"ssrk"`
	Tracker                      types.AEADSafetyTracker `yaml:"-" json:"-" mapstructure:"-"`
	UseEntropy                   bool                    `yaml:"entropy" json:"entropy" mapstructure:"entropyr"`
	UseSimulator                 bool                    `yaml:"simulator" json:"simulator" mapstructure:"simulator"`
}

type PlatformSRKConfig struct {
	CN             string `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	SRKAuth        string `yaml:"srk-auth,omitempty" json:"srk_auth" mapstructure:"srk-auth"`
	SRKHandle      uint32 `yaml:"srk-handle" json:"srk-handle" mapstructure:"srk-handle"`
	PlatformPolicy bool   `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
}

type EKConfig struct {
	CertHandle     uint32           `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN             string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug          bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig      *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle         uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	HierarchyAuth  string           `yaml:"hierarchy-auth,omitempty" json:"hierarchy_auth" mapstructure:"hierarchy-auth"`
	KeyAlgorithm   string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password       string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	PlatformPolicy bool             `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig      *store.RSAConfig `yaml:"rsa,omitempty" json:"rsa" mapstructure:"rsa"`
}

// SRKConfig configures the Shared Storage Root Key (SSRK), the TCG-standard
// storage parent persisted at 0x81000001.
//
// The SSRK carries NO platform policy, and the type deliberately offers no way
// to ask for one: the field a caller would set does not exist. Platform binding
// belongs to the Platform SRK (PlatformSRKConfig.PlatformPolicy), which is
// created after CreatePlatformPolicy has extended the golden measurement into
// the platform PCR and therefore describes the state the machine is actually
// running in.
//
// The SSRK cannot be given the same treatment. Provision creates it inside
// ProvisionOwner, before CreatePlatformPolicy runs, so any AuthPolicy computed
// for it describes a PCR state that no longer exists once provisioning returns.
// Reordering is not an option either: AuthPolicy is part of the template, and
// the template is an input to TPM2_CreatePrimary's key derivation (TPM 2.0
// Part 1, Section 27.2), so changing it derives a different key and orphans
// every existing child.
//
// A configuration file that still asks for one is rejected rather than quietly
// dropped -- see UnmarshalYAML and UnmarshalJSON.
type SRKConfig struct {
	CN            string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug         bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig     *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle        uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	HierarchyAuth string           `yaml:"hierarchy-auth,omitempty" json:"hierarchy-auth" mapstructure:"hierarchy-auth"`
	KeyAlgorithm  string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password      string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	RSAConfig     *store.RSAConfig `yaml:"rsa,omitempty" json:"rsa" mapstructure:"rsa"`
}

// UnmarshalYAML decodes an ssrk configuration section and rejects one that
// asks for a platform policy.
//
// Deleting the field alone would make an operator's `platform-policy: true`
// vanish silently, leaving them to believe the SSRK is platform-bound when it
// is not -- the fail-open behaviour that made the stale-policy defect so hard
// to see in the first place. An explicit false, and an absent key, decode
// normally.
func (c *SRKConfig) UnmarshalYAML(node *yaml.Node) error {
	var legacy struct {
		PlatformPolicy *bool `yaml:"platform-policy"`
	}
	if err := node.Decode(&legacy); err != nil {
		return err
	}
	if legacy.PlatformPolicy != nil && *legacy.PlatformPolicy {
		return &SSRKPlatformPolicyError{Format: "yaml", Key: "platform-policy"}
	}

	// srkConfig has no methods, so decoding into it does not recurse.
	type srkConfig SRKConfig
	var decoded srkConfig
	if err := node.Decode(&decoded); err != nil {
		return err
	}

	*c = SRKConfig(decoded)
	return nil
}

// UnmarshalJSON decodes an ssrk configuration object and rejects one that asks
// for a platform policy. Both the current spelling and the legacy
// "_platform_policy" spelling this field was serialized under are refused, for
// the reason given on UnmarshalYAML.
func (c *SRKConfig) UnmarshalJSON(data []byte) error {
	var legacy struct {
		PlatformPolicy       *bool `json:"platform_policy"`
		LegacyPlatformPolicy *bool `json:"_platform_policy"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	if legacy.PlatformPolicy != nil && *legacy.PlatformPolicy {
		return &SSRKPlatformPolicyError{Format: "json", Key: "platform_policy"}
	}
	if legacy.LegacyPlatformPolicy != nil && *legacy.LegacyPlatformPolicy {
		return &SSRKPlatformPolicyError{Format: "json", Key: "_platform_policy"}
	}

	type srkConfig SRKConfig
	var decoded srkConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	*c = SRKConfig(decoded)
	return nil
}

type IDevIDConfig struct {
	CertHandle         uint32           `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug              bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle             uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string           `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Manufacturer       string           `yaml:"manufacturer,omitempty" json:"manufacturer" mapstructure:"manufacturer"`
	Model              string           `yaml:"model,omitempty" json:"model" mapstructure:"model"`
	Pad                bool             `yaml:"pad" json:"pad" mapstructure:"pad"`
	Password           string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	PlatformPolicy     bool             `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *store.RSAConfig `yaml:"rsa" json:"rsa" mapstructure:"rsa"`
	Serial             string           `yaml:"serial,omitempty" json:"serial" mapstructure:"serial"`
	SignatureAlgorithm string           `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
	Version            string           `yaml:"version,omitempty" json:"version" mapstructure:"version"`
}

type IAKConfig struct {
	CertHandle         uint32           `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug              bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle             uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string           `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password           string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	PlatformPolicy     bool             `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *store.RSAConfig `yaml:"rsa,omitempty" json:"rsa" mapstructure:"rsa"`
	SignatureAlgorithm string           `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

type LDevIDConfig struct {
	CertHandle         uint32           `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug              bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle             uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string           `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Model              string           `yaml:"model" json:"model" mapstructure:"model"`
	Pad                bool             `yaml:"pad" json:"pad" mapstructure:"pad"`
	Password           string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	PlatformPolicy     bool             `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *store.RSAConfig `yaml:"rsa,omitempty" json:"rsa" mapstructure:"rsa"`
	Serial             string           `yaml:"serial,omitempty" json:"serial" mapstructure:"serial"`
	SignatureAlgorithm string           `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

type LAKConfig struct {
	CertHandle         uint32           `yaml:"cert-handle" json:"cert-handle" mapstructure:"cert-handle"`
	CN                 string           `yaml:"cn,omitempty" json:"cn" mapstructure:"cn"`
	Debug              bool             `json:"debug" yaml:"debug" mapstructure:"debug"`
	ECCConfig          *store.ECCConfig `yaml:"ecc,omitempty" json:"ecc" mapstructure:"ecc"`
	Handle             uint32           `yaml:"handle" json:"handle" mapstructure:"handle"`
	Hash               string           `yaml:"hash" json:"hash" mapstructure:"hash"`
	KeyAlgorithm       string           `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Password           string           `yaml:"password,omitempty" json:"password" mapstructure:"password"`
	PlatformPolicy     bool             `yaml:"platform-policy" json:"_platform_policy" mapstructure:"platform-policy"`
	RSAConfig          *store.RSAConfig `yaml:"rsa,omitempty" json:"rsa" mapstructure:"rsa"`
	SignatureAlgorithm string           `yaml:"signature-algorithm" json:"signature-algorithm" mapstructure:"signature-algorithm"`
}

func EKAttributesFromConfig(config EKConfig, policyDigest *tpm2.TPM2BDigest, idevidConfig *IDevIDConfig) (*types.KeyAttributes, error) {

	if config.CN == "" {
		if idevidConfig != nil {
			// Sanitize Model — SMBIOS vendor strings often contain spaces
			// ("SuperMicro X10") which break downstream objectstorage path
			// validators that require no-whitespace, no-control identifiers.
			model := strings.ReplaceAll(idevidConfig.Model, " ", "_")
			config.CN = fmt.Sprintf("ek-%s-%s", model, idevidConfig.Serial)
		} else {
			config.CN = "ek"
		}
	}

	algorithm, err := types.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		switch {
		case config.RSAConfig != nil:
			algorithm = x509.RSA
		case config.ECCConfig != nil:
			algorithm = x509.ECDSA
		default:
			return nil, err
		}
	}

	var ekTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		ekTemplate = tpm2.RSAEKTemplate
	} else {
		ekTemplate = tpm2.ECCEKTemplate
	}

	if config.PlatformPolicy && policyDigest != nil {
		ekTemplate.AuthPolicy = *policyDigest
	}

	// Only set Password/HierarchyAuth when non-empty to avoid selecting the
	// wrong PlatformPolicySession branch on restart (see SRKAttributesFromConfig).
	var ekPassword types.Password
	if config.Password != "" {
		ekPassword = types.NewPassword([]byte(config.Password))
	}
	var ekHierarchyAuth types.Password
	if config.HierarchyAuth != "" {
		ekHierarchyAuth = types.NewPassword([]byte(config.HierarchyAuth))
	}

	attrs := &types.KeyAttributes{
		CN:             config.CN,
		Debug:          config.Debug,
		KeyAlgorithm:   algorithm,
		KeyType:        types.KeyTypeEndorsement,
		Password:       ekPassword,
		PlatformPolicy: config.PlatformPolicy,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			CertHandle:    tpm2.TPMHandle(config.CertHandle),
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMHandle(tpm2.TPMRHEndorsement),
			HierarchyAuth: ekHierarchyAuth,
			Template:      ekTemplate,
		},
	}

	if config.ECCConfig != nil {
		if config.KeyAlgorithm == "" {
			config.KeyAlgorithm = x509.ECDSA.String()
		}
		curve, err := types.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		if config.KeyAlgorithm == "" {
			config.KeyAlgorithm = x509.RSA.String()
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

// SRKAttributesFromConfig builds storage-root-key attributes from an SRKConfig.
//
// The attributes never carry a platform policy: SRKConfig cannot express one
// (see its documentation), so no AuthPolicy is baked into the template here.
// The Platform SRK, which is built from the same shape by
// buildSRKAttrsFromConfig, has its PlatformPolicy set from
// PlatformSRKConfig.PlatformPolicy and its AuthPolicy computed by CreateSRK
// from the platform state that is live at creation time.
func SRKAttributesFromConfig(config SRKConfig) (*types.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "srk"
	}

	algorithm, err := types.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		switch {
		case config.RSAConfig != nil:
			algorithm = x509.RSA
		case config.ECCConfig != nil:
			algorithm = x509.ECDSA
		default:
			return nil, err
		}
	}

	var srkTemplate tpm2.TPMTPublic
	if algorithm == x509.RSA {
		srkTemplate = tpm2.RSASRKTemplate
	} else {
		srkTemplate = tpm2.ECCSRKTemplate
	}

	// Only set Password when the config value is non-empty. An empty
	// password must remain nil so that CreateSession selects the PCR branch
	// of PlatformPolicySession (auto-unseal) instead of the password branch.
	// After a restart the user PIN is not available; a non-nil empty Password
	// would cause CreateSession to choose the password branch with empty auth,
	// mismatching the SRK's actual UserAuth and producing TPM_RC_BAD_AUTH.
	var srkPassword types.Password
	if config.Password != "" {
		srkPassword = types.NewPassword([]byte(config.Password))
	}

	// Same guard for HierarchyAuth: leave nil when the config value is empty
	// so that downstream TPM2_CreatePrimary uses empty auth (TPM default).
	var hierarchyAuth types.Password
	if config.HierarchyAuth != "" {
		hierarchyAuth = types.NewPassword([]byte(config.HierarchyAuth))
	}

	attrs := &types.KeyAttributes{
		CN:           config.CN,
		Debug:        config.Debug,
		KeyAlgorithm: algorithm,
		KeyType:      types.KeyTypeStorage,
		Password:     srkPassword,
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMHandle(tpm2.TPMRHOwner),
			HierarchyAuth: hierarchyAuth,
			Template:      srkTemplate,
		},
	}

	if config.ECCConfig != nil {
		curve, err := types.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

// IAKAttributesFromConfig builds the Initial Attestation Key attributes from
// the platform configuration. TPMAttributes.Template is deliberately left as
// the zero TPMTPublic: CreateIAK constructs the restricted signing template
// itself and never reads the field, and the vestigial EK template formerly
// assigned here misled readers into concluding the IAK was created from an
// EK template (#355). The policyDigest parameter is retained for signature
// stability; platform policy is conveyed by the PlatformPolicy field and
// applied by CreateIAK.
func IAKAttributesFromConfig(
	soPIN types.Password,
	config *IAKConfig,
	_ *tpm2.TPM2BDigest) (*types.KeyAttributes, error) {

	algorithm, err := types.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		switch {
		case config.RSAConfig != nil:
			algorithm = x509.RSA
		case config.ECCConfig != nil:
			algorithm = x509.ECDSA
		default:
			return nil, err
		}
	}

	hash := ParseHash(config.Hash)

	sigAlgo, err := types.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	tpmHashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	attrs := &types.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            types.KeyTypeAttestation,
		Password:           types.NewPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			CertHandle:    tpm2.TPMHandle(config.CertHandle),
			Handle:        tpm2.TPMHandle(config.Handle),
			HandleType:    tpm2.TPMHTPersistent,
			HashAlg:       tpmHashAlg,
			Hierarchy:     tpm2.TPMRHEndorsement,
			HierarchyAuth: soPIN,
		},
	}

	if config.ECCConfig != nil {
		curve, err := types.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

// DevIDCommonName resolves the Common Name an IDevID or IAK is stored and
// certified under. An explicitly configured name wins. Otherwise the name is
// derived from the device's Platform Identity Information -- its model and
// serial number -- which is what TCG "TPM 2.0 Keys for Device Identity and
// Attestation" v1.00 r12 carries in the TCG-CSR-IDEVID (section 7.2.3, step
// 4a) and what IEEE 802.1AR binds a DevID certificate's Subject to (section
// 2.3.4). One rule serves both key kinds, so the IAK and the IDevID of one
// device can never disagree about which device they name.
//
// An empty result is refused rather than defaulted: the key stores compose
// their storage key from the CN, so an empty CN would collapse every such key
// onto one slot, and a fixed default would do the same across devices.
// devidPlatformFromConfig returns the Platform Identity Information the
// IDevID configuration carries -- its configured model and serial number --
// as the input to DevIDCommonName for the IAK. It deliberately does not
// consult DMI discovery: IDevIDAttributesFromConfig names the IDevID from the
// same configured values, so using the same input is what keeps the two keys'
// names symmetric and deterministic. Discovery belongs to the CSR path.
func devidPlatformFromConfig(config *IDevIDConfig) *PlatformAttributes {
	if config == nil {
		return nil
	}
	return &PlatformAttributes{Model: config.Model, Serial: config.Serial}
}

func DevIDCommonName(cn string, platform *PlatformAttributes) (string, error) {
	if cn != "" {
		return cn, nil
	}
	if platform != nil && platform.Model != "" && platform.Serial != "" {
		return fmt.Sprintf("%s-%s", platform.Model, platform.Serial), nil
	}
	return "", ErrDevIDCNUnresolved
}

// IDevIDAttributesFromConfig builds the Initial Device Identifier key
// attributes from the platform configuration. TPMAttributes.Template is
// deliberately left as the zero TPMTPublic: CreateIDevID selects the
// dedicated unrestricted IDevID templates itself and never reads the field
// (#355). The policyDigest parameter is retained for signature stability;
// platform policy is conveyed by the PlatformPolicy field.
func IDevIDAttributesFromConfig(
	config IDevIDConfig,
	_ *tpm2.TPM2BDigest) (*types.KeyAttributes, error) {

	cn, err := DevIDCommonName(config.CN, &PlatformAttributes{Model: config.Model, Serial: config.Serial})
	if err != nil {
		return nil, err
	}
	config.CN = cn

	algorithm, err := types.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		switch {
		case config.RSAConfig != nil:
			algorithm = x509.RSA
		case config.ECCConfig != nil:
			algorithm = x509.ECDSA
		default:
			return nil, err
		}
	}

	hash := ParseHash(config.Hash)

	sigAlgo, err := types.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	hashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	attrs := &types.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            types.KeyTypeIDevID,
		Password:           types.NewPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:     tpm2.TPMHandle(config.Handle),
			HandleType: tpm2.TPMHTPersistent,
			HashAlg:    hashAlg,
			Hierarchy:  tpm2.TPMRHEndorsement,
		},
	}

	if config.ECCConfig != nil {
		curve, err := types.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

// LDevIDAttributesFromConfig builds Locally significant Device Identifier
// key attributes from the platform configuration. TPMAttributes.Template is
// deliberately left as the zero TPMTPublic: an LDevID is created through the
// same CreateIDevID path, which selects its own unrestricted template and
// never reads the field (#355). The policyDigest parameter is retained for
// signature stability; platform policy is conveyed by the PlatformPolicy
// field.
func LDevIDAttributesFromConfig(
	config LDevIDConfig,
	_ *tpm2.TPM2BDigest) (*types.KeyAttributes, error) {

	if config.CN == "" {
		config.CN = "ldevid"
	}

	algorithm, err := types.ParseKeyAlgorithm(config.KeyAlgorithm)
	if err != nil {
		switch {
		case config.RSAConfig != nil:
			algorithm = x509.RSA
		case config.ECCConfig != nil:
			algorithm = x509.ECDSA
		default:
			return nil, err
		}
	}

	hash := ParseHash(config.Hash)

	sigAlgo, err := types.ParseSignatureAlgorithm(config.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	hashAlg, err := ParseHashAlgFromString(config.Hash)
	if err != nil {
		return nil, ErrInvalidHashFunction
	}

	attrs := &types.KeyAttributes{
		CN:                 config.CN,
		Debug:              config.Debug,
		Hash:               hash,
		KeyAlgorithm:       algorithm,
		KeyType:            types.KeyTypeIDevID,
		Password:           types.NewPassword([]byte(config.Password)),
		PlatformPolicy:     config.PlatformPolicy,
		SignatureAlgorithm: sigAlgo,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:     tpm2.TPMHandle(config.Handle),
			HandleType: tpm2.TPMHTPersistent,
			HashAlg:    hashAlg,
			Hierarchy:  tpm2.TPMRHEndorsement,
		},
	}

	if config.ECCConfig != nil {
		curve, err := types.ParseCurve(config.ECCConfig.Curve)
		if err != nil {
			return nil, err
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: curve,
		}
	}

	if config.RSAConfig != nil {
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: config.RSAConfig.KeySize,
		}
	}

	return attrs, nil
}

func ParseHierarchy(hierarchyType string) (tpm2.TPMIRHHierarchy, error) {
	switch hierarchyType {
	case "ENDORSEMENT":
		return tpm2.TPMRHEndorsement, nil
	case "OWNER":
		return tpm2.TPMRHOwner, nil
	case "PLATFORM":
		return tpm2.TPMRHPlatform, nil
	}
	return 0, ErrInvalidHierarchyType
}

// ParseIdentityProvisioningStrategy resolves the configured identity
// provisioning strategy, one of the methods in "TPM 2.0 Keys for Device
// Identity and Attestation", section 6 - Identity Provisioning.
//
// An unset value selects section 6.2 (IAK and IDevID in a single pass), the
// documented default. Any other unrecognized value returns
// EnrollmentStrategyUnknown, which no strategy switch accepts, so the caller
// reports ErrInvalidEnrollmentStrategy.
//
// This used to fall back to the 6.2 default for every unrecognized value, so a
// typo in identity-provisioning-strategy silently ran a different
// device-identity ceremony than the operator configured, with no diagnostic --
// and made ErrInvalidEnrollmentStrategy unreachable in both VerifyTCGCSR and
// CreateTCG_CSR_IDEVID.
func ParseIdentityProvisioningStrategy(strategy string) EnrollmentStrategy {
	switch strategy {
	// Unset: the documented default, section 6.2.
	case "":
		return EnrollmentStrategyIAK_IDEVID_SINGLE_PASS
	// 6.1 OEM Creation of an IAK Certificate
	case string(EnrollmentStrategyIAK):
		return EnrollmentStrategyIAK
	// 6.2 OEM Installation of IAK and IDevID in a Single Pass
	case string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS):
		return EnrollmentStrategyIAK_IDEVID_SINGLE_PASS
	default:
		return EnrollmentStrategyUnknown
	}
}

func ParsePCRBankAlgID(pcrBank string) (tpm2.TPMAlgID, error) {
	tpmAlgID, ok := pcrBankAlgIDMap[strings.ToLower(pcrBank)]
	if !ok {
		return 0, ErrInvalidPCRBankType
	}
	return tpmAlgID, nil
}

func ParsePCRBankCryptoHash(pcrBank string) (crypto.Hash, error) {
	hash, ok := pcrBankCryptoHashMap[strings.ToLower(pcrBank)]
	if !ok {
		return 0, ErrInvalidPCRBankType
	}
	return hash, nil
}

func ParseCryptoHashAlgID(hash crypto.Hash) (tpm2.TPMAlgID, error) {
	tpmAlgID, ok := cryptoHashAlgIDMap[hash.String()]
	if !ok {
		return 0, ErrInvalidCryptoHashAlgID
	}
	return tpmAlgID, nil
}
