package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Returns the Endorsement Public Key
func (tpm *TPM2) EK() (crypto.PublicKey, error) {
	if tpm.ekAttrs == nil {
		return nil, ErrEKNotInitialized
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.ekAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		return nil, &errs.Detail{Err: ErrEKNotInitialized, Detail: fmt.Sprintf("%v", err)}
	}
	return pub, nil
}

// Returns the Endorsement Key name and public area.
func (tpm *TPM2) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if tpm.config.EK == nil {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, ErrEKConfigNil
	}
	ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
	name, pub, err := tpm.ReadHandle(ekHandle)
	if err != nil {
		tpm.logger.Error("failed to read EK public", slog.String("error", err.Error()))
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, &errs.Detail{Err: ErrEKPublicRead, Detail: fmt.Sprintf("%v", err)}
	}
	return name, pub, nil
}

// Returns the Endorsement Public RSA Key.
func (tpm *TPM2) EKRSA() (*rsa.PublicKey, error) {
	if tpm.ekRSAPubKey == nil {
		_, ekPub, err := tpm.EKPublic()
		if err != nil {
			return nil, &errs.Detail{Err: ErrEKRSAParse, Detail: fmt.Sprintf("%v", err)}
		}
		rsaDetail, err := ekPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.Error("failed to get RSA detail", slog.String("error", err.Error()))
			return nil, &errs.Detail{Err: ErrEKRSAParse, Detail: fmt.Sprintf("%v", err)}
		}
		rsaUnique, err := ekPub.Unique.RSA()
		if err != nil {
			tpm.logger.Error("failed to get RSA unique", slog.String("error", err.Error()))
			return nil, &errs.Detail{Err: ErrEKRSAParse, Detail: fmt.Sprintf("%v", err)}
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			tpm.logger.Error("failed to create RSA public key", slog.String("error", err.Error()))
			return nil, &errs.Detail{Err: ErrEKRSAParse, Detail: fmt.Sprintf("%v", err)}
		}
		tpm.ekRSAPubKey = rsaPub
	}
	return tpm.ekRSAPubKey, nil
}

// Returns the Endorsement Public ECC Key.
func (tpm *TPM2) EKECC() (*ecdsa.PublicKey, error) {
	if tpm.ekECCPubKey == nil {
		_, ekPub, err := tpm.EKPublic()
		if err != nil {
			return nil, &errs.Detail{Err: ErrEKECCParse, Detail: fmt.Sprintf("%v", err)}
		}
		eccPub, err := eccPublicKey(&ekPub)
		if err != nil {
			tpm.logger.Error("failed to reconstruct EK ECC public key", slog.String("error", err.Error()))
			return nil, &errs.Detail{Err: ErrEKECCParse, Detail: fmt.Sprintf("%v", err)}
		}
		tpm.ekECCPubKey = eccPub
	}
	return tpm.ekECCPubKey, nil
}

// Returns the Shared Storage Root Key name and public area.
func (tpm *TPM2) SSRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
	name, pub, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		tpm.logger.Error("failed to read SSRK public", slog.String("error", err.Error()))
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, &errs.Detail{Err: ErrSRKPublicRead, Detail: fmt.Sprintf("%v", err)}
	}
	return name, pub, nil
}

// SRKPublic returns the Storage Root Key name and public area.
// This is an alias for SSRKPublic to satisfy the TrustedPlatformModule interface.
func (tpm *TPM2) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm.SSRKPublic()
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IAKAttributes() (*types.KeyAttributes, error) {
	if tpm.iakAttrs == nil {
		if tpm.config.IAK == nil {
			return nil, ErrIAKConfigNil
		}
		iakHandle := tpm2.TPMHandle(tpm.config.IAK.Handle)
		iakAttrs, err := tpm.KeyAttributes(iakHandle)
		if err != nil {
			return nil, err
		}
		// KeyAttributes(handle) describes the key the TPM holds: it carries
		// no CN, labels every key KeyTypeTPM, and knows nothing of the
		// authValue or platform binding the configuration gave the key. Those
		// come from applyIAKConfig, the same function the provisioning path
		// runs, so a restarted process describes and authorizes the key
		// exactly as the process that provisioned it did.
		if err := tpm.applyIAKConfig(iakAttrs); err != nil {
			return nil, err
		}

		// Load parent EK attributes
		ekAttrs, err := tpm.EKAttributes()
		if err != nil {
			return nil, err
		}
		iakAttrs.Parent = ekAttrs

		tpm.iakAttrs = iakAttrs
	}
	return tpm.iakAttrs, nil
}

// applyIAKConfig assigns to attrs every IAK attribute that comes from
// configuration rather than from the TPM: the Common Name, the key type and
// store, platform binding, the signature algorithm and the authValue. It is
// the ONE place both the provisioning path (CreateIAK) and the restart path
// (IAKAttributes) take those from, so a field cannot survive one and not the
// other. Each time the two paths assigned them separately a field was lost on
// restart: the CN in #337, PlatformPolicy and KeyType in #466, and the
// password in #467 -- a key with a configured authValue signed in the process
// that provisioned it and answered TPM_RC_BAD_AUTH from the next boot on.
func (tpm *TPM2) applyIAKConfig(attrs *types.KeyAttributes) error {
	cfg := tpm.config.IAK
	// One naming rule for both DevID keys: an explicit iak.cn, else the
	// device's model and serial number, else refusal (see DevIDCommonName).
	cn, err := DevIDCommonName(cfg.CN, devidPlatformFromConfig(tpm.config.IDevID))
	if err != nil {
		return err
	}
	sigAlgo, err := types.ParseSignatureAlgorithm(cfg.SignatureAlgorithm)
	if err != nil {
		return err
	}
	return applyDevIDConfig(attrs, types.KeyTypeAttestation, cn, sigAlgo, cfg.PlatformPolicy, cfg.Password)
}

// applyIDevIDConfig is the IDevID half of applyIAKConfig, shared by
// CreateIDevID and the IDevIDAttributes rebuild.
func (tpm *TPM2) applyIDevIDConfig(attrs *types.KeyAttributes) error {
	cfg := tpm.config.IDevID
	cn, err := DevIDCommonName(cfg.CN, &PlatformAttributes{Model: cfg.Model, Serial: cfg.Serial})
	if err != nil {
		return err
	}
	sigAlgo, err := types.ParseSignatureAlgorithm(cfg.SignatureAlgorithm)
	if err != nil {
		return err
	}
	return applyDevIDConfig(attrs, types.KeyTypeIDevID, cn, sigAlgo, cfg.PlatformPolicy, cfg.Password)
}

// applyDevIDConfig writes the configuration-derived fields of a device
// identity key. The authValue goes into an enclave through types.NewPassword,
// never a plain string on the heap; a password the attributes already hold --
// the provisioning builders set one -- is cleared before it is replaced, so
// applying the configuration twice leaves no enclave behind.
func applyDevIDConfig(
	attrs *types.KeyAttributes,
	keyType types.KeyType,
	cn string,
	sigAlgo x509.SignatureAlgorithm,
	platformPolicy bool,
	password *types.SecretValue) error {

	passwordBytes, err := types.SecretValueBytes(password)
	if err != nil {
		return err
	}
	pw, err := types.NewPassword(passwordBytes)
	if err != nil {
		return err
	}

	attrs.CN = cn
	attrs.KeyType = keyType
	attrs.StoreType = types.StoreTPM2
	// PlatformPolicy selects the key's USER-role session (devidKeySession):
	// with it clear, a key that has no authValue is used with the empty
	// password regardless of platform state.
	attrs.PlatformPolicy = platformPolicy
	attrs.SignatureAlgorithm = sigAlgo
	if attrs.Password != nil {
		attrs.Password.Clear()
	}
	attrs.Password = pw
	return nil
}

// Returns the Initial Attestation Key public key
func (tpm *TPM2) IAK() (crypto.PublicKey, error) {
	if tpm.iakAttrs == nil {
		return nil, ErrIAKNotInitialized
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.iakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.Error("failed to parse IAK public key", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrIAKPublicParse, Detail: fmt.Sprintf("%v", err)}
	}
	return pub, nil
}

// Returns the Initial Device IDentifier Key Attributes
func (tpm *TPM2) IDevIDAttributes() (*types.KeyAttributes, error) {
	if tpm.idevidAttrs == nil {
		if tpm.config.IDevID == nil {
			return nil, ErrIDevIDConfigNil
		}
		idevidHandle := tpm2.TPMHandle(tpm.config.IDevID.Handle)
		idevidAttrs, err := tpm.KeyAttributes(idevidHandle)
		if err != nil {
			return nil, err
		}
		// See the IAK rebuild above: the configuration-derived fields come
		// from the one function the provisioning path also runs.
		if err := tpm.applyIDevIDConfig(idevidAttrs); err != nil {
			return nil, err
		}
		tpm.idevidAttrs = idevidAttrs
	}
	return tpm.idevidAttrs, nil
}

// Returns the Initial Device IDentifier public key
func (tpm *TPM2) IDevID() (crypto.PublicKey, error) {
	if tpm.idevidAttrs == nil {
		tpm.logger.Error("IDevID not initialized", slog.String("error", ErrIDevIDNotInitialized.Error()))
		return nil, ErrIDevIDNotInitialized
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.idevidAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.Error("failed to parse IDevID public key", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrIDevIDPublicParse, Detail: fmt.Sprintf("%v", err)}
	}
	return pub, nil
}

// Returns the Endorsement Key atrributes using the handle defined
// in the platform configuration file.
// If the persistent EK doesn't exist but a manufacturer EK certificate
// exists in NV RAM, returns attributes based on the configuration.
func (tpm *TPM2) EKAttributes() (*types.KeyAttributes, error) {
	if tpm.ekAttrs == nil {
		if tpm.config.EK == nil {
			return nil, ErrEKConfigNil
		}
		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		ekAttrs, err := tpm.KeyAttributes(ekHandle)
		if err != nil {
			// Check if this is a "handle not found" error (persistent EK doesn't exist)
			isPersistentHandleError := err == tpm2.TPMRC(0x184) || // TPM_RC_VALUE
				err == tpm2.TPMRC(0x18b) // TPM_RC_HANDLE

			if isPersistentHandleError {
				// Persistent EK doesn't exist - check for manufacturer EK certificate in NV RAM
				_, nvErr := tpm2.NVReadPublic{
					NVIndex: tpm2.TPMHandle(tpm.config.EK.CertHandle),
				}.Execute(tpm.transport)

				if nvErr != nil {
					// Neither persistent EK nor manufacturer certificate exists
					return nil, err
				}

				// Manufacturer EK certificate exists - create attributes from config
				tpm.logger.Debug("Persistent EK not found, using config-based attributes with manufacturer certificate",
					slog.String("certHandle", fmt.Sprintf("0x%08X", tpm.config.EK.CertHandle)))

				policyDigest, pdErr := tpm.PlatformPolicyDigest()
				if pdErr != nil {
					return nil, pdErr
				}
				ekAttrs, err = EKAttributesFromConfig(*tpm.config.EK, &policyDigest, tpm.config.IDevID)
				if err != nil {
					return nil, err
				}
				tpm.ekAttrs = ekAttrs
				return tpm.ekAttrs, nil
			}
			return nil, err
		}
		// If no EK common name is provided, try to use the device model and serial
		// naming convention if a IDevID is defined, otherwise use "ek" as the CN.
		if tpm.config.EK.CN == "" {
			if tpm.config.IDevID != nil {
				model := strings.ReplaceAll(tpm.config.IDevID.Model, " ", "_")
				ekAttrs.CN = fmt.Sprintf("ek-%s-%s",
					model, tpm.config.IDevID.Serial)
			} else {
				ekAttrs.CN = "ek"
			}
		}
		ekAttrs.KeyType = types.KeyTypeEndorsement
		ekAttrs.StoreType = types.StoreTPM2

		algo, err := types.ParseKeyAlgorithm(tpm.config.EK.KeyAlgorithm)
		if err != nil {
			return nil, err
		}
		ekAttrs.KeyAlgorithm = algo

		if algo == x509.RSA {
			var keySize int
			if tpm.config.EK.RSAConfig != nil {
				keySize = tpm.config.EK.RSAConfig.KeySize
			} else {
				// Derive key size from the TPM public key
				pubKey, parseErr := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
				if parseErr == nil {
					if rsaPub, ok := pubKey.(*rsa.PublicKey); ok {
						keySize = rsaPub.N.BitLen()
					}
				}
			}
			ekAttrs.RSAAttributes = &types.RSAAttributes{
				KeySize: keySize,
			}
		} else {
			var eccCurve elliptic.Curve
			if tpm.config.EK.ECCConfig != nil {
				parsed, parseErr := types.ParseCurve(tpm.config.EK.ECCConfig.Curve)
				if parseErr != nil {
					return nil, parseErr
				}
				eccCurve = parsed
			} else {
				// Derive curve from the TPM public key
				pubKey, parseErr := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
				if parseErr == nil {
					if eccPub, ok := pubKey.(*ecdsa.PublicKey); ok {
						eccCurve = eccPub.Curve
					}
				}
			}
			ekAttrs.ECCAttributes = &types.ECCAttributes{
				Curve: eccCurve,
			}
		}
		tpm.ekAttrs = ekAttrs
	}
	return tpm.ekAttrs, nil
}

// Returns the Shared Storage Root Key under the Owner hierarchy
// using it's persistent handle.
func (tpm *TPM2) SSRKAttributes() (*types.KeyAttributes, error) {
	if tpm.ssrkAttrs == nil {
		if tpm.config.SSRK == nil {
			return nil, ErrSSRKConfigNil
		}
		srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
		srkAttrs, err := tpm.KeyAttributes(srkHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.SSRK.CN == "" {
			srkAttrs.CN = "shared-srk"
		}
		srkAttrs.KeyType = types.KeyTypeStorage
		srkAttrs.StoreType = types.StoreTPM2
		if err != nil {
			return nil, err
		}
		tpm.ssrkAttrs = srkAttrs
	}
	return tpm.ssrkAttrs, nil
}

// PlatformSRKAttributes returns the Platform Storage Root Key attributes
// using its persistent handle (default 0x81000002).
//
// Configuration is the source of truth for whether this SRK is
// platform-policy bound, on this path exactly as it is for the
// PlatformKeyStore path below: PlatformSRKAttributesFromConfig (the same
// function PlatformKeyStore uses to build the attributes it creates the SRK
// from) supplies PlatformPolicy here too, rather than this method
// re-deriving it or leaving it at the Go zero value. A bare TPM2_ReadPublic
// (tpm.KeyAttributes) has no configuration in scope and cannot set it, and
// the object's live AuthPolicy is deliberately not inspected to infer it --
// inferring from what TPM2_ReadPublic returns would make an unrelated
// object's coincidentally-matching AuthPolicy silently select the PCR
// branch. Without this, a caller with no PlatformKeyStore attached (every
// unattended path: the barrier's TPM2Strategy, PlatformSealer) resolved
// PlatformPolicy: false here even when the SRK was created with a platform
// policy, so CreateSession skipped PlatformPolicySession entirely and tried
// a plain password session with empty auth against an enrolled SRK's real,
// non-empty PIN -- refused with TPM_RC_AUTH_FAIL before the PolicyPCR branch
// the object's AuthPolicy actually supports was ever attempted.
//
// When a PlatformKeyStore is attached and its auth is confirmed (IsAuthReady),
// the SRK auth password from the PlatformKeyStore is included in the returned
// attributes. This allows seal/unseal operations using the SRK to succeed
// when the SRK has a non-empty auth policy.
func (tpm *TPM2) PlatformSRKAttributes() (*types.KeyAttributes, error) {
	if tpm.platformSRKAttrs == nil {
		if tpm.config.PlatformSRK == nil {
			return nil, ErrInvalidPlatformSRKConfiguration
		}
		srkHandle := tpm2.TPMHandle(tpm.config.PlatformSRK.SRKHandle)
		if srkHandle == 0 {
			srkHandle = tpm2.TPMHandle(tpSRKIndex)
		}
		srkAttrs, err := tpm.KeyAttributes(srkHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.PlatformSRK.CN == "" {
			srkAttrs.CN = "platform-srk"
		}
		srkAttrs.KeyType = types.KeyTypeStorage
		srkAttrs.StoreType = types.StoreTPM2

		configAttrs, err := PlatformSRKAttributesFromConfig(tpm.config)
		if err != nil {
			return nil, err
		}
		srkAttrs.PlatformPolicy = configAttrs.PlatformPolicy

		tpm.platformSRKAttrs = srkAttrs
	}

	// Always sync the full SRK attributes from the PlatformKeyStore when
	// available. The PlatformKeyStore may have evicted and recreated the SRK
	// (ensureSRKAuth), which changes the key material and auth value.
	// Without this sync, the cached attrs have stale data and seal operations
	// fail with TPM_RC_BAD_AUTH.
	if pks := tpm.platformKeyStore; pks != nil {
		if concreteKS, ok := pks.(*PlatformKeyStore); ok {
			if pksAttrs := concreteKS.SRKAttributes(); pksAttrs != nil {
				tpm.platformSRKAttrs = pksAttrs
			}
		}
	}

	return tpm.platformSRKAttrs, nil
}

// Reads the public area of the provided persistent TPM handle
// and returns a default set of KeyAttributes with the name,
// public area and algorithm set.
func (tpm *TPM2) KeyAttributes(
	handle tpm2.TPMHandle) (*types.KeyAttributes, error) {

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		// TPM_RC_HANDLE (0x18b) is expected when key doesn't exist - log at debug level
		if err == tpm2.TPMRC(0x18b) {
			tpm.logger.Debug("key handle not found (expected during initialization)",
				slog.String("handle", fmt.Sprintf("0x%x", handle)),
				slog.String("error", err.Error()))
		} else {
			tpm.logger.Error("failed to read public key",
				slog.String("handle", fmt.Sprintf("0x%x", handle)),
				slog.String("error", err.Error()))
		}
		return nil, err
	}

	keyPub, err := pub.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public contents", slog.String("error", err.Error()))
		return nil, err
	}

	keyAlgo := x509.RSA
	if keyPub.Type == tpm2.TPMAlgECC {
		keyAlgo = x509.ECDSA
	}

	pubKey, err := tpm.ParsePublicKey(pub.OutPublic.Bytes())
	if err != nil {
		return nil, err
	}

	publicDER, err := store.EncodePubKey(pubKey)
	if err != nil {
		return nil, err
	}

	hash, err := tpm.algID.Hash()
	if err != nil {
		return nil, err
	}

	attrs := &types.KeyAttributes{
		Debug:        tpm.debugSecrets,
		KeyAlgorithm: keyAlgo,
		KeyType:      types.KeyTypeTPM,
		StoreType:    types.StoreTPM2,
		Hash:         hash,
		TPMAttributes: &types.TPMAttributes{
			BPublic:        pub.OutPublic,
			Handle:         handle,
			HandleType:     tpm2.TPMHTTransient,
			HashAlg:        tpm.algID,
			Hierarchy:      tpm2.TPMRHOwner,
			Name:           pub.Name,
			Public:         *keyPub,
			PublicKeyBytes: publicDER,
		},
	}

	switch keyPub.Type {
	case tpm2.TPMAlgRSA:
		attrs.KeyAlgorithm = x509.RSA
	case tpm2.TPMAlgECC:
		attrs.KeyAlgorithm = x509.ECDSA
	default:
		return nil, store.ErrInvalidKeyAlgorithm
	}

	return attrs, nil
}

// Creates a TCG compliant persistent Endorsement Key under the Endorsement
// Hierarchy. Optionally encrypts bus communication between the CPU <-> TPM
// if enabled in the platform configuration file.
func (tpm *TPM2) CreateEK(
	ekAttrs *types.KeyAttributes) error {

	var err error

	hierarchy := ekAttrs.TPMAttributes.Hierarchy

	var hierarchyAuth, userAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	if ekAttrs.Password != nil {
		userAuth = ekAttrs.Password.Bytes()
	}

	if ekAttrs.PlatformPolicy {
		template := ekAttrs.TPMAttributes.Template
		policyDigest, err := tpm.PlatformPolicyDigest()
		if err != nil {
			return err
		}
		template.AuthPolicy = policyDigest
		ekAttrs.TPMAttributes.Template = template
	}

	tpm.logger.Debug("tpm: creating EK", slog.String("algorithm", ekAttrs.KeyAlgorithm.String()))

	// Create new EK primary key under the Endorsement Hierarchy
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(ekAttrs.TPMAttributes.Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: userAuth,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to create EK primary key", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("tpm: EK created",
		slog.String("algorithm", ekAttrs.KeyAlgorithm.String()),
		slog.String("handle", fmt.Sprintf("0x%x", primaryKey.ObjectHandle)))

	ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
	if ekAttrs.TPMAttributes.Handle != 0 {
		ekHandle = ekAttrs.TPMAttributes.Handle
	}

	// Make the EK persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(ekHandle),
	}.Execute(tpm.transport)
	defer tpm.Flush(primaryKey.ObjectHandle)

	if err != nil {
		tpm.logger.Error("failed to persist EK", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("tpm: EK persisted", slog.String("handle", fmt.Sprintf("0x%x", ekAttrs.TPMAttributes.Handle)))

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to get EK public contents", slog.String("error", err.Error()))
		return err
	}

	hierName, hierErr := HierarchyName(hierarchy)
	if hierErr != nil {
		hierName = fmt.Sprintf("0x%08x", uint32(hierarchy))
	}
	tpm.logger.Debug("tpm: EK Hierarchy", slog.String("hierarchy", hierName))
	tpm.logger.Debug("tpm: EK Name", slog.String("name", fmt.Sprintf("0x%x", Encode(primaryKey.Name.Buffer))))

	ekAttrs.KeyType = types.KeyTypeEndorsement
	ekAttrs.TPMAttributes.Handle = ekHandle
	ekAttrs.TPMAttributes.Name = primaryKey.Name
	ekAttrs.TPMAttributes.Public = *pub

	publicKey, err := tpm.ParsePublicKey(primaryKey.OutPublic.Bytes())
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	ekAttrs.TPMAttributes.PublicKeyBytes = der

	store.DebugKeyAttributes(tpm.logger, ekAttrs)

	return nil
}

// Creates a persistent Storage Root Key (SRK) under the specified
// hierarchy using the Endorsement Key (EK) to salt an HMAC session.
// Optionally encrypts bus communication between the CPU <-> TPM if
// enabled in the platform configuration file. If the HandleType is
// set to TPMHTTransient, the created objects handles are left
// unflushed and the caller is responsible for flushing it when
// done.
func (tpm *TPM2) CreateSRK(
	srkAttrs *types.KeyAttributes) error {

	hierarchy := srkAttrs.TPMAttributes.Hierarchy

	var primaryKey *tpm2.CreatePrimaryResponse
	var err error
	var hierarchyAuth, userAuth []byte

	if srkAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = srkAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	if srkAttrs.Password != nil {
		userAuth = srkAttrs.Password.Bytes()
	}

	// Diagnostic summary of what is about to be passed to CreatePrimary.
	// Lengths and presence flags only -- never the auth bytes themselves, at
	// any log level. The auth values this key is created with are exactly
	// the owner-hierarchy and object secrets this package protects
	// everywhere else (types.SecretValue, memguard enclaves); logging them
	// here would undo that.
	hierName, hierErr := HierarchyName(hierarchy)
	if hierErr != nil {
		hierName = fmt.Sprintf("0x%08x", uint32(hierarchy))
	}
	tpm.logger.Debug("CreateSRK",
		slog.String("hierarchy", hierName),
		slog.String("hierarchy_handle", fmt.Sprintf("0x%08x", uint32(hierarchy))),
		slog.Int("hierarchy_auth_len", len(hierarchyAuth)),
		slog.Bool("hierarchy_auth_nil_field", srkAttrs.TPMAttributes.HierarchyAuth == nil),
		slog.Int("user_auth_len", len(userAuth)),
		slog.Bool("user_auth_nil_field", srkAttrs.Password == nil),
		slog.Bool("platform_policy", srkAttrs.PlatformPolicy),
		slog.String("persistent_handle", fmt.Sprintf("0x%08x", uint32(srkAttrs.TPMAttributes.Handle))),
		slog.String("handle_type", fmt.Sprintf("0x%02x", uint8(srkAttrs.TPMAttributes.HandleType))),
		slog.Bool("encrypt_session", tpm.config.EncryptSession),
		slog.Bool("has_parent", srkAttrs.Parent != nil),
	)

	// The platform policy this SRK is being created under, captured once so
	// the AuthPolicy baked into the template and the record written after the
	// key is persisted describe the same PCR state.
	//
	// Only the Platform SRK reaches this branch. The Shared SRK cannot ask for
	// a platform policy -- SRKConfig has no field for it -- because Provision
	// creates it before CreatePlatformPolicy extends the golden measurement,
	// which would leave it bound to a PCR state it outlives. This branch is
	// therefore reached with the platform PCR already in its steady state.
	//
	// This affects AUTHORIZATION of the persisted SRK only; it does not touch
	// DERIVATION. TPM2_CreatePrimary derives the key from the storage seed and
	// the template, AuthPolicy included, so the digest below must be -- and is
	// -- bit for bit what the live-PCR computation produced before: the pin
	// holds the platform PCR as it reads right now. What the record adds is the
	// ability to rebuild this policy's PolicyPCR branch digest later, when the
	// measurements have moved and the PolicyAuthValue branch is the only way
	// back in.
	//
	// Re-deriving an SRK on a changed platform remains what it always was: a
	// different template yields a different primary key. That is a
	// provisioning-time concern and is deliberately left alone.
	var policyPin *store.PlatformPolicyPin

	if srkAttrs.PlatformPolicy {
		template := srkAttrs.TPMAttributes.Template
		pin, err := tpm.capturePlatformPolicyPin()
		if err != nil {
			return err
		}
		policyDigest, err := platformPolicyDigestFromPin(pin)
		if err != nil {
			return err
		}
		template.AuthPolicy = policyDigest
		srkAttrs.TPMAttributes.Template = template
		policyPin = pin
	}

	// Create SRK
	primaryKeyCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(srkAttrs.TPMAttributes.Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: userAuth,
				},
			},
		},
	}

	if tpm.config.EncryptSession && srkAttrs.Parent != nil {

		var session tpm2.Session
		var closer func() error
		session, closer, err = tpm.CreateSession(srkAttrs)
		if err != nil {
			tpm.logger.Error("failed to create session for SRK", slog.String("error", err.Error()))
			return err
		}
		defer func() {
			if err := closer(); err != nil {
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}()

		primaryKey, err = primaryKeyCMD.Execute(tpm.transport, session)

	} else {
		primaryKey, err = primaryKeyCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error("failed to create SRK primary key", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("tpm: Created SRK", slog.String("handle", fmt.Sprintf("0x%x", primaryKey.ObjectHandle)))

	if srkAttrs.TPMAttributes.HandleType == tpm2.TPMHTPersistent {

		// Make the SRK persistent
		_, err = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: hierarchy, // storage or platform
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			ObjectHandle: &tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   primaryKey.Name,
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			PersistentHandle: srkAttrs.TPMAttributes.Handle,
		}.Execute(tpm.transport)

		tpm.Flush(primaryKey.ObjectHandle)

		if err != nil {
			tpm.logger.Error("failed to persist SRK", slog.String("error", err.Error()))
			return err
		}
		tpm.logger.Debug("tpm: SRK persisted",
			slog.String("handle", fmt.Sprintf("0x%x", srkAttrs.TPMAttributes.Handle)))

	} else {
		srkAttrs.TPMAttributes.Handle = primaryKey.ObjectHandle
	}

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to get SRK public contents", slog.String("error", err.Error()))
		return err
	}

	srkAttrs.KeyType = types.KeyTypeStorage
	srkAttrs.TPMAttributes.Name = primaryKey.Name
	srkAttrs.TPMAttributes.Public = *pub

	// Record the platform policy pin now that the SRK exists at its handle.
	// Recording earlier would leave a record describing a key that was never
	// created; recording it at all is what lets CreateSession rebuild this
	// SRK's PolicyPCR branch digest after the platform measurements change,
	// so a caller holding the SRK's PIN can still authorize TPM2_Load.
	if policyPin != nil {
		if err := tpm.recordPrimaryPolicyPin(srkAttrs, policyPin); err != nil {
			return err
		}
	}

	srkHierName, srkHierErr := HierarchyName(hierarchy)
	if srkHierErr != nil {
		srkHierName = fmt.Sprintf("0x%08x", uint32(hierarchy))
	}
	tpm.logger.Debug("tpm: SRK Hierarchy", slog.String("hierarchy", srkHierName))
	tpm.logger.Debug("tpm: SRK Name", slog.String("name", fmt.Sprintf("0x%s", Encode(primaryKey.Name.Buffer))))

	publicKey, err := tpm.ParsePublicKey(primaryKey.OutPublic.Bytes())
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	srkAttrs.TPMAttributes.PublicKeyBytes = der

	store.DebugKeyAttributes(tpm.logger, srkAttrs)

	return err
}

// Create an Initial Attestation Key
func (tpm *TPM2) CreateIAK(
	ekAttrs *types.KeyAttributes,
	qualifyingData []byte) (*types.KeyAttributes, error) {

	// + Endorsement Hierarchy
	//   - Endorsement Key
	//   - Attestation Key (restricted)
	//   - IDevID Key      (un-restricted)

	var hierarchyAuth, iakAuth, signature []byte
	var err error
	var isRSAPSS bool
	var inScheme tpm2.TPMTSigScheme

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		// Check if hierarchy auth is valid (error passwords return error from String())
		_, err = ekAttrs.TPMAttributes.HierarchyAuth.String()
		if err != nil {
			return nil, err
		}
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	// Create IAK key attributes from platform configuration file
	iakAttrs, err := IAKAttributesFromConfig(
		ekAttrs.TPMAttributes.HierarchyAuth,
		tpm.config.IAK)
	if err != nil {
		tpm.logger.Error("failed to create IAK attributes from config", slog.String("error", err.Error()))
		return nil, &errs.Detail{Err: ErrIAKConfigFailed, Detail: fmt.Sprintf("%v", err)}
	}
	iakAttrs.Parent = ekAttrs
	// The configuration-derived fields are assigned by the same function the
	// restart path runs, so the two cannot drift (see applyIAKConfig).
	if err := tpm.applyIAKConfig(iakAttrs); err != nil {
		return nil, err
	}

	if iakAttrs.Password != nil {
		iakAuth = iakAttrs.Password.Bytes()
	}

	// Get the platform PCR bank hash algorithm
	// This must match the bank used in CreatePlatformPolicy for consistency
	pcrBankHashAlg, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}

	// The IAK is Template H-0 over its configured crypto suite: TCG "TPM 2.0
	// Keys for Device Identity and Attestation" v1.00 r12, section 7.3.4,
	// Templates H-1 (RSA) and H-2 through H-4 (ECC P-256, P-384, P-521).
	//
	// It is built by the same DevIDTemplateSpec the package templates in
	// types.go are built from, so there is one spelling of "the IAK template"
	// in this package. This code used to carry its own inline copies, which is
	// how the exported templates and the created key came to disagree: #455
	// added adminWithPolicy to the inline ones only. Every field of a
	// TPMT_PUBLIC is an input to the derivation, so two spellings are two
	// different keys.
	//
	// nameAlg is the platform PCR bank's hash algorithm rather than the H-x
	// table's, because the same algorithm has to name the key policy, the PCR
	// selection recorded in the creation data and the scheme TPM2_CertifyCreation
	// signs under. H-1 through H-4 pair a suite with a nameAlg; the pairing is
	// the templates' default here and the PCR bank overrides it.
	var keyBits tpm2.TPMKeyBits
	if iakAttrs.RSAAttributes != nil && iakAttrs.RSAAttributes.KeySize > 0 {
		if iakAttrs.RSAAttributes.KeySize > math.MaxUint16 {
			return nil, ErrInvalidKeySize
		}
		keyBits = tpm2.TPMKeyBits(iakAttrs.RSAAttributes.KeySize) // #nosec G115 -- Bounds checked above
	} else {
		keyBits = tpm2.TPMKeyBits(DefaultRSAKeyBits)
	}

	isRSAPSS = iakAttrs.KeyAlgorithm == x509.RSA && types.IsRSAPSS(iakAttrs.SignatureAlgorithm)

	iakSpec := DevIDTemplateSpec{
		Kind:         DevIDKeyAttestation,
		Algorithm:    iakAttrs.KeyAlgorithm,
		KeyBits:      uint16(keyBits), // #nosec G115 -- TPMKeyBits is a uint16
		NameAlg:      pcrBankHashAlg,
		DeviceString: tpm.config.DeviceString,
	}
	if iakAttrs.ECCAttributes != nil {
		iakSpec.Curve = iakAttrs.ECCAttributes.Curve
	}
	if isRSAPSS {
		iakSpec.Scheme = tpm2.TPMAlgRSAPSS
	}

	template, err := iakSpec.Template()
	if err != nil {
		tpm.logger.Error("failed to build the IAK template", slog.String("error", err.Error()))
		return nil, err
	}

	// TPM2_CertifyCreation below signs under the key's own scheme, which a
	// Restricted key always names, so inScheme repeats it rather than choosing
	// one (TCG TPM 2.0 Library Part 3, section 12.1).
	inScheme, err = devidCertifyScheme(template)
	if err != nil {
		return nil, err
	}

	// Create PCR selection for creation data using the platform PCR bank
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      pcrBankHashAlg,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			},
		},
	}
	iakAttrs.TPMAttributes.PCRSelection = pcrSelection

	// Create Attestation Primary Key
	// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
	// section 7.3.4: the IAK's authPolicy is the IDevID/IAK Key Policy for
	// the attestation kind, whose DelegationNV branch is bound to Policy
	// Index DA1..DA3 rather than DS1..DS3. Assigned on the template the
	// primary is derived from; refused if the rest of the template is not
	// Template H-0 with Restricted SET.
	iakPolicy, err := DevIDKeyPolicyDigest(DevIDKeyAttestation, pcrBankHashAlg)
	if err != nil {
		return nil, err
	}
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: iakPolicy}
	if err := assertDevIDTemplateConformant(DevIDKeyAttestation, template); err != nil {
		tpm.logger.Error("refusing to create a non-conformant IAK", slog.String("error", err.Error()))
		return nil, err
	}

	iakPrimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: iakAuth,
				},
			},
		},
		CreationPCR: pcrSelection,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to create IAK primary key", slog.String("error", err.Error()))
		return nil, err
	}
	defer tpm.Flush(iakPrimary.ObjectHandle)

	// Make the AK persistent
	iakHandle := iakAttrs.TPMAttributes.Handle
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.AuthHandle{
			Handle: iakPrimary.ObjectHandle,
			Name:   iakPrimary.Name,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PersistentHandle: iakHandle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to persist IAK", slog.String("error", err.Error()))
		return nil, err
	}

	// Platform binding for an IAK is the platform Delegation Policy in its
	// Policy NV Index (section 7.2.4), never a different key policy: the
	// key above is Template H-0 either way.
	if iakAttrs.PlatformPolicy {
		if err := tpm.provisionDevIDPlatformDelegation(DevIDKeyAttestation, template.NameAlg, hierarchyAuth); err != nil {
			tpm.logger.Error("failed to provision the IAK platform delegation", slog.String("error", err.Error()))
			return nil, err
		}
	}

	// Extract public area
	iakPub, err := iakPrimary.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	// Certify the new IAK primary key. The IAK signs its own creation, so
	// the signing handle is authorized by the IAK's authValue (USER role,
	// userWithAuth SET), not the EK's. Presenting ekAuth here was invisible
	// while both were empty and failed provisioning outright the moment
	// iak.password was set (#467).
	certifyCreation := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: iakHandle,
			Name:   iakPrimary.Name,
			Auth:   tpm2.PasswordAuth(iakAuth),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: iakHandle,
			Name:   iakPrimary.Name,
		},
		CreationHash:   iakPrimary.CreationHash,
		InScheme:       inScheme,
		CreationTicket: iakPrimary.CreationTicket,
		QualifyingData: tpm2.TPM2BData{
			Buffer: qualifyingData,
		},
	}
	rspCC, err := certifyCreation.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}

	var akPublic crypto.PublicKey

	// Sign the attestation structure
	if iakPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		rsaDetail, err := iakPub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		rsaUnique, err := iakPub.Unique.RSA()
		if err != nil {
			return nil, err
		}

		akPublic, err = tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		if isRSAPSS {
			rsaSig, err = rspCC.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, err
			}
		} else {
			rsaSig, err = rspCC.Signature.Signature.RSASSA()
			if err != nil {
				return nil, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if iakPub.Type == tpm2.TPMAlgECC {

		sig, err := rspCC.Signature.Signature.ECDSA()
		if err != nil {
			return nil, err
		}

		akPublic, err = eccPublicKey(iakPub)
		if err != nil {
			tpm.logger.Error("failed to reconstruct IAK ECC public key", slog.String("error", err.Error()))
			return nil, err
		}

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, err
		}
		signature = asn1Sig
	}

	akPublicDER, err := store.EncodePubKey(akPublic)
	if err != nil {
		return nil, err
	}

	iakAttrs.TPMAttributes.Name = iakPrimary.Name
	iakAttrs.TPMAttributes.CertifyInfo = rspCC.CertifyInfo.Bytes()
	iakAttrs.TPMAttributes.BPublic = iakPrimary.OutPublic
	iakAttrs.TPMAttributes.PublicKeyBytes = akPublicDER
	iakAttrs.TPMAttributes.CreationTicketDigest = iakPrimary.CreationTicket.Digest.Buffer
	iakAttrs.TPMAttributes.Signature = signature
	iakAttrs.TPMAttributes.Public = *iakPub

	// Cache the IAK
	tpm.iakAttrs = iakAttrs

	store.DebugKeyAttributes(tpm.logger, iakAttrs)

	return iakAttrs, nil
}

// assertAdminAuthorizable reports whether a template's administration is
// authorizable at all, returning ErrAdminWithPolicyNoAuthPolicy when it sets
// adminWithPolicy while naming no authPolicy.
//
// The two fields are a pair: adminWithPolicy declares that the ADMIN role is
// governed by the object's authPolicy, so a template that sets it without one
// declares administration by a policy that does not exist. Checking the
// template rather than the attributes catches the contradiction wherever it
// enters -- a changed guard, an edited package template, a caller-supplied
// public area -- and does so before TPM2_CreatePrimary, while the object can
// still not be created. Once created the pair cannot be repaired: the
// attribute is an input to the derivation, so the same handle cannot be
// re-derived without it.
func assertAdminAuthorizable(template tpm2.TPMTPublic) error {
	if template.ObjectAttributes.AdminWithPolicy && len(template.AuthPolicy.Buffer) == 0 {
		return ErrAdminWithPolicyNoAuthPolicy
	}
	return nil
}

// assertDevIDTemplateConformant refuses an IDevID or IAK template that does
// not match TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
// Template H-0 (section 7.3.4.1), evaluated on the exact template about to be
// handed to TPM2_CreatePrimary:
//
//	fixedTPM, fixedParent, sensitiveDataOrigin, sign  SET
//	userWithAuth, adminWithPolicy                     SET   (section 7.2.4)
//	decrypt                                           CLEAR
//	Restricted                                        CLEAR for a signing DevID,
//	                                                  SET   for an IAK
//	authPolicy == the IDevID/IAK Key Policy for the template's nameAlg
//
// and, from the H-1 through H-4 tables (sections 7.3.4.2-7.3.4.5):
//
//	unique             == 'IDEVID' or 'IAK', optionally followed by the
//	                      device string (section 7.3.1, Table 2)
//	symmetric          == TPM_ALG_NULL
//	scheme             == TPM_ALG_NULL for an RSA DevID; RSASSA or RSAPSS
//	                      with a hash for an RSA AK; ECDSA with a hash for ECC
//	exponent           == 0                            (RSA)
//	kdf                == TPM_ALG_NULL                 (ECC)
//
// Every one of these is an input to the primary key's derivation, so a
// departure cannot be corrected after the fact; the only safe moment to
// enforce the shape is before the key exists. The policy comparison is what
// stops a template that reached here with a stale or foreign authPolicy from
// producing a key whose ADMIN role answers to the wrong policy, and the
// unique comparison is what stops a key that no other implementation of the
// specification could recreate.
//
// The symmetric and kdf checks are on the Go values rather than on the wire.
// A template that omits those fields marshals identically to one that names
// TPM_ALG_NULL, because go-tpm tags them gotpm:"nullable" and writes
// TPM_ALG_NULL for the Go zero value (measured in devid_template_test.go), so
// omission is not the departure this catches. What it catches is a template
// that names something else -- an AES symmetric definition, a KDF -- which
// H-1 through H-4 do not allow and which does change the key.
func assertDevIDTemplateConformant(kind DevIDKeyKind, template tpm2.TPMTPublic) error {
	fail := devidConformanceFailure(kind)

	if err := assertDevIDAttributesConformant(kind, template); err != nil {
		return err
	}
	switch template.Type {
	case tpm2.TPMAlgRSA:
		return assertDevIDRSAParmsConformant(kind, template, fail)
	case tpm2.TPMAlgECC:
		return assertDevIDECCParmsConformant(kind, template, fail)
	default:
		return fail(fmt.Sprintf(
			"type must be TPM_ALG_RSA (H-1) or TPM_ALG_ECC (H-2..H-4), not %s",
			algorithmName(template.Type)))
	}
}

// devidConformanceFailure builds the refusal for one key kind, so that every
// rule below reports the same error with the failing rule as its detail.
func devidConformanceFailure(kind DevIDKeyKind) func(string) error {
	return func(what string) error {
		return &errs.Detail{Err: ErrDevIDTemplateNonConformant, Detail: fmt.Sprintf("%s: %s", kind, what)}
	}
}

// assertDevIDAttributesConformant checks the TPMA_OBJECT bits and the
// authPolicy of an IDevID or IAK: Template H-0 (section 7.3.4.1) plus the
// section 7.2.4 authorization bits, and the section 7.3.6.6 IDevID/IAK Key
// Policy for the key's nameAlg.
//
// It is separate from the parameter and unique checks because these are the
// only rules that hold for a key that already exists. TPM2_CreatePrimary
// consumes inPublic.unique as derivation input and returns an outPublic whose
// unique field holds the generated public key, so the section 7.3.1 string is
// present in a template and gone from the key made out of it. The attributes
// and the policy, by contrast, are carried through into outPublic unchanged,
// which is what lets a CA verify them on a public area it received.
//
// AssertDevIDKeyConformant is the CA-side caller; assertDevIDTemplateConformant
// runs this and then the creation-only rules.
func assertDevIDAttributesConformant(kind DevIDKeyKind, template tpm2.TPMTPublic) error {
	a := template.ObjectAttributes
	fail := devidConformanceFailure(kind)

	if !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.SignEncrypt {
		return fail("fixedTPM, fixedParent, sensitiveDataOrigin and sign must all be SET")
	}
	if !a.UserWithAuth {
		return fail("userWithAuth must be SET so the authValue can use the key")
	}
	if !a.AdminWithPolicy {
		return fail("adminWithPolicy must be SET so only the key policy can administer the key")
	}
	if a.Decrypt {
		return fail("decrypt must be CLEAR")
	}
	wantRestricted := kind == DevIDKeyAttestation
	if a.Restricted != wantRestricted {
		return fail(fmt.Sprintf("Restricted must be %v", wantRestricted))
	}
	if err := assertAdminAuthorizable(template); err != nil {
		return err
	}
	want, err := DevIDKeyPolicyDigest(kind, template.NameAlg)
	if err != nil {
		return err
	}
	if !bytes.Equal(template.AuthPolicy.Buffer, want) {
		return fail("authPolicy is not the IDevID/IAK Key Policy for the template's nameAlg")
	}
	return nil
}

// assertDevIDRSAParmsConformant checks the TPMS_RSA_PARMS and unique field of
// Template H-1 (section 7.3.4.2, Table 4).
func assertDevIDRSAParmsConformant(
	kind DevIDKeyKind, template tpm2.TPMTPublic, fail func(string) error) error {

	parms, err := template.Parameters.RSADetail()
	if err != nil {
		return fail("the parameters are not a TPMS_RSA_PARMS")
	}
	if parms.Symmetric.Algorithm != tpm2.TPMAlgNull {
		return fail(fmt.Sprintf("symmetric->algorithm must be TPM_ALG_NULL, not %s",
			algorithmName(parms.Symmetric.Algorithm)))
	}
	if parms.Exponent != 0 {
		return fail(fmt.Sprintf("exponent must be 0, not %d", parms.Exponent))
	}
	if kind == DevIDKeyAttestation {
		// "TPM_ALG_RSASSA (AK - PKCSV1_5)" or "TPM_ALG_RSAPSS (AK)" with
		// "TPM_ALG_SHA256 (AK)" details. A Restricted signing key must name a
		// scheme (Part 1, section 25.2.3), and rsaKeySchemeHash reports
		// whether the one it names carries a usable hash.
		if _, fixed, err := rsaKeySchemeHash(parms.Scheme); err != nil || !fixed {
			return fail("an AK's scheme must be TPM_ALG_RSASSA or TPM_ALG_RSAPSS with a hash algorithm")
		}
	} else if parms.Scheme.Scheme != tpm2.TPMAlgNull {
		// "scheme->scheme = TPM_ALG_NULL (Signing)", "scheme->details = NULL".
		return fail(fmt.Sprintf("a DevID's scheme must be TPM_ALG_NULL, not %s",
			algorithmName(parms.Scheme.Scheme)))
	}
	unique, err := template.Unique.RSA()
	if err != nil {
		return fail("the unique field is not a TPM2B_PUBLIC_KEY_RSA")
	}
	return assertDevIDUniqueConformant(kind, unique.Buffer, fail)
}

// assertDevIDECCParmsConformant checks the TPMS_ECC_PARMS and unique field of
// Templates H-2 through H-4 (sections 7.3.4.3-7.3.4.5, Tables 5-7).
func assertDevIDECCParmsConformant(
	kind DevIDKeyKind, template tpm2.TPMTPublic, fail func(string) error) error {

	parms, err := template.Parameters.ECCDetail()
	if err != nil {
		return fail("the parameters are not a TPMS_ECC_PARMS")
	}
	if parms.Symmetric.Algorithm != tpm2.TPMAlgNull {
		return fail(fmt.Sprintf("symmetric->algorithm must be TPM_ALG_NULL, not %s",
			algorithmName(parms.Symmetric.Algorithm)))
	}
	if parms.KDF.Scheme != tpm2.TPMAlgNull {
		return fail(fmt.Sprintf("kdf->scheme must be TPM_ALG_NULL, not %s",
			algorithmName(parms.KDF.Scheme)))
	}
	// "scheme->scheme = TPM_ALG_ECDSA" for both kinds. The tables also say
	// "scheme->details = NULL", which no TPM can represent -- see
	// DevIDTemplateSpec.eccTemplate -- so the details carry a hash and
	// eccKeySchemeHash is what confirms it is a usable one.
	if _, fixed, err := eccKeySchemeHash(parms.Scheme); err != nil || !fixed {
		return fail("the scheme must be TPM_ALG_ECDSA with a hash algorithm")
	}
	if _, ok := devidUniqueSizes[parms.CurveID]; !ok {
		return fail(fmt.Sprintf(
			"curveID %s has no template; H-2 through H-4 define P-256, P-384 and P-521",
			curveName(parms.CurveID)))
	}
	unique, err := template.Unique.ECC()
	if err != nil {
		return fail("the unique field is not a TPMS_ECC_POINT")
	}
	return assertDevIDUniqueConformant(kind, unique.X.Buffer, fail)
}

// assertDevIDUniqueConformant checks the unique field against section 7.3.1,
// Table 2: the required string for the key's purpose, optionally followed by a
// printable-ASCII device string, and not NUL terminated.
//
// It is deliberately a prefix rule rather than an equality one. The device
// string is an OEM value this package does not hold at every point a template
// passes through, so the rule that can always be enforced is that the required
// string is there, that it is there unpadded, and that whatever follows is
// printable ASCII. A zero-filled unique -- what this package created before
// the string was implemented -- fails on the very first octet.
func assertDevIDUniqueConformant(kind DevIDKeyKind, unique []byte, fail func(string) error) error {
	required, ok := devidUniqueStrings[kind]
	if !ok {
		return fail("no unique string is defined for this key kind")
	}
	if !bytes.HasPrefix(unique, []byte(required)) {
		return fail(fmt.Sprintf("unique must begin with the required string %q (section 7.3.1, Table 2)", required))
	}
	// Whatever follows the required string is the device string, and it has
	// to satisfy the same rule the builder applies to it. The reason is
	// reported as a template non-conformance rather than passed through, so
	// that one error identifies every way a template can be refused here.
	if _, err := DevIDUniqueString(kind, string(unique[len(required):])); err != nil {
		return fail(fmt.Sprintf("the device string following %q is not admissible: %v", required, err))
	}
	return nil
}

// devidCertifyScheme returns the TPMT_SIG_SCHEME to hand
// TPM2_CertifyCreation for a key created from an IAK template.
//
// A Restricted signing key always names a scheme, and TPM2_Sign and the
// commands built on it require inScheme to repeat it exactly (TCG TPM 2.0
// Library Part 3, section 12.1), so the scheme is read back off the template
// rather than assembled a second time from the configuration that built it.
func devidCertifyScheme(template tpm2.TPMTPublic) (tpm2.TPMTSigScheme, error) {
	switch template.Type {
	case tpm2.TPMAlgRSA:
		parms, err := template.Parameters.RSADetail()
		if err != nil {
			return tpm2.TPMTSigScheme{}, err
		}
		hashAlg, _, err := rsaKeySchemeHash(parms.Scheme)
		if err != nil {
			return tpm2.TPMTSigScheme{}, err
		}
		return tpm2.TPMTSigScheme{
			Scheme: parms.Scheme.Scheme,
			Details: tpm2.NewTPMUSigScheme(parms.Scheme.Scheme,
				&tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
		}, nil

	case tpm2.TPMAlgECC:
		parms, err := template.Parameters.ECCDetail()
		if err != nil {
			return tpm2.TPMTSigScheme{}, err
		}
		hashAlg, _, err := eccKeySchemeHash(parms.Scheme)
		if err != nil {
			return tpm2.TPMTSigScheme{}, err
		}
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: hashAlg}),
		}, nil

	default:
		return tpm2.TPMTSigScheme{}, &errs.Detail{Err: ErrDevIDTemplateNonConformant,
			Detail: fmt.Sprintf("cannot certify a key of type %s", algorithmName(template.Type))}
	}
}

// Creates an Initial Device IDentifier (IDevID) under the
// Endorsement Hierarchy per TCG - TPM 2.0 Keys for Device Identity
// and Attestation. The Endorsement Key (EK) attributes must contain
// the HierarchyAuth to authorize the creation of the IDevID key under
// the Endorsement hierarchy. The EK is also used to salt an HMAC
// session, and optionally encrypt the bus communication between the
// CPU <-> TPM if enabled in the platform configuration file.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf
func (tpm *TPM2) CreateIDevID(
	akAttrs *types.KeyAttributes,
	ekCert *x509.Certificate,
	qualifyingData []byte) (*types.KeyAttributes, *TCG_CSR_IDEVID, error) {

	// + Endorsement Hierarchy
	//   - Endorsement Key
	//   - Attestation Key (restricted)
	//   - IDevID Key      (un-restricted)

	var hierarchyAuth, akAuth, idevidAuth, signature []byte

	if akAttrs == nil {
		return nil, nil, ErrInvalidAKAttributes
	}
	if akAttrs.Parent == nil {
		return nil, nil, ErrInvalidEKAttributes
	}
	ekAttrs := akAttrs.Parent

	// Create IDevID key attributes from platform configuration file
	if tpm.config.IDevID == nil {
		return nil, nil, ErrNotConfigured
	}
	idevidAttrs, err := IDevIDAttributesFromConfig(*tpm.config.IDevID)
	if err != nil {
		return nil, nil, err
	}
	idevidAttrs.Parent = ekAttrs
	// Same function as the IDevIDAttributes rebuild (see applyIAKConfig).
	if err := tpm.applyIDevIDConfig(idevidAttrs); err != nil {
		return nil, nil, err
	}

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	if akAttrs.Password != nil {
		akAuth = akAttrs.Password.Bytes()
	}

	if idevidAttrs.Password != nil {
		idevidAuth = idevidAttrs.Password.Bytes()
	}

	// The IDevID is Template H-0 over its configured crypto suite: TCG "TPM
	// 2.0 Keys for Device Identity and Attestation" v1.00 r12, section 7.3.4,
	// Templates H-1 (RSA) and H-2 through H-4 (ECC P-256, P-384, P-521). It is
	// built by the same DevIDTemplateSpec the package templates in types.go
	// are built from, which is what carries the required 'IDEVID' unique
	// string of section 7.3.1 and the device string that may follow it.
	//
	// The RSA branch keys off the EK's algorithm rather than the IDevID's
	// because the enrollment ceremony unpacks the AK's certification signature
	// under this key's configured padding; the selection is left as it was.
	idevidSpec := DevIDTemplateSpec{
		Kind:         DevIDKeySigning,
		Algorithm:    idevidAttrs.KeyAlgorithm,
		DeviceString: tpm.config.DeviceString,
	}
	if ekAttrs.KeyAlgorithm == x509.RSA {
		idevidSpec.Algorithm = x509.RSA
	}
	if idevidAttrs.RSAAttributes != nil && idevidAttrs.RSAAttributes.KeySize > 0 {
		if idevidAttrs.RSAAttributes.KeySize > math.MaxUint16 {
			return nil, nil, ErrInvalidKeySize
		}
		idevidSpec.KeyBits = uint16(idevidAttrs.RSAAttributes.KeySize) // #nosec G115 -- Bounds checked above
	}
	if idevidAttrs.ECCAttributes != nil {
		idevidSpec.Curve = idevidAttrs.ECCAttributes.Curve
	}

	idevidTemplate, err := idevidSpec.Template()
	if err != nil {
		tpm.logger.Error("failed to build the IDevID template", slog.String("error", err.Error()))
		return nil, nil, err
	}

	// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
	// section 7.3.4: the template's authPolicy is the IDevID/IAK Key Policy
	// for the key's nameAlg. With adminWithPolicy SET this is the only thing
	// that can authorize the ADMIN role, so it is assigned here, on the
	// template the primary key is derived from, and never anywhere else.
	keyPolicy, err := DevIDKeyPolicyDigest(DevIDKeySigning, idevidTemplate.NameAlg)
	if err != nil {
		return nil, nil, err
	}
	idevidTemplate.AuthPolicy = tpm2.TPM2BDigest{Buffer: keyPolicy}

	if err := assertDevIDTemplateConformant(DevIDKeySigning, idevidTemplate); err != nil {
		tpm.logger.Error("refusing to create an unadministrable IDevID",
			slog.String("error", err.Error()))
		return nil, nil, err
	}

	// Create IDevID Key
	primaryKeyCMD := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		InPublic: tpm2.New2B(idevidTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: idevidAuth,
				},
			},
		},
	}
	// Set PCR selection if available
	// Set PCR selection if available
	if akAttrs.TPMAttributes != nil && len(akAttrs.TPMAttributes.PCRSelection.PCRSelections) > 0 {
		primaryKeyCMD.CreationPCR = akAttrs.TPMAttributes.PCRSelection
	}

	primaryKey, err := primaryKeyCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to create IDevID primary key", slog.String("error", err.Error()))
		return nil, nil, err
	}
	defer tpm.Flush(primaryKey.ObjectHandle)

	// Evict existing key at this handle if it exists
	persistentHandle := idevidAttrs.TPMAttributes.Handle

	// Try to read existing object to get its name for eviction
	readPubResp, readErr := tpm2.ReadPublic{
		ObjectHandle: persistentHandle,
	}.Execute(tpm.transport)

	if readErr == nil {
		// Object exists, evict it
		_, evictErr := tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			ObjectHandle: &tpm2.AuthHandle{
				Handle: persistentHandle,
				Name:   readPubResp.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			PersistentHandle: persistentHandle,
		}.Execute(tpm.transport)
		if evictErr != nil {
			tpm.logger.Debug("Failed to evict existing key")
		}
	}

	// Make the IDevID Key persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		ObjectHandle: &tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(akAuth),
		},
		PersistentHandle: persistentHandle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to persist IDevID", slog.String("error", err.Error()))
		return nil, nil, err
	}

	// Platform binding for an IDevID is the platform Delegation Policy in
	// its Policy NV Index (section 7.2.4), never a different key policy: the
	// key above is Template H-0 either way.
	if idevidAttrs.PlatformPolicy {
		if err := tpm.provisionDevIDPlatformDelegation(DevIDKeySigning, idevidTemplate.NameAlg, hierarchyAuth); err != nil {
			tpm.logger.Error("failed to provision the IDevID platform delegation", slog.String("error", err.Error()))
			return nil, nil, err
		}
	}

	// Extract public area
	idevidPub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	// Certify the new IDevID primary key using the AK to sign the
	// TPMB_Attest structure
	// TPM2_Certify authorizes objectHandle at the ADMIN role (TCG TPM 2.0
	// Part 3, section 18.2). With adminWithPolicy SET the authValue cannot
	// do that -- the TPM answers TPM_RC_AUTH_TYPE -- so the IDevID is
	// certified under the Certify branch of its key policy, as the Privacy
	// Administrator (section 7.3.6.2). The IAK signs at the USER role, which
	// its authValue still authorizes.
	adminSession, closeAdmin, err := tpm.DevIDAdminSession(
		DevIDKeySigning, idevidTemplate.NameAlg, tpm2.TPMCCCertify, hierarchyAuth)
	if err != nil {
		return nil, nil, err
	}
	certify := tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   adminSession,
		},
		SignHandle: tpm2.AuthHandle{
			Handle: akAttrs.TPMAttributes.Handle,
			Name:   akAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(akAuth),
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: qualifyingData,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgNull,
		},
	}
	rspCert, err := certify.Execute(tpm.transport)
	if closeErr := closeAdmin(); closeErr != nil {
		tpm.logger.Warn("failed to close IDevID admin policy session", slog.String("error", closeErr.Error()))
	}
	if err != nil {
		return nil, nil, err
	}

	// Read the AK's public key from the TPM to determine the signature algorithm
	// The AK signs the certification, so we need its type to extract the signature correctly
	akPubResp, err := tpm2.ReadPublic{
		ObjectHandle: akAttrs.TPMAttributes.Handle,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, err
	}

	akPub, err := akPubResp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	// The public key recorded on the attributes is the IDevID's, so it is
	// read from the IDevID's own public area.
	var pubKeyBytes []byte
	switch idevidPub.Type {

	case tpm2.TPMAlgRSA:
		rsaDetail, err := idevidPub.Parameters.RSADetail()
		if err != nil {
			return nil, nil, err
		}
		rsaUnique, err := idevidPub.Unique.RSA()
		if err != nil {
			return nil, nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, nil, err
		}
		rsaDER, err := store.EncodePubKey(rsaPub)
		if err != nil {
			tpm.logger.Error("failed to encode RSA public key", slog.String("error", err.Error()))
			return nil, nil, err
		}
		pubKeyBytes = rsaDER

	case tpm2.TPMAlgECC:
		eccPub, err := eccPublicKey(idevidPub)
		if err != nil {
			tpm.logger.Error("failed to reconstruct IDevID ECC public key", slog.String("error", err.Error()))
			return nil, nil, err
		}
		eccDER, err := store.EncodePubKey(eccPub)
		if err != nil {
			tpm.logger.Error("failed to encode ECC public key", slog.String("error", err.Error()))
			return nil, nil, err
		}
		pubKeyBytes = eccDER

	default:
		return nil, nil, types.ErrInvalidKeyAlgorithm
	}

	// The certification was signed by the AK with InScheme = TPM_ALG_NULL, so
	// the TPM signed it under the AK's own scheme (TCG Part 3 §18.2). Both the
	// algorithm and the RSA padding of rspCert.Signature are therefore the
	// AK's, and are read from akPub. Deriving the padding from the IDevID's
	// configured signature algorithm instead made a device with a PSS AK and an
	// SSA IDevID -- or the reverse -- fail to enroll at all, and was invisible
	// wherever the two happened to be configured alike.
	switch akPub.Type {

	case tpm2.TPMAlgRSA:
		akDetail, err := akPub.Parameters.RSADetail()
		if err != nil {
			return nil, nil, err
		}

		var rsaSig *tpm2.TPMSSignatureRSA
		switch akDetail.Scheme.Scheme {
		case tpm2.TPMAlgRSAPSS:
			rsaSig, err = rspCert.Signature.Signature.RSAPSS()
		case tpm2.TPMAlgRSASSA:
			rsaSig, err = rspCert.Signature.Signature.RSASSA()
		default:
			// A NULL or non-signing scheme leaves nothing to unpack: the
			// certification could not have been produced under it.
			return nil, nil, ErrUnsupportedCertifyScheme
		}
		if err != nil {
			return nil, nil, err
		}
		signature = rsaSig.Sig.Buffer

	case tpm2.TPMAlgECC:
		sig, err := rspCert.Signature.Signature.ECDSA()
		if err != nil {
			return nil, nil, err
		}
		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, nil, err
		}
		signature = asn1Sig

	default:
		return nil, nil, ErrUnsupportedCertifyScheme
	}

	tpm.logger.Debug("tpm: IDevID Key Hierarchy: Endorsement")

	tpm.logger.Debug("tpm: IDevID Key persisted to handle",
		slog.String("handle", fmt.Sprintf("0x%x", idevidAttrs.TPMAttributes.Handle)))

	tpm.logger.Debug("tpm: IDevID Key Name",
		slog.String("name", Encode(primaryKey.Name.Buffer)))

	idevidAttrs.TPMAttributes.Name = primaryKey.Name
	idevidAttrs.TPMAttributes.BPublic = primaryKey.OutPublic
	idevidAttrs.TPMAttributes.CertifyInfo = rspCert.CertifyInfo.Bytes()
	idevidAttrs.TPMAttributes.PublicKeyBytes = pubKeyBytes
	idevidAttrs.TPMAttributes.Public = *idevidPub
	idevidAttrs.TPMAttributes.Signature = signature

	tcgCSR, err := tpm.CreateTCG_CSR_IDEVID(
		ekCert, akAttrs, idevidAttrs)
	if err != nil {
		return nil, nil, err
	}

	// Cache the IDevID key attributes
	tpm.idevidAttrs = idevidAttrs

	store.DebugKeyAttributes(tpm.logger, idevidAttrs)

	return idevidAttrs, &tcgCSR, nil
}

func (tpm *TPM2) DeleteKey(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) error {

	if keyAttrs.TPMAttributes != nil &&
		keyAttrs.TPMAttributes.HandleType != 0 &&
		keyAttrs.TPMAttributes.HandleType == tpm2.TPMHTPersistent {

		if tpm.transport == nil {
			return ErrInstallTransportNotInitialized
		}

		var err error
		var hierarchyAuth []byte
		if keyAttrs.TPMAttributes.HierarchyAuth != nil {
			hierarchyAuth = keyAttrs.TPMAttributes.HierarchyAuth.Bytes()
		}
		_, err = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(hierarchyAuth),
			},
			ObjectHandle: &tpm2.NamedHandle{
				Handle: keyAttrs.TPMAttributes.Handle,
				Name:   keyAttrs.TPMAttributes.Name,
			},
			PersistentHandle: keyAttrs.TPMAttributes.Handle,
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to evict key", slog.String("error", err.Error()))
			return err
		}
		return nil
	}

	// For signing keys (RSA/ECDSA), skip the unseal check since they cannot be unsealed.
	// Unseal only works for sealed objects (KEYEDHASH).
	// For signing keys, we just verify the key can be loaded and then delete the files.
	if keyAttrs.KeyAlgorithm == x509.RSA || keyAttrs.KeyAlgorithm == x509.ECDSA {
		// Load the key to verify ownership/authorization
		loadResp, err := tpm.LoadKeyPair(keyAttrs, nil, backend)
		if err != nil {
			return err
		}
		tpm.Flush(loadResp.ObjectHandle)
	} else {
		// For sealed objects (KEYEDHASH), perform an unseal operation to ensure the caller owns the key
		if _, err := tpm.UnsealKey(keyAttrs, backend); err != nil {
			return err
		}
	}

	// Delete the key pair from the backend
	if err := tpm.DeleteKeyPair(keyAttrs, backend); err != nil {
		tpm.logger.Error("failed to delete key pair", slog.String("error", err.Error()))
		return err
	}

	return nil
}
