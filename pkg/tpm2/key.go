package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Returns the Endorsement Public Key
func (tpm *TPM2) EK() crypto.PublicKey {
	if tpm.ekAttrs == nil {
		panic(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.ekAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		panic(ErrNotInitialized)
	}
	return pub
}

// Returns the Endorsement Key name and public area. Errors
// are fatal.
func (tpm *TPM2) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic) {
	ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
	name, pub, err := tpm.ReadHandle(ekHandle)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	return name, pub
}

// Returns the Endorsement Public RSA Key. Errors
// are fatal.
func (tpm *TPM2) EKRSA() *rsa.PublicKey {
	if tpm.ekRSAPubKey == nil {
		_, ekPub := tpm.EKPublic()
		rsaDetail, err := ekPub.Parameters.RSADetail()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		rsaUnique, err := ekPub.Unique.RSA()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			tpm.logger.FatalError(err)
		}
		tpm.ekRSAPubKey = rsaPub
	}
	return tpm.ekRSAPubKey
}

// Returns the Endorsement Public ECC Key. Errors
// are fatal.
func (tpm *TPM2) EKECC() *ecdsa.PublicKey {
	if tpm.ekECCPubKey == nil {
		_, ekPub := tpm.EKPublic()
		ecDetail, err := ekPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		eccUnique, err := ekPub.Unique.ECC()
		if err != nil {
			tpm.logger.FatalError(err)
		}
		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		tpm.ekECCPubKey = eccPub
	}
	return tpm.ekECCPubKey
}

// Returns the Shared Storage Root Key name and public area.
// Errors are fatal.
func (tpm *TPM2) SSRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic) {
	srkHandle := tpm2.TPMHandle(tpm.config.SSRK.Handle)
	name, pub, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	return name, pub
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IAKAttributes() (*types.KeyAttributes, error) {
	if tpm.iakAttrs == nil {
		iakHandle := tpm2.TPMHandle(tpm.config.IAK.Handle)
		iakAttrs, err := tpm.KeyAttributes(iakHandle)
		if err != nil {
			return nil, err
		}
		if tpm.config.IAK.CN == "" {
			iakAttrs.CN = "default-device-id"
		}
		iakAttrs.KeyType = types.KeyTypeAttestation
		iakAttrs.StoreType = types.StoreTPM2

		// Set signature algorithm from config
		sigAlgo, err := types.ParseSignatureAlgorithm(tpm.config.IAK.SignatureAlgorithm)
		if err == nil {
			iakAttrs.SignatureAlgorithm = sigAlgo
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

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IAK() crypto.PublicKey {
	if tpm.iakAttrs == nil {
		panic(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.iakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	return pub
}

// Returns the Initial Device IDentifier Key Attributes
func (tpm *TPM2) IDevIDAttributes() (*types.KeyAttributes, error) {
	if tpm.idevidAttrs == nil {
		idevidHandle := tpm2.TPMHandle(tpm.config.IDevID.Handle)
		signatureAlgorithm, err := types.ParseSignatureAlgorithm(tpm.config.IDevID.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		idevidAttrs, err := tpm.KeyAttributes(idevidHandle)
		if err != nil {
			return nil, err
		}
		idevidAttrs.CN = tpm.config.IDevID.CN
		idevidAttrs.SignatureAlgorithm = signatureAlgorithm
		tpm.idevidAttrs = idevidAttrs
	}
	return tpm.idevidAttrs, nil
}

// Returns the Initial Attestation Key Attributes
func (tpm *TPM2) IDevID() crypto.PublicKey {
	if tpm.idevidAttrs == nil {
		tpm.logger.FatalError(ErrNotInitialized)
	}
	pub, err := x509.ParsePKIXPublicKey(tpm.iakAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	return pub
}

// Returns the Endorsement Key atrributes using the handle defined
// in the platform configuration file.
func (tpm *TPM2) EKAttributes() (*types.KeyAttributes, error) {
	if tpm.ekAttrs == nil {
		ekHandle := tpm2.TPMHandle(tpm.config.EK.Handle)
		ekAttrs, err := tpm.KeyAttributes(ekHandle)
		if err != nil {
			return nil, err
		}
		// If no EK common name is provided, try to use the device model and serial
		// naming convention if a IDevID is defined, otherwise use "ek" as the CN.
		if tpm.config.EK.CN == "" {
			if tpm.config.IDevID != nil {
				ekAttrs.CN = fmt.Sprintf("ek-%s-%s",
					tpm.config.IDevID.Model, tpm.config.IDevID.Serial)
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
			ekAttrs.RSAAttributes = &types.RSAAttributes{
				KeySize: tpm.config.EK.RSAConfig.KeySize,
			}
		} else {
			curve, err := types.ParseCurve(tpm.config.EK.ECCConfig.Curve)
			if err != nil {
				return nil, err
			}
			ekAttrs.ECCAttributes = &types.ECCAttributes{
				Curve: curve,
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

// Reads the public area of the provided persistent TPM handle
// and returns a default set of KeyAttributes with the name,
// public area and algorithm set.
func (tpm *TPM2) KeyAttributes(
	handle tpm2.TPMHandle) (*types.KeyAttributes, error) {

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	keyPub, err := pub.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
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

	if keyPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		attrs.KeyAlgorithm = x509.RSA
	} else if keyPub.Type == tpm2.TPMAlgECC {
		attrs.KeyAlgorithm = x509.ECDSA
	} else {
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
		template.AuthPolicy = tpm.PlatformPolicyDigest()
		ekAttrs.TPMAttributes.Template = template
	}

	tpm.logger.Debugf("tpm: creating %s EK...", ekAttrs.KeyAlgorithm.String())

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
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: %s EK: 0x%x",
		ekAttrs.KeyAlgorithm.String(), primaryKey.ObjectHandle)

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
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: EK persisted to 0x%x", ekAttrs.TPMAttributes.Handle)

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: EK Hierarchy: %s", HierarchyName(hierarchy))
	tpm.logger.Debugf("tpm: EK Name: 0x%x", Encode(primaryKey.Name.Buffer))

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

	if srkAttrs.PlatformPolicy {
		template := srkAttrs.TPMAttributes.Template
		template.AuthPolicy = tpm.PlatformPolicyDigest()
		srkAttrs.TPMAttributes.Template = template
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
			tpm.logger.Error(err)
			return err
		}
		defer func() {
			if err := closer(); err != nil {
				tpm.logger.Errorf("failed to close session: %v", err)
			}
		}()

		primaryKey, err = primaryKeyCMD.Execute(tpm.transport, session)

	} else {
		primaryKey, err = primaryKeyCMD.Execute(tpm.transport)
	}
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	tpm.logger.Debugf("tpm: Created SRK: 0x%x", primaryKey.ObjectHandle)

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
			tpm.logger.Error(err)
			return err
		}
		tpm.logger.Debugf("tpm: SRK persisted to 0x%x",
			srkAttrs.TPMAttributes.Handle)

	} else {
		srkAttrs.TPMAttributes.Handle = primaryKey.ObjectHandle
	}

	// Extract the public area
	pub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	srkAttrs.KeyType = types.KeyTypeStorage
	srkAttrs.TPMAttributes.Name = primaryKey.Name
	srkAttrs.TPMAttributes.Public = *pub

	tpm.logger.Debugf("tpm: SRK Hierarchy: %s", HierarchyName(hierarchy))
	tpm.logger.Debugf("tpm: SRK Name: 0x%s", Encode(primaryKey.Name.Buffer))

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

	var hierarchyAuth, ekAuth, iakAuth, signature []byte
	var err error
	var isRSAPSS bool

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		// Check if hierarchy auth is valid (error passwords return error from String())
		_, err = ekAttrs.TPMAttributes.HierarchyAuth.String()
		if err != nil {
			return nil, err
		}
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	if ekAttrs.Password != nil {
		// Check if password is valid (error passwords return error from String())
		_, err = ekAttrs.Password.String()
		if err != nil {
			return nil, err
		}
		ekAuth = ekAttrs.Password.Bytes()
	}

	// Create IAK key attributes from platform configuration file
	policyDigest := tpm.PlatformPolicyDigest()
	iakAttrs, err := IAKAttributesFromConfig(
		ekAttrs.TPMAttributes.HierarchyAuth,
		tpm.config.IAK,
		&policyDigest)
	if err != nil {
		tpm.logger.FatalError(err)
	}
	iakAttrs.Parent = ekAttrs

	if iakAttrs.Password != nil {
		iakAuth = iakAttrs.Password.Bytes()
	}

	// Get the platform PCR bank hash algorithm
	// This must match the bank used in CreatePlatformPolicy for consistency
	pcrBankHashAlg, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}

	// Build signing scheme based on key algorithm
	// Use platform PCR bank hash algorithm for consistency with TPM PCR banks
	var inScheme tpm2.TPMTSigScheme
	if iakAttrs.KeyAlgorithm == x509.RSA {

		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
					HashAlg: pcrBankHashAlg,
				}),
		}

	} else {

		// ECDSA
		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: pcrBankHashAlg,
				},
			),
		}
	}

	// Define the AK template
	// Build template from scratch to ensure all fields are properly initialized
	// and avoid issues with shared slices from template constants
	var template tpm2.TPMTPublic
	var keyBits tpm2.TPMKeyBits
	if iakAttrs.RSAAttributes != nil && iakAttrs.RSAAttributes.KeySize > 0 {
		if iakAttrs.RSAAttributes.KeySize > math.MaxUint16 {
			return nil, ErrInvalidKeySize
		}
		keyBits = tpm2.TPMKeyBits(iakAttrs.RSAAttributes.KeySize) // #nosec G115 -- Bounds checked above
	} else {
		keyBits = 2048 // Default RSA key size
	}

	if iakAttrs.KeyAlgorithm == x509.RSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		if types.IsRSAPSS(iakAttrs.SignatureAlgorithm) {
			template = tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: pcrBankHashAlg,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Restricted:          true,
					SignEncrypt:         true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Symmetric: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgNull,
						},
						Scheme: tpm2.TPMTRSAScheme{
							Scheme: tpm2.TPMAlgRSAPSS,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgRSAPSS,
								&tpm2.TPMSSigSchemeRSAPSS{
									HashAlg: pcrBankHashAlg,
								},
							),
						},
						KeyBits:  keyBits,
						Exponent: 0, // Use default exponent (65537)
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: make([]byte, keyBits/8),
					},
				),
			}
			inScheme = tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgRSAPSS,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgRSAPSS, &tpm2.TPMSSchemeHash{
						HashAlg: pcrBankHashAlg,
					}),
			}
			isRSAPSS = true
		} else {
			template = tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: pcrBankHashAlg,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					Restricted:          true,
					SignEncrypt:         true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Symmetric: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgNull,
						},
						Scheme: tpm2.TPMTRSAScheme{
							Scheme: tpm2.TPMAlgRSASSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgRSASSA,
								&tpm2.TPMSSigSchemeRSASSA{
									HashAlg: pcrBankHashAlg,
								},
							),
						},
						KeyBits:  keyBits,
						Exponent: 0, // Use default exponent (65537)
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: make([]byte, keyBits/8),
					},
				),
			}
			inScheme = tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
						HashAlg: pcrBankHashAlg,
					}),
			}
		}

	} else if iakAttrs.KeyAlgorithm == x509.ECDSA {
		template = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: pcrBankHashAlg,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgNull,
					},
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: pcrBankHashAlg,
							},
						),
					},
					CurveID: tpm2.TPMECCNistP256,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
				},
			),
		}
		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: pcrBankHashAlg,
				},
			),
		}
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
		tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return nil, err
	}

	// Extract public area
	iakPub, err := iakPrimary.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	// Certify the new IAK primary key
	certifyCreation := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: iakHandle,
			Name:   iakPrimary.Name,
			Auth:   tpm2.PasswordAuth(ekAuth),
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

		ecDetail, err := iakPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		eccUnique, err := iakPub.Unique.ECC()
		if err != nil {
			tpm.logger.Error(err)
			return nil, err
		}
		akPublic = &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
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
	var isRSAPSS bool

	if akAttrs == nil {
		return nil, nil, ErrInvalidAKAttributes
	}
	if akAttrs.Parent == nil {
		return nil, nil, ErrInvalidEKAttributes
	}
	ekAttrs := akAttrs.Parent

	// if ekAttrs.Password != nil {
	// 	ekAuth, err = ekAttrs.Password.Bytes()
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// }

	// Create IDevID key attributes from platform configuration file
	if tpm.config.IDevID == nil {
		return nil, nil, ErrNotConfigured
	}
	policyDigest := tpm.PlatformPolicyDigest()
	idevidAttrs, err := IDevIDAttributesFromConfig(
		*tpm.config.IDevID, &policyDigest)
	if err != nil {
		return nil, nil, err
	}
	idevidAttrs.Parent = ekAttrs

	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	if akAttrs.Password != nil {
		akAuth = akAttrs.Password.Bytes()
	}

	if idevidAttrs.Password != nil {
		idevidAuth = idevidAttrs.Password.Bytes()
	}

	var idevidTemplate tpm2.TPMTPublic
	if ekAttrs.KeyAlgorithm == x509.RSA {
		if types.IsRSAPSS(idevidAttrs.SignatureAlgorithm) {
			idevidTemplate = RSAPSSIDevIDTemplate
			isRSAPSS = true
		} else {
			idevidTemplate = RSASSAIDevIDTemplate
		}
	} else if idevidAttrs.KeyAlgorithm == x509.ECDSA {
		idevidTemplate = ECCIDevIDP256Template
	}

	// TPM 2.0 Keys for Device Identity and Attestation - Section 3.10 - Key
	// Authorizations: Applications using only Policy to control key
	// administration MUST SET the adminWithPolicy attribute when creating
	// the key. When adminWithPolicy is CLEAR, the authValue may be used in
	// an HMAC session to perform Admin operations.
	if idevidAttrs.Password == nil && idevidAttrs.PlatformPolicy {
		idevidTemplate.ObjectAttributes.AdminWithPolicy = true
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
	// unique := tpm2.NewTPMUPublicID(
	// 	tpm2.TPMAlgRSA,
	// 	&tpm2.TPM2BPublicKeyRSA{
	// 		Buffer: []byte(idevidAttrs.CN),
	// 	},
	// )
	// inPub, err := primaryKeyCMD.InPublic.Contents()
	// if err != nil {
	// 	return nil, nil, err
	// }
	// inPub.Unique = unique

	primaryKey, err := primaryKeyCMD.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return nil, nil, err
	}

	// Extract public area
	idevidPub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	// Certify the new IDevID primary key using the AK to sign the
	// TPMB_Attest structure
	certify := tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(idevidAuth),
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
	if err != nil {
		return nil, nil, err
	}

	akPub, err := primaryKey.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}

	var pubKeyBytes []byte

	// Sign the attestation structure
	if akPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch

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
			tpm.logger.Error(err)
			return nil, nil, err
		}
		pubKeyBytes = rsaDER

		var rsaSig *tpm2.TPMSSignatureRSA
		if isRSAPSS {
			rsaSig, err = rspCert.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, nil, err
			}
		} else {
			rsaSig, err = rspCert.Signature.Signature.RSASSA()
			if err != nil {
				return nil, nil, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if akPub.Type == tpm2.TPMAlgECC {

		sig, err := rspCert.Signature.Signature.ECDSA()
		if err != nil {
			return nil, nil, err
		}

		ecDetail, err := idevidPub.Parameters.ECCDetail()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		eccUnique, err := idevidPub.Unique.ECC()
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

		eccDER, err := store.EncodePubKey(eccPub)
		if err != nil {
			tpm.logger.Error(err)
			return nil, nil, err
		}
		pubKeyBytes = eccDER

		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}

		asn1Sig, err := asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, nil, err
		}
		signature = asn1Sig
	}

	tpm.logger.Debug("tpm: IDevID Key Hierarchy: Endorsement")

	tpm.logger.Debugf(
		"tpm: IDevID Key persistent to handle 0x%x",
		idevidAttrs.TPMAttributes.Handle)

	tpm.logger.Debugf(
		"tpm: IDevID Key Name: %s",
		Encode(primaryKey.Name.Buffer))

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
			return errors.New("TPM transport not initialized")
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
			tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return err
	}

	return nil
}
