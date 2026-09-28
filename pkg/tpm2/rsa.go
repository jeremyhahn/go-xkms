package tpm2

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Creates a new RSA child key using the provided key attributes
func (tpm *TPM2) CreateRSA(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	overwrite bool) (*rsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidKeyAttributes
	}

	var keyUserAuth []byte
	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var private tpm2.TPM2BPrivate
	var public tpm2.TPM2BPublic

	// Get the persisted SRK
	srkHandle := keyAttrs.Parent.TPMAttributes.Handle
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided
	if keyAttrs.Password != nil {
		keyUserAuth = keyAttrs.Password.Bytes()
	}

	// Build the template for the key the caller asked for.
	//
	// The modulus size comes from the request rather than from a template
	// constant, and the algorithms involved are checked against what this TPM
	// reports through TPM2_GetCapability, so a request the device cannot serve
	// is refused by name instead of failing inside TPM2_Create.
	//
	// The scheme is left TPM_ALG_NULL for signing keys so the digest and the
	// padding are chosen per operation (TCG TPM 2.0 Library Part 3, section
	// 12.1). An RSA-PSS signature algorithm in the key attributes is the one
	// case that still pins the key, because that is what asking for a PSS-only
	// key means; see RSAPSSTemplate.
	spec := KeyTemplateSpec{
		Algorithm: x509.RSA,
		KeyBits:   DefaultRSAKeyBits,
		NameAlg:   tpm.algID,
	}
	if keyAttrs.RSAAttributes != nil && keyAttrs.RSAAttributes.KeySize > 0 {
		spec.KeyBits = uint16(keyAttrs.RSAAttributes.KeySize)
	}

	// A modulus size a caller actually named is held to the project's
	// RSAKeySize2048 floor here, before it ever reaches KeyTemplate: that
	// function's own definedRSAKeyBits check answers a different question
	// (which sizes TPM 2.0 defines at all, which still includes 1024) and
	// is a device-capability concern, not this project's minimum-strength
	// policy. Leaving RSAKeySize2048 unenforced here let a caller obtain a
	// 1024-bit key straight from CreateRSA, independent of whatever the RPC
	// service validated (go-xkms#1204).
	if err := types.ValidateRSAKeySize(int(spec.KeyBits)); err != nil {
		return nil, err
	}

	if keyAttrs.KeyType == types.KeyTypeEncryption {
		// A decryption key carries the decrypt attribute rather than
		// signEncrypt, and stays unrestricted so TPM2_RSA_Decrypt may be used
		// on it with a caller-supplied scheme.
		spec.Sign = false
		spec.Decrypt = true
	} else if types.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
		spec.Scheme = tpm2.TPMAlgRSAPSS
		spec.SchemeHash = tpm.algID
	}

	rsaTemplate, err := tpm.KeyTemplate(spec)
	if err != nil {
		tpm.logger.Error("failed to build RSA key template",
			slog.String("error", err.Error()),
			slog.String("cn", keyAttrs.CN))
		return nil, err
	}

	// Attach platform PCR policy digest if configured.
	//
	// The digest is computed from a captured pin rather than straight from live
	// PCRs. The value is identical, but capturing it lets the record written
	// after the blobs are saved name the exact PolicyPCR branch this key's
	// AuthPolicy covers, so the key's PIN branch can still reproduce the
	// PolicyOR digest once the platform measurements change.
	var policyPin *store.PlatformPolicyPin

	if keyAttrs.PlatformPolicy {
		pin, err := tpm.capturePlatformPolicyPin()
		if err != nil {
			return nil, err
		}
		policyDigest, err := platformPolicyDigestFromPin(pin)
		if err != nil {
			return nil, err
		}
		rsaTemplate.AuthPolicy = policyDigest
		policyPin = pin
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	// The sensitive area carries the new key's authValue, so it is
	// encrypted on its way into the TPM by a salted session of its own: the
	// parent's authorization may be a policy session, which cannot carry it.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptIn)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "key creation encryption")

	response, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyUserAuth,
				},
			},
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		if errors.Is(err, ErrCommandNotSupported) {
			// Perform create and load using logacy command sequence
			createRsp, err := tpm2.Create{
				ParentHandle: tpm2.AuthHandle{
					Handle: srkHandle,
					Name:   srkName,
					Auth:   session,
				},
				InPublic: tpm2.New2B(rsaTemplate),
				InSensitive: tpm2.TPM2BSensitiveCreate{
					Sensitive: &tpm2.TPMSSensitiveCreate{
						UserAuth: tpm2.TPM2BAuth{
							Buffer: keyUserAuth,
						},
					},
				},
			}.Execute(tpm.transport, encSession)
			if err != nil {
				return nil, err
			}

			session2, closer, err := tpm.CreateSession(keyAttrs)
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := closer(); err != nil {
					tpm.logger.Error("failed to close key session", slog.String("error", err.Error()))
				}
			}()

			loadResponse, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: keyAttrs.Parent.TPMAttributes.Handle,
					Name:   keyAttrs.Parent.TPMAttributes.Name,
					Auth:   session2,
				},
				InPrivate: tpm2.TPM2BPrivate{
					Buffer: createRsp.OutPrivate.Buffer,
				},
				InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](createRsp.OutPublic.Bytes()),
			}.Execute(tpm.transport)
			if err != nil {
				tpm.logger.Error("failed to load RSA key", slog.String("error", err.Error()), slog.String("cn", keyAttrs.CN))
				return nil, err
			}
			handle = loadResponse.ObjectHandle
			name = loadResponse.Name
			private = createRsp.OutPrivate
			public = createRsp.OutPublic
		} else {
			tpm.logger.Error("failed to create RSA key", slog.String("error", err.Error()))
			return nil, err
		}
	} else {
		handle = response.ObjectHandle
		name = response.Name
		private = response.OutPrivate
		public = response.OutPublic
	}

	// TPM2_CreateLoaded -- and the TPM2_Create plus TPM2_Load fallback above --
	// leave the new object LOADED in transient TPM memory (TCG TPM 2.0 Library
	// Part 3, sections 12.9 and 12.2). A TPM offers only a handful of transient
	// object slots, so the handle has to be released on every path out of this
	// function, the successful one included.
	//
	// Nothing after this point needs the object to stay loaded: what is
	// persisted is the public/private blob pair, and every later operation on
	// this key reloads those under the SRK through LoadKeyPair. Holding the
	// handle open past the return stranded one object slot per key created --
	// the caller was told it owned the handle but no caller ever flushed it --
	// and a TPM with three slots then failed every subsequent TPM2_Load with
	// TPM_RC_OBJECT_MEMORY, including for unrelated keys that had been working.
	//
	// This mirrors CreateECDSA, which has always released its handle here.
	defer tpm.Flush(handle)

	tpm.logger.Debug("RSA key loaded to transient handle", slog.String("handle", Encode([]byte{byte(handle >> 24), byte(handle >> 16), byte(handle >> 8), byte(handle)})))
	tpm.logger.Debug("RSA key name", slog.String("name", Encode(name.Buffer)))
	tpm.logger.Debug("RSA parent (SRK) name", slog.String("name", Encode(srkName.Buffer)))

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &types.TPMAttributes{
			Name:   name,
			Handle: handle,
		}
	} else {
		keyAttrs.TPMAttributes.Name = name
		keyAttrs.TPMAttributes.Handle = handle
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(keyAttrs, private, public, backend, overwrite); err != nil {
		return nil, err
	}

	// Record the platform policy pin beside the blobs it describes. Without it
	// this key's PIN branch could only be satisfied while the platform PCR
	// still held the value it holds right now.
	if policyPin != nil {
		if err := tpm.recordKeyPolicyPin(
			keyAttrs, backend, policyPin, overwrite); err != nil {

			return nil, err
		}
	}

	pub, err := public.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public contents", slog.String("error", err.Error()))
		return nil, err
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error("failed to get RSA detail", slog.String("error", err.Error()))
		return nil, err
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		tpm.logger.Error("failed to get RSA unique", slog.String("error", err.Error()))
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error("failed to create RSA public key", slog.String("error", err.Error()))
		return nil, err
	}

	return rsaPub, nil
}

// func (tpm *TPM2) RSADecrypt(
// 	keyAttrs *types.KeyAttributes, blob []byte) ([]byte, error) {
// 	response, err := tpm2.RSADecrypt{
// 		KeyHandle: tpm2.NamedHandle{
// 			Handle: keyAttrs.TPMAttributes.Handle,
// 			Name:   keyAttrs.TPMAttributes.Name,
// 			// Auth:   tpm2.PasswordAuth(keyAuth),
// 		},
// 		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: blob},
// 		InScheme: tpm2.TPMTRSADecrypt{
// 			Scheme: tpm2.TPMAlgOAEP,
// 			Details: tpm2.NewTPMUAsymScheme(
// 				tpm2.TPMAlgOAEP,
// 				&tpm2.TPMSEncSchemeOAEP{
// 					HashAlg: tpm2.TPMAlgSHA256,
// 				},
// 			),
// 		},
// 	}.Execute(tpm.transport)
// 	if err != nil {
// 		tpm.logger.Error("RSA decrypt failed", slog.String("error", err.Error()))
// 		return nil, err
// 	}
// 	return response.Message.Buffer, nil
// }

// Performs RSA decryption. The recovered plaintext leaves the TPM encrypted
// under a salted session.
func (tpm *TPM2) RSADecrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, blob []byte) ([]byte, error) {
	encSession, closeEncSession, err := tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "RSADecrypt encryption")

	response, err := tpm2.RSADecrypt{
		KeyHandle: tpm2.NamedHandle{
			Handle: handle,
			Name:   name,
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: blob},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		tpm.logger.Error("RSA decrypt failed", slog.String("error", err.Error()))
		return nil, err
	}
	return response.Message.Buffer, nil
}

// Performs RSA encryption
func (tpm *TPM2) RSAEncrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, message []byte) ([]byte, error) {

	response, err := tpm2.RSAEncrypt{
		KeyHandle: tpm2.NamedHandle{
			Handle: handle,
			Name:   name,
		},
		Message: tpm2.TPM2BPublicKeyRSA{Buffer: message},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("RSA encrypt failed", slog.String("error", err.Error()))
		return nil, err
	}
	return response.OutData.Buffer, nil
}
