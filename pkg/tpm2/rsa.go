package tpm2

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Creates a new RSA child key using the provided key attributes
func (tpm *TPM2) CreateRSA(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	overwrite bool) (*rsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidKeyAttributes
	}

	// var keyUserAuth, secretBytes []byte
	var keyUserAuth []byte
	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var private tpm2.TPM2BPrivate
	var public tpm2.TPM2BPublic

	// Get the persisted SRK
	srkHandle := keyAttrs.Parent.TPMAttributes.Handle.(tpm2.TPMHandle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided
	if keyAttrs.Password != nil {
		keyUserAuth = keyAttrs.Password.Bytes()
	}

	// Create new RSA key under the SRK, optionally sealing a secret
	// protected by the platform auth policy that requires the platform
	// PCR value with the Golden Integrity Measurements to release.
	rsaTemplate := RSASSATemplate
	rsaTemplate.NameAlg = tpm.algID

	if types.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
		rsaTemplate = RSAPSSTemplate
		rsaTemplate.NameAlg = tpm.algID
	}

	// For encryption keys, set Decrypt attribute instead of SignEncrypt
	if keyAttrs.KeyType == types.KeyTypeEncryption {
		rsaTemplate.ObjectAttributes.Decrypt = true
		rsaTemplate.ObjectAttributes.SignEncrypt = false
		// Encryption keys must be unrestricted
		rsaTemplate.ObjectAttributes.Restricted = false
		// Set scheme to Null for unrestricted decryption
		// Use standard 2048-bit key size (same as templates default)
		rsaTemplate.Parameters = tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		)
	}

	// Attach platform PCR policy digest if configured
	if keyAttrs.PlatformPolicy {
		rsaTemplate.AuthPolicy = tpm.PlatformPolicyDigest()
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer() }()

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
	}.Execute(tpm.transport)
	if err != nil {
		if err == ErrCommandNotSupported {
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
			}.Execute(tpm.transport)
			if err != nil {
				return nil, err
			}

			session2, closer, err := tpm.CreateSession(keyAttrs)
			if err != nil {
				return nil, err
			}
			defer func() { _ = closer() }()

			loadResponse, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: keyAttrs.Parent.TPMAttributes.Handle.(tpm2.TPMHandle),
					Name:   keyAttrs.Parent.TPMAttributes.Name.(tpm2.TPM2BName),
					Auth:   session2,
				},
				InPrivate: tpm2.TPM2BPrivate{
					Buffer: createRsp.OutPrivate.Buffer,
				},
				InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](createRsp.OutPublic.Bytes()),
			}.Execute(tpm.transport)
			if err != nil {
				tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
				return nil, err
			}
			handle = loadResponse.ObjectHandle
			name = loadResponse.Name
			private = createRsp.OutPrivate
			public = createRsp.OutPublic
			// Caller is responsible for flushing the handle
		} else {
			tpm.logger.Error(err)
			return nil, err
		}
	} else {
		handle = response.ObjectHandle
		name = response.Name
		private = response.OutPrivate
		public = response.OutPublic
		// Caller is responsible for flushing the handle
	}

	tpm.logger.Debugf("tpm: RSA Key loaded to transient handle 0x%x", handle)
	tpm.logger.Debugf("tpm: RSA Key Name: %s", Encode(name.Buffer))
	tpm.logger.Debugf("tpm: RSA Parent (SRK) Name: %s", Encode(srkName.Buffer))

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

	pub, err := public.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error(err)
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
// 		tpm.logger.Error(err)
// 		return nil, err
// 	}
// 	return response.Message.Buffer, nil
// }

// Performs RSA decryption
func (tpm *TPM2) RSADecrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, blob []byte) ([]byte, error) {
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
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
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
		tpm.logger.Error(err)
		return nil, err
	}
	return response.OutData.Buffer, nil
}
