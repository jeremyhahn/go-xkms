package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Creates a new ECDSA child key using the provided key attributes
func (tpm *TPM2) CreateECDSA(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	overwrite bool) (*ecdsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
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

	// Get the key password
	if keyAttrs.Password != nil {
		keyUserAuth = keyAttrs.Password.Bytes()
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Errorf("failed to close session: %v", err)
		}
	}()

	// Select the appropriate ECC template based on the curve
	eccTemplate := ECCP256Template
	if keyAttrs.ECCAttributes != nil && keyAttrs.ECCAttributes.Curve != nil {
		curveName := keyAttrs.ECCAttributes.Curve.Params().Name
		switch curveName {
		case elliptic.P256().Params().Name:
			eccTemplate = ECCP256Template
		case elliptic.P384().Params().Name:
			eccTemplate = ECCP384Template
		case elliptic.P521().Params().Name:
			eccTemplate = ECCP521Template
		default:
			tpm.logger.Debugf("tpm: unsupported curve %s, defaulting to P-256", curveName)
			eccTemplate = ECCP256Template
		}
	}

	eccTemplate.NameAlg = tpm.algID

	if keyAttrs.PlatformPolicy {
		// Attach platform PCR policy digest if configured
		eccTemplate.AuthPolicy = tpm.PlatformPolicyDigest()
	}

	// Create ECC key
	response, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
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
				InPublic: tpm2.New2B(eccTemplate),
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

			session2, closer, err := tpm.CreateKeySession(keyAttrs)
			if err != nil {
				return nil, err
			}
			defer func() {
				if err := closer(); err != nil {
					tpm.logger.Errorf("failed to close key session: %v", err)
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
				tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
				return nil, err
			}
			handle = loadResponse.ObjectHandle
			name = loadResponse.Name
			private = createRsp.OutPrivate
			public = createRsp.OutPublic
			defer tpm.Flush(loadResponse.ObjectHandle)
		} else {
			tpm.logger.Error(err)
			return nil, err
		}
	} else {
		handle = response.ObjectHandle
		name = response.Name
		private = response.OutPrivate
		public = response.OutPublic
		defer tpm.Flush(response.ObjectHandle)
	}

	tpm.logger.Debugf("tpm: ECC Key loaded to transient handle 0x%x", handle)
	tpm.logger.Debugf("tpm: ECC Key Name: %s", Encode(name.Buffer))
	tpm.logger.Debugf("tpm: ECC Parent (SRK) Name: %s", Encode(srkName.Buffer))

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

	outPub, err := public.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	curve, err := ecDetail.CurveID.Curve()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	eccPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	return eccPub, nil
}
