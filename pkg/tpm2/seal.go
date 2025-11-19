package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/crypto/aesgcm"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Creates a new key under the provided Storage Root Key (SRK),
// optionally sealing a provided secret to the current Platform
// Golden Integrity Measurements. If a secret is not provided, a
// random AES-256 key will be generated. If the
// HandleType is marked as TPMHTTransient, the created objects handles
// are left unflushed and the caller is responsible for flushing it when
// done.
func (tpm *TPM2) Seal(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	overwrite bool) (*tpm2.CreateResponse, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
	}

	var session tpm2.Session
	var closer func() error
	var err error
	var keyUserAuth, secretBytes []byte

	srkHandle := keyAttrs.Parent.TPMAttributes.Handle.(tpm2.TPMHandle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided
	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
		keyUserAuth = keyAttrs.Password.Bytes()
	}

	template := KeyedHashTemplate
	template.NameAlg = tpm.algID

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &types.TPMAttributes{
			Template: template,
		}
	}
	if keyAttrs.TPMAttributes.Template == nil || keyAttrs.TPMAttributes.Template.(tpm2.TPMTPublic).Type == 0 {
		keyAttrs.TPMAttributes.Template = template
	}

	if keyAttrs.PlatformPolicy {
		// Attach platform PCR policy digest if configured
		tpl := keyAttrs.TPMAttributes.Template.(tpm2.TPMTPublic)
		tpl.AuthPolicy = tpm.PlatformPolicyDigest()
		keyAttrs.TPMAttributes.Template = tpl
	}

	if keyAttrs.Secret == nil {
		tpm.logger.Infof("Generating %s HMAC seal secret", keyAttrs.CN)
		secretBytes = aesgcm.NewAESGCM(tpm).GenerateKey()
		if keyAttrs.PlatformPolicy {
			// keyAttrs.Secret = NewPlatformSecret(tpm, keyAttrs)
			keyAttrs.Secret = store.NewClearPassword(secretBytes)
		} else {
			keyAttrs.Secret = store.NewClearPassword(secretBytes)
		}
	} else {
		secretBytes = keyAttrs.Secret.Bytes()
		if secretBytes == nil {
			return nil, store.ErrInvalidKeyedHashSecret
		}
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf(
			"tpm: sealing %s HMAC secret: %s",
			keyAttrs.CN, secretBytes)
	}

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Create a new seal key under the persisted SRK
	sealKeyResponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(keyAttrs.TPMAttributes.Template.(tpm2.TPMTPublic)),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyUserAuth,
				},
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{
						Buffer: secretBytes,
					},
				),
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	if err := closer(); err != nil {
		tpm.logger.Errorf("failed to close session: %v", err)
	} // tpm2.Create CreateSession

	// Create a new tpm2.Load session
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer func() { _ = closer() }()

	var loadResponse *tpm2.LoadResponse
	loadResponse, err = tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic:  sealKeyResponse.OutPublic,
		InPrivate: sealKeyResponse.OutPrivate,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: %s key loaded to transient handle 0x%x",
		keyAttrs.CN, loadResponse.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: %s key Name: %s",
		keyAttrs.CN, Encode(loadResponse.Name.Buffer))

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &types.TPMAttributes{
			Name:   loadResponse.Name,
			Handle: loadResponse.ObjectHandle,
		}
	} else {
		keyAttrs.TPMAttributes.Name = loadResponse.Name
		keyAttrs.TPMAttributes.Handle = loadResponse.ObjectHandle
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(
		keyAttrs,
		sealKeyResponse.OutPrivate,
		sealKeyResponse.OutPublic,
		backend,
		overwrite); err != nil {

		return nil, err
	}

	return sealKeyResponse, nil
}

// Returns sealed data for a keyed hash using the platform
// PCR Policy Session to satisfy the TPM to release the secret.
func (tpm *TPM2) Unseal(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) ([]byte, error) {

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
	}

	var session tpm2.Session
	var closer func() error
	var err error

	// Create session from parent key attributes
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		if closer != nil {
			if err := closer(); err != nil {
				tpm.logger.Errorf("failed to close: %v", err)
			}
		}
		tpm.logger.Error(err)
		return nil, err
	}

	// Not using defer closer() here because the session needs
	// to be flushed as soon as possible to prevent too many
	// sessions open at one time causing TPM_RC_SESSION_MEMORY

	// Load the key pair from disk using the parent session
	sealKey, err := tpm.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		if closer != nil {
			if err := closer(); err != nil {
				tpm.logger.Errorf("failed to close: %v", err)
			}
		}
		tpm.logger.Error(err)
		return nil, err
	}
	if err := closer(); err != nil {
		tpm.logger.Errorf("failed to close: %v", err)
	}
	defer tpm.Flush(sealKey.ObjectHandle)

	// Create key session
	session2, closer2, err2 := tpm.CreateKeySession(keyAttrs)
	defer func() { _ = closer2() }()
	if err2 != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Unseal the data using the key session
	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
			Auth:   session2,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Set TPM attributes
	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &types.TPMAttributes{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
		}
	} else {
		keyAttrs.TPMAttributes.Name = sealKey.Name
		keyAttrs.TPMAttributes.Handle = sealKey.ObjectHandle
	}

	secret := unseal.OutData.Buffer

	if tpm.debugSecrets {
		tpm.logger.Debugf(
			"Retrieved sealed HMAC secret: %s:%s",
			keyAttrs.CN, secret)
	}

	return secret, nil
}
