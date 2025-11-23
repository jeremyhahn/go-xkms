package tpm2

import (
	"errors"

	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

type PlatformPassword struct {
	backend  store.KeyBackend
	logger   *logging.Logger
	tpm      TrustedPlatformModule
	keyAttrs *types.KeyAttributes
	types.Password
}

// Just-in-time password retrieval of TPM keyed hash (HMAC) objects
// used for password storage. This object keeps the password sealed
// to  the TPM and retrieves it when the String() or Bytes() method
// is called, using the platform PCR authorization session policy.
func NewPlatformPassword(
	logger *logging.Logger,
	tpm TrustedPlatformModule,
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) types.Password {

	return &PlatformPassword{
		backend:  backend,
		logger:   logger,
		tpm:      tpm,
		keyAttrs: keyAttrs}
}

// Returns the secret as a string
func (p *PlatformPassword) String() (string, error) {
	secret := p.Bytes()
	if secret == nil {
		return "", errors.New("failed to retrieve platform password")
	}
	return string(secret), nil
}

// Returns the secret as bytes
func (p *PlatformPassword) Bytes() []byte {
	if p.keyAttrs.Debug {
		p.logger.Debugf(
			"keystore/tpm2: retrieving platform password: %s",
			p.keyAttrs.CN)
	}
	// Copy the key attributes to a new "secret attributes"
	// object so it can be loaded from the backend using the
	// key type
	secretAttrs := *p.keyAttrs
	secretAttrs.KeyType = types.KeyTypeHMAC
	data, err := p.tpm.Unseal(&secretAttrs, p.backend)
	if err != nil {
		// Log the error and return nil - this matches the common.Password interface
		// which doesn't allow Bytes() to return an error
		p.logger.Errorf("keystore/tpm2: failed to unseal platform password: %v", err)
		return nil
	}
	return data
}

// Clear is a no-op for PlatformPassword since the password is sealed in the TPM
// and retrieved on-demand. There's no in-memory password to clear.
func (p *PlatformPassword) Clear() {
	// No-op: password is sealed in TPM, not stored in memory
}

// Seals a password to the TPM as a keyed hash object. If the key
// attributes have the platform policy defined, a PlatformSecret is
// returned, otherwise, RequiredPassword which returns ErrPasswordRequired
// when it's member methods are invoked. If the provided password is the
// default platform password, a random 32 byte (AES-256) key is generated.
func (p *PlatformPassword) Create() error {

	var passwd []byte
	if p.keyAttrs.Password == nil {
		p.keyAttrs.Password = store.NewClearPassword(nil)
		return nil
	} else {
		// Check if password is valid (error passwords return error from String())
		_, err := p.keyAttrs.Password.String()
		if err != nil {
			return err
		}
		passwd = p.keyAttrs.Password.Bytes()
		if string(passwd) == store.DEFAULT_PASSWORD {
			passwd = make([]byte, 32) // AES-256 key
			rng := p.tpm.RandomSource()
			if _, err := rng.Read(passwd); err != nil {
				return err
			}
			p.keyAttrs.Password = store.NewClearPassword(passwd)
		}
	}
	if _, err := p.tpm.Seal(p.keyAttrs, p.backend, false); err != nil {
		return err
	}
	if p.keyAttrs.PlatformPolicy {
		p.keyAttrs.Password = p
	} else {
		p.keyAttrs.Password = store.NewRequiredPassword()
	}
	return nil
}
