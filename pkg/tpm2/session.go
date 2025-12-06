package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Creates an unsalted, unauthenticated HMAC session with the TPM. If
// session encryption is enabled in the platform configuration file,
// the TPM <-> CPU bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMAC(auth []byte) tpm2.Session {
	if tpm.config.EncryptSession {
		tpm.logger.Debugf(
			"tpm: creating unauthenticated, unsalted, encrypted HMAC session")
		return tpm2.HMAC(
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			// AESEncryption uses the session to encrypt the first parameter sent to/from
			// the TPM.
			// Note that only commands whose first command/response parameter is a 2B can
			// support session encryption.
			// EncryptIn specifies a decrypt session.
			// EncryptOut specifies an encrypt session.
			// EncryptInOut specifies a decrypt+encrypt session
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut))
	}
	tpm.logger.Debugf(
		"tpm: creating unauthenticated, unsalted, UNencrypted HMAC session")

	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Password(auth))
}

// Creates an authenticated, unsalted HMAC session with the TPM. If session
// encryption is enabled in the platform configuration file, the TPM <-> CPU
// bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMACSession(auth []byte) (s tpm2.Session, close func() error, err error) {
	if tpm.config.EncryptSession {
		tpm.logger.Debug("tpm: creating encrypted HMAC session")
		if tpm.debugSecrets {
			tpm.logger.Debugf("tpm: HMAC session auth: %s", auth)
		}
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut))
	}
	tpm.logger.Debugf("tpm: creating UNencrypted HMAC session")
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: HMAC session auth: %s", auth)
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(auth))
}

// Creates an authenticated, salted HMAC session with the TPM. If session
// encryption is enabled in the platform configuration file, the TPM <-> CPU
// bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMACSaltedSession(
	handle tpm2.TPMHandle,
	pub tpm2.TPMTPublic,
	auth []byte) (s tpm2.Session, close func() error, err error) {

	if tpm.config.EncryptSession {
		tpm.logger.Debugf(
			"tpm: creating salted, encrypted HMAC session with primary key: 0x%x",
			handle)
		if tpm.debugSecrets {
			tpm.logger.Debugf("tpm: HMAC session auth: %s", auth)
		}
		return tpm2.HMACSession(
			tpm.transport,
			tpm2.TPMAlgSHA256,
			16,
			tpm2.Auth(auth),
			tpm2.AESEncryption(
				128,
				tpm2.EncryptInOut),
			tpm2.Salted(handle, pub))
	}
	tpm.logger.Debugf(
		"tpm: creating salted, UNencrypted HMAC session with key: 0x%x",
		handle)
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: HMAC session auth: %s", auth)
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		[]tpm2.AuthOption{tpm2.Auth(auth)}...)
}

// Creates a new platform policy session with the platform PCR selected
// using the Owner child key created during platform provisioning under the
// SRK. Returns the policy session along with a session closer that needs to
// be called when finished with the session.
func (tpm *TPM2) PlatformPolicySession() (tpm2.Session, func() error, error) {

	var closer func() error
	var err error

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, nil, err
	}

	// Create PCR selection using "platform-pcr" defined in the platform
	// configuration file TPM section.
	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      hashAlgID,
			PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
		}},
	}

	digest, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return nil, nil, err
	}

	// Create the policy session
	session, closer, err := tpm2.PolicySession(
		tpm.transport, hashAlgID, 16, []tpm2.AuthOption{}...)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}

	// Create the PCR policy
	_, err = tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		// Clean up session before returning error
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Errorf("Failed to close session after PolicyPCR error: %v", closeErr)
		}
		return nil, nil, err
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		// Clean up session before returning error
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Errorf("Failed to close session after PolicyGetDigest error: %v", closeErr)
		}
		return nil, nil, err
	}

	// tpm.logger.Debugf("tpm: platform PCR policy session digest: %x", digest)
	// tpm.logger.Debugf("tpm: pgd.PolicyDigest.Buffer: %x", pgd.PolicyDigest.Buffer)

	tpm.policyDigest = pgd.PolicyDigest

	return session, closer, nil
}

// Creates a one-time use TPM nonce session
func (tpm *TPM2) NonceSession(hierarchyAuth types.Password) (tpm2.Session, func() error, error) {

	var auth []byte
	if hierarchyAuth != nil {
		auth = hierarchyAuth.Bytes()
	}

	session, closer, err := tpm2.PolicySession(
		tpm.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, err
	}

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(auth),
		},
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		// Clean up session before returning error
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Errorf("Failed to close session after PolicySecret error: %v", closeErr)
		}
		return nil, nil, err
	}

	return session, closer, nil
}

// Returns an authorization session for a key based on the provided parent
// key attributes and platform configuration file. If the parent PlatformPolicy
// is true, a PCR policy session is returned. If PlatformPolicy is false,
// a password authorization session is returned. If a password has not been
// defined, an empty password authorization session is returned. If PlatformPolicy
// is false and encryption is enabled in the platform configuration file, a salted,
// encrypted session is created using the EK. This function returns a session
// closer function that needs to be called to close the session when complete.
func (tpm *TPM2) CreateSession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var err error
	var parentAuth []byte

	closer := func() error { return nil }

	if keyAttrs.Parent == nil {
		return tpm.CreateKeySession(keyAttrs)
	}

	// Extract the parent authorization password if the parent doesn't have
	// a platform PCR policy applied
	if keyAttrs.Parent.Password != nil && !keyAttrs.Parent.PlatformPolicy {
		parentAuth = keyAttrs.Parent.Password.Bytes()
	}

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle
	_, parentPub, err := tpm.ReadHandle(parentHandle)
	if err != nil {
		return session, closer, err
	}

	if keyAttrs.Parent.PlatformPolicy {

		// Create platform PCR policy session
		session, closer, err = tpm.PlatformPolicySession()
		if err != nil {
			return session, closer, err
		}
		// dont forget to call closer() when finished
		// defer closer()
		tpm.logger.Debugf(
			"tpm: created platform policy session for %s", keyAttrs.CN)

		if err != nil {
			return session, closer, err
		}
		return session, closer, nil
	}

	if tpm.config.EncryptSession {

		// var ekAuth []byte
		// ekAttrs := tpm.EKAttributes()
		// if ekAttrs.Password != nil && !ekAttrs.PlatformPolicy {
		// 	ekAuth, err = ekAttrs.Password.Bytes()
		// 	if err != nil {
		// 		return session, nil, err
		// 	}
		// }

		// // Create salted (encrypted?) session using EK
		// session, closer, err = tpm.HMACSaltedSession(
		// 	ekAttrs.TPMAttributes.Handle,
		// 	ekAttrs.TPMAttributes.Public,
		// 	ekAuth)
		// if err != nil {
		// 	tpm.logger.Error(err)
		// 	return session, nil, err
		// }

		// Create salted (encrypted?) session using parent (EK)
		session, closer, err = tpm.HMACSaltedSession(
			parentHandle,
			parentPub,
			parentAuth)
		if err != nil {
			tpm.logger.Error(err)
			return session, closer, err
		}
		// dont forget to call closer() when finished
		// defer closer()
		return session, closer, nil
	}

	session = tpm2.PasswordAuth(parentAuth)
	return session, closer, nil
}

// Returns an authorization session for a child key based on the provided
// key attributes. If the child PlatformPolicy is true, a PCR policy session
// is returned with a closer function that needs to be called to close the
// session when complete. If PlatformPolicy is false, a password authorization
// session is returned instead. If a password has not been defined,
// an empty password authorization session is returned. This function returns
// a session closer function that needs to be called to close the session when
// complete.
func (tpm *TPM2) CreateKeySession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var closer func() error
	var err error
	var keyAuth []byte

	// if keyAttrs.PlatformPolicy && keyAttrs.Parent.PlatformPolicy {
	if keyAttrs.PlatformPolicy {
		session, closer, err = tpm.PlatformPolicySession()
		if err != nil {
			return session, closer, err
		}
		// defer closer()
	} else {

		if keyAttrs.Password != nil {
			// Check if password is valid (error passwords return error from String())
			_, err = keyAttrs.Password.String()
			if err != nil {
				return nil, nil, err
			}
			keyAuth = keyAttrs.Password.Bytes()
			session = tpm2.PasswordAuth(keyAuth)
		} else {
			session = tpm2.PasswordAuth(nil)
		}
	}

	if closer == nil {
		closer = func() error { return nil }
	}

	return session, closer, nil
}

// Loads the requested TPMAlgKeyedHash encrypted public and private
// blobs from blob storage. The returned handle must be closed when
// finished to prevent memory leaks / exhaustion.
func (tpm *TPM2) LoadKeyPair(
	keyAttrs *types.KeyAttributes,
	session *tpm2.Session,
	backend store.KeyBackend) (*tpm2.LoadResponse, error) {

	var auth []byte

	// Use custom backend if provided, otherwise use the
	// default platform backend passed in during instantiation
	if backend == nil {
		backend = tpm.backend
	}

	// Load the public and private area blobs
	priv, err := backend.Get(keyAttrs, store.FSEXT_PRIVATE_BLOB)
	if err != nil {
		tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
		return nil, err
	}
	pub, err := backend.Get(keyAttrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
		return nil, err
	}

	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
		auth = keyAttrs.Password.Bytes()
	}

	// Create basic session if not provided
	if session == nil {
		hmac := tpm.HMAC(auth)
		session = &hmac
	}

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle
	parentName := keyAttrs.Parent.TPMAttributes.Name

	tpm.logger.Debugf(
		"tpm: loading key pair, parent handle: 0x%x",
		parentHandle)

	tpm.logger.Debugf(
		"tpm: loading key pair, parent name: 0x%s",
		Encode(parentName.Buffer))

	// Load the public and private areas into the TPM
	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   parentName,
			Auth:   *session,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: priv,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](pub),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
		return nil, err
	}
	// defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debugf("tpm: loaded key pair 0x%x", loadResponse.ObjectHandle)

	return loadResponse, nil
}

// LoadKeyPairFromBlobs loads a key pair from provided public and private blobs
// instead of reading from backend storage. This enables loading keys from in-memory
// data (e.g., blobs loaded from EFI partition files during boot).
//
// This is similar to LoadKeyPair but uses provided blobs instead of reading from storage.
func (tpm *TPM2) LoadKeyPairFromBlobs(
	keyAttrs *types.KeyAttributes,
	session *tpm2.Session,
	tpmPublic, tpmPrivate []byte) (*tpm2.LoadResponse, error) {

	var auth []byte

	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
		auth = keyAttrs.Password.Bytes()
	}

	// Create basic session if not provided
	if session == nil {
		hmac := tpm.HMAC(auth)
		session = &hmac
	}

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle
	parentName := keyAttrs.Parent.TPMAttributes.Name

	tpm.logger.Debugf(
		"tpm: loading key pair from blobs, parent handle: 0x%x",
		parentHandle)

	tpm.logger.Debugf(
		"tpm: loading key pair from blobs, parent name: 0x%s",
		Encode(parentName.Buffer))

	// Load the public and private areas into the TPM
	loadResponse, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   parentName,
			Auth:   *session,
		},
		InPrivate: tpm2.TPM2BPrivate{
			Buffer: tpmPrivate,
		},
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](tpmPublic),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Errorf("failed to load key pair from blobs: %s: %v", keyAttrs.CN, err)
		return nil, err
	}

	tpm.logger.Debugf("tpm: loaded key pair from blobs 0x%x", loadResponse.ObjectHandle)

	return loadResponse, nil
}

// Saves the requested TPMAlgKeyedHash encrypted public and private
// blobs to the blob store.
func (tpm *TPM2) SaveKeyPair(
	keyAttrs *types.KeyAttributes,
	outPrivate tpm2.TPM2BPrivate,
	outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic],
	backend store.KeyBackend,
	overwrite bool) error {

	tpm.logger.Debugf("tpm: saving key pair: %s", keyAttrs.CN)

	if backend == nil {
		backend = tpm.backend
	}
	err := backend.Save(keyAttrs, outPrivate.Buffer, store.FSEXT_PRIVATE_BLOB, overwrite)
	if err != nil {
		return err
	}
	err = backend.Save(keyAttrs, outPublic.Bytes(), store.FSEXT_PUBLIC_BLOB, overwrite)
	if err != nil {
		return err
	}
	return nil
}

// Deletes the requested encrypted public and private blobs from
// the blob store.
func (tpm *TPM2) DeleteKeyPair(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) error {

	tpm.logger.Debugf("tpm: deleting key pair: %s", keyAttrs.CN)
	if backend == nil {
		backend = tpm.backend
	}
	err := backend.Delete(keyAttrs)
	if err != nil {
		return err
	}
	return nil
}

// // Saves a key to an encrypted context file only readable by this TPM
// func (tpm *TPM2) saveContext(keyAttrs *types.KeyAttributes) error {
// 	response, err := tpm2.ContextSave{
// 		SaveHandle: keyAttrs.TPMAttributes.Handle,
// 	}.Execute(tpm.transport)
// 	if err != nil {
// 		tpm.logger.Error(err)
// 		return err
// 	}
// 	err = tpm.backend.Save(
// 		keyAttrs, response.Context.ContextBlob.Buffer, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error(err)
// 		return err
// 	}
// 	return nil
// }

// // Loads an encrypted context file only readable by this TPM
// func (tpm *TPM2) loadContext(keyAttrs *types.KeyAttributes) ([]byte, error) {
// 	ctx, err := tpm.backend.Get(keyAttrs, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error(err)
// 		return nil, err
// 	}
// 	return ctx, nil
// }
