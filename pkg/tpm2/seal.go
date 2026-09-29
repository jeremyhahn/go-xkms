package tpm2

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealKeyInternal creates a new key under the provided Storage Root Key (SRK),
// optionally sealing a provided secret to the current Platform
// Golden Integrity Measurements. If a secret is not provided, a
// random AES-256 key will be generated. If the
// HandleType is marked as TPMHTTransient, the created objects handles
// are left unflushed and the caller is responsible for flushing it when
// done.
//
// This is an internal method. Use Seal() for the public types.Sealer interface.
func (tpm *TPM2) sealKeyInternal(
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

	srkHandle := keyAttrs.Parent.TPMAttributes.Handle
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided.
	//
	// This applies under PlatformPolicy too. The platform policy is a PolicyOR
	// of PolicyPCR and PolicyAuthValue, and CreateKeySession takes the
	// PolicyAuthValue branch whenever the key carries a password. That branch
	// can only be satisfied by an object that actually has the auth value, so
	// skipping it here (the previous "&& !keyAttrs.PlatformPolicy") sealed the
	// object with empty auth and made the PIN fallback structurally impossible:
	// every password unseal returned TPM_RC_AUTH_FAIL and incremented the
	// dictionary-attack counter, eventually locking the TPM out.
	if keyAttrs.Password != nil {
		keyUserAuth = keyAttrs.Password.Bytes()
	}

	template := KeyedHashTemplate
	template.NameAlg = tpm.algID

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &types.TPMAttributes{
			Template: template,
		}
	}
	if keyAttrs.TPMAttributes.Template.Type == 0 {
		keyAttrs.TPMAttributes.Template = template
	}

	// The pin of the platform policy this object is created under, captured
	// once so the AuthPolicy attached to the object and the record persisted
	// beside it describe the same PCR state.
	var policyPin *store.PlatformPolicyPin

	if keyAttrs.TPMPolicy == types.TPMPolicyPlatform {
		// Attach platform policy digest (PolicyOR of PolicyPCR + PolicyAuthValue)
		// This MUST match what PlatformPolicySession() produces during unseal.
		// The SRK uses PlatformPolicyDigest (key.go), and CreateKeySession uses
		// PlatformPolicySession -- the sealed object must use the same digest.
		//
		// The digest is computed from a captured pin rather than straight from
		// live PCRs. The value is identical -- the pin holds the PCR state as
		// it reads right now -- but capturing it lets the record written below
		// name the exact PolicyPCR branch this object's AuthPolicy covers, so
		// the PIN branch can still reproduce the PolicyOR digest after the
		// platform measurements change.
		tpl := keyAttrs.TPMAttributes.Template
		pin, err := tpm.capturePlatformPolicyPin()
		if err != nil {
			return nil, err
		}
		policyDigest, err := platformPolicyDigestFromPin(pin)
		if err != nil {
			return nil, err
		}
		tpm.logger.Info("tpm: sealKeyInternal - using PlatformPolicyDigest for sealed object AuthPolicy",
			slog.String("policy_digest", fmt.Sprintf("%x", policyDigest.Buffer)),
			slog.String("pcr_digest", fmt.Sprintf("%x", pin.PCRDigest)),
			slog.String("cn", keyAttrs.CN))
		tpl.AuthPolicy = policyDigest
		keyAttrs.TPMAttributes.Template = tpl
		policyPin = pin
	}

	// A named, authorized policy replaces the password path entirely: the
	// template gets the policy's authPolicy and loses USERWITHAUTH.
	sealTemplate := keyAttrs.TPMAttributes.Template
	policyBinding, err := tpm.namedPolicyBinding(keyAttrs, &sealTemplate)
	if err != nil {
		return nil, err
	}
	keyAttrs.TPMAttributes.Template = sealTemplate

	if keyAttrs.SealData == nil {
		tpm.logger.Info("Generating HMAC seal data", slog.String("cn", keyAttrs.CN))
		secretBytes = make([]byte, 32) // AES-256 key
		if _, err := tpm.random.Read(secretBytes); err != nil {
			return nil, err
		}
		keyAttrs.SealData = types.NewSealData(secretBytes)
	} else {
		secretBytes = keyAttrs.SealData.Bytes()
		if secretBytes == nil {
			return nil, store.ErrInvalidKeyedHashSecret
		}
	}
	// secretBytes is this function's own copy -- SealData.Bytes copies, and
	// the generated secret is copied into keyAttrs.SealData -- so it is wiped
	// once the object is created rather than left in the heap.
	defer enclave.Wipe(secretBytes)

	if tpm.debugSecrets {
		tpm.logger.Debug("tpm: sealing HMAC secret",
			slog.String("cn", keyAttrs.CN),
			slog.String("secret", string(secretBytes)))
	}

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error("failed to create session for seal", slog.String("error", err.Error()))
		return nil, err
	}

	// The sealed secret and the object's authValue are encrypted on their
	// way into the TPM by a salted session of their own: the parent's
	// authorization may be a policy session, which cannot carry them.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptIn)
	if err != nil {
		tpm.closeSession(closer, "seal parent")
		return nil, err
	}

	// Create a new seal key under the persisted SRK
	sealKeyResponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(keyAttrs.TPMAttributes.Template),
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
	}.Execute(tpm.transport, encSession)
	tpm.closeSession(closeEncSession, "seal encryption")
	if err != nil {
		tpm.closeSession(closer, "seal parent")
		tpm.logger.Error("failed to create seal key", slog.String("error", err.Error()))
		return nil, err
	}
	if err := closer(); err != nil {
		tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
	} // tpm2.Create CreateSession

	// Create a new tpm2.Load session
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error("failed to create load session", slog.String("error", err.Error()))
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close load session", slog.String("error", err.Error()))
		}
	}()

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
		tpm.logger.Error("failed to load sealed key", slog.String("error", err.Error()))
		return nil, err
	}
	defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debug("tpm: key loaded to transient handle",
		slog.String("cn", keyAttrs.CN),
		slog.String("handle", Encode([]byte{byte(loadResponse.ObjectHandle >> 24), byte(loadResponse.ObjectHandle >> 16), byte(loadResponse.ObjectHandle >> 8), byte(loadResponse.ObjectHandle)})))

	tpm.logger.Debug("tpm: key Name",
		slog.String("cn", keyAttrs.CN),
		slog.String("name", Encode(loadResponse.Name.Buffer)))

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

	// Persist the platform policy pin beside the key blobs. Without it the
	// PolicyAuthValue (PIN) branch of this object could only be satisfied
	// while the platform PCR still holds the value it holds right now.
	if policyPin != nil {
		if err := tpm.recordKeyPolicyPin(
			keyAttrs, backend, policyPin, overwrite); err != nil {

			return nil, err
		}
	}

	// Record which named policy this object follows. Without it the object
	// could not be used: nothing else says which policy session to build.
	if policyBinding != nil {
		if err := tpm.recordPolicyBinding(
			keyAttrs, backend, policyBinding, overwrite); err != nil {

			return nil, err
		}
	}

	return sealKeyResponse, nil
}

// unsealKeyInternal returns sealed data for a keyed hash using the platform
// PCR Policy Session to satisfy the TPM to release the secret.
//
// This is an internal method. Use Unseal() for the public types.Sealer interface.
func (tpm *TPM2) unsealKeyInternal(
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
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}
		tpm.logger.Error("failed to create session for unseal", slog.String("error", err.Error()))
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
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}
		// Log at debug level for "not found" errors - expected during fresh initialization
		if errors.Is(err, storage.ErrNotFound) {
			tpm.logger.Debug("key not found (expected during initialization)", slog.String("error", err.Error()))
		} else {
			tpm.logger.Error("failed to load key pair for unseal", slog.String("error", err.Error()))
		}
		return nil, err
	}
	if err := closer(); err != nil {
		tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
	}
	defer tpm.Flush(sealKey.ObjectHandle)

	// Create key session. The backend is threaded through so the object's
	// platform policy pin is read from the same store the blobs came from.
	session2, closer2, err2 := tpm.createKeySession(keyAttrs, backend)
	defer func() {
		if err := closer2(); err != nil {
			tpm.logger.Error("failed to close key session", slog.String("error", err.Error()))
		}
	}()
	if err2 != nil {
		tpm.logger.Error("failed to create key session", slog.String("error", err2.Error()))
		return nil, err2
	}

	// The sealed secret leaves the TPM encrypted under a salted session of
	// its own: the key session may answer the PCR branch of the platform
	// policy, which cannot encrypt it.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "unseal encryption")

	// Unseal the data using the key session
	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
			Auth:   session2,
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		tpm.logger.Error("failed to unseal data", slog.String("error", err.Error()))
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
		tpm.logger.Debug("Retrieved sealed HMAC secret",
			slog.String("cn", keyAttrs.CN),
			slog.String("secret", string(secret)))
	}

	return secret, nil
}

// unsealFromBlobs unseals data using provided TPMPublic and TPMPrivate blobs directly,
// without reading from backend storage. This is used when the sealed data blobs are
// provided in-memory (e.g., loaded from EFI partition files during boot).
//
// This follows the same workflow as unsealKeyInternal but uses LoadKeyPairFromBlobs
// instead of LoadKeyPair.
func (tpm *TPM2) unsealFromBlobs(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	tpmPublic, tpmPrivate []byte) ([]byte, error) {

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
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}
		tpm.logger.Error("failed to create session for unseal from blobs", slog.String("error", err.Error()))
		return nil, err
	}

	// Not using defer closer() here because the session needs
	// to be flushed as soon as possible to prevent too many
	// sessions open at one time causing TPM_RC_SESSION_MEMORY

	// Load the key pair from provided blobs
	sealKey, err := tpm.LoadKeyPairFromBlobs(keyAttrs, &session, tpmPublic, tpmPrivate)
	if err != nil {
		if closer != nil {
			if err := closer(); err != nil {
				tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
			}
		}
		tpm.logger.Error("failed to load key pair from blobs", slog.String("error", err.Error()))
		return nil, err
	}
	if err := closer(); err != nil {
		tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
	}
	defer tpm.Flush(sealKey.ObjectHandle)

	// Create key session
	tpm.logger.Info("tpm: unsealFromBlobs - creating key session",
		slog.String("tpm_policy", keyAttrs.TPMPolicy),
		slog.String("cn", keyAttrs.CN))
	session2, closer2, err2 := tpm.createKeySession(keyAttrs, backend)
	defer func() {
		if err := closer2(); err != nil {
			tpm.logger.Error("failed to close key session", slog.String("error", err.Error()))
		}
	}()
	if err2 != nil {
		tpm.logger.Error("failed to create key session for unseal from blobs", slog.String("error", err2.Error()))
		return nil, err2
	}

	// The sealed secret leaves the TPM encrypted under a salted session of
	// its own: the key session may answer the PCR branch of the platform
	// policy, which cannot encrypt it.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "unseal encryption")

	// Unseal the data using the key session
	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
			Auth:   session2,
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		tpm.logger.Error("failed to unseal data from blobs", slog.String("error", err.Error()))
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
		tpm.logger.Debug("Retrieved sealed HMAC secret from blobs",
			slog.String("cn", keyAttrs.CN),
			slog.String("secret", string(secret)))
	}

	return secret, nil
}
