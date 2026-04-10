package tpm2

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	// ErrPlatformPolicySession is returned when the platform policy session
	// creation fails.
	ErrPlatformPolicySession = errors.New("tpm2: failed to create platform policy session")

	// ErrPlatformPolicyDigestCompute is returned when the platform policy digest
	// computation fails.
	ErrPlatformPolicyDigestCompute = errors.New("tpm2: failed to compute platform policy digest")
)

// Creates an unsalted, unauthenticated HMAC session with the TPM. If
// session encryption is enabled in the platform configuration file,
// the TPM <-> CPU bus is encrypted using AES-128 CFB.
func (tpm *TPM2) HMAC(auth []byte) tpm2.Session {
	if tpm.config.EncryptSession {
		tpm.logger.Debug("tpm: creating unauthenticated, unsalted, encrypted HMAC session")
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
	tpm.logger.Debug("tpm: creating unauthenticated, unsalted, UNencrypted HMAC session")

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
			tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
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
	tpm.logger.Debug("tpm: creating UNencrypted HMAC session")
	if tpm.debugSecrets {
		tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
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
		tpm.logger.Debug("tpm: creating salted, encrypted HMAC session with primary key",
			slog.String("handle", fmt.Sprintf("0x%x", handle)))
		if tpm.debugSecrets {
			tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
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
	tpm.logger.Debug("tpm: creating salted, UNencrypted HMAC session with key",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))
	if tpm.debugSecrets {
		tpm.logger.Debug("tpm: HMAC session auth", slog.String("auth", string(auth)))
	}
	return tpm2.HMACSession(
		tpm.transport,
		tpm2.TPMAlgSHA256,
		16,
		[]tpm2.AuthOption{tpm2.Auth(auth)}...)
}

// PlatformPolicySession creates a PolicyOR session supporting both PCR-based
// automatic unlock and password-based PIN fallback. The session satisfies
// the platform policy digest (PolicyOR of PolicyPCR + PolicyAuthValue).
//
// When auth is nil, the session executes the PCR branch (PolicyPCR followed
// by PolicyOR). When auth is non-nil, the session executes the password
// branch (PolicyAuthValue followed by PolicyOR), binding the auth value to
// the session so the HMAC computation includes it (per TPM 2.0 Part 1,
// Section 19.6: HMAC key = sessionKey || authValue).
//
// The resulting policy digest is cached in tpm.policyDigest.
func (tpm *TPM2) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {

	usePCRBranch := auth == nil

	hashAlgID, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformPolicySession, err)
	}

	// Compute branch digests for PolicyOR (needed for both branches)
	pcrDigest, err := tpm.PlatformPolicyDigestHash()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformPolicySession, err)
	}

	// Branch 1 trial digest: PolicyPCR
	pcrCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformPolicySession, err)
	}
	pcrCmd := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrDigest,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      hashAlgID,
				PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
			}},
		},
	}
	if err := pcrCmd.Update(pcrCalc); err != nil {
		return nil, nil, fmt.Errorf("%w: PolicyPCR trial: %v", ErrPlatformPolicySession, err)
	}
	branch1Digest := pcrCalc.Hash().Digest

	// Branch 2 trial digest: PolicyAuthValue
	authCalc, err := tpm2.NewPolicyCalculator(hashAlgID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformPolicySession, err)
	}
	authCmd := tpm2.PolicyAuthValue{}
	if err := authCmd.Update(authCalc); err != nil {
		return nil, nil, fmt.Errorf("%w: PolicyAuthValue trial: %v", ErrPlatformPolicySession, err)
	}
	branch2Digest := authCalc.Hash().Digest

	// Create the real policy session.
	// When using the password branch (PolicyAuthValue), the auth value must
	// be bound to the session so that the HMAC computation includes it.
	// Per TPM 2.0 Part 1, Section 19.6: HMAC key = sessionKey || authValue.
	var sessionOpts []tpm2.AuthOption
	if !usePCRBranch && len(auth) > 0 {
		sessionOpts = append(sessionOpts, tpm2.Auth(auth))
	}
	session, closer, err := tpm2.PolicySession(
		tpm.transport, hashAlgID, 16, sessionOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlatformPolicySession, err)
	}

	if usePCRBranch {
		// Execute PolicyPCR in the live session
		_, err = tpm2.PolicyPCR{
			PolicySession: session.Handle(),
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: pcrDigest,
			},
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      hashAlgID,
					PCRSelect: tpm2.PCClientCompatible.PCRs(tpm.config.PlatformPCR),
				}},
			},
		}.Execute(tpm.transport)
		if err != nil {
			if closeErr := closer(); closeErr != nil {
				tpm.logger.Error("failed to close session after PolicyPCR error",
					slog.String("error", closeErr.Error()))
			}
			return nil, nil, fmt.Errorf("%w: PolicyPCR execute: %v", ErrPlatformPolicySession, err)
		}
		tpm.logger.Debug("tpm: PlatformPolicySession - PCR branch executed")
	} else {
		// Execute PolicyAuthValue in the live session
		_, err = tpm2.PolicyAuthValue{
			PolicySession: session.Handle(),
		}.Execute(tpm.transport)
		if err != nil {
			if closeErr := closer(); closeErr != nil {
				tpm.logger.Error("failed to close session after PolicyAuthValue error",
					slog.String("error", closeErr.Error()))
			}
			return nil, nil, fmt.Errorf("%w: PolicyAuthValue execute: %v", ErrPlatformPolicySession, err)
		}
		tpm.logger.Debug("tpm: PlatformPolicySession - password branch executed")
	}

	// Execute PolicyOR with both branch digests to complete the session policy
	_, err = tpm2.PolicyOr{
		PolicySession: session.Handle(),
		PHashList: tpm2.TPMLDigest{
			Digests: []tpm2.TPM2BDigest{
				{Buffer: branch1Digest},
				{Buffer: branch2Digest},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("failed to close session after PolicyOR error",
				slog.String("error", closeErr.Error()))
		}
		return nil, nil, fmt.Errorf("%w: PolicyOR execute: %v", ErrPlatformPolicySession, err)
	}

	// Get the final session policy digest for caching
	pgd, pgdErr := tpm2.PolicyGetDigest{
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if pgdErr == nil {
		tpm.policyDigest = pgd.PolicyDigest
		tpm.logger.Info("tpm: PlatformPolicySession - final session policy digest",
			slog.Bool("pcr_branch", usePCRBranch),
			slog.String("session_digest", fmt.Sprintf("%x", pgd.PolicyDigest.Buffer)),
			slog.String("branch1_pcr", fmt.Sprintf("%x", branch1Digest)),
			slog.String("branch2_auth", fmt.Sprintf("%x", branch2Digest)))
	}

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
		tpm.logger.Error("failed to create nonce policy session", slog.String("error", err.Error()))
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
		tpm.logger.Error("failed to execute PolicySecret", slog.String("error", err.Error()))
		// Clean up session before returning error
		if closeErr := closer(); closeErr != nil {
			tpm.logger.Error("Failed to close session after PolicySecret error", slog.String("error", closeErr.Error()))
		}
		return nil, nil, err
	}

	return session, closer, nil
}

// Returns an authorization session for a key based on the provided parent
// key attributes and platform configuration file.
//
// Session selection logic for the parent key:
//   - Password != nil AND PlatformPolicy = true: PlatformPolicySession(password)
//     (password branch of PolicyOR for auto-unseal-capable keys)
//   - Password == nil AND PlatformPolicy = true: PlatformPolicySession(nil)
//     (PCR branch of PolicyOR for automatic unlock)
//   - Password != nil AND PlatformPolicy = false: PasswordAuth(password)
//     (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// When PlatformPolicy is false and encryption is enabled, a salted HMAC
// session is created using the parent key. This function returns a session
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

	parentHandle := keyAttrs.Parent.TPMAttributes.Handle

	if keyAttrs.Parent.PlatformPolicy {

		// Determine whether the parent has a meaningful (non-empty) auth value.
		// A nil Password or a Password with zero-length bytes means "no auth" and
		// should use the PCR branch for automatic unlock. After a restart the
		// cached SRK attributes carry no password (config file has empty string),
		// so selecting the password branch with empty auth would produce
		// TPM_RC_BAD_AUTH because the actual SRK UserAuth is the user PIN set
		// during initial setup.
		var parentAuth []byte
		if keyAttrs.Parent.Password != nil {
			parentAuth = keyAttrs.Parent.Password.Bytes()
		}

		if len(parentAuth) > 0 {
			// Password + PlatformPolicy: use compound policy password branch.
			// The parent's auth value must be passed so the session HMAC
			// includes it (TPM 2.0 Part 1, Section 19.6).
			session, closer, err = tpm.PlatformPolicySession(parentAuth)
			if err != nil {
				return session, closer, err
			}
			tpm.logger.Debug("tpm: created platform policy session (password branch)",
				slog.String("cn", keyAttrs.CN))
			return session, closer, nil
		}

		// PlatformPolicy without password: use compound policy PCR branch
		session, closer, err = tpm.PlatformPolicySession(nil)
		if err != nil {
			return session, closer, err
		}
		tpm.logger.Debug("tpm: created platform policy session (PCR branch)",
			slog.String("cn", keyAttrs.CN))
		return session, closer, nil
	}

	// No PlatformPolicy: extract password for standard auth
	if keyAttrs.Parent.Password != nil {
		parentAuth = keyAttrs.Parent.Password.Bytes()
	}

	_, parentPub, err := tpm.ReadHandle(parentHandle)
	if err != nil {
		return session, closer, err
	}

	if tpm.config.EncryptSession {

		// Create salted (encrypted) session using parent key
		session, closer, err = tpm.HMACSaltedSession(
			parentHandle,
			parentPub,
			parentAuth)
		if err != nil {
			tpm.logger.Error("failed to create salted session", slog.String("error", err.Error()))
			return session, closer, err
		}
		return session, closer, nil
	}

	session = tpm2.PasswordAuth(parentAuth)
	return session, closer, nil
}

// Returns an authorization session for a child key based on the provided
// key attributes.
//
// Session selection logic:
//   - Password != nil AND PlatformPolicy = true: PlatformPolicySession(password)
//     (password branch of PolicyOR for auto-unseal-capable keys)
//   - Password == nil AND PlatformPolicy = true: PlatformPolicySession(nil)
//     (PCR branch of PolicyOR for automatic unlock)
//   - Password != nil AND PlatformPolicy = false: PasswordAuth(password)
//     (default password-only, no auto-unseal)
//   - Neither: empty password auth
//
// This function returns a session closer function that needs to be called
// to close the session when complete.
func (tpm *TPM2) CreateKeySession(
	keyAttrs *types.KeyAttributes) (tpm2.Session, func() error, error) {

	var session tpm2.Session
	var closer func() error
	var err error

	if keyAttrs.PlatformPolicy {

		// Determine whether the key has a meaningful (non-empty) auth value.
		// See CreateSession for the full rationale on why empty auth must be
		// treated as nil to avoid TPM_RC_BAD_AUTH after restart.
		var keyAuth []byte
		if keyAttrs.Password != nil {
			keyAuth = keyAttrs.Password.Bytes()
		}

		if len(keyAuth) > 0 {
			// Password + PlatformPolicy: use platform policy password branch.
			// The key's auth value must be passed so the session HMAC
			// includes it (TPM 2.0 Part 1, Section 19.6).
			session, closer, err = tpm.PlatformPolicySession(keyAuth)
			if err != nil {
				return session, closer, err
			}
		} else {
			// PlatformPolicy without password: use platform policy PCR branch
			session, closer, err = tpm.PlatformPolicySession(nil)
			if err != nil {
				return session, closer, err
			}
		}
	} else {

		if keyAttrs.Password != nil {
			// Check if password is valid (error passwords return error from String())
			_, err = keyAttrs.Password.String()
			if err != nil {
				return nil, nil, err
			}
			keyAuth := keyAttrs.Password.Bytes()
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
	tpm.logger.Debug("tpm: LoadKeyPair - loading blobs",
		slog.String("cn", keyAttrs.CN),
		slog.String("keyType", fmt.Sprintf("%v", keyAttrs.KeyType)))
	priv, err := backend.Get(keyAttrs, store.FSEXT_PRIVATE_BLOB)
	if err != nil {
		// Log at debug level - this is expected during fresh initialization
		// when the key doesn't exist yet
		tpm.logger.Debug("tpm: LoadKeyPair - failed to load private blob",
			slog.String("error", err.Error()),
			slog.String("cn", keyAttrs.CN))
		return nil, err
	}
	tpm.logger.Debug("tpm: LoadKeyPair - loaded private blob", slog.Int("bytes", len(priv)))
	pub, err := backend.Get(keyAttrs, store.FSEXT_PUBLIC_BLOB)
	if err != nil {
		// Log at debug level - this is expected during fresh initialization
		// when the key doesn't exist yet
		tpm.logger.Debug("tpm: LoadKeyPair - failed to load public blob",
			slog.String("error", err.Error()),
			slog.String("cn", keyAttrs.CN))
		return nil, err
	}
	tpm.logger.Debug("tpm: LoadKeyPair - loaded public blob", slog.Int("bytes", len(pub)))

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

	// Ensure the parent Name is populated. After an app restart the cached
	// SRK attributes may only contain the persistent handle without the Name
	// (built from config, not from TPM2_ReadPublic). TPM2_Load requires a
	// valid Name for the ParentHandle parameter -- without it the go-tpm
	// marshaller returns "missing Name for 'ParentHandle' parameter".
	if len(parentName.Buffer) == 0 {
		tpm.logger.Debug("tpm: LoadKeyPair - parent Name empty, reading from TPM",
			slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))
		resolvedName, _, readErr := tpm.ReadHandle(parentHandle)
		if readErr != nil {
			return nil, readErr
		}
		parentName = resolvedName
		keyAttrs.Parent.TPMAttributes.Name = resolvedName
	}

	tpm.logger.Debug("tpm: loading key pair",
		slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))

	tpm.logger.Debug("tpm: loading key pair",
		slog.String("parent_name", fmt.Sprintf("0x%s", Encode(parentName.Buffer))))

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
		tpm.logger.Error("failed to load key pair",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, err
	}
	// defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debug("tpm: loaded key pair", slog.String("handle", fmt.Sprintf("0x%x", loadResponse.ObjectHandle)))

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

	// Ensure the parent Name is populated. After an app restart the cached
	// SRK attributes may only contain the persistent handle without the Name
	// (built from config, not from TPM2_ReadPublic). TPM2_Load requires a
	// valid Name for the ParentHandle parameter -- without it the go-tpm
	// marshaller returns "missing Name for 'ParentHandle' parameter".
	if len(parentName.Buffer) == 0 {
		tpm.logger.Debug("tpm: LoadKeyPairFromBlobs - parent Name empty, reading from TPM",
			slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))
		resolvedName, _, readErr := tpm.ReadHandle(parentHandle)
		if readErr != nil {
			return nil, readErr
		}
		parentName = resolvedName
		keyAttrs.Parent.TPMAttributes.Name = resolvedName
	}

	tpm.logger.Debug("tpm: loading key pair from blobs",
		slog.String("parent_handle", fmt.Sprintf("0x%x", parentHandle)))

	tpm.logger.Debug("tpm: loading key pair from blobs",
		slog.String("parent_name", fmt.Sprintf("0x%s", Encode(parentName.Buffer))))

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
		tpm.logger.Error("failed to load key pair from blobs",
			slog.String("cn", keyAttrs.CN),
			slog.String("error", err.Error()))
		return nil, err
	}

	tpm.logger.Debug("tpm: loaded key pair from blobs", slog.String("handle", fmt.Sprintf("0x%x", loadResponse.ObjectHandle)))

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

	tpm.logger.Debug("tpm: saving key pair", slog.String("cn", keyAttrs.CN))

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

	tpm.logger.Debug("tpm: deleting key pair", slog.String("cn", keyAttrs.CN))
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
// 		tpm.logger.Error("failed to save context", slog.String("error", err.Error()))
// 		return err
// 	}
// 	err = tpm.backend.Save(
// 		keyAttrs, response.Context.ContextBlob.Buffer, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error("failed to save context to backend", slog.String("error", err.Error()))
// 		return err
// 	}
// 	return nil
// }

// // Loads an encrypted context file only readable by this TPM
// func (tpm *TPM2) loadContext(keyAttrs *types.KeyAttributes) ([]byte, error) {
// 	ctx, err := tpm.backend.Get(keyAttrs, store.FSEXT_TPM_CONTEXT)
// 	if err != nil {
// 		tpm.logger.Error("failed to load context", slog.String("error", err.Error()))
// 		return nil, err
// 	}
// 	return ctx, nil
// }
