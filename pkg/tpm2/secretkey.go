package tpm2

import (
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Creates a new RSA child key using the provided key attributes
func (tpm *TPM2) CreateSecretKey(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) error {

	if keyAttrs.Parent == nil {
		return store.ErrInvalidKeyAttributes
	}

	// Get the persisted SRK
	srkHandle := keyAttrs.Parent.TPMAttributes.Handle
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return err
	}

	// Create new AES key under the SRK, optionally protected by the
	// platform auth policy that requires the platform PCR value with
	// the Golden Integrity Measurements to release.
	aesTemplate := AES256CFBTemplate

	// Set the key password authorization value if provided.
	//
	// The platform policy is a PolicyOR of PolicyPCR and PolicyAuthValue, and
	// CreateKeySession takes the PolicyAuthValue branch whenever the key
	// carries a password. That branch can only be satisfied by an object that
	// actually has the auth value, so a key created with no UserAuth makes the
	// PIN branch structurally impossible: every attempt returns
	// TPM_RC_AUTH_FAIL, which is an auth failure rather than a policy failure
	// and therefore also feeds the dictionary-attack counter.
	var keyUserAuth []byte
	if keyAttrs.Password != nil {
		keyUserAuth = keyAttrs.Password.Bytes()
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
			return err
		}
		policyDigest, err := platformPolicyDigestFromPin(pin)
		if err != nil {
			return err
		}
		aesTemplate.AuthPolicy = policyDigest
		policyPin = pin
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	response, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(aesTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyUserAuth,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(
		keyAttrs,
		response.OutPrivate,
		response.OutPublic,
		backend,
		false); err != nil {

		return err
	}

	// Record the platform policy pin beside the blobs it describes. Without it
	// this key's PIN branch could only be satisfied while the platform PCR
	// still held the value it holds right now. The overwrite policy matches
	// SaveKeyPair's above.
	if policyPin != nil {
		if err := tpm.recordKeyPolicyPin(
			keyAttrs, backend, policyPin, false); err != nil {

			return err
		}
	}

	return nil
}
