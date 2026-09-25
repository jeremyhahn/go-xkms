package tpm2

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	// Build the template for the curve the caller asked for.
	//
	// The curve comes from the request and is checked against what this TPM
	// reports through TPM2_GetCapability, so a curve the device does not
	// implement is refused by name. The previous shape carried a table of three
	// templates and quietly fell back to P-256 for anything else: a caller that
	// asked for a curve this package had no template for was handed a P-256 key
	// and told it had succeeded, which is a key of a security level nobody
	// chose. It also meant a device implementing P-224 could not be asked for
	// one.
	spec := KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		NameAlg:   tpm.algID,
	}
	if keyAttrs.ECCAttributes != nil {
		spec.Curve = keyAttrs.ECCAttributes.Curve
	}

	eccTemplate, err := tpm.KeyTemplate(spec)
	if err != nil {
		tpm.logger.Error("failed to build ECC key template",
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
		eccTemplate.AuthPolicy = policyDigest
		policyPin = pin
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
		if errors.Is(err, ErrCommandNotSupported) {
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

			// TPM2_Load authorizes the PARENT (the SRK), not the child key
			// being loaded -- the child has no TPM-resident auth yet, only
			// the blob pair being loaded. CreateSession(keyAttrs) resolves
			// the session against keyAttrs.Parent for exactly this reason;
			// CreateKeySession(keyAttrs) would instead build a session
			// against the child's own (nil) auth, which authorizes nothing
			// TPM2_Load's ParentHandle checks against and fails
			// TPM_RC_AUTH_FAIL against any SRK with a real auth value. See
			// the matching, correct call in rsa.go's identical fallback.
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
				tpm.logger.Error("failed to load ECC key", slog.String("error", err.Error()), slog.String("cn", keyAttrs.CN))
				return nil, err
			}
			handle = loadResponse.ObjectHandle
			name = loadResponse.Name
			private = createRsp.OutPrivate
			public = createRsp.OutPublic
		} else {
			tpm.logger.Error("failed to create ECC key", slog.String("error", err.Error()))
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
	// this key reloads those under the SRK through LoadKeyPair.
	//
	// A single deferred flush covers both branches above and both outcomes. The
	// previous shape registered one unconditional flush per branch plus a
	// second, success-guarded one, so every error path flushed the same handle
	// twice and logged a spurious failure for the second attempt.
	defer tpm.Flush(handle)

	tpm.logger.Debug("ECC key loaded to transient handle", slog.String("handle", Encode([]byte{byte(handle >> 24), byte(handle >> 16), byte(handle >> 8), byte(handle)})))
	tpm.logger.Debug("ECC key name", slog.String("name", Encode(name.Buffer)))
	tpm.logger.Debug("ECC parent (SRK) name", slog.String("name", Encode(srkName.Buffer)))

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

	outPub, err := public.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public contents", slog.String("error", err.Error()))
		return nil, err
	}
	eccPub, err := eccPublicKey(outPub)
	if err != nil {
		tpm.logger.Error("failed to reconstruct ECC public key", slog.String("error", err.Error()))
		return nil, err
	}

	return eccPub, nil
}
