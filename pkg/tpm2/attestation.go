package tpm2

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CertifyResult holds the output of a TPM2_Certify operation.
// Per TCG TPM 2.0 Part 3 - Commands, Section 18.2, TPM2_Certify proves
// that an object with a specific Name is loaded in the TPM. The signing
// key (IAK) produces a signature over the TPMS_ATTEST structure that
// includes the Name of the certified object.
type CertifyResult struct {
	// CertifyInfo is the raw TPMS_ATTEST structure produced by TPM2_Certify
	CertifyInfo []byte

	// Signature is the IAK signature over CertifyInfo
	Signature []byte

	// SignatureAlgorithm is the x509 signature algorithm used by the IAK
	SignatureAlgorithm x509.SignatureAlgorithm

	// AttestingKeyPublic is the IAK public key that signed the attestation
	AttestingKeyPublic crypto.PublicKey

	// AttestedKeyPublic is the certified key's public key
	AttestedKeyPublic crypto.PublicKey

	// Nonce is the echoed qualifying data from the caller
	Nonce []byte

	// CertifyInfoSignature is the signature as a marshalled TPMT_SIGNATURE.
	//
	// [Signature] above carries the raw signature value, which is what a
	// local caller comparing against a crypto.PublicKey wants. A *remote*
	// verifier needs the algorithm and hash too, and those live in the
	// TPMT_SIGNATURE -- so this is the form that travels, and the form
	// [VerifyCertify] takes.
	CertifyInfoSignature []byte

	// AttestingKeyPublicArea is the IAK's marshalled TPMT_PUBLIC.
	//
	// Needed by a verifier because the certified Name is a digest over the
	// public *area*, not over the public key: it cannot be recomputed from a
	// crypto.PublicKey alone.
	AttestingKeyPublicArea []byte

	// AttestedKeyPublicArea is the certified key's marshalled TPMT_PUBLIC.
	AttestedKeyPublicArea []byte
}

// CertifyKey performs TPM2_Certify on a key, producing a signed
// TPMS_ATTEST structure that proves the key is resident in this TPM.
// The IAK (Initial Attestation Key) signs the certification.
//
// Per TCG TPM 2.0 Part 3 - Commands, Section 18.2:
//   - ObjectHandle: the key to be certified
//   - SignHandle: the key used to sign the attestation (IAK)
//   - QualifyingData: caller-supplied nonce for freshness
//   - InScheme: TPM_ALG_NULL lets the TPM use the key's default scheme
//
// Persistent handles (0x81000000-0x81FFFFFF) are certified directly since
// they are already resident in the TPM. Transient keys are loaded from
// blob storage via the provided key backend before certification.
func (tpm *TPM2) CertifyKey(
	keyAttrs *types.KeyAttributes,
	nonce []byte,
	backend store.KeyBackend) (*CertifyResult, error) {

	// ErrNotInitialized takes priority over ErrIAKNotProvisioned: an
	// uninitialized TPM has no way to tell whether an IAK was ever
	// provisioned, so reporting "not provisioned" would claim more than is
	// known. certifyKeyAs makes the identical check for CertifyLAK and
	// CertifyKeyWithLAK; it is repeated here only so this ordering holds
	// before the signer is even resolved.
	if tpm.transport == nil {
		return nil, ErrNotInitialized
	}
	if tpm.iakAttrs == nil {
		return nil, ErrIAKNotProvisioned
	}
	return tpm.certifyKeyAs(tpm.iakAttrs, keyAttrs, nonce, backend)
}

// certifyKeyAs is the TPM2_Certify mechanics shared by CertifyKey (signer is
// always the IAK), CertifyLAK (the IAK certifies the LAK once, at
// provisioning time) and CertifyKeyWithLAK (the LAK certifies an ordinary key
// such as a WebAuthn credential key, go-xkms#715). Only which key signs
// differs; the certified object's own authorization -- the DevID admin-policy
// session for an IAK/IDevID target, ordinary password auth otherwise -- is
// unaffected by who the signer is.
func (tpm *TPM2) certifyKeyAs(
	signerAttrs *types.KeyAttributes,
	keyAttrs *types.KeyAttributes,
	nonce []byte,
	backend store.KeyBackend) (*CertifyResult, error) {

	if tpm.transport == nil {
		return nil, ErrNotInitialized
	}

	if signerAttrs == nil {
		return nil, ErrIAKNotProvisioned
	}

	if keyAttrs == nil {
		return nil, ErrInvalidKeyAttributes
	}

	tpm.logger.Info("Performing TPM2_Certify",
		slog.String("cn", keyAttrs.CN))

	// Determine the target key handle and public area.
	// Persistent handles (0x81xxxxxx) are already resident in the TPM and
	// can be certified directly via ReadPublic. Transient keys must first
	// be loaded from blob storage.
	var targetHandle tpm2.TPMHandle
	var targetPubResp *tpm2.ReadPublicResponse

	handle := keyAttrs.TPMAttributes.Handle
	if uint32(handle) >= 0x81000000 && uint32(handle) <= 0x81FFFFFF {
		// Persistent handle — already resident in the TPM.
		targetHandle = handle
		var err error
		targetPubResp, err = tpm2.ReadPublic{
			ObjectHandle: targetHandle,
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to read persistent key public",
				slog.String("handle", fmt.Sprintf("0x%08X", handle)),
				slog.String("error", err.Error()))
			return nil, &errs.Wrapped{Msg: "failed to read persistent key public", Err: err}
		}
	} else {
		// Transient key — load from blob storage.
		loadResp, err := tpm.LoadKeyPair(keyAttrs, nil, backend)
		if err != nil {
			tpm.logger.Error("failed to load target key for certification",
				slog.String("error", err.Error()))
			return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: fmt.Sprintf("failed to load target key: %v", err)}
		}
		defer tpm.Flush(loadResp.ObjectHandle)
		targetHandle = loadResp.ObjectHandle

		targetPubResp, err = tpm2.ReadPublic{
			ObjectHandle: targetHandle,
		}.Execute(tpm.transport)
		if err != nil {
			tpm.logger.Error("failed to read target key public",
				slog.String("error", err.Error()))
			return nil, &errs.Wrapped{Msg: "failed to read target key public", Err: err}
		}
	}

	// Execute TPM2_Certify: the signer (IAK or LAK) signs a TPMS_ATTEST
	// structure containing the Name of the target key.
	//
	// The signer's own USER-role authorization goes through objectSession
	// (object_policy.go), not a bare password session: an IAK/IDevID is
	// authorized through its TCG DevID Key Policy (devidKeySession, which
	// also falls back to the platform Delegation Policy when the key has no
	// authValue and asks for platform binding); the LAK, an ordinary
	// Platform-SRK child, is authorized the same way every other generic
	// object is -- a named policy, the platform policy, or its password --
	// whichever bindObjectPolicy bound it to at creation. Resolving the
	// signer's session from its own TPM-resident authPolicy, rather than
	// presenting its authValue (or an empty one) unconditionally, is what
	// keeps a policy-bound signer's empty-password bypass closed
	// (go-xkms#715): a signer whose authPolicy requires a policy session
	// cannot be satisfied merely by omitting a password.
	signerSession, closeSignerSession, err := tpm.objectSession(signerAttrs, backend, signerAttrs.TPMAttributes.Handle)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeSignerSession, "Certify signer")

	// TPM2_Certify authorizes objectHandle (the target) at the ADMIN role,
	// not USER -- unlike the signer above, so objectSession does not apply
	// here. For an IDevID or IAK -- which carry the TCG IDevID/IAK Key
	// Policy with adminWithPolicy SET -- the authValue is refused, and the
	// Certify branch of the key policy, satisfied as the Privacy
	// Administrator, is what authorizes it (section 7.3.6.2).
	//
	// Every other target, the LAK included when it is the object being
	// certified (CertifyLAK), is built from this package's generic
	// templates, which never set adminWithPolicy (KeyTemplateSpec.Template,
	// template.go): TCG TPM 2.0 Part 1 section 19.7.5 makes adminWithPolicy
	// CLEAR mean ADMIN-role actions are authorized by the object's authValue
	// alone -- a policy session is refused for that role even when its
	// digest matches the object's authPolicy exactly, confirmed against the
	// simulator while diagnosing this. authPolicy and USERWITHAUTH govern
	// the USER role only (Sign, Certify's SignHandle, ordinary use), which
	// is where the generic object-policy hardening
	// (bindObjectPolicy/objectSession, go-xkms#715) actually closes a
	// bypass; TPM2_Certify naming an object as its target discloses no
	// secret the object's own policy protects, so password-only ADMIN
	// authorization here is the TPM's own design, not a gap this package
	// should route around.
	var targetAuth tpm2.Session
	if kind, isDevID := devidKeyKindOf(keyAttrs.KeyType); isDevID {
		targetPublic, err := targetPubResp.OutPublic.Contents()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to parse target key public", Err: err}
		}
		var hierarchyAuth []byte
		if signerAttrs.Parent != nil && signerAttrs.Parent.TPMAttributes != nil &&
			signerAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
			hierarchyAuth = signerAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
		}
		adminSession, closeAdmin, err := tpm.DevIDAdminSession(
			kind, targetPublic.NameAlg, tpm2.TPMCCCertify, hierarchyAuth)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := closeAdmin(); closeErr != nil {
				tpm.logger.Error("failed to close DevID admin policy session", slog.String("error", closeErr.Error()))
			}
		}()
		targetAuth = adminSession
	} else {
		var targetAuthValue []byte
		if keyAttrs.Password != nil {
			targetAuthValue = keyAttrs.Password.Bytes()
		}
		targetSession, closeTargetSession, err := tpm.objectAuthSession(targetAuthValue, encryptNone)
		if err != nil {
			return nil, err
		}
		defer tpm.closeSession(closeTargetSession, "Certify object")
		targetAuth = targetSession
	}
	certify := tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: targetHandle,
			Name:   targetPubResp.Name,
			Auth:   targetAuth,
		},
		SignHandle: tpm2.AuthHandle{
			Handle: signerAttrs.TPMAttributes.Handle,
			Name:   signerAttrs.TPMAttributes.Name,
			Auth:   signerSession,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgNull,
		},
	}
	rspCert, err := certify.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("TPM2_Certify failed",
			slog.String("error", err.Error()))
		return nil, &errs.Wrapped{Msg: "TPM2_Certify failed", Err: err}
	}

	// Read IAK public to determine signature type
	iakPubResp, err := tpm2.ReadPublic{
		ObjectHandle: signerAttrs.TPMAttributes.Handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to read IAK public",
			slog.String("error", err.Error()))
		return nil, &errs.Wrapped{Msg: "failed to read IAK public", Err: err}
	}

	iakPub, err := iakPubResp.OutPublic.Contents()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get IAK public contents", Err: err}
	}

	// Extract the signature from the Certify response, following the same
	// pattern as Quote() for handling RSA and ECDSA signatures
	var signature []byte

	switch iakPub.Type {
	case tpm2.TPMAlgRSA:
		var rsaSig *tpm2.TPMSSignatureRSA
		if store.IsRSAPSS(signerAttrs.SignatureAlgorithm) {
			rsaSig, err = rspCert.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to extract RSA-PSS signature", Err: err}
			}
		} else {
			rsaSig, err = rspCert.Signature.Signature.RSASSA()
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to extract RSASSA signature", Err: err}
			}
		}
		signature = rsaSig.Sig.Buffer

	case tpm2.TPMAlgECC:
		sig, err := rspCert.Signature.Signature.ECDSA()
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to extract ECDSA signature", Err: err}
		}
		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}
		signature, err = asn1.Marshal(asn1Struct)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to marshal ECDSA signature", Err: err}
		}
	default:
		return nil, &errs.Detail{Err: store.ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unsupported IAK key type: %v", iakPub.Type)}
	}

	// Extract IAK public key
	iakPubKey, err := tpm.extractPublicKey(iakPub)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to extract IAK public key", Err: err}
	}

	// Extract target key public key
	targetPub, err := targetPubResp.OutPublic.Contents()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get target key public contents", Err: err}
	}
	targetPubKey, err := tpm.extractPublicKey(targetPub)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to extract target public key", Err: err}
	}

	tpm.logger.Debug("TPM2_Certify completed",
		slog.String("cn", keyAttrs.CN),
		slog.Int("certify_info_len", len(rspCert.CertifyInfo.Bytes())),
		slog.Int("signature_len", len(signature)))

	return &CertifyResult{
		CertifyInfo:            rspCert.CertifyInfo.Bytes(),
		Signature:              signature,
		SignatureAlgorithm:     signerAttrs.SignatureAlgorithm,
		AttestingKeyPublic:     iakPubKey,
		AttestedKeyPublic:      targetPubKey,
		Nonce:                  nonce,
		CertifyInfoSignature:   tpm2.Marshal(rspCert.Signature),
		AttestingKeyPublicArea: tpm2.Marshal(*iakPub),
		AttestedKeyPublicArea:  tpm2.Marshal(*targetPub),
	}, nil
}

// extractPublicKey converts a TPMTPublic to a crypto.PublicKey.
func (tpm *TPM2) extractPublicKey(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	if pub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, err
		}
		return rsaPub, nil

	} else if pub.Type == tpm2.TPMAlgECC {
		return eccPublicKey(pub)
	}

	return nil, &errs.Detail{Err: store.ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("unsupported key type: %v", pub.Type)}
}

// Returns an Attestation Key Profile (EK, AK, AK Name, TCG_CSR_IDEVID)
func (tpm *TPM2) AKProfile() (AKProfile, error) {

	// Resolve through the accessors rather than reading the caches directly.
	// EKAttributes/IAKAttributes populate ekAttrs/iakAttrs lazily on first use,
	// so reading the fields made this report ErrNotInitialized on a fully
	// provisioned TPM until some other call happened to warm them -- the result
	// depended on call order rather than on TPM state.
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return AKProfile{}, err
	}

	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return AKProfile{}, err
	}

	if ekAttrs.TPMAttributes == nil || iakAttrs.TPMAttributes == nil {
		return AKProfile{}, ErrNotInitialized
	}

	return AKProfile{
		EKPub:              ekAttrs.TPMAttributes.PublicKeyBytes,
		AKPub:              iakAttrs.TPMAttributes.PublicKeyBytes,
		AKName:             iakAttrs.TPMAttributes.Name,
		SignatureAlgorithm: iakAttrs.SignatureAlgorithm,
	}, nil
}

// Performs TPM2_MakeCredential, returning the new credential
// challenge for an Attestor. If the secret parameter is
// not provided, a random AES-256 secret will be generated.
func (tpm *TPM2) MakeCredential(
	akName tpm2.TPM2BName,
	secret []byte) ([]byte, []byte, []byte, error) {

	tpm.logger.Info("Creating new Activation Credential")

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, nil, nil, err
	}

	if secret == nil {
		secret = make([]byte, 32) // AES-256 key
		if _, err := tpm.random.Read(secret); err != nil {
			return nil, nil, nil, err
		}
	}
	digest := tpm2.TPM2BDigest{Buffer: secret}

	// Create the new credential challenge
	mc, err := tpm2.MakeCredential{
		Handle:     ekAttrs.TPMAttributes.Handle,
		Credential: digest,
		ObjectName: akName,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("MakeCredential failed", slog.String("error", err.Error()))
		return nil, nil, nil, err
	}

	return mc.CredentialBlob.Buffer, mc.Secret.Buffer, digest.Buffer, nil
}

// MakeCredentialWithExternalEK performs TPM2_MakeCredential using an external EK certificate.
// This is used by CA servers to create credential challenges for clients whose EK certificate
// comes from a CSR (TCG-CSR-IDEVID), not from the server's own TPM.
//
// Parameters:
//   - ekCert: The client's EK certificate (from CSR)
//   - iakPubBytes: The client's IAK public area bytes (from CSR's AttestPub)
//   - secret: Optional secret to use (if nil, a random 32-byte secret is generated)
//
// Returns:
//   - credentialBlob: The encrypted credential blob
//   - encryptedSecret: The encrypted secret
//   - secret: The plaintext secret (for verification)
//   - error: Any error encountered
func (tpm *TPM2) MakeCredentialWithExternalEK(
	ekCert *x509.Certificate,
	iakPubBytes []byte,
	secret []byte) ([]byte, []byte, []byte, error) {

	tpm.logger.Info("Creating Activation Credential with external EK certificate")

	if ekCert == nil {
		return nil, nil, nil, &errs.Message{Msg: "EK certificate is required"}
	}

	if len(iakPubBytes) == 0 {
		return nil, nil, nil, &errs.Message{Msg: "IAK public area bytes are required"}
	}

	// Generate secret if not provided
	if secret == nil {
		secret = make([]byte, 32) // AES-256 key
		if _, err := tpm.random.Read(secret); err != nil {
			return nil, nil, nil, &errs.Wrapped{Msg: "failed to generate secret", Err: err}
		}
	}

	// Load the IAK public key onto the TPM to get the TPM-computed name
	iakLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](iakPubBytes),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, &errs.Wrapped{Msg: "failed to load IAK public key", Err: err}
	}
	defer tpm.Flush(iakLoadRsp.ObjectHandle)

	// Read the IAK name from the TPM (Name is computed by the TPM based on the public area)
	readPubRsp, err := tpm2.ReadPublic{
		ObjectHandle: iakLoadRsp.ObjectHandle,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, &errs.Wrapped{Msg: "failed to read IAK public", Err: err}
	}

	// Convert EK certificate public key to TPM public structure
	ekPublic, err := CertificateToTPMPublic(ekCert)
	if err != nil {
		return nil, nil, nil, &errs.Wrapped{Msg: "failed to convert EK certificate", Err: err}
	}

	// Load the client's EK public key onto the TPM
	ekLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic:  tpm2.New2B(*ekPublic),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, &errs.Wrapped{Msg: "failed to load EK public key", Err: err}
	}
	defer tpm.Flush(ekLoadRsp.ObjectHandle)

	// Always log the IAK name for debugging credential activation issues
	tpm.logger.Debug("MakeCredentialWithExternalEK IAK info",
		slog.String("iak_name_hex", fmt.Sprintf("%x", readPubRsp.Name.Buffer)),
		slog.Int("iak_pub_bytes_len", len(iakPubBytes)))

	// Perform TPM2_MakeCredential
	digest := tpm2.TPM2BDigest{Buffer: secret}
	mc, err := tpm2.MakeCredential{
		Handle:     ekLoadRsp.ObjectHandle,
		Credential: digest,
		ObjectName: readPubRsp.Name,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, &errs.Wrapped{Msg: "TPM2_MakeCredential failed", Err: err}
	}

	return mc.CredentialBlob.Buffer, mc.Secret.Buffer, secret, nil
}

// Activates a credential challenge previously initiated by MakeCredential
func (tpm *TPM2) ActivateCredential(
	credentialBlob, encryptedSecret []byte) ([]byte, error) {

	tpm.logger.Info("Activating Credential")

	ekAttrs := tpm.iakAttrs.Parent

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	// Always use IAK for credential activation. The credential was made using
	// the IAK Name (from AttestPub in the CSR), so activation must use the IAK
	// regardless of the enrollment strategy. The strategy affects how the CSR
	// is signed, but TPM2_MakeCredential always binds to the IAK.
	keyAttrs := tpm.iakAttrs

	// Validate that key attributes are properly initialized
	if keyAttrs == nil || keyAttrs.TPMAttributes == nil {
		return nil, &errs.Message{Msg: "IAK attributes not initialized, TPM may not be properly provisioned"}
	}

	// Activate the credential, proving the AK and EK are both loaded
	// into the same TPM, and the EK is able to decrypt the secret.
	tpm.logger.Debug("activating credential",
		slog.String("iak_handle", fmt.Sprintf("0x%x", keyAttrs.TPMAttributes.Handle)),
		slog.String("iak_name", fmt.Sprintf("%x", keyAttrs.TPMAttributes.Name.Buffer)),
		slog.String("ek_handle", fmt.Sprintf("0x%x", ekAttrs.TPMAttributes.Handle)),
		slog.String("ek_name", fmt.Sprintf("%x", ekAttrs.TPMAttributes.Name.Buffer)),
		slog.Int("credential_blob_len", len(credentialBlob)),
		slog.Int("encrypted_secret_len", len(encryptedSecret)))

	// TPM2_ActivateCredential authorizes activateHandle at the ADMIN role
	// (TCG TPM 2.0 Part 3, section 12.6). The IAK carries the TCG IDevID/IAK
	// Key Policy with adminWithPolicy SET, so its authValue cannot do that;
	// the ActivateCredential branch of the policy, satisfied as the Privacy
	// Administrator with endorsementAuth, is what releases the credential
	// (section 7.3.6.3). keyHandle is the EK, at the USER role, under the
	// EK policy session built by activateCredential below.
	iakNameAlg, err := ParsePCRBankAlgID(tpm.config.PlatformPCRBank)
	if err != nil {
		return nil, err
	}
	iakAdmin, closeIAKAdmin, err := tpm.DevIDAdminSession(
		DevIDKeyAttestation, iakNameAlg, tpm2.TPMCCActivateCredential, hierarchyAuth)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeIAKAdmin(); closeErr != nil {
			tpm.logger.Error("failed to close IAK admin policy session", slog.String("error", closeErr.Error()))
		}
	}()

	return tpm.activateCredential(
		ekAttrs, keyAttrs.TPMAttributes.Handle, keyAttrs.TPMAttributes.Name, iakAdmin,
		credentialBlob, encryptedSecret)
}

// activateCredential is the TPM2_ActivateCredential mechanics shared by
// ActivateCredential (always the IAK) and AnswerCredentialChallenge (any
// CreateActivationKey object): build an EK policy session satisfying
// PolicySecret(ENDORSEMENT), then activate credentialBlob/encryptedSecret
// against activateHandle/activateName, authorized in the ADMIN role by
// activateAuth.
//
// Only how each caller builds activateAuth differs, because the two kinds
// of key satisfy the ADMIN role differently: the IAK's adminWithPolicy Key
// Policy needs a policy session (DevIDAdminSession, built by the caller); an
// ordinary CreateActivationKey object clears adminWithPolicy, so its own
// (empty) password auth already satisfies ADMIN.
func (tpm *TPM2) activateCredential(
	ekAttrs *types.KeyAttributes,
	activateHandle tpm2.TPMHandle,
	activateName tpm2.TPM2BName,
	activateAuth tpm2.Session,
	credentialBlob, encryptedSecret []byte) ([]byte, error) {

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	session, closer, err := tpm.startPolicySession(tpm2.TPMAlgSHA256, nil)
	if err != nil {
		tpm.logger.Error("failed to create policy session", slog.String("error", err.Error()))
		return nil, err
	}
	defer tpm.closeSession(closer, "ActivateCredential EK policy")

	err = tpm.policySecret(tpm2.TPMRHEndorsement, hierarchyAuth, session)
	if err != nil {
		tpm.logger.Error("PolicySecret failed", slog.String("error", err.Error()))
		return nil, err
	}

	// The recovered credential is the secret the challenge proves possession
	// of, so it leaves the TPM encrypted under a salted session.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "ActivateCredential encryption")

	activateCredentialsResponse, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{
			Handle: activateHandle,
			Name:   activateName,
			Auth:   activateAuth,
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ekAttrs.TPMAttributes.Handle,
			Name:   ekAttrs.TPMAttributes.Name,
			Auth:   session,
		},
		CredentialBlob: tpm2.TPM2BIDObject{
			Buffer: credentialBlob,
		},
		Secret: tpm2.TPM2BEncryptedSecret{
			Buffer: encryptedSecret,
		},
	}.Execute(tpm.transport, encSession)
	if err != nil {
		tpm.logger.Error("ActivateCredential failed", slog.String("error", err.Error()))
		return nil, ErrInvalidActivationCredential
	}

	// Return the decrypted secret
	return activateCredentialsResponse.CertInfo.Buffer, nil
}

// Performs a TPM 2.0 quote over the PCRs defined in the
// TPM section of the platform configuration file, used
// for local attestation. The quote, event log, and PCR
// state is optionally signed and saved to the CA blob store.
func (tpm *TPM2) Quote(pcrs []uint, nonce []byte) (Quote, error) {

	if tpm.iakAttrs == nil {
		return Quote{}, ErrNotInitialized
	}

	if tpm.iakAttrs.Parent == nil {
		return Quote{}, ErrInvalidAKAttributes
	}

	tpm.logger.Info("Performing TPM 2.0 Quote")

	var quote Quote
	var akAuth []byte
	var err error

	if tpm.iakAttrs.Password != nil {
		akAuth = tpm.iakAttrs.Password.Bytes()
	}

	// Create PCR selection(s)
	// All PCRs should be in a single selection with the same hash algorithm
	pcrSelect := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm.iakAttrs.TPMAttributes.HashAlg,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	akSession, closeAKSession, err := tpm.objectAuthSession(akAuth, encryptNone)
	if err != nil {
		return Quote{}, err
	}
	defer tpm.closeSession(closeAKSession, "Quote")

	// Create the quote
	q, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: tpm.iakAttrs.TPMAttributes.Handle,
			Name:   tpm.iakAttrs.TPMAttributes.Name,
			Auth:   akSession,
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		PCRSelect: pcrSelect,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("Quote failed", slog.String("error", err.Error()))
		return Quote{}, err
	}

	var signature []byte

	var rsaSig *tpm2.TPMSSignatureRSA
	if tpm.iakAttrs.KeyAlgorithm == x509.RSA { //nolint:staticcheck // QF1003: if-else preferred over switch

		if store.IsRSAPSS(tpm.iakAttrs.SignatureAlgorithm) {
			rsaSig, err = q.Signature.Signature.RSAPSS()
			if err != nil {
				return quote, err
			}
		} else {
			rsaSig, err = q.Signature.Signature.RSASSA()
			if err != nil {
				tpm.logger.Error("failed to get RSASSA signature", slog.String("error", err.Error()))
				return quote, err
			}
		}
		signature = rsaSig.Sig.Buffer

	} else if tpm.iakAttrs.KeyAlgorithm == x509.ECDSA {
		sig, err := q.Signature.Signature.ECDSA()
		if err != nil {
			return quote, err
		}
		r := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
		s := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, s}
		signature, err = asn1.Marshal(asn1Struct)
		if err != nil {
			return quote, err
		}
	}

	// Get the event log:
	// Rather than parsing the event log and secure boot state,
	// capture the raw binary log as a blob so it can be signed
	// and imported to the CA blob storage. Verify should do a byte
	// level comparison and digest verification for the system state
	// integrity check.
	// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
	eventLog, err := tpm.EventLog()
	if err != nil {
		// Some embedded systems have no measurement log, the log may be
		// unreadable for permission reasons, and simulators have none at all.
		// None of those is fatal: the quote below stands on its own, so log the
		// warning and carry on without an event log.
		tpm.logger.Warn(ErrMissingMeasurementLog.Error())
	}

	allBanks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		tpm.logger.Error("failed to read PCRs", slog.String("error", err.Error()))
		return Quote{}, err
	}

	pcrBytes, err := EncodePCRs(allBanks)
	if err != nil {
		tpm.logger.Error("failed to encode PCRs", slog.String("error", err.Error()))
		return Quote{}, err
	}

	return Quote{
		EventLog:  eventLog,
		Nonce:     nonce,
		PCRs:      pcrBytes,
		Quoted:    q.Quoted.Bytes(),
		Signature: signature,
	}, nil
}

// Create a random nonce and issue a quote command to the TPM for the PCR specified
// in the platform configuration file.
func (tpm *TPM2) PlatformQuote(
	keyAttrs *types.KeyAttributes) (Quote, []byte, error) {

	tpm.logger.Info("Performing local TPM 2.0 Quote")
	nonce, err := tpm.Random()
	if err != nil {
		return Quote{}, nil, err
	}
	quote, err := tpm.Quote(tpm.config.PlatformPCRs, nonce)
	if err != nil {
		return Quote{}, nil, err
	}
	return quote, nonce, nil
}
