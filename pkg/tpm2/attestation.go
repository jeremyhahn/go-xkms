package tpm2

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Returns an Attestation Key Profile (EK, AK, AK Name, TCG_CSR_IDEVID)
func (tpm *TPM2) AKProfile() (AKProfile, error) {

	if tpm.ekAttrs == nil {
		return AKProfile{}, ErrNotInitialized
	}

	if tpm.iakAttrs == nil {
		return AKProfile{}, ErrNotInitialized
	}
	return AKProfile{
		EKPub:              tpm.ekAttrs.TPMAttributes.PublicKeyBytes,
		AKPub:              tpm.iakAttrs.TPMAttributes.PublicKeyBytes,
		AKName:             tpm.iakAttrs.TPMAttributes.Name,
		SignatureAlgorithm: tpm.iakAttrs.SignatureAlgorithm,
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

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredential secret: %s", secret)
	}

	// Create the new credential challenge
	mc, err := tpm2.MakeCredential{
		Handle:     ekAttrs.TPMAttributes.Handle,
		Credential: digest,
		ObjectName: akName,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, nil, nil, err
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredential: secret (raw): %s", digest.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret (hex): 0x%x", Encode(digest.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (raw): %s", mc.CredentialBlob.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: encrypted secret (hex): 0x%x", Encode(mc.CredentialBlob.Buffer))

		tpm.logger.Debugf("tpm: MakeCredential: secret response (raw): %s", mc.Secret.Buffer)
		tpm.logger.Debugf("tpm: MakeCredential: secret response (hex): 0x%x", Encode(mc.Secret.Buffer))
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
		return nil, nil, nil, fmt.Errorf("EK certificate is required")
	}

	if len(iakPubBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("IAK public area bytes are required")
	}

	// Generate secret if not provided
	if secret == nil {
		secret = make([]byte, 32) // AES-256 key
		if _, err := tpm.random.Read(secret); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate secret: %w", err)
		}
	}

	// Load the IAK public key onto the TPM to get the TPM-computed name
	iakLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](iakPubBytes),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load IAK public key: %w", err)
	}
	defer tpm.Flush(iakLoadRsp.ObjectHandle)

	// Read the IAK name from the TPM (Name is computed by the TPM based on the public area)
	readPubRsp, err := tpm2.ReadPublic{
		ObjectHandle: iakLoadRsp.ObjectHandle,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read IAK public: %w", err)
	}

	// Convert EK certificate public key to TPM public structure
	ekPublic, err := CertificateToTPMPublic(ekCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to convert EK certificate: %w", err)
	}

	// Load the client's EK public key onto the TPM
	ekLoadRsp, err := tpm2.LoadExternal{
		Hierarchy: tpm2.TPMRHEndorsement,
		InPublic:  tpm2.New2B(*ekPublic),
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load EK public key: %w", err)
	}
	defer tpm.Flush(ekLoadRsp.ObjectHandle)

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredentialWithExternalEK: IAK name: 0x%x", readPubRsp.Name.Buffer)
		tpm.logger.Debugf("tpm: MakeCredentialWithExternalEK: secret: 0x%x", secret)
	}

	// Perform TPM2_MakeCredential
	digest := tpm2.TPM2BDigest{Buffer: secret}
	mc, err := tpm2.MakeCredential{
		Handle:     ekLoadRsp.ObjectHandle,
		Credential: digest,
		ObjectName: readPubRsp.Name,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM2_MakeCredential failed: %w", err)
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: MakeCredentialWithExternalEK: credential blob: 0x%x", mc.CredentialBlob.Buffer)
		tpm.logger.Debugf("tpm: MakeCredentialWithExternalEK: encrypted secret: 0x%x", mc.Secret.Buffer)
	}

	return mc.CredentialBlob.Buffer, mc.Secret.Buffer, secret, nil
}

// Activates a credential challenge previously initiated by MakeCredential
func (tpm *TPM2) ActivateCredential(
	credentialBlob, encryptedSecret []byte) ([]byte, error) {

	tpm.logger.Info("Activating Credential")

	ekAttrs := tpm.iakAttrs.Parent

	var hierarchyAuth []byte
	var err error

	if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	session, closer, err := tpm2.PolicySession(tpm.transport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Errorf("failed to close policy session: %v", err)
		}
	}()

	_, err = tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NonceTPM:      session.NonceTPM(),
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Always use IAK for credential activation. The credential was made using
	// the IAK Name (from AttestPub in the CSR), so activation must use the IAK
	// regardless of the enrollment strategy. The strategy affects how the CSR
	// is signed, but TPM2_MakeCredential always binds to the IAK.
	keyAttrs := tpm.iakAttrs

	// Validate that key attributes are properly initialized
	if keyAttrs == nil || keyAttrs.TPMAttributes == nil {
		return nil, fmt.Errorf("IAK attributes not initialized, TPM may not be properly provisioned")
	}

	// Activate the credential, proving the AK and EK are both loaded
	// into the same TPM, and the EK is able to decrypt the secret.
	tpm.logger.Debug("tpm2: activating credential")
	activateCredentialsResponse, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{
			Handle: keyAttrs.TPMAttributes.Handle,
			Name:   keyAttrs.TPMAttributes.Name,
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
	}.Execute(tpm.transport)
	if err != nil {
		fmt.Println(err)
		tpm.logger.Error(err)
		return nil, ErrInvalidActivationCredential
	}

	// Release the decrypted secret. Print some helpful info
	// if secret debugging is enabled.
	digest := activateCredentialsResponse.CertInfo.Buffer
	if tpm.debugSecrets {
		tpm.logger.Debugf("tpm: credential encrypted secret (raw): %s", encryptedSecret)
		tpm.logger.Debugf("tpm: credential encrypted secret (hex): 0x%x", Encode(encryptedSecret))

		tpm.logger.Debugf("tpm: TPM2BDigest (raw): %s", digest)
		tpm.logger.Debugf("tpm: TPM2BDigest (hex): 0x%x", Encode(digest))
	}

	// Return the decrypted secret
	return digest, nil
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

	// Create the quote
	q, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: tpm.iakAttrs.TPMAttributes.Handle,
			Name:   tpm.iakAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(akAuth),
		},
		QualifyingData: tpm2.TPM2BData{
			Buffer: nonce,
		},
		PCRSelect: pcrSelect,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
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
				tpm.logger.Error(err)
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
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			// Some embedded systems may not have a measurement log or there may be a permission
			// problem. Log the warning and carry on...
			tpm.logger.Warn(ErrMissingMeasurementLog.Error())
		} else {
			tpm.logger.Warn(ErrMissingMeasurementLog.Error())
			// Continue without event log for simulator or permission-denied cases
		}
	}

	allBanks, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		tpm.logger.Error(err)
		return Quote{}, err
	}

	pcrBytes, err := EncodePCRs(allBanks)
	if err != nil {
		tpm.logger.Error(err)
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
	quote, err := tpm.Quote([]uint{uint(tpm.config.PlatformPCR)}, nonce)
	if err != nil {
		return Quote{}, nil, err
	}
	return quote, nonce, nil
}
