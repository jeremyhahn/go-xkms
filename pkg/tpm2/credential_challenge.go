// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

// credentialChallengeSecretSize is the size, in bytes, of the random secret
// NewCredentialChallenge protects. 32 bytes (AES-256) matches the size this
// package's TPM-resident MakeCredential/MakeCredentialWithExternalEK
// generate when no caller-supplied secret is given, so a challenge built by
// either path looks the same on the wire.
const credentialChallengeSecretSize = 32

// CredentialChallenge is the TPM2_MakeCredential output: a TPM2B_ID_OBJECT
// and its TPM2B_ENCRYPTED_SECRET. NewCredentialChallenge builds one entirely
// in software, so a verifier needs no TPM of its own. It is answered by
// whichever TPM holds the EK it was built against -- AnswerCredentialChallenge
// for a CreateActivationKey object, or ActivateCredential for the IAK-bound
// legacy path.
type CredentialChallenge struct {
	// CredentialBlob is the TPM2B_ID_OBJECT: the secret, encrypted and
	// integrity-protected under a symmetric key derived from a seed shared
	// with the EK.
	CredentialBlob []byte

	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET: the seed, encrypted to
	// the EK's public key (RSA-OAEP or ECDH, per the EK's key type).
	EncryptedSecret []byte
}

// NewCredentialChallenge builds a TPM2_MakeCredential challenge for ekPub in
// software, using the construction TCG TPM 2.0 Part 1, section 24
// ("Credential Protection") defines: a random seed encrypted to ekPub, a
// symmetric key derived from that seed with KDFa, the secret encrypted under
// it with AES-CFB, and an HMAC computed over the encrypted secret and the
// activation key's Name -- exactly what TPM2_MakeCredential itself would
// produce, without needing a TPM to run it on. The construction is
// google/go-tpm's own (tpm2.CreateCredential), not reimplemented here.
//
// activationKeyName is the TPM Name (TPM2B_NAME contents: nameAlg || digest)
// of the key that will answer the challenge -- see ActivationKeyName, or
// ActivationKey.Name from CreateActivationKey on the device side. It is
// never a raw public key: the credential is cryptographically bound to this
// exact Name, and ActivateCredential against any other key fails the
// integrity check baked into the challenge.
//
// Returns the challenge and the random secret it protects. The caller
// compares that plaintext secret against whatever AnswerCredentialChallenge
// (or ActivateCredential) returns: only a TPM that holds the private half of
// ekPub, and that has loaded the exact object named by activationKeyName,
// can recover it.
func NewCredentialChallenge(
	ekPub crypto.PublicKey, activationKeyName []byte) (*CredentialChallenge, []byte, error) {

	if ekPub == nil {
		return nil, nil, ErrEKPublicRequired
	}
	if len(activationKeyName) == 0 {
		return nil, nil, ErrActivationKeyNameRequired
	}

	ekTPMPublic, err := publicKeyToTPMPublic(ekPub)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("convert EK public key: %v", err)}
	}

	encKey, err := tpm2.ImportEncapsulationKey(ekTPMPublic)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("import EK as encapsulation key: %v", err)}
	}

	secret := make([]byte, credentialChallengeSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("generate secret: %v", err)}
	}

	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, encKey, activationKeyName, secret)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("create credential: %v", err)}
	}

	return &CredentialChallenge{
		CredentialBlob:  idObject,
		EncryptedSecret: encSecret,
	}, secret, nil
}

// ActivationKeyName computes the TPM Name (TCG TPM 2.0 Part 1, section 16:
// nameAlg || digest) of a public area a verifier received off the wire --
// a TCG-CSR-IDEVID's AttestPub field, or an ActivationKey.Public a device
// sent alongside its challenge request -- entirely in software, matching the
// Name any TPM that later loads the same public area computes. It is the
// activationKeyName NewCredentialChallenge needs.
//
// publicArea is a marshaled TPMT_PUBLIC, not TPM2B-wrapped: the format
// TCG-CSR-IDEVID's AttestPub carries, and what ActivationKey.Public becomes
// once marshaled with tpm2.Marshal.
func ActivationKeyName(publicArea []byte) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](publicArea)
	if err != nil {
		return nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("unmarshal public area: %v", err)}
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, &errs.Detail{Err: ErrCredentialChallenge, Detail: fmt.Sprintf("compute name: %v", err)}
	}
	return name.Buffer, nil
}
