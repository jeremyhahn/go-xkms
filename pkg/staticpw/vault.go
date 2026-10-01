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

package staticpw

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/vaultkey"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The personal vault.
//
// Each user's personal entries are encrypted with a random per-user data key
// (DEK) that never changes. The DEK is stored only wrapped, once per factor
// the user enrolled:
//
//   - passphrase: KEK = Argon2id(passphrase, salt), the repository's default
//     Argon2id cost (kdf.DefaultParams: 64 MiB, t=3, p=4);
//   - passkey: KEK = HKDF-SHA256(hmac-secret output, salt), where the output
//     is the FIDO2 hmac-secret (WebAuthn PRF) the user's authenticator
//     evaluates over the factor's PRFSalt;
//   - recovery: KEK = HKDF-SHA256(recovery code, salt). The code is issued on
//     first enrollment, shown once, and replaced every time it is used;
//   - piv, certificate, tpm (key factors): KEK = HKDF-SHA256(secret, salt),
//     where the secret is drawn at enrollment by sealing to the factor's
//     public key (pkg/vaultkey: ECDH-ES or RSA-OAEP-256). The server keeps
//     only the sealed form; the holder of the private key recovers the
//     secret and presents it. The server cannot unlock alone, and the DEK
//     never leaves it.
//
// The wrapped DEKs live in the tenant barrier, so reading a personal entry
// needs both the tenant barrier and one of the user's own factors: the
// tenant key alone unwraps nothing.

// VaultFeature is the keyspace feature holding the vault keyrings:
// "{tenant}/staticpw-vault/users/{subject}/factors/{id}".
const VaultFeature = "staticpw-vault"

// FactorType is the kind of credential a vault factor wraps the DEK under.
type FactorType string

// Factor types.
const (
	// FactorPassphrase is a passphrase the user chose.
	FactorPassphrase FactorType = "passphrase"
	// FactorPasskey is a FIDO2 credential with the hmac-secret extension.
	FactorPasskey FactorType = "passkey"
	// FactorRecovery is the one-time recovery code.
	FactorRecovery FactorType = "recovery"
	// FactorPIV is the key in a PIV card's key-management slot (9d).
	FactorPIV FactorType = "piv"
	// FactorCertificate is a client certificate's key, held in software,
	// on a PKCS#11 token or in a TPM.
	FactorCertificate FactorType = "certificate"
	// FactorTPM is a TPM key under a named TPM policy: it opens only on
	// that machine, in the state the policy expects.
	FactorTPM FactorType = "tpm"
)

// IsKeyFactor reports whether t is a key factor: one whose secret is
// sealed to a public key (piv, certificate, tpm).
func (t FactorType) IsKeyFactor() bool {
	return t == FactorPIV || t == FactorCertificate || t == FactorTPM
}

// Vault parameters.
const (
	// MinPassphraseLength is the shortest passphrase a factor accepts: NIST
	// SP 800-63B's minimum for a user-chosen memorized secret.
	MinPassphraseLength = 8

	// PasskeySecretLength is the length of an hmac-secret (PRF) output for
	// one salt.
	PasskeySecretLength = 32

	// PRFSaltLength is the length of the salt the authenticator evaluates
	// hmac-secret over.
	PRFSaltLength = 32

	dekLength          = 32
	kdfSaltLength      = 16
	recoveryCodeBytes  = 20 // 160 bits
	recoveryGroupWidth = 4
	factorIDBytes      = 8
	factorsSegment     = "factors/"
	wrapAADPrefix      = "xkms/staticpw/vault/v1"
	passkeyHKDFInfo    = "xkms/staticpw/vault/v1/passkey"
	recoveryHKDFInfo   = "xkms/staticpw/vault/v1/recovery"
	keyHKDFInfo        = "xkms/staticpw/vault/v1/key"
)

// Vault errors.
var (
	// ErrVaultNotInitialized is returned when a user with no enrolled factor
	// unlocks or manages factors. The first enrollment initializes the vault.
	ErrVaultNotInitialized = errors.New("staticpw: personal vault has no enrolled factor")

	// ErrVaultCredentialRejected is returned when a presented credential
	// unwraps no factor: a wrong passphrase, an unknown passkey, a wrong
	// hmac-secret output or a wrong recovery code.
	ErrVaultCredentialRejected = errors.New("staticpw: credential rejected")

	// ErrVaultInvalidCredential is returned for a malformed credential: an
	// unknown factor type, a passphrase shorter than MinPassphraseLength, an
	// hmac-secret output or PRF salt of the wrong length, or a passkey
	// without a credential ID.
	ErrVaultInvalidCredential = errors.New("staticpw: invalid credential")

	// ErrVaultFactorNotFound is returned when a factor ID names no factor.
	ErrVaultFactorNotFound = errors.New("staticpw: vault factor not found")

	// ErrVaultLastFactor is returned when removing a factor would leave the
	// user with no passphrase or passkey.
	ErrVaultLastFactor = errors.New("staticpw: cannot remove the last unlock factor")

	// ErrVaultRecoveryFactor is returned when the recovery factor is named
	// where a passphrase or passkey is required: it is managed by recovery
	// alone.
	ErrVaultRecoveryFactor = errors.New("staticpw: the recovery code is not a removable or rotatable factor")

	// ErrVaultPasskeyExists is returned when a passkey credential ID is
	// already enrolled.
	ErrVaultPasskeyExists = errors.New("staticpw: passkey already enrolled")

	// ErrVaultKeyExists is returned when a key factor's key is already
	// enrolled.
	ErrVaultKeyExists = errors.New("staticpw: this key is already enrolled")

	// ErrVaultPasskeyUnavailable is returned when a passkey is enrolled on
	// a deployment with no WebAuthn relying party configured: a passkey is
	// scoped to the console's domain, so without one it could not unlock
	// from a browser.
	ErrVaultPasskeyUnavailable = errors.New("staticpw: passkeys need the server's WebAuthn relying party (webauthn.rp_id) configured")

	// ErrVaultRelyingPartyMismatch is returned when a passkey enrollment
	// names a relying party other than the server's.
	ErrVaultRelyingPartyMismatch = errors.New("staticpw: the passkey was created for another relying party")
)

// defaultPassphraseKDFParams returns the Argon2id cost a new passphrase
// factor is wrapped with unless the owning TenantPasswordStoreManager was
// built with WithPassphraseKDFParams: the repository default
// (kdf.DefaultParams). The cost is stored on the factor, so changing it
// affects new wraps only.
func defaultPassphraseKDFParams() *kdf.KDFParams {
	return kdf.DefaultParams(kdf.AlgorithmArgon2id)
}

// VaultCredential is a factor a user presents to unlock, enroll or recover.
type VaultCredential struct {
	// Type is the factor type.
	Type FactorType

	// Secret is the passphrase, the hmac-secret output, or the recovery
	// code, sealed in protected memory. It is opened only to derive a
	// factor's key-encryption key (kek) or to check its length (validate).
	Secret *secure.Secret

	// CredentialID identifies a passkey.
	CredentialID []byte

	// PRFSalt is the salt a passkey's hmac-secret was evaluated over. It is
	// required when enrolling a passkey and ignored otherwise: an enrolled
	// passkey's salt is read from its factor (VaultFactorInfo.PRFSalt).
	PRFSalt []byte

	// Label names an enrolled factor for the user ("laptop key").
	Label string

	// RelyingParty is the WebAuthn relying party ID a passkey was created
	// for. Required to enroll a passkey: it must be the server's.
	RelyingParty string

	// PublicKey (PKIX DER) or Certificate (DER) is the key a key factor is
	// enrolled with. A certificate factor needs Certificate.
	PublicKey   []byte
	Certificate []byte

	// KeyFingerprint selects the key factor a credential unlocks with
	// (VaultFactorInfo.KeyFingerprint).
	KeyFingerprint string

	// KeyRef records, at enrollment, where the client keeps a key factor's
	// private key, so any client can find it again.
	KeyRef VaultKeyRef
}

// VaultKeyRef is where a key factor's private key lives on the client: the
// xkms backend holding it, its key ID there, and for a TPM key the named
// TPM policy it is bound to. It is a hint for selecting the token; the
// fingerprint is what proves the key.
type VaultKeyRef struct {
	Backend   string `json:"backend,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	TPMPolicy string `json:"tpm_policy,omitempty"`
}

// VaultFactorInfo is the public description of a factor: no key material.
type VaultFactorInfo struct {
	ID           string     `json:"id"`
	Type         FactorType `json:"type"`
	Label        string     `json:"label,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CredentialID []byte     `json:"credential_id,omitempty"`
	PRFSalt      []byte     `json:"prf_salt,omitempty"`

	// RelyingParty is the relying party ID a passkey was created for;
	// every client evaluates the passkey for this ID.
	RelyingParty string `json:"rp_id,omitempty"`

	// Key factors: the key's fingerprint (vaultkey.Fingerprint), the sealed
	// secret (KeyAlgorithm, KeyChallenge), its key-check value, where the
	// client keeps the key, and a certificate's subject for display.
	KeyFingerprint     string      `json:"key_fingerprint,omitempty"`
	KeyAlgorithm       string      `json:"key_algorithm,omitempty"`
	KeyChallenge       []byte      `json:"key_challenge,omitempty"`
	KeyCheck           []byte      `json:"key_check,omitempty"`
	KeyRef             VaultKeyRef `json:"key_ref,omitzero"`
	CertificateSubject string      `json:"certificate_subject,omitempty"`
}

// vaultFactor is a factor as stored: its public description, the KDF input
// and the DEK wrapped under the factor's key.
type vaultFactor struct {
	VaultFactorInfo
	Salt         []byte `json:"salt"`
	ArgonTime    uint32 `json:"argon_time,omitempty"`
	ArgonMemory  uint32 `json:"argon_memory_kib,omitempty"`
	ArgonThreads uint8  `json:"argon_threads,omitempty"`
	WrappedDEK   []byte `json:"wrapped_dek"`
}

// validate checks a credential's shape for its type. Enrollment also needs
// a passkey's PRF salt.
func (c VaultCredential) validate(enrolling bool) error {
	secretLen, err := secretSize(c.Secret)
	if err != nil {
		return err
	}
	switch c.Type {
	case FactorPassphrase:
		if secretLen < MinPassphraseLength {
			return ErrVaultInvalidCredential
		}
	case FactorPasskey:
		if len(c.CredentialID) == 0 || secretLen != PasskeySecretLength {
			return ErrVaultInvalidCredential
		}
		if enrolling && len(c.PRFSalt) != PRFSaltLength {
			return ErrVaultInvalidCredential
		}
	case FactorRecovery:
		if enrolling {
			return ErrVaultRecoveryFactor
		}
		if secretLen == 0 {
			return ErrVaultInvalidCredential
		}
	case FactorPIV, FactorCertificate, FactorTPM:
		if enrolling {
			if c.Type == FactorCertificate && len(c.Certificate) == 0 {
				return ErrVaultInvalidCredential
			}
			if _, err := c.keyFingerprint(); err != nil {
				return err
			}
			return nil
		}
		if c.KeyFingerprint == "" || secretLen != vaultkey.SecretLength {
			return ErrVaultInvalidCredential
		}
	default:
		return ErrVaultInvalidCredential
	}
	return nil
}

// keyFingerprint parses an enrolling key factor's key and returns its
// fingerprint. An unparsable or unsupported key is an invalid credential.
func (c VaultCredential) keyFingerprint() (string, error) {
	pub, _, err := vaultkey.ParsePublicKey(c.PublicKey, c.Certificate)
	if err != nil {
		return "", &VaultKeyError{Err: err}
	}
	return vaultkey.Fingerprint(pub)
}

// VaultKeyError reports a key factor whose key cannot be enrolled: it does
// not parse, or it is not RSA (2048 bits or more) or EC P-256/P-384/P-521.
// It matches ErrVaultInvalidCredential.
type VaultKeyError struct {
	Err error
}

// Error implements the error interface.
func (e *VaultKeyError) Error() string { return "staticpw: key factor: " + e.Err.Error() }

// Unwrap returns the vaultkey failure.
func (e *VaultKeyError) Unwrap() error { return e.Err }

// Is matches ErrVaultInvalidCredential, so every transport maps it as a
// malformed credential.
func (e *VaultKeyError) Is(target error) bool { return target == ErrVaultInvalidCredential }

// secretSize returns the length of the plaintext secret holds, or 0 when
// secret is nil (no credential presented).
func secretSize(secret *secure.Secret) (int, error) {
	if secret == nil {
		return 0, nil
	}
	buf, err := secret.Open()
	if err != nil {
		return 0, &VaultCryptoError{Op: "open", Err: err}
	}
	defer buf.Destroy()
	return buf.Size(), nil
}

// vaultKeyring persists one user's factors in the tenant barrier.
type vaultKeyring struct {
	backend   storage.Backend
	prefix    string
	tenantID  string
	subject   string
	kdfParams func() *kdf.KDFParams
}

// newVaultKeyring returns subject's keyring in tenantID over backend. New
// passphrase factors wrap the DEK at the Argon2id cost kdfParams returns.
func newVaultKeyring(backend storage.Backend, tenantID, subject string, kdfParams func() *kdf.KDFParams) (*vaultKeyring, error) {
	prefix, err := scope.PersonalPrefix(tenantID, VaultFeature, subject)
	if err != nil {
		return nil, err
	}
	return &vaultKeyring{
		backend:   backend,
		prefix:    prefix + factorsSegment,
		tenantID:  tenantID,
		subject:   subject,
		kdfParams: kdfParams,
	}, nil
}

// factors returns every stored factor, oldest first.
func (k *vaultKeyring) factors(ctx context.Context) ([]*vaultFactor, error) {
	var out []*vaultFactor
	err := k.backend.Scan(ctx, k.prefix, func(key string, value []byte) error {
		var f vaultFactor
		if err := json.Unmarshal(value, &f); err != nil {
			return &VaultStoreError{Op: "decode", Key: key, Err: err}
		}
		out = append(out, &f)
		return nil
	})
	if err != nil {
		var storeErr *VaultStoreError
		if errors.As(err, &storeErr) {
			return nil, err
		}
		return nil, &VaultStoreError{Op: "scan", Key: k.prefix, Err: err}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// put stores f.
func (k *vaultKeyring) put(ctx context.Context, f *vaultFactor) error {
	data, err := json.Marshal(f)
	if err != nil {
		return &VaultStoreError{Op: "encode", Key: f.ID, Err: err}
	}
	if err := k.backend.Put(ctx, k.prefix+f.ID, data); err != nil {
		return &VaultStoreError{Op: "put", Key: f.ID, Err: err}
	}
	return nil
}

// remove deletes the factor id.
func (k *vaultKeyring) remove(ctx context.Context, id string) error {
	if err := k.backend.Delete(ctx, k.prefix+id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrVaultFactorNotFound
		}
		return &VaultStoreError{Op: "delete", Key: id, Err: err}
	}
	return nil
}

// aad binds a wrapped DEK to its tenant, user and factor, so a wrap copied
// to another user or factor does not open.
func (k *vaultKeyring) aad(factorID string) []byte {
	return []byte(wrapAADPrefix + "|" + k.tenantID + "|" + k.subject + "|" + factorID)
}

// wrap builds a factor of cred's type wrapping dek.
func (k *vaultKeyring) wrap(cred VaultCredential, dek []byte) (*vaultFactor, error) {
	id, err := randomHex(factorIDBytes)
	if err != nil {
		return nil, err
	}
	salt, err := randomBytes(kdfSaltLength)
	if err != nil {
		return nil, err
	}
	f := &vaultFactor{
		VaultFactorInfo: VaultFactorInfo{ID: id, Type: cred.Type, Label: cred.Label, CreatedAt: time.Now().UTC()},
		Salt:            salt,
	}
	secret := cred.Secret
	switch {
	case cred.Type == FactorPasskey:
		f.CredentialID = append([]byte(nil), cred.CredentialID...)
		f.PRFSalt = append([]byte(nil), cred.PRFSalt...)
		f.RelyingParty = cred.RelyingParty
	case cred.Type == FactorPassphrase:
		params := k.kdfParams()
		f.ArgonTime, f.ArgonMemory, f.ArgonThreads = params.Time, params.Memory, params.Threads
	case cred.Type.IsKeyFactor():
		keySecret, err := sealKeyFactor(f, cred)
		if err != nil {
			return nil, err
		}
		defer keySecret.Destroy()
		secret = keySecret
	}
	kek, err := f.kek(secret)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	f.WrappedDEK, err = aesgcm.EncryptWithAAD(kek, dek, k.aad(f.ID))
	if err != nil {
		return nil, &VaultCryptoError{Op: "wrap", Err: err}
	}
	return f, nil
}

// unwrap returns the DEK f wraps, or ErrVaultCredentialRejected when secret
// is not f's.
func (k *vaultKeyring) unwrap(f *vaultFactor, secret *secure.Secret) ([]byte, error) {
	kek, err := f.kek(secret)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	dek, err := aesgcm.DecryptWithAAD(kek, f.WrappedDEK, k.aad(f.ID))
	if err != nil {
		return nil, ErrVaultCredentialRejected
	}
	return dek, nil
}

// sealKeyFactor records a key factor's key on f and draws its secret, sealed
// to the key (vaultkey.Seal). It returns the secret in protected memory; the
// caller wraps the DEK with it and destroys it: only its sealed form is stored.
func sealKeyFactor(f *vaultFactor, cred VaultCredential) (*secure.Secret, error) {
	pub, cert, err := vaultkey.ParsePublicKey(cred.PublicKey, cred.Certificate)
	if err != nil {
		return nil, &VaultKeyError{Err: err}
	}
	fingerprint, err := vaultkey.Fingerprint(pub)
	if err != nil {
		return nil, &VaultKeyError{Err: err}
	}
	sealed, err := vaultkey.Seal(pub)
	if err != nil {
		return nil, &VaultCryptoError{Op: "seal key factor", Err: err}
	}
	f.KeyFingerprint = fingerprint
	f.KeyAlgorithm = sealed.Algorithm
	f.KeyChallenge = sealed.Challenge
	f.KeyCheck = sealed.Check
	f.KeyRef = cred.KeyRef
	if cert != nil {
		f.CertificateSubject = cert.Subject.String()
	}
	return sealed.Secret, nil
}

// kek derives the factor's key-encryption key from secret, opening it only
// for the duration of the derivation.
func (f *vaultFactor) kek(secret *secure.Secret) ([]byte, error) {
	if secret == nil {
		return nil, &VaultCryptoError{Op: "kdf", Err: ErrVaultInvalidCredential}
	}
	buf, err := secret.Open()
	if err != nil {
		return nil, &VaultCryptoError{Op: "open", Err: err}
	}
	defer buf.Destroy()
	var key []byte
	if err := buf.WithBytes(func(plaintext []byte) error {
		var derr error
		key, derr = f.deriveKEK(plaintext)
		return derr
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// deriveKEK runs the factor's KDF over plaintext. It is called only from
// inside kek's borrow, so it must not reach into pkg/secure.
func (f *vaultFactor) deriveKEK(plaintext []byte) ([]byte, error) {
	switch f.Type {
	case FactorPassphrase:
		if f.ArgonTime == 0 || f.ArgonMemory == 0 || f.ArgonThreads == 0 {
			return nil, &VaultCryptoError{Op: "kdf", Err: ErrVaultInvalidCredential}
		}
		return argon2.IDKey(plaintext, f.Salt, f.ArgonTime, f.ArgonMemory, f.ArgonThreads, aesgcm.KeySize), nil
	case FactorPasskey:
		return hkdfKey(plaintext, f.Salt, passkeyHKDFInfo)
	case FactorRecovery:
		return hkdfKey(plaintext, f.Salt, recoveryHKDFInfo)
	case FactorPIV, FactorCertificate, FactorTPM:
		return hkdfKey(plaintext, f.Salt, keyHKDFInfo+"|"+f.KeyFingerprint)
	default:
		return nil, ErrVaultInvalidCredential
	}
}

// hkdfKey derives an AES-256 key with HKDF-SHA256.
func hkdfKey(secret, salt []byte, info string) ([]byte, error) {
	key := make([]byte, aesgcm.KeySize)
	if _, err := hkdf.New(sha256.New, secret, salt, []byte(info)).Read(key); err != nil {
		return nil, &VaultCryptoError{Op: "hkdf", Err: err}
	}
	return key, nil
}

// newRecoveryCode returns a fresh recovery code for display ("ABCD-EFGH-…",
// 160 bits) and its normalized secret, sealed in protected memory.
func newRecoveryCode() (display string, secret *secure.Secret, err error) {
	raw, err := randomBytes(recoveryCodeBytes)
	if err != nil {
		return "", nil, err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	groups := make([]string, 0, len(encoded)/recoveryGroupWidth+1)
	for i := 0; i < len(encoded); i += recoveryGroupWidth {
		groups = append(groups, encoded[i:min(i+recoveryGroupWidth, len(encoded))])
	}
	sealed, err := secure.NewSecret([]byte(encoded))
	if err != nil {
		return "", nil, &VaultCryptoError{Op: "seal", Err: err}
	}
	return strings.Join(groups, "-"), sealed, nil
}

// normalizeRecoveryCode returns the secret of a recovery code as the user
// typed it: case, spaces and dashes are ignored.
func normalizeRecoveryCode(code []byte) []byte {
	var b strings.Builder
	for _, r := range strings.ToUpper(string(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return []byte(b.String())
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, &VaultCryptoError{Op: "random", Err: err}
	}
	return b, nil
}

// randomHex returns n random bytes, hex encoded.
func randomHex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// VaultStoreError wraps a failure reading or writing a vault keyring.
type VaultStoreError struct {
	Op  string
	Key string
	Err error
}

// Error implements the error interface.
func (e *VaultStoreError) Error() string {
	return "staticpw: vault keyring " + e.Op + " " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *VaultStoreError) Unwrap() error { return e.Err }

// VaultCryptoError wraps a key-derivation or wrapping failure.
type VaultCryptoError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *VaultCryptoError) Error() string {
	return "staticpw: vault " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *VaultCryptoError) Unwrap() error { return e.Err }
