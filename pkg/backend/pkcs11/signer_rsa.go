// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build pkcs11

package pkcs11

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/miekg/pkcs11"
)

// hashInfo maps crypto.Hash to PKCS#11 mechanism constants and key sizes.
type hashInfo struct {
	hashAlg uint
	mgfAlg  uint
	hashLen uint
}

// hashMap maps Go crypto.Hash values to PKCS#11 hash and MGF mechanism constants.
var hashMap = map[crypto.Hash]hashInfo{
	crypto.SHA1:   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20},
	crypto.SHA224: {pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28},
	crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32},
	crypto.SHA384: {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48},
	crypto.SHA512: {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64},
}

// digestInfoPrefix contains the DER-encoded DigestInfo prefix for PKCS#1 v1.5 signatures.
// These are defined in RFC 8017 Section 9.2 Note 1.
var digestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// pkcs11RSASigner implements crypto.Signer and crypto.Decrypter for RSA keys
// stored in a PKCS#11 HSM. All cryptographic operations are performed on the
// hardware; private key material never leaves the device.
type pkcs11RSASigner struct {
	pool          *SessionPool
	privateHandle pkcs11.ObjectHandle
	publicKey     *rsa.PublicKey
	label         string
}

// Compile-time interface checks.
var (
	_ crypto.Signer    = (*pkcs11RSASigner)(nil)
	_ crypto.Decrypter = (*pkcs11RSASigner)(nil)
)

// Public returns the RSA public key corresponding to the hardware-backed private key.
func (s *pkcs11RSASigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the RSA private key on the HSM.
//
// Supported opts:
//   - *rsa.PSSOptions: uses CKM_RSA_PKCS_PSS with the specified hash and salt length.
//     PSSSaltLengthAuto is not supported (returns error).
//   - crypto.Hash(0): uses CKM_RSA_PKCS (PKCS#1 v1.5) over digest verbatim.
//     See signPKCS1v15.
//   - nil or other: uses CKM_RSA_PKCS (PKCS#1 v1.5) with DigestInfo DER prefix.
func (s *pkcs11RSASigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return s.signPSS(digest, pssOpts)
	}
	return s.signPKCS1v15(digest, opts)
}

// signPKCS1v15 performs PKCS#1 v1.5 signing with CKM_RSA_PKCS on the HSM.
//
// A nil opts means the caller expressed no preference and selects the SHA-256
// default, matching xkms.ResolveHash's treatment of an unspecified hash name.
//
// A zero opts.HashFunc() — crypto.Hash(0), the value xkms.ResolveHash returns
// for the wire sentinel "NONE" — means the caller has already built the exact
// bytes to pad and sign, so digest is signed verbatim with no DigestInfo
// prepended. This is the case PKCS#11's raw CKM_RSA_PKCS mechanism produces:
// libp11 and a TLS 1.3 CertificateVerify both hand the token a complete
// DigestInfo. Prepending a second one signs bytes nobody chose, and the
// resulting signature verifies against nothing. crypto/rsa gives crypto.Hash(0)
// exactly this meaning in SignPKCS1v15, so the software and PKCS#11 backends
// answer the same request the same way.
//
// Any other hash names the DigestInfo to build. A hash with no prefix in
// RFC 8017 §9.2 is refused rather than defaulted, because substituting a digest
// the caller did not ask for reports success for a signature it cannot use.
func (s *pkcs11RSASigner) signPKCS1v15(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := crypto.SHA256
	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	signed := digest
	if hashFunc != 0 {
		prefix, ok := digestInfoPrefix[hashFunc]
		if !ok {
			return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("unsupported hash for PKCS1v15: %v", hashFunc)}
		}

		// DigestInfo is the concatenation of the ASN.1 prefix and the digest.
		signed = make([]byte, len(prefix)+len(digest))
		copy(signed, prefix)
		copy(signed[len(prefix):], digest)
	}

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PKCS1v15 SignInit", Err: err}
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, signed)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PKCS1v15 Sign", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// signPSS performs RSA-PSS signing using CKM_RSA_PKCS_PSS on the HSM.
func (s *pkcs11RSASigner) signPSS(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	hashFunc := opts.HashFunc()
	if hashFunc == 0 {
		hashFunc = crypto.SHA256
	}

	info, ok := hashMap[hashFunc]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("unsupported hash for PSS: %v", hashFunc)}
	}

	saltLen := opts.SaltLength
	switch saltLen {
	case rsa.PSSSaltLengthAuto:
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: "PSSSaltLengthAuto not supported by PKCS#11"}
	case rsa.PSSSaltLengthEqualsHash:
		saltLen = int(info.hashLen)
	}
	if saltLen < 0 {
		saltLen = int(info.hashLen)
	}

	pssParams := pkcs11.NewPSSParams(info.hashAlg, info.mgfAlg, uint(saltLen))

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PSS SignInit", Err: err}
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PSS Sign", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Decrypt decrypts ciphertext with the RSA private key on the HSM.
//
// Supported opts:
//   - *rsa.OAEPOptions: uses CKM_RSA_PKCS_OAEP
//   - *rsa.PKCS1v15DecryptOptions or nil: uses CKM_RSA_PKCS
func (s *pkcs11RSASigner) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		return s.decryptOAEP(ciphertext, oaepOpts)
	}
	return s.decryptPKCS1v15(ciphertext)
}

// decryptPKCS1v15 decrypts using CKM_RSA_PKCS (PKCS#1 v1.5).
func (s *pkcs11RSASigner) decryptPKCS1v15(ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().DecryptInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PKCS1v15 DecryptInit", Err: err}
		}

		var err error
		plaintext, err = s.pool.Ctx().Decrypt(session, ciphertext)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA PKCS1v15 Decrypt", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// decryptOAEP decrypts using CKM_RSA_PKCS_OAEP.
func (s *pkcs11RSASigner) decryptOAEP(ciphertext []byte, opts *rsa.OAEPOptions) ([]byte, error) {
	hashFunc := opts.Hash
	if hashFunc == 0 {
		hashFunc = crypto.SHA256
	}

	info, ok := hashMap[hashFunc]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("unsupported hash for OAEP: %v", hashFunc)}
	}

	// The MGF1 hash is a separate choice from the label hash. crypto.Decrypter
	// defines OAEPOptions.MGFHash as exactly that, defaulting to Hash when it is
	// zero, and CK_RSA_PKCS_OAEP_PARAMS likewise carries hashAlg and mgf as
	// independent fields. Deriving the MGF from Hash unconditionally meant a
	// caller asking for OAEP(SHA-256, MGF1-SHA-1) silently got MGF1-SHA-256 --
	// a different scheme from the one requested, whose ciphertext a conformant
	// peer cannot decrypt.
	mgfInfo := info
	if opts.MGFHash != 0 && opts.MGFHash != hashFunc {
		mgfInfo, ok = hashMap[opts.MGFHash]
		if !ok {
			return nil, &errs.Detail{Err: ErrUnsupportedOperation, Detail: fmt.Sprintf("unsupported MGF1 hash for OAEP: %v", opts.MGFHash)}
		}
	}

	oaepParams := pkcs11.NewOAEPParams(info.hashAlg, mgfInfo.mgfAlg, pkcs11.CKZ_DATA_SPECIFIED, opts.Label)

	var plaintext []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().DecryptInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams),
		}, s.privateHandle); err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA OAEP DecryptInit", Err: err}
		}

		var err error
		plaintext, err = s.pool.Ctx().Decrypt(session, ciphertext)
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: RSA OAEP Decrypt", Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// exportRSAPublicKey extracts the RSA public key from a PKCS#11 public key object handle.
// It reads CKA_MODULUS and CKA_PUBLIC_EXPONENT attributes and constructs an *rsa.PublicKey.
func exportRSAPublicKey(pool *SessionPool, pubHandle pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	var pub *rsa.PublicKey
	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		attrs, err := pool.Ctx().GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: get RSA public key attributes", Err: err}
		}

		if len(attrs) < 2 || len(attrs[0].Value) == 0 || len(attrs[1].Value) == 0 {
			return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "missing modulus or exponent"}
		}

		modulus := new(big.Int).SetBytes(attrs[0].Value)
		exponent := new(big.Int).SetBytes(attrs[1].Value)

		pub = &rsa.PublicKey{
			N: modulus,
			E: int(exponent.Int64()),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// rsaPublicExponent65537 is the standard RSA public exponent (0x10001).
var rsaPublicExponent65537 = []byte{0x01, 0x00, 0x01}

// generatedKeySensitive and generatedKeyExtractable are the protection
// attributes written into the private key template of every key pair this
// backend generates on a token, for both RSA and EC.
//
// Both are written explicitly rather than left to the token. PKCS#11 3.2 §4.9
// gives CKA_SENSITIVE and CKA_EXTRACTABLE on a generated private key a default
// that is "token-specific, and may depend on the values of other attributes",
// so a template that omits them produces a differently protected key on every
// module. SoftHSM2 happens to generate CKA_SENSITIVE=CK_TRUE,
// CKA_EXTRACTABLE=CK_FALSE, which is stricter than the specification requires —
// exactly the situation buildImportKeyTemplate warns about, where the tests
// pass and a conforming HSM still hands out a weaker key.
//
// The two attributes answer different questions and are chosen separately:
//
//   - CKA_SENSITIVE=CK_TRUE is what keeps the private key secret. Per the
//     footnotes to the §4.9 attribute tables, the value of a key whose
//     CKA_SENSITIVE is CK_TRUE is never revealed in plaintext, so
//     C_GetAttributeValue cannot read it out.
//
//   - CKA_EXTRACTABLE=CK_FALSE says the key may not be wrapped (§4.9 Table 30).
//     It is not a plaintext-disclosure control — CKA_SENSITIVE already is — and
//     it is one-way: §4.9 permits CK_TRUE to CK_FALSE and never the reverse, so
//     a key generated this way can never be backed up or escrowed, in any form,
//     for its whole lifetime.
//
// CK_FALSE is nevertheless the right value here, and this is a deliberate
// difference from buildImportKeyTemplate, which writes the caller's
// attrs.Exportable policy instead:
//
//   - A key that was generated on the token has never existed anywhere else.
//     Sealing it in is the property the caller asked for by generating in
//     hardware rather than importing, and ExportKey already refuses these keys
//     today — the token answers C_WrapKey with CKR_KEY_UNEXTRACTABLE. Writing
//     CK_FALSE pins that behaviour on every module instead of inheriting it
//     from SoftHSM2 by luck.
//
//   - The generate entry points take no exportability policy from the caller,
//     so there is nothing to honour here the way the import path honours
//     attrs.Exportable. A caller that needs an escrow-capable key generates the
//     material itself and calls ImportKey with Exportable set, which is the
//     path that carries a copy of the key outside the token anyway.
const (
	generatedKeySensitive   = true
	generatedKeyExtractable = false
)

// buildYubiKeyRSATemplates returns the minimal RSA key pair templates required by
// YubiKey's libykcs11. YubiKey PIV slots set CKA_TOKEN, CKA_SIGN, CKA_VERIFY,
// CKA_PRIVATE, and CKA_SENSITIVE automatically based on the slot; supplying them
// explicitly causes CKR_ATTRIBUTE_VALUE_INVALID.
func buildYubiKeyRSATemplates(id []byte, keySize int) (pub, priv []*pkcs11.Attribute) {
	pub = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, rsaPublicExponent65537),
	}
	priv = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	return pub, priv
}

// generateRSAKeyPair generates an RSA key pair on the HSM using the raw PKCS#11 API
// and returns a pkcs11RSASigner wrapping the handles.
//
// When isYubiKeyPIV is true, a minimal attribute template is used as required by
// YubiKey's libykcs11. Otherwise, the full template suitable for SoftHSM and
// generic PKCS#11 modules is used.
//
// The generic private key template names every operation the key is allowed to
// perform, because PKCS#11 3.2 §4.9 defaults the usage flags it omits to
// CK_FALSE: CKA_SIGN and CKA_DECRYPT for the signer and decrypter this returns,
// and CKA_UNWRAP so an imported key can be delivered under this one.
// CKA_DERIVE is deliberately absent — it is the flag C_DeriveKey checks on its
// base key, and no derive mechanism in this backend takes an RSA base key, so
// the §4.9 default of CK_FALSE is the correct value and granting it would widen
// the key's permissions for no operation it can actually perform. That is the
// opposite of generateECDSAKeyPair, whose keys are the base keys of
// CKM_ECDH1_DERIVE.
//
// For CKA_SENSITIVE and CKA_EXTRACTABLE see generatedKeySensitive.
func generateRSAKeyPair(pool *SessionPool, id, label []byte, keySize int, isYubiKeyPIV bool, soPIN, userPIN string) (*pkcs11RSASigner, error) {
	var pubTemplate, privTemplate []*pkcs11.Attribute
	if isYubiKeyPIV {
		pubTemplate, privTemplate = buildYubiKeyRSATemplates(id, keySize)
	} else {
		pubTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, rsaPublicExponent65537),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
		privTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, generatedKeySensitive),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, generatedKeyExtractable),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}
	}

	var pubHandle, privHandle pkcs11.ObjectHandle
	genFn := func(session pkcs11.SessionHandle) error {
		var err error
		pubHandle, privHandle, err = pool.Ctx().GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
			pubTemplate,
			privTemplate,
		)
		return err
	}
	var err error
	if isYubiKeyPIV {
		if soPIN == "" {
			return nil, &errs.Wrapped{Msg: "pkcs11: generate RSA key pair", Err: ErrSOPINRequired}
		}
		err = pool.WithSOSession(soPIN, userPIN, genFn)
	} else {
		err = pool.WithSession(genFn)
	}
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: generate RSA key pair", Err: err}
	}

	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: export RSA public key after generation", Err: err}
	}

	return &pkcs11RSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(label),
	}, nil
}

// generateRSAWrappingKeyPair generates an RSA wrapping key pair with wrap/unwrap capabilities.
// This is used for key import/export operations.
func generateRSAWrappingKeyPair(pool *SessionPool, keyID []byte, keySize int) (*pkcs11RSASigner, error) {
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, keySize),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, rsaPublicExponent65537),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	var pubHandle, privHandle pkcs11.ObjectHandle
	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		pubHandle, privHandle, err = pool.Ctx().GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
			pubTemplate,
			privTemplate,
		)
		return err
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: generate RSA wrapping key pair", Err: err}
	}

	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: export wrapping public key", Err: err}
	}

	return &pkcs11RSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(keyID),
	}, nil
}

// findRSASigner locates an RSA key pair by CKA_ID and returns a pkcs11RSASigner.
func findRSASigner(pool *SessionPool, id []byte) (*pkcs11RSASigner, error) {
	var privHandle, pubHandle pkcs11.ObjectHandle
	var found bool

	err := pool.WithSession(func(session pkcs11.SessionHandle) error {
		// Find private key
		priv, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: FindObjectsInit for RSA private key", Err: err}
		}
		if priv == 0 {
			return nil // not found
		}
		privHandle = priv

		// Find public key
		pub, err := pool.FindObjectHandle(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: FindObjectsInit for RSA public key", Err: err}
		}
		if pub == 0 {
			return nil // private found but no public — unusual but handle gracefully
		}
		pubHandle = pub
		found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, err
	}

	return &pkcs11RSASigner{
		pool:          pool,
		privateHandle: privHandle,
		publicKey:     pub,
		label:         string(id),
	}, nil
}
