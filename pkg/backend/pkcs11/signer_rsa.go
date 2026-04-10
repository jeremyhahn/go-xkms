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
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

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
//   - nil or other: uses CKM_RSA_PKCS (PKCS#1 v1.5) with DigestInfo DER prefix.
func (s *pkcs11RSASigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		return s.signPSS(digest, pssOpts)
	}
	return s.signPKCS1v15(digest, opts)
}

// signPKCS1v15 performs PKCS#1 v1.5 signing by prepending the DigestInfo DER prefix
// and calling CKM_RSA_PKCS on the HSM.
func (s *pkcs11RSASigner) signPKCS1v15(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := crypto.SHA256
	if opts != nil {
		hashFunc = opts.HashFunc()
	}

	prefix, ok := digestInfoPrefix[hashFunc]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported hash for PKCS1v15: %v", ErrUnsupportedOperation, hashFunc)
	}

	// DigestInfo = prefix || digest
	signed := make([]byte, len(prefix)+len(digest))
	copy(signed, prefix)
	copy(signed[len(prefix):], digest)

	var signature []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().SignInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
		}, s.privateHandle); err != nil {
			return fmt.Errorf("pkcs11: RSA PKCS1v15 SignInit: %w", err)
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, signed)
		if err != nil {
			return fmt.Errorf("pkcs11: RSA PKCS1v15 Sign: %w", err)
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
		return nil, fmt.Errorf("%w: unsupported hash for PSS: %v", ErrUnsupportedOperation, hashFunc)
	}

	saltLen := opts.SaltLength
	switch saltLen {
	case rsa.PSSSaltLengthAuto:
		return nil, fmt.Errorf("%w: PSSSaltLengthAuto not supported by PKCS#11", ErrUnsupportedOperation)
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
			return fmt.Errorf("pkcs11: RSA PSS SignInit: %w", err)
		}

		var err error
		signature, err = s.pool.Ctx().Sign(session, digest)
		if err != nil {
			return fmt.Errorf("pkcs11: RSA PSS Sign: %w", err)
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
			return fmt.Errorf("pkcs11: RSA PKCS1v15 DecryptInit: %w", err)
		}

		var err error
		plaintext, err = s.pool.Ctx().Decrypt(session, ciphertext)
		if err != nil {
			return fmt.Errorf("pkcs11: RSA PKCS1v15 Decrypt: %w", err)
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
		return nil, fmt.Errorf("%w: unsupported hash for OAEP: %v", ErrUnsupportedOperation, hashFunc)
	}

	oaepParams := pkcs11.NewOAEPParams(info.hashAlg, info.mgfAlg, pkcs11.CKZ_DATA_SPECIFIED, opts.Label)

	var plaintext []byte
	err := s.pool.WithSession(func(session pkcs11.SessionHandle) error {
		if err := s.pool.Ctx().DecryptInit(session, []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, oaepParams),
		}, s.privateHandle); err != nil {
			return fmt.Errorf("pkcs11: RSA OAEP DecryptInit: %w", err)
		}

		var err error
		plaintext, err = s.pool.Ctx().Decrypt(session, ciphertext)
		if err != nil {
			return fmt.Errorf("pkcs11: RSA OAEP Decrypt: %w", err)
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
			return fmt.Errorf("pkcs11: get RSA public key attributes: %w", err)
		}

		if len(attrs) < 2 || len(attrs[0].Value) == 0 || len(attrs[1].Value) == 0 {
			return fmt.Errorf("%w: missing modulus or exponent", ErrInvalidKeyAttributes)
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
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
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
	if isYubiKeyPIV && soPIN != "" {
		err = pool.WithSOSession(soPIN, userPIN, genFn)
	} else {
		err = pool.WithSession(genFn)
	}
	if err != nil {
		return nil, fmt.Errorf("pkcs11: generate RSA key pair: %w", err)
	}

	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: export RSA public key after generation: %w", err)
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
		return nil, fmt.Errorf("pkcs11: generate RSA wrapping key pair: %w", err)
	}

	pub, err := exportRSAPublicKey(pool, pubHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: export wrapping public key: %w", err)
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
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for RSA private key: %w", err)
		}
		privObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for RSA private key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for RSA private key: %w", err)
		}
		if len(privObjs) == 0 {
			return nil // not found
		}
		privHandle = privObjs[0]

		// Find public key
		if err := pool.Ctx().FindObjectsInit(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsInit for RSA public key: %w", err)
		}
		pubObjs, _, err := pool.Ctx().FindObjects(session, 1)
		if err != nil {
			pool.Ctx().FindObjectsFinal(session)
			return fmt.Errorf("pkcs11: FindObjects for RSA public key: %w", err)
		}
		if err := pool.Ctx().FindObjectsFinal(session); err != nil {
			return fmt.Errorf("pkcs11: FindObjectsFinal for RSA public key: %w", err)
		}
		if len(pubObjs) == 0 {
			return nil // private found but no public — unusual but handle gracefully
		}
		pubHandle = pubObjs[0]
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

// marshalRSAPublicKeyOID returns the DER-encoded OID for RSA keys.
// This is not currently used but kept for potential future PKCS#11 attribute needs.
var rsaOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
