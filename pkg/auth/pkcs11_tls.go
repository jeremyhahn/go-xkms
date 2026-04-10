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

package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"

	pkcs11module "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// PKCS#11 TLS adapter typed errors.
var (
	ErrPKCS11ModulePathRequired = errors.New("pkcs11: module path is required")
	ErrPKCS11PINRequired        = errors.New("pkcs11: PIN is required")
	ErrPKCS11OpenSession        = errors.New("pkcs11: failed to open session")
	ErrPKCS11Login              = errors.New("pkcs11: login failed")
	ErrPKCS11NoCertFound        = errors.New("pkcs11: no certificate found")
	ErrPKCS11NoKeyFound         = errors.New("pkcs11: no private key found matching certificate")
	ErrPKCS11CertParse          = errors.New("pkcs11: failed to parse certificate")
	ErrPKCS11SignInit           = errors.New("pkcs11: SignInit failed")
	ErrPKCS11Sign               = errors.New("pkcs11: Sign failed")
	ErrPKCS11UnsupportedKeyType = errors.New("pkcs11: unsupported key type for TLS")
	ErrPKCS11NilConfig          = errors.New("pkcs11: config is nil")
	ErrPKCS11ModuleInit         = errors.New("pkcs11: module initialization failed")
)

// PKCS11TLSConfig configures PKCS#11-backed TLS client authentication.
type PKCS11TLSConfig struct {
	// ModulePath is the filesystem path to the PKCS#11 shared object (e.g., libxkey11.so).
	ModulePath string

	// SlotID is the PKCS#11 slot to use (default: 0).
	SlotID int

	// PIN is the token PIN for authentication.
	PIN string

	// CertLabel is an optional filter for finding the certificate by label.
	// When empty, the first certificate found is used.
	CertLabel string

	// CACerts is an optional pool of CA certificates for server verification.
	// When nil, the system root CAs are used.
	CACerts *x509.CertPool

	// Module is an optional pre-initialized PKCS#11 module instance.
	// When set, NewPKCS11TLSConfig skips module creation and initialization,
	// using this module directly. This enables unit testing with the in-memory
	// store without requiring a real PKCS#11 shared object.
	Module *pkcs11module.Module
}

// pkcs11Signer implements crypto.Signer backed by a PKCS#11 token.
// It delegates signing operations to the PKCS#11 module's SignInit + Sign
// operations, keeping private key material within the hardware token boundary.
type pkcs11Signer struct {
	module    *pkcs11module.Module
	session   pkcs11module.SessionHandle
	keyHandle pkcs11module.ObjectHandle
	publicKey crypto.PublicKey
}

// Public returns the public key corresponding to the PKCS#11 private key.
func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign delegates to the PKCS#11 module's C_SignInit + C_Sign operations.
// The mechanism is selected based on the public key type and the hash
// algorithm specified in opts.
func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	mechanism, err := selectMechanism(s.publicKey, opts)
	if err != nil {
		return nil, err
	}

	rv := s.module.SignInit(s.session, mechanism, s.keyHandle)
	if rv != pkcs11module.CKR_OK {
		return nil, &PKCS11TLSError{
			Op:   "SignInit",
			Code: rv,
			Err:  ErrPKCS11SignInit,
		}
	}

	signature, rv := s.module.Sign(s.session, digest)
	if rv != pkcs11module.CKR_OK {
		return nil, &PKCS11TLSError{
			Op:   "Sign",
			Code: rv,
			Err:  ErrPKCS11Sign,
		}
	}

	return signature, nil
}

// PKCS11TLSError wraps a PKCS#11 operation error with context.
type PKCS11TLSError struct {
	Op   string
	Code pkcs11module.CK_RV
	Err  error
}

// Error implements the error interface.
func (e *PKCS11TLSError) Error() string {
	return "pkcs11 tls: " + e.Op + ": " + e.Code.String() + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *PKCS11TLSError) Unwrap() error {
	return e.Err
}

// selectMechanism maps a crypto.PublicKey and crypto.SignerOpts to the
// appropriate PKCS#11 signing mechanism. For TLS handshake signing, the
// digest is pre-hashed, so we use raw mechanisms (CKM_RSA_PKCS for RSA,
// CKM_ECDSA for ECDSA).
//
// Mechanism mapping:
//   - RSA keys: CKM_RSA_PKCS (PKCS#1 v1.5, pre-hashed)
//   - ECDSA keys: CKM_ECDSA (raw ECDSA, pre-hashed)
//   - Ed25519 keys: CKM_EDDSA
func selectMechanism(pub crypto.PublicKey, opts crypto.SignerOpts) (*pkcs11module.Mechanism, error) {
	mechanism, ok := mechanismDispatch(pub, opts)
	if !ok {
		return nil, ErrPKCS11UnsupportedKeyType
	}
	return mechanism, nil
}

// mechanismDispatch selects the PKCS#11 mechanism based on key type and
// signer options. Returns the mechanism and true if a match was found.
func mechanismDispatch(pub crypto.PublicKey, opts crypto.SignerOpts) (*pkcs11module.Mechanism, bool) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return selectRSAMechanism(opts), true
	case *ecdsa.PublicKey:
		return pkcs11module.NewMechanism(pkcs11module.CKM_ECDSA), true
	case ed25519.PublicKey:
		return pkcs11module.NewMechanism(pkcs11module.CKM_EDDSA), true
	default:
		return nil, false
	}
}

// selectRSAMechanism selects the RSA signing mechanism. For TLS, the Go
// standard library provides pre-hashed digests, so we use CKM_RSA_PKCS
// (PKCS#1 v1.5 raw) which accepts DigestInfo-prefixed data. If PSS opts
// are provided, we use CKM_RSA_PKCS_PSS instead.
func selectRSAMechanism(opts crypto.SignerOpts) *pkcs11module.Mechanism {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return pkcs11module.NewMechanism(pkcs11module.CKM_RSA_PKCS_PSS)
	}
	return pkcs11module.NewMechanism(pkcs11module.CKM_RSA_PKCS)
}

// NewPKCS11TLSConfig creates a tls.Config that uses a PKCS#11 token for
// client authentication. It initializes the PKCS#11 module, opens a session,
// authenticates, locates the certificate and matching private key, and
// constructs a tls.Config with a PKCS#11-backed crypto.Signer.
//
// The returned cleanup function must be called when the TLS config is no
// longer needed to close the PKCS#11 session, log out, and release resources.
//
// Per OASIS PKCS#11 specification, the function performs:
//   - C_Initialize (via Module.Initialize)
//   - C_OpenSession with CKF_RW_SESSION | CKF_SERIAL_SESSION
//   - C_Login with CKU_USER
//   - C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal for certificate lookup
//   - C_GetAttributeValue to extract certificate DER bytes and CKA_ID
//   - C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal for private key lookup
//   - Certificate parsing and crypto.Signer construction
func NewPKCS11TLSConfig(cfg *PKCS11TLSConfig) (*tls.Config, func(), error) {
	if cfg == nil {
		return nil, nil, ErrPKCS11NilConfig
	}
	if cfg.Module == nil && cfg.ModulePath == "" {
		return nil, nil, ErrPKCS11ModulePathRequired
	}
	if cfg.PIN == "" {
		return nil, nil, ErrPKCS11PINRequired
	}

	mod := cfg.Module
	moduleOwned := mod == nil

	if moduleOwned {
		// Create and initialize the PKCS#11 module.
		moduleCfg := pkcs11module.DefaultConfig()
		moduleCfg.AutoInitToken = true
		moduleCfg.UserPIN = cfg.PIN
		moduleCfg.SOPIN = cfg.PIN
		moduleCfg.TokenLabel = "pkcs11-tls"

		var err error
		mod, err = pkcs11module.New(pkcs11module.WithConfig(moduleCfg))
		if err != nil {
			return nil, nil, &PKCS11TLSError{Op: "New", Err: ErrPKCS11ModuleInit}
		}

		rv := mod.Initialize(moduleCfg)
		if rv != pkcs11module.CKR_OK {
			return nil, nil, &PKCS11TLSError{
				Op:   "Initialize",
				Code: rv,
				Err:  ErrPKCS11ModuleInit,
			}
		}
	}

	// Track state for cleanup on error.
	var sessionOpened bool
	var session pkcs11module.SessionHandle
	slotID := pkcs11module.SlotID(cfg.SlotID)

	cleanup := func() {
		if sessionOpened {
			mod.Logout(session)
			mod.CloseSession(session)
		}
		if moduleOwned {
			mod.Finalize()
		}
	}

	// Open a read-write session on the specified slot.
	var rv pkcs11module.CK_RV
	session, rv = mod.OpenSession(slotID,
		pkcs11module.CKF_RW_SESSION|pkcs11module.CKF_SERIAL_SESSION)
	if rv != pkcs11module.CKR_OK {
		if moduleOwned {
			mod.Finalize()
		}
		return nil, nil, &PKCS11TLSError{
			Op:   "OpenSession",
			Code: rv,
			Err:  ErrPKCS11OpenSession,
		}
	}
	sessionOpened = true

	// Login as normal user. CKR_USER_ALREADY_LOGGED_IN is acceptable when
	// the caller provides a pre-authenticated module.
	rv = mod.Login(session, pkcs11module.CKU_USER, []byte(cfg.PIN))
	if rv != pkcs11module.CKR_OK && rv != pkcs11module.CKR_USER_ALREADY_LOGGED_IN {
		cleanup()
		return nil, nil, &PKCS11TLSError{
			Op:   "Login",
			Code: rv,
			Err:  ErrPKCS11Login,
		}
	}

	// Find the certificate object.
	certObj, certID, err := findCertificate(mod, session, cfg.CertLabel)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	// Parse the X.509 certificate from DER bytes.
	cert, err := x509.ParseCertificate(certObj)
	if err != nil {
		cleanup()
		return nil, nil, &PKCS11TLSError{Op: "ParseCertificate", Err: ErrPKCS11CertParse}
	}

	// Find the matching private key by CKA_ID.
	keyHandle, err := findPrivateKey(mod, session, certID)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	// Construct the PKCS#11-backed signer.
	signer := &pkcs11Signer{
		module:    mod,
		session:   session,
		keyHandle: keyHandle,
		publicKey: cert.PublicKey,
	}

	// Build the TLS certificate chain.
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certObj},
		PrivateKey:  signer,
		Leaf:        cert,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.CACerts != nil {
		tlsConfig.RootCAs = cfg.CACerts
	}

	return tlsConfig, cleanup, nil
}

// findCertificate searches the token for a certificate object, optionally
// filtered by CertLabel. Returns the DER-encoded certificate bytes and
// the CKA_ID attribute for matching with the private key.
func findCertificate(mod *pkcs11module.Module, session pkcs11module.SessionHandle, certLabel string) ([]byte, []byte, error) {
	// Build the search template for X.509 certificates.
	template := []pkcs11module.Attribute{
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CLASS, uint32(pkcs11module.CKO_CERTIFICATE)),
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CERTIFICATE_TYPE, pkcs11module.CKC_X_509),
	}

	if certLabel != "" {
		template = append(template,
			pkcs11module.NewStringAttribute(pkcs11module.CKA_LABEL, certLabel))
	}

	rv := mod.FindObjectsInit(session, template)
	if rv != pkcs11module.CKR_OK {
		return nil, nil, &PKCS11TLSError{
			Op:   "FindObjectsInit(cert)",
			Code: rv,
			Err:  ErrPKCS11NoCertFound,
		}
	}

	handles, rv := mod.FindObjects(session, 1)
	if rv != pkcs11module.CKR_OK {
		mod.FindObjectsFinal(session)
		return nil, nil, &PKCS11TLSError{
			Op:   "FindObjects(cert)",
			Code: rv,
			Err:  ErrPKCS11NoCertFound,
		}
	}

	mod.FindObjectsFinal(session)

	if len(handles) == 0 {
		return nil, nil, ErrPKCS11NoCertFound
	}

	// Extract CKA_VALUE (DER certificate) and CKA_ID from the certificate object.
	attrTemplate := []pkcs11module.Attribute{
		{Type: pkcs11module.CKA_VALUE},
		{Type: pkcs11module.CKA_ID},
	}

	attrs, rv := mod.GetAttributeValue(session, handles[0], attrTemplate)
	if rv != pkcs11module.CKR_OK {
		return nil, nil, &PKCS11TLSError{
			Op:   "GetAttributeValue(cert)",
			Code: rv,
			Err:  ErrPKCS11NoCertFound,
		}
	}

	var certDER, certID []byte
	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11module.CKA_VALUE:
			certDER = attr.Value
		case pkcs11module.CKA_ID:
			certID = attr.Value
		}
	}

	if len(certDER) == 0 {
		return nil, nil, ErrPKCS11NoCertFound
	}

	return certDER, certID, nil
}

// findPrivateKey searches the token for a private key object matching the
// provided CKA_ID (from the certificate). Per PKCS#11 convention, certificates
// and their corresponding private keys share the same CKA_ID value.
func findPrivateKey(mod *pkcs11module.Module, session pkcs11module.SessionHandle, certID []byte) (pkcs11module.ObjectHandle, error) {
	template := []pkcs11module.Attribute{
		pkcs11module.NewUint32Attribute(pkcs11module.CKA_CLASS, uint32(pkcs11module.CKO_PRIVATE_KEY)),
	}

	// If we have a CKA_ID from the certificate, use it to match the private key.
	if len(certID) > 0 {
		template = append(template, pkcs11module.NewAttribute(pkcs11module.CKA_ID, certID))
	}

	rv := mod.FindObjectsInit(session, template)
	if rv != pkcs11module.CKR_OK {
		return pkcs11module.ObjectHandle(pkcs11module.InvalidHandle), &PKCS11TLSError{
			Op:   "FindObjectsInit(key)",
			Code: rv,
			Err:  ErrPKCS11NoKeyFound,
		}
	}

	handles, rv := mod.FindObjects(session, 1)
	if rv != pkcs11module.CKR_OK {
		mod.FindObjectsFinal(session)
		return pkcs11module.ObjectHandle(pkcs11module.InvalidHandle), &PKCS11TLSError{
			Op:   "FindObjects(key)",
			Code: rv,
			Err:  ErrPKCS11NoKeyFound,
		}
	}

	mod.FindObjectsFinal(session)

	if len(handles) == 0 {
		return pkcs11module.ObjectHandle(pkcs11module.InvalidHandle), ErrPKCS11NoKeyFound
	}

	return handles[0], nil
}

// SelectMechanism is exported for testing purposes. It maps a public key
// and signer options to the appropriate PKCS#11 signing mechanism.
func SelectMechanism(pub crypto.PublicKey, opts crypto.SignerOpts) (*pkcs11module.Mechanism, error) {
	return selectMechanism(pub, opts)
}

// keyTypeForPublicKey returns the PKCS#11 key type constant for the given
// public key. This is used for attribute template construction.
func keyTypeForPublicKey(pub crypto.PublicKey) (uint32, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return uint32(pkcs11module.CKK_RSA), nil
	case *ecdsa.PublicKey:
		return uint32(pkcs11module.CKK_EC), nil
	case ed25519.PublicKey:
		return uint32(pkcs11module.CKK_EC_EDWARDS), nil
	default:
		return 0, ErrPKCS11UnsupportedKeyType
	}
}

// curveByteSize returns the byte size of the private key for the given
// elliptic curve. Used for ECDSA signature length validation.
func curveByteSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// uint32ToBytes converts a uint32 to a little-endian byte slice,
// matching the PKCS#11 attribute encoding convention used by the module.
func uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf
}

// bytesToUint32 converts a little-endian byte slice to uint32,
// matching the PKCS#11 attribute encoding convention.
func bytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(b[:4])
}

// matchesAttributeValue checks if two attribute values are byte-equal.
func matchesAttributeValue(a, b []byte) bool {
	return bytes.Equal(a, b)
}
