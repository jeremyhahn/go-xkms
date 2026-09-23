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

package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"

	"github.com/jeremyhahn/go-enclave"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
)

// Attestation provisioning errors.
var (
	// ErrAttestationCertNotIssuedForKey indicates the certificate an SO is
	// installing certifies a different key than the one on this device.
	ErrAttestationCertNotIssuedForKey = errors.New("authenticator: attestation certificate does not certify this device's attestation key")

	// ErrAttestationChainInvalid indicates an attestation certificate chain
	// could not be parsed or does not chain leaf-to-issuer.
	ErrAttestationChainInvalid = errors.New("authenticator: attestation certificate chain is invalid")
)

// attestationCSRCommonNamePrefix prefixes the Common Name of the certificate
// signing request a device emits for its attestation key. The AAGUID follows so
// an operator's CA can tell one authenticator model's requests from another's.
const attestationCSRCommonNamePrefix = "xkey FIDO2 Attestation "

// deviceAttestationSource exposes the Security Officer-provisioned device
// attestation identity — the key held by the KeyManager and the certificate
// chain held in AuthenticatorState — as a keybackend.AttestationKeySource.
//
// This is the consumer the attestation subsystem was missing. The key material
// and its persistence already existed; nothing signed with it.
type deviceAttestationSource struct {
	auth *Authenticator
}

// Compile-time proof that the device identity satisfies the backend contract.
var _ keybackend.AttestationKeySource = (*deviceAttestationSource)(nil)

// GenerateAttestationKey creates a new P-256 device attestation key, wraps it
// under the SO/user key hierarchy and discards any certificate issued for the
// previous key. The manager must be SO-unlocked: provisioning the device
// attestation identity is a Security Officer operation.
func (s *deviceAttestationSource) GenerateAttestationKey() (crypto.Signer, error) {
	if s.auth.keyManager == nil {
		return nil, ErrKeyManagerNoSOPIN
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrKeyGenerationFailed
	}

	// x509 can only marshal onto the heap; NewBufferFromBytes wipes that copy
	// as it moves the encoding into protected memory, and the wrap reads it
	// from there (go-xkms#387).
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrCryptoError
	}
	pkcs8Buf, err := secure.NewBufferFromBytes(pkcs8)
	if err != nil {
		enclave.Wipe(pkcs8)
		return nil, &SentinelCauseError{Sentinel: ErrKeyManagerProtectedMemory, Cause: err}
	}
	defer pkcs8Buf.Destroy()

	if err := s.auth.keyManager.WrapAttestationKey(pkcs8Buf); err != nil {
		return nil, err
	}

	// A certificate issued for the previous key certifies a key this device no
	// longer holds. Keeping it would make every registration fail the
	// certificate/key agreement check instead of cleanly degrading to "none"
	// until the new key is certified.
	s.auth.state.AttestationCert = nil
	s.auth.state.AttestationCertChain = nil

	// The freshly generated key is not returned: the caller signs through the
	// KeyManager signer, which unwraps into protected memory per use. Handing
	// back the *ecdsa.PrivateKey would put a retained plaintext copy back on
	// the Go heap, which is exactly what the wrapped-only design removes.
	return s.auth.keyManager.AttestationSigner()
}

// AttestationSigner returns the provisioned device attestation key.
func (s *deviceAttestationSource) AttestationSigner() (crypto.Signer, error) {
	if s.auth.keyManager == nil {
		return nil, keybackend.ErrNoAttestationKey
	}

	signer, err := s.auth.keyManager.AttestationSigner()
	if err != nil {
		// A device the Security Officer has not provisioned, or one whose key
		// is still wrapped, has no attestation identity. That is reported as an
		// absent key so MakeCredential degrades to "none" rather than failing
		// the registration outright.
		return nil, errors.Join(keybackend.ErrNoAttestationKey, err)
	}

	return signer, nil
}

// AttestationCertificateChain returns the installed chain, leaf first,
// excluding the root the relying party is configured to trust.
func (s *deviceAttestationSource) AttestationCertificateChain() ([]*x509.Certificate, error) {
	// A registration can run concurrently with a Security Officer installing a
	// new chain, so the stored DER is read under the authenticator lock. The
	// provisioning commands hold the write side while they replace it.
	s.auth.mu.RLock()
	defer s.auth.mu.RUnlock()

	if len(s.auth.state.AttestationCert) == 0 {
		return nil, keybackend.ErrNoAttestationCertificate
	}

	chain := make([]*x509.Certificate, 0, 1+len(s.auth.state.AttestationCertChain))

	leaf, err := x509.ParseCertificate(s.auth.state.AttestationCert)
	if err != nil {
		return nil, errors.Join(ErrAttestationChainInvalid, err)
	}
	chain = append(chain, leaf)

	for _, der := range s.auth.state.AttestationCertChain {
		intermediate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, errors.Join(ErrAttestationChainInvalid, parseErr)
		}
		chain = append(chain, intermediate)
	}

	return chain, nil
}

// GetAttestationStatement builds an attestation statement signed by the device
// attestation key. It lets the device identity stand in for an attesting key
// backend on the legacy path, where no key backend is configured.
func (s *deviceAttestationSource) GetAttestationStatement(format string, authData, clientDataHash []byte) (*keybackend.FIDO2AttestationStatement, error) {
	return keybackend.AttestationStatement(s, format, authData, clientDataHash)
}

// AttestationCSR returns a PKCS#10 certificate signing request for the device
// attestation key, in DER form.
//
// The private key never leaves the device: the operator's attestation CA
// certifies the public key in this request and the resulting certificate is
// installed with the setAttestCert vendor command. The request carries the
// Subject-OU and the id-fido-gen-ce-aaguid extension WebAuthn Level 2 §8.2.1
// requires; the CA supplies Subject-C and Subject-O, which name the CA's own
// legal entity and are not knowable on the device.
func (a *Authenticator) AttestationCSR() ([]byte, error) {
	signer, err := a.attestation.AttestationSigner()
	if err != nil {
		return nil, err
	}

	aaguidExtension, err := keybackend.MarshalAAGUIDExtensionValue(a.state.AAGUID[:])
	if err != nil {
		return nil, err
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{keybackend.AttestationCertificateOU},
			CommonName:         attestationCSRCommonNamePrefix + hex.EncodeToString(a.state.AAGUID[:]),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{{
			Id:       keybackend.OIDFIDOGenCEAAGUID,
			Critical: false,
			Value:    aaguidExtension,
		}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, errors.Join(ErrCryptoError, err)
	}

	return csr, nil
}

// InstallAttestationCertificate installs the certificate chain an operator's
// attestation CA issued for this device's attestation key. The leaf comes
// first; intermediates follow in leaf-to-root order and exclude the root, which
// the relying party is configured to trust out of band.
//
// Every check a relying party performs on arrival is performed here, so a chain
// that would be rejected at registration is rejected at provisioning time
// instead of silently disabling attestation later.
func (a *Authenticator) InstallAttestationCertificate(leafDER []byte, intermediateDER [][]byte) error {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return errors.Join(ErrAttestationChainInvalid, err)
	}

	signer, err := a.attestation.AttestationSigner()
	if err != nil {
		return err
	}

	// The certificate must certify the key that will sign attestation
	// statements. Without this check an SO could install a well-formed
	// certificate for an unrelated key and every registration would produce a
	// signature no relying party could verify.
	deviceKey, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !deviceKey.Equal(leaf.PublicKey) {
		return ErrAttestationCertNotIssuedForKey
	}

	if err := keybackend.ValidateAttestationCertificate(leaf, a.state.AAGUID[:]); err != nil {
		return err
	}

	intermediates := make([][]byte, 0, len(intermediateDER))
	previous := leaf
	for _, der := range intermediateDER {
		intermediate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return errors.Join(ErrAttestationChainInvalid, parseErr)
		}
		// x5c must be an ordered chain. Verifying the link here means a relying
		// party's path build cannot fail on ordering alone.
		if err := previous.CheckSignatureFrom(intermediate); err != nil {
			return errors.Join(ErrAttestationChainInvalid, err)
		}
		intermediates = append(intermediates, append([]byte(nil), der...))
		previous = intermediate
	}

	a.state.AttestationCert = append([]byte(nil), leafDER...)
	a.state.AttestationCertChain = intermediates

	return nil
}
