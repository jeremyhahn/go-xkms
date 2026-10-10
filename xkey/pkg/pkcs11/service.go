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

// Package pkcs11 provides an EmbeddedTransport implementation of
// xkms.PKCS11Transport. It delegates all 20 transport operations to the
// go-xkms singleton, enabling the PKCS#11 module to operate without a
// remote daemon connection.
package pkcs11

import (
	"context"
	"errors"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// EmbeddedTransport implements xkms.PKCS11Transport by delegating all
// operations to the go-xkms package singleton. This enables the PKCS#11
// module to use an in-process xkms without network overhead.
//
// Every key operation runs in the XKMSService, the one implementation every
// other transport reaches. This type assembles no key attributes, dispatches
// on no algorithm and touches no backend itself: a second copy of those rules
// here is how the two paths drift, and this one had drifted. Its GenerateKey
// knew only RSA, ECDSA and Ed25519, so C_GenerateKey failed for every secret
// key, and its ExportKeyMaterial released the plaintext of a CKA_SENSITIVE key
// the service refuses to export.
type EmbeddedTransport struct{}

// Compile-time interface compliance check.
var _ xkms.PKCS11Transport = (*EmbeddedTransport)(nil)

// NewEmbeddedTransport creates a new embedded transport for the PKCS#11 module.
// The xkms package must be initialized before calling this.
func NewEmbeddedTransport() (*EmbeddedTransport, error) {
	if !xkms.IsInitialized() {
		return nil, ErrServiceNotInitialized
	}
	return &EmbeddedTransport{}, nil
}

// Connect is a no-op for the embedded transport (in-process, no network).
func (t *EmbeddedTransport) Connect(_ context.Context) error {
	return nil
}

// Close is a no-op for the embedded transport (in-process, no network).
func (t *EmbeddedTransport) Close() error {
	return nil
}

// callService runs op, one of the XKMSService's methods, on the process-global
// service. A failure is reported under the operation's sentinel, together
// with ErrServiceNotInitialized when there is no service, or under
// ErrKeyNotFound or ErrBackendNotFound when the service could not find the key
// or backend the request names.
func callService[Req, Resp any](
	ctx context.Context,
	req *Req,
	operation error,
	op func(*xkms.XKMSService, context.Context, *Req) (*Resp, error),
) (*Resp, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	svc, err := xkms.Get()
	if err != nil {
		notInitialized := &SentinelCauseError{Sentinel: ErrServiceNotInitialized, Cause: err}
		return nil, &SentinelCauseError{Sentinel: operation, Cause: notInitialized}
	}
	resp, err := op(svc, ctx, req)
	if err != nil {
		return nil, serviceError(operation, err)
	}
	return resp, nil
}

// serviceLookupErrors maps the xkms service's lookup failures to this
// package's sentinels, so callers match a missing key or backend the same
// way whichever operation reported it.
var serviceLookupErrors = []struct {
	service error
	local   error
}{
	{service: xkms.ServiceErrKeyNotFound, local: ErrKeyNotFound},
	{service: xkms.ServiceErrBackendNotFound, local: ErrBackendNotFound},
}

// serviceError wraps an xkms service failure under this package's sentinel
// for it: the lookup sentinel when the key or backend is missing, otherwise
// the operation's own sentinel.
func serviceError(operation error, err error) error {
	for _, m := range serviceLookupErrors {
		if errors.Is(err, m.service) {
			return &SentinelCauseError{Sentinel: m.local, Cause: err}
		}
	}
	return &SentinelCauseError{Sentinel: operation, Cause: err}
}

// GenerateKey generates a new key in the specified backend through the xkms
// service. Algorithm names the key: RSA (KeySize), ECDSA (Curve), Ed25519, or
// a symmetric algorithm such as the "Symmetric" the module sends for
// CKM_AES_KEY_GEN, which KeySize sizes. KeyType names the key's purpose, and
// Exportable and Sensitive are stored with the key. A symmetric key's response
// carries no public key.
func (t *EmbeddedTransport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return callService(ctx, req, ErrKeyGenerationFailed, (*xkms.XKMSService).GenerateKey)
}

// Sign signs data with the specified key through the xkms service, which
// owns the signing rules: Data is hashed with Hash unless DataIsDigest says
// it already is that digest, Padding selects RSA PKCS#1 v1.5 or PSS with
// SaltLength, and Ed25519 signs the message and refuses a digest.
func (t *EmbeddedTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return callService(ctx, req, ErrSigningFailed, (*xkms.XKMSService).Sign)
}

// Verify verifies a signature with the specified key.
func (t *EmbeddedTransport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return callService(ctx, req, ErrVerifyFailed, (*xkms.XKMSService).Verify)
}

// Encrypt encrypts data with the specified key through the xkms service,
// which owns the cipher rules: Mode selects the symmetric cipher (the key's
// AEAD default when empty), Nonce or IV carries the caller's AEAD nonce or
// CBC IV, AdditionalData and TagSize parameterize the AEAD, and an RSA key
// encrypts with PKCS#1 v1.5.
func (t *EmbeddedTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return callService(ctx, req, ErrEncryptionFailed, (*xkms.XKMSService).Encrypt)
}

// EncryptAsym encrypts plaintext with an RSA public key using OAEP padding,
// through the xkms service.
//
// The module routes CKM_RSA_PKCS_OAEP here rather than through Encrypt because
// the generic encrypt request carries no digest selector, so a caller's
// CK_RSA_PKCS_OAEP_PARAMS.hashAlg would have nowhere to travel. The service
// resolves that digest, rejecting a weak one exactly as the server does, and
// binds the request's OAEP label into the ciphertext.
func (t *EmbeddedTransport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return callService(ctx, req, ErrEncryptionFailed, (*xkms.XKMSService).EncryptAsym)
}

// Decrypt decrypts data with the specified key through the xkms service,
// which honours every parameter Encrypt and EncryptAsym produced: the
// symmetric Mode, IV, AdditionalData, nonce mode and TagSize, and for an
// RSA key the Padding (PKCS#1 v1.5 or OAEP), OAEP Hash and Label.
func (t *EmbeddedTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return callService(ctx, req, ErrDecryptionFailed, (*xkms.XKMSService).Decrypt)
}

// DeriveKey derives a key with the KDF the request names, running the
// derivation in the service layer rather than in this process's address space.
//
// The whole body is a delegation on purpose. The algorithm dispatch, the
// per-construction parameter applicability rules, the hash approval sets and
// the choice of where the KDF executes all live in the one service-layer
// implementation every other transport reaches; a second assembly of them here
// is how the two paths drift, and this one had already drifted twice:
//
//   - It ignored req.Algorithm entirely and always ran HKDF. A
//     CKM_SP800_108_COUNTER_KDF request derived HKDF bytes and returned
//     CKR_OK — wrong key material under a successful status, which no
//     status check can detect.
//   - It resolved a base key named by identity by calling ExportKeyMaterial
//     and running the KDF locally. That is precisely what
//     types.SymmetricKeyDeriver exists to prevent (see its doc comment): the
//     module runs inside the calling application, so pulling a base key's
//     material there either fails outright for a TPM- or HSM-resident key —
//     the keys that most need C_DeriveKey — or strips the protection that
//     made the key worth storing in hardware.
//
// The service layer resolves the base key from exactly one of the two forms
// the request may carry: raw InputKeyMaterial, which is the application's own
// CKA_VALUE arriving from C_CreateObject and is legitimately already in this
// process, or the backend+key identity, which is derived from inside the
// backend that holds the key. A backend that cannot derive from its own stored
// key implements no SymmetricKeyDeriver and the caller receives
// ErrOperationNotSupported naming it, never a local derivation over exported
// material.
func (t *EmbeddedTransport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return callService(ctx, req, ErrDerivationFailed, (*xkms.XKMSService).DeriveKey)
}

// DeriveKeyECDH performs ECDH key agreement with the specified ECDSA key and
// derives a symmetric key from the shared secret, through the xkms service.
// KDFHash defaults to SHA-256 and KeyLength to 32 bytes; KeyVersion selects
// the local key's version, and the response reports the version used.
func (t *EmbeddedTransport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return callService(ctx, req, ErrDerivationFailed, (*xkms.XKMSService).DeriveKeyECDH)
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key
// IDs -- the PKCS#11 C_WrapKey primitive. The XKMSService's WrapKeyByID
// (pkg/xkms/servicer_key.go) encrypts the target key material directly under
// the wrapping key named by req.WrappingKeyID. This is deliberately
// independent of the key-IMPORT ceremony (GetImportParameters / ImportKey),
// which serves an unrelated feature and always wraps under a freshly generated
// ephemeral key pair rather than the caller's own designated wrapping key.
func (t *EmbeddedTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return callService(ctx, req, ErrWrappingFailed, (*xkms.XKMSService).WrapKeyByID)
}

// UnwrapKeyByID unwraps key material and imports it as a new key -- the
// PKCS#11 C_UnwrapKey primitive. The XKMSService's UnwrapKeyByID
// (pkg/xkms/servicer_key.go) decrypts the wrapped material directly with the
// unwrapping key named by req.UnwrappingKeyID and imports the recovered
// plaintext into req.TargetKeyBackend. See WrapKeyByID's doc comment for why
// this does not route through the key-IMPORT ceremony.
func (t *EmbeddedTransport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return callService(ctx, req, ErrWrappingFailed, (*xkms.XKMSService).UnwrapKeyByID)
}

// ExportKeyMaterial exports the raw bytes of an exportable symmetric key
// through the xkms service, which refuses an asymmetric key, a key stored
// non-exportable, and a sensitive key whatever the caller's own copy of
// CKA_SENSITIVE says.
func (t *EmbeddedTransport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return callService(ctx, req, ErrExportFailed, (*xkms.XKMSService).ExportKeyMaterial)
}

// GetImportParameters obtains the wrapping public key and import token a
// key-import ceremony requires, through the xkms service.
//
// It is the first half of the ceremony that ImportKey completes: the caller
// wraps its externally generated key material under the returned public key
// before sending it, so plaintext key material never crosses the boundary.
// The key template (KeyType, KeySize, Curve) is optional; when a kind is
// named, it decides the KeySpec the backend negotiates.
func (t *EmbeddedTransport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return callService(ctx, req, ErrGetImportParamsFailed, (*xkms.XKMSService).GetImportParameters)
}

// ImportKey installs externally generated key material that was wrapped under
// the public key GetImportParameters issued, through the xkms service.
//
// It is the second half of that ceremony. The plaintext key never exists
// outside the backend: what arrives here is the wrapped blob plus the
// single-use import token that binds it to the parameters previously minted
// for this key ID. The service shapes the key from the same template fields
// GetImportParameters read, so the two halves cannot disagree on its kind.
func (t *EmbeddedTransport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return callService(ctx, req, ErrImportKeyFailed, (*xkms.XKMSService).ImportKey)
}

// ListPIVSlots returns the status of all PIV slots in the specified backend.
func (t *EmbeddedTransport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return xkms.ListPIVSlots(ctx, req)
}

// GetPIVCertificate retrieves the certificate from a PIV slot.
func (t *EmbeddedTransport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return xkms.GetPIVCertificate(ctx, req)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
func (t *EmbeddedTransport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return xkms.GeneratePIVKey(ctx, req)
}

// StorePIVCertificate stores a certificate in a PIV slot.
func (t *EmbeddedTransport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return xkms.StorePIVCertificate(ctx, req)
}

// DeletePIVCertificate removes the certificate from a PIV slot.
func (t *EmbeddedTransport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return xkms.DeletePIVCertificate(ctx, req)
}

// ImportPIVCertificate imports an externally issued certificate into a PIV slot.
func (t *EmbeddedTransport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return xkms.ImportPIVCertificate(ctx, req)
}

// ExportPIVCertificate exports the certificate from a PIV slot in the requested format.
func (t *EmbeddedTransport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return xkms.ExportPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (t *EmbeddedTransport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return xkms.GeneratePIVCSR(ctx, req)
}
