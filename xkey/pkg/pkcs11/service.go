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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// EmbeddedTransport implements xkms.PKCS11Transport by delegating all
// operations to the go-xkms package singleton. This enables the PKCS#11
// module to use an in-process xkms without network overhead.
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

// GenerateKey generates a new key in the specified backend.
func (t *EmbeddedTransport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	attrs := &xkms.KeyAttributes{
		CN:        req.KeyID,
		KeyType:   xkms.KeyTypeSigning,
		StoreType: xkms.StoreType(req.Backend),
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}

	var privKey crypto.PrivateKey

	switch {
	case xkms.AlgorithmRSA.Equals(algorithm):
		keySize := req.KeySize
		if keySize == 0 {
			keySize = xkms.RSAKeySize2048
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkms.RSAAttributes{
			KeySize: keySize,
		}
		privKey, err = ks.GenerateRSA(ctx, attrs)

	case xkms.AlgorithmECDSA.Equals(algorithm):
		curve := req.Curve
		if curve == "" {
			curve = string(xkms.CurveP256)
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := xkms.ParseCurve(curve)
		if curveErr != nil {
			return nil, &WrappedError{Msg: "invalid curve", Err: curveErr}
		}
		attrs.ECCAttributes = &xkms.ECCAttributes{
			Curve: parsedCurve,
		}
		privKey, err = ks.GenerateECDSA(ctx, attrs)

	case xkms.AlgorithmEd25519.Equals(algorithm):
		attrs.KeyAlgorithm = x509.Ed25519
		privKey, err = ks.GenerateEd25519(ctx, attrs)

	default:
		return nil, &MessageError{Msg: fmt.Sprintf("unsupported algorithm: %s", algorithm)}
	}

	if err != nil {
		return nil, &WrappedError{Msg: "failed to generate key", Err: err}
	}

	pubKeyPEM, err := extractPublicKeyPEM(privKey)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to extract public key", Err: err}
	}

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// Sign signs data with the specified key.
func (t *EmbeddedTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	signer, err := ks.Signer(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: err}
	}

	// Ed25519 uses pure signing (no prehashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, signErr := signer.Sign(nil, req.Data, crypto.Hash(0))
		if signErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: signErr}
		}
		return &transport.SignResponse{
			Signature: signature,
		}, nil
	}

	hashAlg := parseHashAlgorithm(req.Hash)
	hasher := hashAlg.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(nil, digest, hashAlg)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSigningFailed, Cause: err}
	}

	return &transport.SignResponse{
		Signature: signature,
	}, nil
}

// Verify verifies a signature with the specified key.
func (t *EmbeddedTransport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	// Get the signer to extract the public key
	signer, err := ks.Signer(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrVerifyFailed, Cause: err}
	}

	pubKey := signer.Public()
	valid := verifySignature(pubKey, req.Data, req.Signature, req.Hash, attrs.KeyAlgorithm)

	return &transport.VerifyResponse{
		Valid: valid,
	}, nil
}

// Encrypt encrypts data with the specified symmetric key.
func (t *EmbeddedTransport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	symBackend, ok := ks.KeyProvider().(xkms.SymmetricKeyProvider)
	if !ok {
		return nil, &DetailError{Err: ErrEncryptionFailed, Detail: ": backend does not support symmetric encryption"}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	encrypter, err := symBackend.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	encrypted, err := encrypter.Encrypt(req.Plaintext, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	return &transport.EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
	}, nil
}

// EncryptAsym encrypts plaintext with an RSA public key using OAEP padding.
//
// The module routes CKM_RSA_PKCS_OAEP here rather than through Encrypt because
// the generic encrypt request carries no digest selector, so a caller's
// CK_RSA_PKCS_OAEP_PARAMS.hashAlg would have nowhere to travel.
//
// The OAEP digest is resolved by the SDK's shared ResolveOAEPHash, not by a
// rule restated here, so this transport rejects a weak digest exactly as the
// server does. Re-deriving that check locally is how two entry points end up
// disagreeing about padding strength.
func (t *EmbeddedTransport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, err
	}

	signer, err := ks.Signer(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &DetailError{Err: ErrEncryptionFailed, Detail: ": key is not RSA, asymmetric encryption requires RSA"}
	}

	hash, err := xkms.ResolveOAEPHash(req.Hash)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(hash.New(), rand.Reader, rsaPub, req.Plaintext, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEncryptionFailed, Cause: err}
	}

	return &transport.EncryptAsymResponse{Ciphertext: ciphertext}, nil
}

// Decrypt decrypts data with the specified symmetric key.
func (t *EmbeddedTransport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	symBackend, ok := ks.KeyProvider().(xkms.SymmetricKeyProvider)
	if !ok {
		return nil, &DetailError{Err: ErrDecryptionFailed, Detail: ": backend does not support symmetric decryption"}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	encrypter, err := symBackend.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDecryptionFailed, Cause: err}
	}

	plaintext, err := encrypter.Decrypt(&xkms.EncryptedData{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDecryptionFailed, Cause: err}
	}

	return &transport.DecryptResponse{
		Plaintext: plaintext,
	}, nil
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
	if req == nil {
		return nil, ErrNilRequest
	}

	service, err := xkms.Get()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrServiceNotInitialized, Cause: err}
	}

	return service.DeriveKey(ctx, req)
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
func (t *EmbeddedTransport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	kap, ok := ks.KeyProvider().(xkms.KeyAgreementProvider)
	if !ok {
		return nil, &DetailError{Err: ErrDerivationFailed, Detail: ": backend does not support key agreement"}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	kdfHash := req.KDFHash
	if kdfHash == "" {
		kdfHash = "SHA-256"
	}
	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = 32
	}

	kdfParams := &xkms.KDFParams{
		Hash:      kdfHash,
		Salt:      req.KDFSalt,
		Info:      req.KDFInfo,
		KeyLength: keyLength,
	}

	derived, err := kap.DeriveKeyECDH(context.Background(), attrs, req.PeerPublicKey, kdfParams)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrDerivationFailed, Cause: err}
	}

	return &transport.DeriveKeyECDHResponse{
		DerivedKey: derived,
	}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key
// IDs -- the PKCS#11 C_WrapKey primitive. It delegates to the XKMSService
// singleton's WrapKeyByID (pkg/xkms/servicer_key.go), which encrypts the
// target key material directly under the wrapping key named by
// req.WrappingKeyID. This is deliberately independent of the key-IMPORT
// ceremony (xkms.ExportKey / xkms.WrapKey / xkms.GetImportParameters), which
// serves an unrelated feature and always wraps under a freshly generated
// ephemeral key pair rather than the caller's own designated wrapping key.
func (t *EmbeddedTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	resp, err := xkms.WrapKeyByID(ctx, req)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWrappingFailed, Cause: err}
	}

	return resp, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key -- the
// PKCS#11 C_UnwrapKey primitive. It delegates to the XKMSService singleton's
// UnwrapKeyByID (pkg/xkms/servicer_key.go), which decrypts the wrapped
// material directly with the unwrapping key named by req.UnwrappingKeyID and
// imports the recovered plaintext into req.TargetKeyBackend. See
// WrapKeyByID's doc comment for why this does not route through the
// key-IMPORT ceremony.
func (t *EmbeddedTransport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	resp, err := xkms.UnwrapKeyByID(ctx, req)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWrappingFailed, Cause: err}
	}

	return resp, nil
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
func (t *EmbeddedTransport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, &DetailError{Err: ErrBackendNotFound, Detail: fmt.Sprintf(": %s", req.Backend)}
	}

	ieBackend, ok := ks.KeyProvider().(xkms.ImportExportBackend)
	if !ok {
		return nil, &DetailError{Err: ErrExportFailed, Detail: ": backend does not support key material export"}
	}

	attrs, err := findKeyAttributes(ctx, ks, req.KeyID)
	if err != nil {
		return nil, &DetailError{Err: ErrKeyNotFound, Detail: fmt.Sprintf(": %s", req.KeyID)}
	}

	keyMaterial, err := ieBackend.ExportKeyMaterial(ctx, attrs)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrExportFailed, Cause: err}
	}

	// KeyType names the algorithm family of the material just exported, and it
	// is resolved by the one canonical method so this transport cannot report a
	// family the key is not addressed under (go-xkms#336, #402). The daemon-side
	// producer of the same response field answers with the key's symmetric
	// algorithm; AlgorithmString agrees with it here, because a backend only
	// releases raw material for a single-family symmetric key -- it refuses a
	// descriptor naming two families and refuses anything asymmetric outright.
	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: keyMaterial,
		KeyType:     attrs.AlgorithmString(),
		KeySize:     len(keyMaterial) * 8,
	}, nil
}

// GetImportParameters obtains the wrapping public key and import token a
// key-import ceremony requires, delegating to the in-process xkms backend.
//
// It is the first half of the ceremony that ImportKey completes: the caller
// wraps its externally generated key material under the returned public key
// before sending it, so plaintext key material never crosses the boundary.
//
// The key template is optional. A caller that has not chosen a key kind can
// still request a wrapping key; when a kind is named, it decides the KeySpec
// the backend negotiates. Only asymmetric kinds are honoured here, matching
// what this transport's GenerateKey produces -- a symmetric template is refused
// rather than negotiated for a key spec the embedded module cannot fulfil.
func (t *EmbeddedTransport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	attrs := &xkms.KeyAttributes{
		CN:        req.KeyID,
		StoreType: xkms.StoreType(req.Backend),
	}
	if err := applyImportKeyTemplate(attrs, req); err != nil {
		return nil, err
	}

	params, err := xkms.ServiceGetImportParameters(
		ctx, req.Backend, attrs, xkms.WrappingAlgorithm(req.Algorithm),
	)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrGetImportParamsFailed, Cause: err}
	}

	wrappingPubKeyBytes, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		return nil, &WrappedError{Msg: "marshal wrapping public key", Err: err}
	}

	resp := &transport.GetImportParametersResponse{
		WrappingPublicKey: wrappingPubKeyBytes,
		ImportToken:       params.ImportToken,
		Algorithm:         string(params.Algorithm),
		KeySpec:           params.KeySpec,
	}
	if params.ExpiresAt != nil {
		resp.ExpiresAt = params.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return resp, nil
}

// applyImportKeyTemplate sets the asymmetric key kind on attrs from an import
// request, using the same mapping as GenerateKey so the negotiated KeySpec
// agrees with what this transport can generate.
//
// An empty key type is left untouched: the caller is asking for a wrapping key
// without committing to a kind. A symmetric or otherwise unrecognised type is
// refused, because negotiating import parameters for a key the embedded module
// does not produce would return a KeySpec the caller cannot satisfy.
func applyImportKeyTemplate(attrs *xkms.KeyAttributes, req *transport.GetImportParametersRequest) error {
	return applyKeyTemplate(attrs, keyTemplate{
		KeyType: req.KeyType,
		KeySize: req.KeySize,
		Curve:   req.Curve,
	})
}

// keyTemplate is the key-shape subset shared by GetImportParametersRequest and
// ImportKeyRequest.
//
// The two requests carry identical shape fields and MUST produce identical key
// attributes: the wrapping parameters are minted from one and the key is
// installed from the other, so any divergence yields a key that imports
// "successfully" at the wrong size or curve — a failure that surfaces much
// later, as a signature nobody can verify. One template function, two callers.
type keyTemplate struct {
	KeyType string
	KeySize int
	Curve   string
}

// applyKeyTemplate sets the asymmetric key kind on attrs from a key template.
// An empty KeyType leaves attrs untouched, which is how symmetric imports opt
// out of asymmetric shaping.
func applyKeyTemplate(attrs *xkms.KeyAttributes, tmpl keyTemplate) error {
	if tmpl.KeyType == "" {
		return nil
	}

	switch {
	case xkms.AlgorithmRSA.Equals(tmpl.KeyType):
		keySize := tmpl.KeySize
		if keySize == 0 {
			keySize = xkms.RSAKeySize2048
		}
		attrs.KeyType = xkms.KeyTypeSigning
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkms.RSAAttributes{KeySize: keySize}
		return nil

	case xkms.AlgorithmECDSA.Equals(tmpl.KeyType):
		curve := tmpl.Curve
		if curve == "" {
			curve = string(xkms.CurveP256)
		}
		parsedCurve, err := xkms.ParseCurve(curve)
		if err != nil {
			return &WrappedError{Msg: "invalid curve", Err: err}
		}
		attrs.KeyType = xkms.KeyTypeSigning
		attrs.KeyAlgorithm = x509.ECDSA
		attrs.ECCAttributes = &xkms.ECCAttributes{Curve: parsedCurve}
		return nil

	case xkms.AlgorithmEd25519.Equals(tmpl.KeyType):
		attrs.KeyType = xkms.KeyTypeSigning
		attrs.KeyAlgorithm = x509.Ed25519
		return nil

	default:
		return &DetailError{Err: ErrImportTemplateUnsupported, Detail: ": " + tmpl.KeyType}
	}
}

// ImportKey installs externally generated key material that was wrapped under
// the public key GetImportParameters issued.
//
// It is the second half of that ceremony. The plaintext key never exists
// outside the backend: what arrives here is the wrapped blob plus the
// single-use import token that binds it to the parameters previously minted
// for this key ID.
func (t *EmbeddedTransport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	attrs := &xkms.KeyAttributes{
		CN:        req.KeyID,
		StoreType: xkms.StoreType(req.Backend),
	}
	if err := applyKeyTemplate(attrs, keyTemplate{
		KeyType: req.KeyType,
		KeySize: req.KeySize,
		Curve:   req.Curve,
	}); err != nil {
		return nil, err
	}

	wrapped := &xkms.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   xkms.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
	}

	if err := xkms.ServiceImportKey(ctx, req.Backend, attrs, wrapped); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrImportKeyFailed, Cause: err}
	}

	return &transport.ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
	}, nil
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

// ========================================================================
// Helper Functions
// ========================================================================

// findKeyAttributes searches for a key by ID in the given keystore.
func findKeyAttributes(ctx context.Context, ks xkms.ServiceBackend, keyID string) (*xkms.KeyAttributes, error) {
	attrs, err := ks.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, ErrKeyNotFound
}

// parseHashAlgorithm parses a hash algorithm name into a crypto.Hash value.
// Uses map-based dispatch for O(1) constant-time lookup.
var hashAlgorithms = map[string]crypto.Hash{
	"sha256":  crypto.SHA256,
	"SHA256":  crypto.SHA256,
	"sha384":  crypto.SHA384,
	"SHA384":  crypto.SHA384,
	"sha512":  crypto.SHA512,
	"SHA512":  crypto.SHA512,
	"sha1":    crypto.SHA1,
	"SHA1":    crypto.SHA1,
	"sha-256": crypto.SHA256,
	"sha-384": crypto.SHA384,
	"sha-512": crypto.SHA512,
	"SHA-256": crypto.SHA256,
	"SHA-384": crypto.SHA384,
	"SHA-512": crypto.SHA512,
}

func parseHashAlgorithm(name string) crypto.Hash {
	if h, ok := hashAlgorithms[name]; ok {
		return h
	}
	return crypto.SHA256
}

// signerPublicKey is satisfied by every crypto.PrivateKey this function
// receives in practice: the stdlib *rsa.PrivateKey, *ecdsa.PrivateKey and
// ed25519.PrivateKey all implement it directly, and so does *opaque.Opaque,
// the wrapper xkms.ServiceBackend.GenerateRSA/GenerateECDSA/GenerateEd25519
// actually return so hardware-backed key material never has to leave the
// backend. A type switch on the three stdlib concrete types alone rejected
// every key GenerateKey's own callers hand it, with "unsupported key type:
// *opaque.Opaque" -- the extraction step failed for every backend, not a
// specific one.
type signerPublicKey interface {
	Public() crypto.PublicKey
}

// extractPublicKeyPEM extracts the public key from a private key and returns it as PEM.
func extractPublicKeyPEM(privKey crypto.PrivateKey) (string, error) {
	signer, ok := privKey.(signerPublicKey)
	if !ok {
		return "", &MessageError{Msg: fmt.Sprintf("unsupported key type: %T", privKey)}
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", &WrappedError{Msg: "failed to marshal public key", Err: err}
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// verifySignature verifies a signature against the given public key.
func verifySignature(pubKey crypto.PublicKey, data, signature []byte, hashName string, keyAlg x509.PublicKeyAlgorithm) bool {
	switch keyAlg {
	case x509.Ed25519:
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(edKey, data, signature)

	case x509.ECDSA:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		hashAlg := parseHashAlgorithm(hashName)
		hasher := hashAlg.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return ecdsa.VerifyASN1(ecKey, digest, signature)

	case x509.RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		hashAlg := parseHashAlgorithm(hashName)
		hasher := hashAlg.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return rsa.VerifyPKCS1v15(rsaKey, hashAlg, digest, signature) == nil

	default:
		return false
	}
}
