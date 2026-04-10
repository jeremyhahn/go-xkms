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

package services

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

// RemoteBackendInfo describes a server-side backend for the frontend.
type RemoteBackendInfo struct {
	ID             string                        `json:"id"`
	Type           string                        `json:"type"`
	HardwareBacked bool                          `json:"hardware_backed"`
	Capabilities   transport.BackendCapabilities `json:"capabilities"`
}

// RemoteKeyInfo describes a remote key for the frontend.
type RemoteKeyInfo struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	Algorithm    string `json:"algorithm"`
	Backend      string `json:"backend"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// GenerateKeyParams holds parameters for key generation from the frontend.
type GenerateKeyParams struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	Purpose    string `json:"purpose"`   // KeyType: SIGNING, ENCRYPTION, CA, TLS, SECRET, HMAC, ATTESTATION
	Algorithm  string `json:"algorithm"` // rsa, ecdsa, ed25519, aes256-gcm, etc.
	KeyType    string `json:"key_type"`  // Deprecated: use Purpose instead
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Exportable bool   `json:"exportable,omitempty"`

	// TPM-specific options (used when Backend is "tpm2").
	Hierarchy    string `json:"hierarchy,omitempty"`
	Handle       uint32 `json:"handle,omitempty"`
	IsPrimary    bool   `json:"is_primary,omitempty"`
	ParentHandle uint32 `json:"parent_handle,omitempty"`
}

// GenerateKeyResult holds the result of key generation.
type GenerateKeyResult struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Message      string `json:"message"`
}

// ImportKeyParams holds parameters for key import.
type ImportKeyParams struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	KeyType    string `json:"key_type"`
	KeyData    string `json:"key_data"` // base64 encoded
	Format     string `json:"format"`
	Exportable bool   `json:"exportable,omitempty"`
}

// AttestKeyResult holds attestation results.
type AttestKeyResult struct {
	Format           string   `json:"format"`
	CertificateChain []string `json:"certificate_chain"`
	AttestationData  string   `json:"attestation_data"`
	Signature        string   `json:"signature"`
}

// SupportedKeyTypes describes what key types a backend supports.
type SupportedKeyTypes struct {
	Algorithms []string `json:"algorithms"`
	Purposes   []string `json:"purposes"`
	Curves     []string `json:"curves"`
	KeySizes   []int    `json:"key_sizes"`
}

// hardwareBackendTypes contains backend type substrings that indicate
// hardware-backed key storage.
var hardwareBackendTypes = []string{"tpm2", "pkcs11", "phone"}

// KeyService exposes remote key management to the frontend.
// It is bound to the Wails runtime so every exported method is
// callable from the Svelte frontend.
type KeyService struct {
	ctx         context.Context
	log         *slog.Logger
	clientFunc  func() xkms.Client // remote server client
	localClient xkms.Client        // embedded local client (always available after init)
	auditLogger audit.Logger
	registry    backendregistry.Registry
}

// NewKeyService creates a new KeyService.
func NewKeyService() *KeyService {
	return &KeyService{
		log: slog.Default().With("component", "key_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *KeyService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetClientFunc sets the function used to obtain the SDK client.
func (s *KeyService) SetClientFunc(fn func() xkms.Client) {
	s.clientFunc = fn
}

// SetAuditLogger sets the audit logger for key operations.
func (s *KeyService) SetAuditLogger(l audit.Logger) {
	s.auditLogger = l
}

// SetLocalClient sets the embedded local client for local key operations.
func (s *KeyService) SetLocalClient(c xkms.Client) {
	s.localClient = c
}

// SetRegistry sets the backend registry for listing registered backends.
func (s *KeyService) SetRegistry(r backendregistry.Registry) {
	s.registry = r
}

// capabilityMapper maps a backendregistry.Capability to a function that sets
// the corresponding field on transport.BackendCapabilities.
var capabilityMapper = map[backendregistry.Capability]func(*transport.BackendCapabilities){
	backendregistry.CapSigning: func(c *transport.BackendCapabilities) {
		c.Signing = true
		c.Keys = true
	},
	backendregistry.CapEncryption: func(c *transport.BackendCapabilities) {
		c.Decryption = true
		c.Keys = true
	},
	backendregistry.CapAttestation: func(c *transport.BackendCapabilities) {
		c.Attestation = true
	},
	backendregistry.CapSealing: func(c *transport.BackendCapabilities) {
		c.Sealing = true
	},
}

// convertRegistryCapabilities converts a backendregistry capability map
// to a transport.BackendCapabilities struct.
func convertRegistryCapabilities(caps map[backendregistry.Capability]bool) transport.BackendCapabilities {
	var bc transport.BackendCapabilities
	for cap, enabled := range caps {
		if !enabled {
			continue
		}
		if setter, ok := capabilityMapper[cap]; ok {
			setter(&bc)
		}
	}
	return bc
}

// ListRegisteredBackends queries the backend registry for backends that
// support signing or encryption and returns them as RemoteBackendInfo.
// This allows the frontend Generate Key dialog to see all registered
// backends (software, TPM, PKCS11, etc.) regardless of client connectivity.
func (s *KeyService) ListRegisteredBackends() ([]RemoteBackendInfo, error) {
	if s.registry == nil {
		return nil, ErrKeyServiceNoRegistry
	}
	backends := s.registry.List()
	result := make([]RemoteBackendInfo, 0, len(backends))
	for _, rb := range backends {
		// Only include backends that can generate keys (signing or encryption).
		if !rb.HasCapability(backendregistry.CapSigning) && !rb.HasCapability(backendregistry.CapEncryption) {
			continue
		}
		state := rb.State()
		if state == backendregistry.StateError || state == backendregistry.StateOffline {
			continue
		}
		info := RemoteBackendInfo{
			ID:             rb.ID,
			Type:           string(rb.Category),
			HardwareBacked: rb.Category != backendregistry.CategorySoftware,
			Capabilities:   convertRegistryCapabilities(rb.Capabilities),
		}
		result = append(result, info)
	}
	return result, nil
}

// getClient returns the SDK client for the given source ("local" or "server").
func (s *KeyService) getClient(source string) (xkms.Client, error) {
	if source == "local" {
		if s.localClient == nil {
			return nil, ErrKeyServiceNoLocalClient
		}
		return s.localClient, nil
	}
	// Default to server/remote client
	if s.clientFunc == nil {
		return nil, ErrKeyServiceNoClient
	}
	client := s.clientFunc()
	if client == nil {
		return nil, ErrKeyServiceNoClient
	}
	return client, nil
}

// ListBackends returns all available server-side backends.
func (s *KeyService) ListBackends(source string) ([]RemoteBackendInfo, error) {
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListBackends(s.ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RemoteBackendInfo, len(resp.Backends))
	for i, b := range resp.Backends {
		result[i] = convertBackendInfo(&b)
	}
	return result, nil
}

// ListKeyProviders returns full-service backends that support key management.
// The server's Backends() already excludes partial key providers (pkcs8, symmetric,
// quantum, frost, threshold), so this delegates directly to ListBackends.
func (s *KeyService) ListKeyProviders(source string) ([]RemoteBackendInfo, error) {
	return s.ListBackends(source)
}

// GetSupportedKeyTypes returns the key types supported by a specific backend.
// This maps backend capabilities to available algorithms and purposes.
func (s *KeyService) GetSupportedKeyTypes(source, backendID string) (*SupportedKeyTypes, error) {
	backend, err := s.GetBackend(source, backendID)
	if err != nil {
		return nil, err
	}

	result := &SupportedKeyTypes{
		Algorithms: make([]string, 0),
		Purposes:   make([]string, 0),
		Curves:     []string{"P-256", "P-384", "P-521"},
		KeySizes:   []int{2048, 3072, 4096},
	}

	caps := backend.Capabilities

	// Add algorithms based on backend type and capabilities.
	backendType := strings.ToLower(backend.Type)
	switch backendType {
	case "software":
		result.Algorithms = append(result.Algorithms, "rsa", "ecdsa", "ed25519", "aes")
		if caps.QuantumSigning {
			result.Algorithms = append(result.Algorithms, "ml-dsa-44", "ml-dsa-65", "ml-dsa-87")
		}
		if caps.KeyEncapsulation {
			result.Algorithms = append(result.Algorithms, "ml-kem-512", "ml-kem-768", "ml-kem-1024")
		}
	case "tpm2":
		result.Algorithms = append(result.Algorithms, "rsa", "ecdsa")
		result.Curves = []string{"P-256", "P-384"} // TPM typically limits curves
	case "pkcs11":
		result.Algorithms = append(result.Algorithms, "rsa", "ecdsa")
	case "phone":
		result.Algorithms = append(result.Algorithms, "ecdsa")
		result.Curves = []string{"P-256"}
	default:
		result.Algorithms = append(result.Algorithms, "rsa", "ecdsa", "ed25519")
	}

	// Add purposes based on capabilities.
	if caps.Signing {
		result.Purposes = append(result.Purposes, "SIGNING", "CA", "TLS")
	}
	if caps.Decryption {
		result.Purposes = append(result.Purposes, "ENCRYPTION")
	}
	if caps.KeyEncapsulation {
		result.Purposes = append(result.Purposes, "ENCAPSULATION")
	}
	if caps.SymmetricEncryption {
		result.Purposes = append(result.Purposes, "SECRET", "HMAC")
	}
	if caps.Attestation {
		result.Purposes = append(result.Purposes, "ATTESTATION")
	}

	// Ensure at least basic purposes are present.
	if len(result.Purposes) == 0 {
		result.Purposes = []string{"SIGNING", "ENCRYPTION"}
	}

	return result, nil
}

// GetBackend returns information about a specific backend.
func (s *KeyService) GetBackend(source, id string) (*RemoteBackendInfo, error) {
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	b, err := client.GetBackend(s.ctx, id)
	if err != nil {
		return nil, err
	}
	info := convertBackendInfo(b)
	return &info, nil
}

// ListKeys returns the keys stored in a specific backend.
func (s *KeyService) ListKeys(source, backend string) ([]RemoteKeyInfo, error) {
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListKeys(s.ctx, backend)
	if err != nil {
		return nil, err
	}
	result := make([]RemoteKeyInfo, len(resp.Keys))
	for i, k := range resp.Keys {
		result[i] = convertKeyInfo(&k)
	}
	return result, nil
}

// ListAllKeys aggregates keys from every available backend.
func (s *KeyService) ListAllKeys(source string) ([]RemoteKeyInfo, error) {
	backends, err := s.ListBackends(source)
	if err != nil {
		return nil, err
	}
	var all []RemoteKeyInfo
	for _, b := range backends {
		keys, err := s.ListKeys(source, b.ID)
		if err != nil {
			s.log.Warn("failed to list keys for backend",
				"backend", b.ID,
				"error", err)
			continue
		}
		all = append(all, keys...)
	}
	return all, nil
}

// GetKey returns information about a specific key.
func (s *KeyService) GetKey(source, backend, keyID string) (*RemoteKeyInfo, error) {
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetKey(s.ctx, backend, keyID)
	if err != nil {
		return nil, err
	}
	info := convertKeyInfo(&resp.KeyInfo)
	// GetKeyResponse has its own PublicKeyPEM that may override the embedded one.
	if resp.PublicKeyPEM != "" {
		info.PublicKeyPEM = resp.PublicKeyPEM
	}
	return &info, nil
}

// GenerateKey generates a new key in the specified backend.
func (s *KeyService) GenerateKey(source string, req *GenerateKeyParams) (*GenerateKeyResult, error) {
	start := time.Now()
	if req == nil || req.KeyID == "" || req.Backend == "" {
		return nil, ErrKeyInvalidRequest
	}
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	// Map frontend fields to transport request.
	// Purpose is the semantic KeyType (SIGNING, CA, TLS, etc.).
	// Algorithm is the crypto algorithm (rsa, ecdsa, ed25519, aes256-gcm, etc.).
	keyType := req.Purpose
	if keyType == "" {
		keyType = req.KeyType // backwards compat
	}
	resp, err := client.GenerateKey(s.ctx, &transport.GenerateKeyRequest{
		KeyID:      req.KeyID,
		Backend:    req.Backend,
		KeyType:    keyType,
		Algorithm:  req.Algorithm,
		KeySize:    req.KeySize,
		Curve:      req.Curve,
		Exportable: req.Exportable,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyCreated, req.Backend, req.KeyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}
	return &GenerateKeyResult{
		KeyID:        resp.KeyID,
		KeyType:      resp.KeyType,
		PublicKeyPEM: resp.PublicKeyPEM,
		Message:      resp.Message,
	}, nil
}

// DeleteKey deletes a key from the specified backend.
func (s *KeyService) DeleteKey(source, backend, keyID string) error {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return err
	}
	_, err = client.DeleteKey(s.ctx, backend, keyID)
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyDeleted, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	return err
}

// SignData signs base64-encoded data and returns the base64-encoded signature.
func (s *KeyService) SignData(source, backend, keyID, algorithm, data string) (string, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return "", err
	}
	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	resp, err := client.Sign(s.ctx, &transport.SignRequest{
		Backend: backend,
		KeyID:   keyID,
		Hash:    algorithm,
		Data:    rawData,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpSignRequest, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(resp.Signature), nil
}

// VerifySignature verifies a base64-encoded signature over base64-encoded data.
func (s *KeyService) VerifySignature(source, backend, keyID, algorithm, data, signature string) (bool, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return false, err
	}
	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return false, err
	}
	rawSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	resp, err := client.Verify(s.ctx, &transport.VerifyRequest{
		Backend:   backend,
		KeyID:     keyID,
		Hash:      algorithm,
		Data:      rawData,
		Signature: rawSig,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpVerifyRequest, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return false, err
	}
	return resp.Valid, nil
}

// EncryptData encrypts base64-encoded plaintext and returns base64-encoded ciphertext.
func (s *KeyService) EncryptData(source, backend, keyID, algorithm, plaintext string) (string, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return "", err
	}
	rawPlaintext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return "", err
	}
	resp, err := client.Encrypt(s.ctx, &transport.EncryptRequest{
		Backend:   backend,
		KeyID:     keyID,
		Plaintext: rawPlaintext,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpEncryptRequest, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(resp.Ciphertext), nil
}

// DecryptData decrypts base64-encoded ciphertext and returns base64-encoded plaintext.
func (s *KeyService) DecryptData(source, backend, keyID, algorithm, ciphertext string) (string, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return "", err
	}
	rawCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	resp, err := client.Decrypt(s.ctx, &transport.DecryptRequest{
		Backend:    backend,
		KeyID:      keyID,
		Ciphertext: rawCiphertext,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpDecryptRequest, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(resp.Plaintext), nil
}

// ImportKey imports a key into the specified backend. KeyData must be base64-encoded.
func (s *KeyService) ImportKey(source string, req *ImportKeyParams) (*RemoteKeyInfo, error) {
	start := time.Now()
	if req == nil || req.KeyID == "" || req.Backend == "" {
		return nil, ErrKeyInvalidRequest
	}
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	rawKeyData, err := base64.StdEncoding.DecodeString(req.KeyData)
	if err != nil {
		return nil, err
	}
	resp, err := client.ImportKey(s.ctx, &transport.ImportKeyRequest{
		Backend:            req.Backend,
		KeyID:              req.KeyID,
		KeyType:            req.KeyType,
		WrappedKeyMaterial: rawKeyData,
		Algorithm:          req.Format,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyImported, req.Backend, req.KeyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}
	return &RemoteKeyInfo{
		KeyID:        resp.KeyID,
		Backend:      req.Backend,
		PublicKeyPEM: resp.PublicKeyPEM,
	}, nil
}

// ExportKey exports a key and returns the base64-encoded wrapped key material.
func (s *KeyService) ExportKey(source, backend, keyID, format string) (string, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return "", err
	}
	resp, err := client.ExportKey(s.ctx, &transport.ExportKeyRequest{
		Backend:   backend,
		KeyID:     keyID,
		Algorithm: format,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyExported, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(resp.WrappedKeyMaterial), nil
}

// RotateKey rotates the specified key and returns the updated key info.
func (s *KeyService) RotateKey(source, backend, keyID string) (*RemoteKeyInfo, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	resp, err := client.RotateKey(s.ctx, &transport.RotateKeyRequest{
		Backend: backend,
		KeyID:   keyID,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyRotated, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}
	return &RemoteKeyInfo{
		KeyID:        resp.KeyID,
		Backend:      backend,
		PublicKeyPEM: resp.PublicKeyPEM,
	}, nil
}

// AttestKey requests hardware attestation for a key.
func (s *KeyService) AttestKey(source, backend, keyID, nonce string) (*AttestKeyResult, error) {
	start := time.Now()
	client, err := s.getClient(source)
	if err != nil {
		return nil, err
	}
	var nonceBytes []byte
	if nonce != "" {
		nonceBytes, err = base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			return nil, err
		}
	}
	resp, err := client.AttestKey(s.ctx, &transport.AttestKeyRequest{
		Backend: backend,
		KeyID:   keyID,
		Nonce:   nonceBytes,
	})
	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpKeyAttested, backend, keyID, err == nil, err, time.Since(start).Milliseconds())
	}
	if err != nil {
		return nil, err
	}
	chain := make([]string, len(resp.CertificateChain))
	for i, cert := range resp.CertificateChain {
		chain[i] = base64.StdEncoding.EncodeToString(cert)
	}
	return &AttestKeyResult{
		Format:           resp.Format,
		CertificateChain: chain,
		AttestationData:  base64.StdEncoding.EncodeToString(resp.AttestationData),
		Signature:        base64.StdEncoding.EncodeToString(resp.Signature),
	}, nil
}

// BrowseFile opens a native file dialog and returns the selected path.
func (s *KeyService) BrowseFile() (string, error) {
	if s.ctx == nil {
		return "", ErrKeyServiceNoClient
	}
	return wailsruntime.OpenFileDialog(s.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select File",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
}

// SaveFileAs opens a native save-file dialog and returns the chosen path.
func (s *KeyService) SaveFileAs(defaultName string) (string, error) {
	if s.ctx == nil {
		return "", ErrKeyServiceNoClient
	}
	return wailsruntime.SaveFileDialog(s.ctx, wailsruntime.SaveDialogOptions{
		DefaultFilename: defaultName,
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "All Files", Pattern: "*"},
		},
	})
}

// EncryptFile reads a file, encrypts it with the specified key, and writes
// the result to outputPath. The encoding parameter controls the output
// format ("base64" or "hex").
func (s *KeyService) EncryptFile(source, backend, keyID, inputPath, outputPath, encoding string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return ErrFileReadFailed
	}
	b64Input := base64.StdEncoding.EncodeToString(raw)
	ciphertextB64, err := s.EncryptData(source, backend, keyID, "", b64Input)
	if err != nil {
		return err
	}
	var output []byte
	switch encoding {
	case "hex":
		decoded, err := base64.StdEncoding.DecodeString(ciphertextB64)
		if err != nil {
			return err
		}
		output = []byte(hex.EncodeToString(decoded))
	default:
		output = []byte(ciphertextB64)
	}
	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		return ErrFileWriteFailed
	}
	return nil
}

// DecryptFile reads an encrypted file, decrypts it, and writes the raw
// plaintext to outputPath. The inputEncoding parameter indicates how the
// ciphertext file is encoded ("base64" or "hex").
func (s *KeyService) DecryptFile(source, backend, keyID, inputPath, outputPath, inputEncoding string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return ErrFileReadFailed
	}
	var ciphertextB64 string
	switch inputEncoding {
	case "hex":
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		ciphertextB64 = base64.StdEncoding.EncodeToString(decoded)
	default:
		ciphertextB64 = strings.TrimSpace(string(raw))
	}
	plaintextB64, err := s.DecryptData(source, backend, keyID, "", ciphertextB64)
	if err != nil {
		return err
	}
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return ErrFileWriteFailed
	}
	return nil
}

// SignFile reads a file, signs it with the specified key, and writes the
// signature to outputPath. The encoding parameter controls the output
// format ("base64" or "hex").
func (s *KeyService) SignFile(source, backend, keyID, algorithm, inputPath, outputPath, encoding string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return ErrFileReadFailed
	}
	b64Input := base64.StdEncoding.EncodeToString(raw)
	sigB64, err := s.SignData(source, backend, keyID, algorithm, b64Input)
	if err != nil {
		return err
	}
	var output []byte
	switch encoding {
	case "hex":
		decoded, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return err
		}
		output = []byte(hex.EncodeToString(decoded))
	default:
		output = []byte(sigB64)
	}
	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		return ErrFileWriteFailed
	}
	return nil
}

// VerifyFileSignature reads a data file and signature file, then verifies
// the signature. The sigEncoding parameter indicates how the signature
// file is encoded ("base64" or "hex").
func (s *KeyService) VerifyFileSignature(source, backend, keyID, algorithm, dataPath, sigPath, sigEncoding string) (bool, error) {
	dataRaw, err := os.ReadFile(dataPath)
	if err != nil {
		return false, ErrFileReadFailed
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return false, ErrFileReadFailed
	}
	dataB64 := base64.StdEncoding.EncodeToString(dataRaw)
	var sigB64 string
	switch sigEncoding {
	case "hex":
		decoded, err := hex.DecodeString(strings.TrimSpace(string(sigRaw)))
		if err != nil {
			return false, err
		}
		sigB64 = base64.StdEncoding.EncodeToString(decoded)
	default:
		sigB64 = strings.TrimSpace(string(sigRaw))
	}
	return s.VerifySignature(source, backend, keyID, algorithm, dataB64, sigB64)
}

// GetKeyCount returns the total number of remote keys across all backends.
// Returns 0 if an error occurs.
func (s *KeyService) GetKeyCount(source string) int {
	keys, err := s.ListAllKeys(source)
	if err != nil {
		return 0
	}
	return len(keys)
}

// convertBackendInfo converts a transport.BackendInfo to a RemoteBackendInfo.
func convertBackendInfo(b *transport.BackendInfo) RemoteBackendInfo {
	hwBacked := b.HardwareBacked || b.Capabilities.HardwareBacked
	if !hwBacked {
		lower := strings.ToLower(b.Type)
		for _, hwType := range hardwareBackendTypes {
			if strings.Contains(lower, hwType) {
				hwBacked = true
				break
			}
		}
	}
	return RemoteBackendInfo{
		ID:             b.ID,
		Type:           b.Type,
		HardwareBacked: hwBacked,
		Capabilities:   b.Capabilities,
	}
}

// convertKeyInfo converts a transport.KeyInfo to a RemoteKeyInfo.
func convertKeyInfo(k *transport.KeyInfo) RemoteKeyInfo {
	return RemoteKeyInfo{
		KeyID:        k.KeyID,
		KeyType:      k.KeyType,
		Algorithm:    k.Algorithm,
		Backend:      k.Backend,
		PublicKeyPEM: k.PublicKeyPEM,
	}
}
