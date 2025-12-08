// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package mcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// findKeyByCN searches for a key by its common name and returns the full attributes.
// It uses ListKeys to find all keys and matches by CN.
func (s *Server) findKeyByCN(keyID string) (*types.KeyAttributes, error) {
	keys, err := s.keystore.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	for _, attr := range keys {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, fmt.Errorf("key not found: %s", keyID)
}

// handleHealth handles the health check method
func (s *Server) handleHealth(req *JSONRPCRequest) (interface{}, error) {
	return HealthResult{Status: "healthy"}, nil
}

// handleListBackends handles the listBackends method
func (s *Server) handleListBackends(req *JSONRPCRequest) (interface{}, error) {
	backends := keychain.Backends()
	return ListBackendsResult{Backends: backends}, nil
}

// handleGenerateKey handles the generateKey method
func (s *Server) handleGenerateKey(req *JSONRPCRequest) (interface{}, error) {
	var params GenerateKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	// Create key attributes based on backend type
	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	// Parse backend type
	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	} else {
		attrs.StoreType = types.StorePKCS8 // Default to software
	}

	// Generate key based on type
	var privKey interface{}
	var err error

	switch params.KeyType {
	case "rsa":
		attrs.KeyType = types.KeyTypeTLS
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: params.KeySize,
		}
		if attrs.RSAAttributes.KeySize == 0 {
			attrs.RSAAttributes.KeySize = 2048 // Default
		}
		privKey, err = s.keystore.GenerateRSA(attrs)

	case "ecdsa":
		attrs.KeyType = types.KeyTypeTLS
		attrs.ECCAttributes = &types.ECCAttributes{}
		if params.Curve != "" {
			curve, curveErr := types.ParseCurve(params.Curve)
			if curveErr != nil {
				return nil, fmt.Errorf("invalid curve: %s", params.Curve)
			}
			attrs.ECCAttributes.Curve = curve
		} else {
			defaultCurve, curveErr := types.ParseCurve("P-256")
			if curveErr != nil {
				return nil, fmt.Errorf("invalid default curve: %v", curveErr)
			}
			attrs.ECCAttributes.Curve = defaultCurve
		}
		privKey, err = s.keystore.GenerateECDSA(attrs)

	case "ed25519":
		attrs.KeyType = types.KeyTypeTLS
		privKey, err = s.keystore.GenerateEd25519(attrs)

	case "aes":
		// Handle symmetric key generation
		symBackend, ok := s.keystore.Backend().(types.SymmetricBackend)
		if !ok {
			return nil, fmt.Errorf("backend does not support symmetric operations")
		}

		// Parse algorithm from params.Algorithm or default to AES256-GCM
		algorithm := params.Algorithm
		if algorithm == "" {
			algorithm = "aes256-gcm" // Default
		}

		keyAlgorithm, algErr := types.ParseKeyAlgorithm(algorithm)
		if algErr != nil {
			return nil, fmt.Errorf("invalid algorithm: %s", algorithm)
		}

		attrs.KeyAlgorithm = keyAlgorithm

		// Generate symmetric key
		_, err = symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
		}

		// Notify subscribers
		go s.NotifyEvent("key.created", params.KeyID, map[string]interface{}{
			"key_id":    params.KeyID,
			"backend":   params.Backend,
			"key_type":  params.KeyType,
			"algorithm": algorithm,
		})

		// For symmetric keys, no public key to return
		return GenerateKeyResult{
			KeyID: params.KeyID,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", params.KeyType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Extract public key PEM
	var pubKeyPEM string
	if privKey != nil {
		pubKey, err := extractPublicKey(privKey)
		if err == nil {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err == nil {
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyBytes,
				}
				pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
			}
		}
	}

	// Notify subscribers
	go s.NotifyEvent("key.created", params.KeyID, map[string]interface{}{
		"key_id":  params.KeyID,
		"backend": params.Backend,
	})

	return GenerateKeyResult{
		KeyID:        params.KeyID,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// handleGetKey handles the getKey method
func (s *Server) handleGetKey(req *JSONRPCRequest) (interface{}, error) {
	var params GetKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	// Look up the key to get full attributes
	attrs, err := s.findKeyByCN(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	privKey, err := s.keystore.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Extract public key PEM
	var pubKeyPEM string
	pubKey, err := extractPublicKey(privKey)
	if err == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err == nil {
			pemBlock := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubKeyBytes,
			}
			pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
		}
	}

	return GetKeyResult{
		KeyID:        params.KeyID,
		PublicKeyPEM: pubKeyPEM,
		Backend:      params.Backend,
	}, nil
}

// handleDeleteKey handles the deleteKey method
func (s *Server) handleDeleteKey(req *JSONRPCRequest) (interface{}, error) {
	var params DeleteKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	// Look up the key to get full attributes
	attrs, err := s.findKeyByCN(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	if err := s.keystore.DeleteKey(attrs); err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("key.deleted", params.KeyID, map[string]interface{}{
		"key_id":  params.KeyID,
		"backend": params.Backend,
	})

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleListKeys handles the listKeys method
func (s *Server) handleListKeys(req *JSONRPCRequest) (interface{}, error) {
	keyAttrs, err := s.keystore.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// Convert to KeyInfo structs
	keys := make([]KeyInfo, 0, len(keyAttrs))
	for _, attr := range keyAttrs {
		keys = append(keys, KeyInfo{
			CN: attr.CN,
		})
	}

	return ListKeysResult{
		Keys: keys,
	}, nil
}

// handleSign handles the sign method
func (s *Server) handleSign(req *JSONRPCRequest) (interface{}, error) {
	var params SignParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	// Look up the key to get full attributes
	attrs, err := s.findKeyByCN(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	signer, err := s.keystore.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
	}

	// Ed25519 uses pure signing (no prehashing) - pass raw message with Hash(0)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, err := signer.Sign(nil, params.Data, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}
		return SignResult{
			Signature: signature,
		}, nil
	}

	// Hash the data for other algorithms
	hash, err := parseHashAlgorithm(params.Hash)
	if err != nil {
		return nil, err
	}

	hasher := hash.New()
	hasher.Write(params.Data)
	digest := hasher.Sum(nil)

	// Sign the digest
	signature, err := signer.Sign(nil, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return SignResult{
		Signature: signature,
	}, nil
}

// handleVerify handles the verify method
func (s *Server) handleVerify(req *JSONRPCRequest) (interface{}, error) {
	var params VerifyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	// Look up the key to get full attributes
	attrs, err := s.findKeyByCN(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	// Get the key
	privKey, err := s.keystore.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Convert signature to bytes
	var sigBytes []byte
	switch sig := params.Signature.(type) {
	case []byte:
		sigBytes = sig
	case string:
		// JSON encodes []byte as base64 string, so decode it
		decoded, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			// Not base64, treat as raw bytes
			sigBytes = []byte(sig)
		} else {
			sigBytes = decoded
		}
	case []interface{}:
		// JSON array of numbers (e.g., [0, 255, 128, ...])
		sigBytes = make([]byte, len(sig))
		for i, v := range sig {
			if b, ok := v.(float64); ok {
				sigBytes[i] = byte(b)
			}
		}
	default:
		// Try to marshal and unmarshal
		sigJSON, _ := json.Marshal(params.Signature)
		_ = json.Unmarshal(sigJSON, &sigBytes) // Best-effort unmarshal
	}

	// Ed25519 uses pure verification (no prehashing) - verify against raw data
	if attrs.KeyAlgorithm == x509.Ed25519 {
		valid, err := verifySignature(pubKey, params.Data, sigBytes, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("failed to verify: %w", err)
		}
		return VerifyResult{Valid: valid}, nil
	}

	// Hash the data for other algorithms
	hash, err := parseHashAlgorithm(params.Hash)
	if err != nil {
		return nil, err
	}

	hasher := hash.New()
	hasher.Write(params.Data)
	digest := hasher.Sum(nil)

	// Verify signature
	valid, err := verifySignature(pubKey, digest, sigBytes, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify: %w", err)
	}

	return VerifyResult{
		Valid: valid,
	}, nil
}

// handleSubscribe handles the subscribe method
func (s *Server) handleSubscribe(req *JSONRPCRequest, conn net.Conn) (interface{}, error) {
	var params SubscribeParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Create or update subscriber
	s.subMutex.Lock()
	sub, exists := s.subscribers[conn]
	if !exists {
		sub = &Subscriber{
			conn:   conn,
			events: make(map[string]bool),
		}
		s.subscribers[conn] = sub
	}
	s.subMutex.Unlock()

	// Add events to subscription
	sub.mutex.Lock()
	for _, event := range params.Events {
		sub.events[event] = true
	}
	sub.mutex.Unlock()

	return map[string]interface{}{
		"success":     true,
		"events":      params.Events,
		"total_count": len(sub.events),
	}, nil
}

// handleRotateKey handles the rotateKey method
func (s *Server) handleRotateKey(req *JSONRPCRequest) (interface{}, error) {
	var params RotateKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Rotate the key
	privKey, err := s.keystore.RotateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	// Extract public key PEM
	var pubKeyPEM string
	if privKey != nil {
		pubKey, err := extractPublicKey(privKey)
		if err == nil {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err == nil {
				pemBlock := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyBytes,
				}
				pubKeyPEM = string(pem.EncodeToMemory(pemBlock))
			}
		}
	}

	// Notify subscribers
	go s.NotifyEvent("key.rotated", params.KeyID, map[string]interface{}{
		"key_id":  params.KeyID,
		"backend": params.Backend,
	})

	return RotateKeyResult{
		KeyID:        params.KeyID,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// handleDecrypt handles the decrypt method
func (s *Server) handleDecrypt(req *JSONRPCRequest) (interface{}, error) {
	var params DecryptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Check if this is symmetric decryption (has nonce and tag)
	if len(params.Nonce) > 0 || len(params.Tag) > 0 {
		// Symmetric decryption
		symBackend, ok := s.keystore.Backend().(types.SymmetricBackend)
		if !ok {
			return nil, fmt.Errorf("backend does not support symmetric operations")
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
		}

		encryptedData := &types.EncryptedData{
			Ciphertext: params.Ciphertext,
			Nonce:      params.Nonce,
			Tag:        params.Tag,
		}

		decryptOpts := &types.DecryptOptions{
			AdditionalData: params.AdditionalData,
		}

		plaintext, err := encrypter.Decrypt(encryptedData, decryptOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}

		return DecryptResult{
			Plaintext: plaintext,
		}, nil
	}

	// Asymmetric decryption
	decrypter, err := s.keystore.Decrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypter: %w", err)
	}

	plaintext, err := decrypter.Decrypt(nil, params.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return DecryptResult{
		Plaintext: plaintext,
	}, nil
}

// handleEncrypt handles the encrypt method
func (s *Server) handleEncrypt(req *JSONRPCRequest) (interface{}, error) {
	var params EncryptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	if len(params.Plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Get symmetric backend
	symBackend, ok := s.keystore.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric operations")
	}

	// Get encrypter
	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
	}

	// Prepare encryption options
	encryptOpts := &types.EncryptOptions{
		AdditionalData: params.AdditionalData,
	}

	// Encrypt
	encryptedData, err := encrypter.Encrypt(params.Plaintext, encryptOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return EncryptResult{
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		Tag:        encryptedData.Tag,
	}, nil
}

// handleSaveCert handles the saveCert method
func (s *Server) handleSaveCert(req *JSONRPCRequest) (interface{}, error) {
	var params SaveCertParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	if params.CertPEM == "" {
		return nil, fmt.Errorf("cert_pem is required")
	}

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(params.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if err := s.keystore.SaveCert(params.KeyID, cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("cert.saved", params.KeyID, map[string]interface{}{
		"key_id": params.KeyID,
	})

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleGetCert handles the getCert method
func (s *Server) handleGetCert(req *JSONRPCRequest) (interface{}, error) {
	var params GetCertParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	cert, err := s.keystore.GetCert(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	certPEM := string(pem.EncodeToMemory(pemBlock))

	return GetCertResult{
		KeyID:   params.KeyID,
		CertPEM: certPEM,
	}, nil
}

// handleDeleteCert handles the deleteCert method
func (s *Server) handleDeleteCert(req *JSONRPCRequest) (interface{}, error) {
	var params DeleteCertParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	if err := s.keystore.DeleteCert(params.KeyID); err != nil {
		return nil, fmt.Errorf("failed to delete certificate: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("cert.deleted", params.KeyID, map[string]interface{}{
		"key_id": params.KeyID,
	})

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleListCerts handles the listCerts method
func (s *Server) handleListCerts(req *JSONRPCRequest) (interface{}, error) {
	keyIDs, err := s.keystore.ListCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	return ListCertsResult{
		KeyIDs: keyIDs,
	}, nil
}

// handleCertExists handles the certExists method
func (s *Server) handleCertExists(req *JSONRPCRequest) (interface{}, error) {
	var params CertExistsParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	exists, err := s.keystore.CertExists(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate existence: %w", err)
	}

	return CertExistsResult{
		Exists: exists,
	}, nil
}

// handleSaveCertChain handles the saveCertChain method
func (s *Server) handleSaveCertChain(req *JSONRPCRequest) (interface{}, error) {
	var params SaveCertChainParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	if len(params.ChainPEMs) == 0 {
		return nil, fmt.Errorf("chain_pems is required")
	}

	// Parse all certificates
	chain := make([]*x509.Certificate, 0, len(params.ChainPEMs))
	for i, pemStr := range params.ChainPEMs {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid certificate PEM at index %d", i)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}

		chain = append(chain, cert)
	}

	if err := s.keystore.SaveCertChain(params.KeyID, chain); err != nil {
		return nil, fmt.Errorf("failed to save certificate chain: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("cert.chain.saved", params.KeyID, map[string]interface{}{
		"key_id":      params.KeyID,
		"chain_count": len(chain),
	})

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleGetCertChain handles the getCertChain method
func (s *Server) handleGetCertChain(req *JSONRPCRequest) (interface{}, error) {
	var params GetCertChainParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	chain, err := s.keystore.GetCertChain(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %w", err)
	}

	// Encode all certificates to PEM
	chainPEMs := make([]string, len(chain))
	for i, cert := range chain {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		chainPEMs[i] = string(pem.EncodeToMemory(pemBlock))
	}

	return GetCertChainResult{
		KeyID:     params.KeyID,
		ChainPEMs: chainPEMs,
	}, nil
}

// handleGetTLSCertificate handles the getTLSCertificate method
func (s *Server) handleGetTLSCertificate(req *JSONRPCRequest) (interface{}, error) {
	var params GetTLSCertificateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	tlsCert, err := s.keystore.GetTLSCertificate(params.KeyID, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS certificate: %w", err)
	}

	// Convert certificate to PEM
	var certPEM string
	if len(tlsCert.Certificate) > 0 {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[0],
		}
		certPEM = string(pem.EncodeToMemory(pemBlock))
	}

	// Convert chain to PEM
	chainPEMs := make([]string, 0, len(tlsCert.Certificate)-1)
	for i := 1; i < len(tlsCert.Certificate); i++ {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: tlsCert.Certificate[i],
		}
		chainPEMs = append(chainPEMs, string(pem.EncodeToMemory(pemBlock)))
	}

	// Determine private key type
	var keyType string
	if tlsCert.PrivateKey != nil {
		keyType = fmt.Sprintf("%T", tlsCert.PrivateKey)
	}

	return GetTLSCertificateResult{
		CertPEM:        certPEM,
		ChainPEMs:      chainPEMs,
		PrivateKeyType: keyType,
	}, nil
}

// handleGetImportParameters handles getting import parameters for key import
func (s *Server) handleGetImportParameters(req *JSONRPCRequest) (interface{}, error) {
	var params GetImportParametersParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Check if backend supports import/export
	importExportBackend, ok := s.keystore.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(params.Algorithm)

	// Get import parameters
	importParams, err := importExportBackend.GetImportParameters(attrs, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get import parameters: %w", err)
	}

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(importParams.WrappingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pubKeyPEM := string(pem.EncodeToMemory(pemBlock))

	result := GetImportParametersResult{
		WrappingPublicKeyPEM: pubKeyPEM,
		ImportToken:          importParams.ImportToken,
		Algorithm:            string(importParams.Algorithm),
		KeySpec:              importParams.KeySpec,
	}

	// Add expiration time if present
	if importParams.ExpiresAt != nil {
		expiresAt := importParams.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		result.ExpiresAt = &expiresAt
	}

	return result, nil
}

// handleWrapKey handles wrapping key material for secure transport
func (s *Server) handleWrapKey(req *JSONRPCRequest) (interface{}, error) {
	var params WrapKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Check if backend supports import/export
	importExportBackend, ok := s.keystore.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
	}

	// Parse wrapping public key from PEM
	block, _ := pem.Decode([]byte(params.WrappingPublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid wrapping public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Build import parameters
	importParams := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       params.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(params.Algorithm),
	}

	// Wrap the key material
	wrapped, err := importExportBackend.WrapKey(params.KeyMaterial, importParams)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	return WrapKeyResult{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// handleImportKeyMaterial handles importing externally generated key material
func (s *Server) handleImportKeyMaterial(req *JSONRPCRequest) (interface{}, error) {
	var params ImportKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Check if backend supports import/export
	importExportBackend, ok := s.keystore.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
	}

	// Build wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  params.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(params.Algorithm),
		ImportToken: params.ImportToken,
		Metadata:    params.Metadata,
	}

	// Import the key
	if err := importExportBackend.ImportKey(attrs, wrapped); err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("key.imported", params.KeyID, map[string]interface{}{
		"key_id":  params.KeyID,
		"backend": params.Backend,
	})

	return map[string]interface{}{
		"success": true,
	}, nil
}

// handleExportKeyMaterial handles exporting a key in wrapped form
func (s *Server) handleExportKeyMaterial(req *JSONRPCRequest) (interface{}, error) {
	var params ExportKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Check if backend supports import/export
	importExportBackend, ok := s.keystore.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import/export operations")
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(params.Algorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(attrs, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("key.exported", params.KeyID, map[string]interface{}{
		"key_id":  params.KeyID,
		"backend": params.Backend,
	})

	return ExportKeyResult{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// handleAsymmetricEncrypt handles asymmetric (RSA) encryption
func (s *Server) handleAsymmetricEncrypt(req *JSONRPCRequest) (interface{}, error) {
	var params AsymmetricEncryptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Get the key
	privKey, err := s.keystore.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Extract public key for encryption
	pubKey, err := extractPublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Encrypt with RSA-OAEP
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA key")
	}

	hash := crypto.SHA256
	ciphertext, err := rsa.EncryptOAEP(hash.New(), rand.Reader, rsaPubKey, params.Plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return AsymmetricEncryptResult{
		Ciphertext: ciphertext,
	}, nil
}

// handleAsymmetricDecrypt handles asymmetric (RSA) decryption
func (s *Server) handleAsymmetricDecrypt(req *JSONRPCRequest) (interface{}, error) {
	var params AsymmetricDecryptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if params.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	attrs := &types.KeyAttributes{
		CN: params.KeyID,
	}

	if params.Backend != "" {
		storeType := types.ParseStoreType(params.Backend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid backend: %s", params.Backend)
		}
		attrs.StoreType = storeType
	}

	// Get decrypter
	decrypter, err := s.keystore.Decrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypter: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := decrypter.Decrypt(nil, params.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return AsymmetricDecryptResult{
		Plaintext: plaintext,
	}, nil
}

// handleCopyKey handles copying a key from one backend to another
func (s *Server) handleCopyKey(req *JSONRPCRequest) (interface{}, error) {
	var params CopyKeyParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Validate required fields
	if params.SourceBackend == "" {
		return nil, fmt.Errorf("source_backend is required")
	}
	if params.SourceKeyID == "" {
		return nil, fmt.Errorf("source_key_id is required")
	}
	if params.DestBackend == "" {
		return nil, fmt.Errorf("dest_backend is required")
	}
	if params.DestKeyID == "" {
		return nil, fmt.Errorf("dest_key_id is required")
	}
	if params.Algorithm == "" {
		return nil, fmt.Errorf("algorithm is required")
	}

	// Get source and destination backends
	sourceKS, err := keychain.Backend(params.SourceBackend)
	if err != nil {
		return nil, fmt.Errorf("source backend not found: %w", err)
	}
	sourceBackend, ok := sourceKS.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("source backend does not support import/export operations")
	}

	destKS, err := keychain.Backend(params.DestBackend)
	if err != nil {
		return nil, fmt.Errorf("destination backend not found: %w", err)
	}
	destBackend, ok := destKS.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("destination backend does not support import/export operations")
	}

	// Build source key attributes
	sourceAttrs := &types.KeyAttributes{
		CN: params.SourceKeyID,
	}
	if params.SourceBackend != "" {
		storeType := types.ParseStoreType(params.SourceBackend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid source backend: %s", params.SourceBackend)
		}
		sourceAttrs.StoreType = storeType
	}

	// Build destination key attributes
	destAttrs := &types.KeyAttributes{
		CN: params.DestKeyID,
	}
	if params.DestBackend != "" {
		storeType := types.ParseStoreType(params.DestBackend)
		if storeType == types.StoreUnknown {
			return nil, fmt.Errorf("invalid destination backend: %s", params.DestBackend)
		}
		destAttrs.StoreType = storeType
	}

	// Parse wrapping algorithm
	algorithm := backend.WrappingAlgorithm(params.Algorithm)

	// Export from source backend
	wrapped, err := sourceBackend.ExportKey(sourceAttrs, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	// Import to destination backend
	if err := destBackend.ImportKey(destAttrs, wrapped); err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	// Notify subscribers
	go s.NotifyEvent("key.copied", params.DestKeyID, map[string]interface{}{
		"source_backend": params.SourceBackend,
		"source_key_id":  params.SourceKeyID,
		"dest_backend":   params.DestBackend,
		"dest_key_id":    params.DestKeyID,
	})

	return CopyKeyResult{
		Success: true,
		Message: fmt.Sprintf("Key copied from %s/%s to %s/%s successfully",
			params.SourceBackend, params.SourceKeyID, params.DestBackend, params.DestKeyID),
	}, nil
}
