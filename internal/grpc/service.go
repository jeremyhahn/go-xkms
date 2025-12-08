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

package grpc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	pb "github.com/jeremyhahn/go-keychain/api/proto/keychainv1"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// getBackendDescription returns a human-readable description for a backend type
func getBackendDescription(bt types.BackendType) string {
	descriptions := map[types.BackendType]string{
		types.BackendTypePKCS8:        "Software-based PKCS#8 key storage",
		types.BackendTypePKCS11:       "Hardware Security Module (PKCS#11)",
		types.BackendTypeTPM2:         "Trusted Platform Module 2.0",
		types.BackendTypeAWSKMS:       "AWS Key Management Service",
		types.BackendTypeGCPKMS:       "Google Cloud Key Management Service",
		types.BackendTypeAzureKV:      "Azure Key Vault",
		types.BackendTypeVault:        "HashiCorp Vault",
		types.BackendTypeSoftware:     "Software-based key storage with AES encryption",
		types.BackendTypeAES:          "AES-GCM encrypted key storage",
		types.BackendTypeSmartCardHSM: "SmartCard-HSM (Nitrokey, CardContact)",
	}

	if desc, ok := descriptions[bt]; ok {
		return desc
	}

	return string(bt)
}

// Service implements the KeystoreService gRPC interface
type Service struct {
	pb.UnimplementedKeystoreServiceServer
}

// NewService creates a new gRPC service
// The service uses the global keychain service for backend management
func NewService() *Service {
	return &Service{}
}

// Health returns the health status of the service
func (s *Service) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Status:  "healthy",
		Version: keychain.Version(),
	}, nil
}

// ListBackends returns all available backend providers
func (s *Service) ListBackends(ctx context.Context, req *pb.ListBackendsRequest) (*pb.ListBackendsResponse, error) {
	backendNames := keychain.Backends()

	backends := make([]*pb.BackendInfo, 0, len(backendNames))
	for _, name := range backendNames {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue // Skip backends that can't be retrieved
		}

		backend := ks.Backend()
		caps := backend.Capabilities()

		backends = append(backends, &pb.BackendInfo{
			Name:               name,
			Type:               string(backend.Type()),
			Description:        getBackendDescription(backend.Type()),
			HardwareBacked:     caps.HardwareBacked,
			SupportsSigning:    caps.Signing,
			SupportsDecryption: caps.Decryption,
			SupportsRotation:   caps.KeyRotation,
		})
	}

	return &pb.ListBackendsResponse{
		Backends: backends,
		Count:    int32(len(backends)), // #nosec G115 - Backend count fits in int32
	}, nil
}

// GetBackendInfo returns detailed information about a specific backend
func (s *Service) GetBackendInfo(ctx context.Context, req *pb.GetBackendInfoRequest) (*pb.GetBackendInfoResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "backend name is required")
	}

	ks, err := keychain.Backend(req.Name)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	backend := ks.Backend()
	caps := backend.Capabilities()

	return &pb.GetBackendInfoResponse{
		Backend: &pb.BackendInfo{
			Name:               req.Name,
			Type:               string(backend.Type()),
			Description:        getBackendDescription(backend.Type()),
			HardwareBacked:     caps.HardwareBacked,
			SupportsSigning:    caps.Signing,
			SupportsDecryption: caps.Decryption,
			SupportsRotation:   caps.KeyRotation,
		},
	}, nil
}

// GenerateKey generates a new cryptographic key
func (s *Service) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	// Validate request
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	// Get keystore
	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Parse key type
	keyType := types.ParseKeyType(req.KeyType)
	// Default to KeyTypeSigning if the parsed key type is invalid
	// (e.g., when req.KeyType is an algorithm name like "rsa", "ecdsa", "ed25519")
	if keyType == 0 {
		keyType = types.KeyTypeSigning
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   keyType,
		StoreType: types.StoreType(req.Backend),
		Hash:      parseHashAlgorithm(req.Hash),
		Partition: types.Partition(req.Partition),
	}

	// Set algorithm-specific attributes
	var privKey crypto.PrivateKey
	switch strings.ToLower(req.KeyType) {
	case "rsa":
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = 2048 // Default
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
		privKey, err = ks.GenerateRSA(attrs)

	case "ecdsa":
		curve := req.Curve
		if curve == "" {
			curve = "P256" // Default
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
		privKey, err = ks.GenerateECDSA(attrs)

	case "ed25519":
		attrs.KeyAlgorithm = x509.Ed25519
		privKey, err = ks.GenerateEd25519(attrs)

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type: %s", req.KeyType)
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
	}

	// Extract public key PEM
	publicKeyPem, err := extractPublicKeyPEM(privKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract public key: %v", err)
	}

	return &pb.GenerateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      req.KeyType,
		PublicKeyPem: publicKeyPem,
		CreatedAt:    timestamppb.Now(),
	}, nil
}

// ListKeys lists all keys in the specified backend
func (s *Service) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	// Apply pagination
	offset := int(req.Offset)
	limit := int(req.Limit)
	if limit == 0 {
		limit = 100 // Default limit
	}

	end := offset + limit
	if end > len(attrs) {
		end = len(attrs)
	}
	if offset > len(attrs) {
		offset = len(attrs)
	}

	paginatedAttrs := attrs[offset:end]

	// Convert to protobuf format
	keys := make([]*pb.KeyInfo, len(paginatedAttrs))
	for i, attr := range paginatedAttrs {
		keys[i] = &pb.KeyInfo{
			KeyId:     attr.CN,
			Backend:   req.Backend,
			KeyType:   string(attr.KeyType),
			Algorithm: getAlgorithmString(attr),
			Partition: string(attr.Partition),
			CreatedAt: timestamppb.Now(), // Note: actual creation time not tracked in KeyAttributes
		}

		// Add algorithm-specific info
		if attr.RSAAttributes != nil {
			keys[i].KeySize = int32(attr.RSAAttributes.KeySize) // #nosec G115 - RSA key size fits in int32
		}
		if attr.ECCAttributes != nil {
			keys[i].Curve = types.CurveName(attr.ECCAttributes.Curve)
		}
	}

	return &pb.ListKeysResponse{
		Keys:  keys,
		Total: int32(len(attrs)), // #nosec G115 - Key count fits in int32
	}, nil
}

// GetKey retrieves information about a specific key
func (s *Service) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// List all keys and find the matching one
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list keys: %v", err)
	}

	for _, attr := range attrs {
		if attr.CN == req.KeyId {
			keyInfo := &pb.KeyInfo{
				KeyId:     attr.CN,
				Backend:   req.Backend,
				KeyType:   string(attr.KeyType),
				Algorithm: getAlgorithmString(attr),
				Partition: string(attr.Partition),
				CreatedAt: timestamppb.Now(),
			}

			if attr.RSAAttributes != nil {
				keyInfo.KeySize = int32(attr.RSAAttributes.KeySize) // #nosec G115 - RSA key size fits in int32
			}
			if attr.ECCAttributes != nil {
				keyInfo.Curve = types.CurveName(attr.ECCAttributes.Curve)
			}

			return &pb.GetKeyResponse{
				Key: keyInfo,
			}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "key not found: %s", req.KeyId)
}

// Sign signs data with the specified key
func (s *Service) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get signer
	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get signer: %v", err)
	}

	// Ed25519 uses pure signing (no prehashing) - pass raw message with Hash(0)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, err := signer.Sign(nil, req.Data, crypto.Hash(0))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
		}
		return &pb.SignResponse{
			Signature: signature,
		}, nil
	}

	// Determine hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)
	cryptoHash := hashAlg

	// Hash the data
	hasher := cryptoHash.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	// Sign
	signature, err := signer.Sign(nil, digest, cryptoHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign: %v", err)
	}

	return &pb.SignResponse{
		Signature: signature,
	}, nil
}

// Verify verifies a signature with the specified key
func (s *Service) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data is required")
	}
	if len(req.Signature) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the key
	privKey, err := ks.GetKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get key: %v", err)
	}

	// Extract public key
	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		// Handle OpaqueKey and other Signer implementations
		pubKey = k.Public()
	default:
		return nil, status.Error(codes.Internal, "unsupported key type")
	}

	// Determine hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)
	cryptoHash := hashAlg

	// Hash the data
	hasher := cryptoHash.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	// Verify signature based on public key type
	valid := false
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, cryptoHash, digest, req.Signature)
		valid = (err == nil)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(pub, digest, req.Signature)
	case ed25519.PublicKey:
		valid = ed25519.Verify(pub, req.Data, req.Signature)
	}

	message := "signature is valid"
	if !valid {
		message = "signature is invalid"
	}

	return &pb.VerifyResponse{
		Valid:   valid,
		Message: message,
	}, nil
}

// DeleteKey deletes a key from the backend
func (s *Service) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Delete the key
	err = ks.DeleteKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete key: %v", err)
	}

	return &pb.DeleteKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s deleted successfully", req.KeyId),
	}, nil
}

// RotateKey rotates an existing key
func (s *Service) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Rotate the key
	newKey, err := ks.RotateKey(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to rotate key: %v", err)
	}

	// Extract public key PEM
	publicKeyPem, err := extractPublicKeyPEM(newKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract public key: %v", err)
	}

	return &pb.RotateKeyResponse{
		KeyId:        req.KeyId,
		Backend:      req.Backend,
		KeyType:      string(attrs.KeyType),
		PublicKeyPem: publicKeyPem,
		RotatedAt:    timestamppb.Now(),
	}, nil
}

// Encrypt encrypts data with the specified key (symmetric encryption)
func (s *Service) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the backend to check if it supports symmetric encryption
	backendImpl := ks.Backend()
	symmetricBackend, ok := backendImpl.(types.SymmetricBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support symmetric encryption", req.Backend)
	}

	// Get symmetric encrypter
	encrypter, err := symmetricBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get symmetric encrypter: %v", err)
	}

	// Build encrypt options
	opts := &types.EncryptOptions{
		AdditionalData: req.AdditionalData,
	}

	// Encrypt the data
	encryptedData, err := encrypter.Encrypt(req.Plaintext, opts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt: %v", err)
	}

	return &pb.EncryptResponse{
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		Tag:        encryptedData.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key
func (s *Service) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get decrypter
	decrypter, err := ks.Decrypter(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get decrypter: %v", err)
	}

	// Decrypt
	plaintext, err := decrypter.Decrypt(nil, req.Ciphertext, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decrypt: %v", err)
	}

	return &pb.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}

// SaveCert stores a certificate
func (s *Service) SaveCert(ctx context.Context, req *pb.SaveCertRequest) (*pb.SaveCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.CertPem == "" {
		return nil, status.Error(codes.InvalidArgument, "cert_pem is required")
	}

	// Parse PEM to certificate
	cert, err := parseCertFromPEM(req.CertPem)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid certificate PEM: %v", err)
	}

	// Get any backend's keystore for cert operations (they all share the same cert storage)
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate
	err = ks.SaveCert(req.KeyId, cert)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save certificate: %v", err)
	}

	return &pb.SaveCertResponse{
		Success: true,
		Message: fmt.Sprintf("certificate for %s saved successfully", req.KeyId),
	}, nil
}

// GetCert retrieves a certificate
func (s *Service) GetCert(ctx context.Context, req *pb.GetCertRequest) (*pb.GetCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate
	cert, err := ks.GetCert(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "certificate not found: %v", err)
	}

	// Convert to PEM
	certPem := encodeCertToPEM(cert)

	return &pb.GetCertResponse{
		CertPem: certPem,
	}, nil
}

// DeleteCert removes a certificate
func (s *Service) DeleteCert(ctx context.Context, req *pb.DeleteCertRequest) (*pb.DeleteCertResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Delete the certificate
	err = ks.DeleteCert(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete certificate: %v", err)
	}

	return &pb.DeleteCertResponse{
		Success: true,
		Message: fmt.Sprintf("certificate for %s deleted successfully", req.KeyId),
	}, nil
}

// ListCerts lists all certificates
func (s *Service) ListCerts(ctx context.Context, req *pb.ListCertsRequest) (*pb.ListCertsResponse, error) {
	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// List certificates
	keyIDs, err := ks.ListCerts()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list certificates: %v", err)
	}

	return &pb.ListCertsResponse{
		KeyIds: keyIDs,
		Total:  int32(len(keyIDs)), // #nosec G115 - Certificate count fits in int32
	}, nil
}

// CertExists checks if a certificate exists
func (s *Service) CertExists(ctx context.Context, req *pb.CertExistsRequest) (*pb.CertExistsResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Check if certificate exists
	exists, err := ks.CertExists(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check certificate existence: %v", err)
	}

	return &pb.CertExistsResponse{
		Exists: exists,
	}, nil
}

// SaveCertChain stores a certificate chain
func (s *Service) SaveCertChain(ctx context.Context, req *pb.SaveCertChainRequest) (*pb.SaveCertChainResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if len(req.CertChainPem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cert_chain_pem is required")
	}

	// Parse PEM chain to certificates
	chain := make([]*x509.Certificate, len(req.CertChainPem))
	for i, certPem := range req.CertChainPem {
		cert, err := parseCertFromPEM(certPem)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid certificate PEM at index %d: %v", i, err)
		}
		chain[i] = cert
	}

	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Save the certificate chain
	err = ks.SaveCertChain(req.KeyId, chain)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save certificate chain: %v", err)
	}

	return &pb.SaveCertChainResponse{
		Success: true,
		Message: fmt.Sprintf("certificate chain for %s saved successfully", req.KeyId),
	}, nil
}

// GetCertChain retrieves a certificate chain
func (s *Service) GetCertChain(ctx context.Context, req *pb.GetCertChainRequest) (*pb.GetCertChainResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	// Get any backend's keystore for cert operations
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get backend: %v", err)
	}

	// Get the certificate chain
	chain, err := ks.GetCertChain(req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "certificate chain not found: %v", err)
	}

	// Convert to PEM
	chainPem := make([]string, len(chain))
	for i, cert := range chain {
		chainPem[i] = encodeCertToPEM(cert)
	}

	return &pb.GetCertChainResponse{
		CertChainPem: chainPem,
	}, nil
}

// GetTLSCertificate returns a TLS certificate with private key
func (s *Service) GetTLSCertificate(ctx context.Context, req *pb.GetTLSCertificateRequest) (*pb.GetTLSCertificateResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Get the TLS certificate
	tlsCert, err := ks.GetTLSCertificate(req.KeyId, attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get TLS certificate: %v", err)
	}

	// Convert leaf certificate to PEM
	if len(tlsCert.Certificate) == 0 {
		return nil, status.Error(codes.Internal, "TLS certificate has no data")
	}

	leafCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse leaf certificate: %v", err)
	}
	certPem := encodeCertToPEM(leafCert)

	// Convert certificate chain to PEM (excluding leaf)
	chainPem := make([]string, 0, len(tlsCert.Certificate)-1)
	for i := 1; i < len(tlsCert.Certificate); i++ {
		cert, err := x509.ParseCertificate(tlsCert.Certificate[i])
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse certificate at index %d: %v", i, err)
		}
		chainPem = append(chainPem, encodeCertToPEM(cert))
	}

	// Convert private key to PEM
	privKeyPem, err := encodePrivateKeyToPEM(tlsCert.PrivateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encode private key: %v", err)
	}

	return &pb.GetTLSCertificateResponse{
		CertPem:       certPem,
		CertChainPem:  chainPem,
		PrivateKeyPem: privKeyPem,
	}, nil
}

// GetImportParameters retrieves parameters needed to import a key
func (s *Service) GetImportParameters(ctx context.Context, req *pb.GetImportParametersRequest) (*pb.GetImportParametersResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.Backend()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Parse key type and build attributes
	keyType := types.ParseKeyType(req.KeyType)
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   keyType,
		StoreType: types.StoreType(req.Backend),
		Hash:      parseHashAlgorithm(req.Hash),
		Partition: types.Partition(req.Partition),
	}

	// Set algorithm-specific attributes
	switch strings.ToLower(req.KeyType) {
	case "rsa":
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = 2048 // Default
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case "ecdsa":
		curve := req.Curve
		if curve == "" {
			curve = "P256" // Default
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case "ed25519":
		attrs.KeyAlgorithm = x509.Ed25519
	case "aes":
		// For symmetric keys, we'll need to handle differently
		// Set KeySize for AES keys
		if req.KeySize == 0 {
			return nil, status.Error(codes.InvalidArgument, "key_size is required for AES keys")
		}
		attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(fmt.Sprintf("AES-%d-GCM", req.KeySize))
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type: %s", req.KeyType)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Get import parameters from backend
	params, err := importExportBackend.GetImportParameters(attrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get import parameters: %v", err)
	}

	// Marshal public key to DER format
	pubKeyDER, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal public key: %v", err)
	}

	response := &pb.GetImportParametersResponse{
		WrappingPublicKey: pubKeyDER,
		ImportToken:       params.ImportToken,
		Algorithm:         string(params.Algorithm),
		KeySpec:           params.KeySpec,
	}

	if params.ExpiresAt != nil {
		response.ExpiresAt = timestamppb.New(*params.ExpiresAt)
	}

	return response, nil
}

// WrapKey wraps key material for secure transport
func (s *Service) WrapKey(ctx context.Context, req *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	if len(req.KeyMaterial) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key_material is required")
	}
	if len(req.WrappingPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapping_public_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}

	// Parse public key from DER
	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	// Create import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	// Get any backend to perform the wrapping operation
	// Wrapping is typically done client-side, so we can use any backend that implements the interface
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	var wrapped *backend.WrappedKeyMaterial
	for _, backendName := range backends {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}

		backendImpl := ks.Backend()
		importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
		if ok {
			wrapped, err = importExportBackend.WrapKey(req.KeyMaterial, params)
			if err == nil {
				break
			}
		}
	}

	if wrapped == nil {
		return nil, status.Error(codes.Internal, "failed to wrap key: no suitable backend found or wrapping failed")
	}

	return &pb.WrapKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// UnwrapKey unwraps previously wrapped key material
func (s *Service) UnwrapKey(ctx context.Context, req *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	if len(req.WrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}
	if len(req.WrappingPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapping_public_key is required")
	}

	// Parse public key from DER
	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse wrapping public key: %v", err)
	}

	// Create wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Create import parameters
	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
		KeySpec:           req.KeySpec,
	}

	// Get any backend to perform the unwrapping operation
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, status.Error(codes.Internal, "no backends available")
	}

	var keyMaterial []byte
	for _, backendName := range backends {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}

		backendImpl := ks.Backend()
		importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
		if ok {
			keyMaterial, err = importExportBackend.UnwrapKey(wrapped, params)
			if err == nil {
				break
			}
		}
	}

	if keyMaterial == nil {
		return nil, status.Error(codes.Internal, "failed to unwrap key: no suitable backend found or unwrapping failed")
	}

	return &pb.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// ImportKey imports externally generated key material into the backend
func (s *Service) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if len(req.WrappedKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "wrapped_key is required")
	}
	if req.Algorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "algorithm is required")
	}
	if req.KeyType == "" {
		return nil, status.Error(codes.InvalidArgument, "key_type is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.Backend()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Parse key type and build attributes
	keyType := types.ParseKeyType(req.KeyType)
	attrs := &types.KeyAttributes{
		CN:        req.KeyId,
		KeyType:   keyType,
		StoreType: types.StoreType(req.Backend),
		Hash:      parseHashAlgorithm(req.Hash),
		Partition: types.Partition(req.Partition),
	}

	// Set algorithm-specific attributes
	switch strings.ToLower(req.KeyType) {
	case "rsa":
		keySize := int(req.KeySize)
		if keySize == 0 {
			keySize = 2048 // Default
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
	case "ecdsa":
		curve := req.Curve
		if curve == "" {
			curve = "P256" // Default
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid curve: %v", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
	case "ed25519":
		attrs.KeyAlgorithm = x509.Ed25519
	case "aes":
		if req.KeySize == 0 {
			return nil, status.Error(codes.InvalidArgument, "key_size is required for AES keys")
		}
		attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(fmt.Sprintf("AES-%d-GCM", req.KeySize))
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key type: %s", req.KeyType)
	}

	// Create wrapped key material
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  req.WrappedKey,
		Algorithm:   backend.WrappingAlgorithm(req.Algorithm),
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
	}

	// Import the key
	err = importExportBackend.ImportKey(attrs, wrapped)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to import key: %v", err)
	}

	return &pb.ImportKeyResponse{
		Success: true,
		Message: fmt.Sprintf("key %s imported successfully into backend %s", req.KeyId, req.Backend),
		KeyId:   req.KeyId,
	}, nil
}

// ExportKey exports a key in wrapped form for secure transport
func (s *Service) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	if req.Backend == "" {
		return nil, status.Error(codes.InvalidArgument, "backend is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "backend not found: %v", err)
	}

	// Check if backend supports import/export
	backendImpl := ks.Backend()
	importExportBackend, ok := backendImpl.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "backend %s does not support import/export operations", req.Backend)
	}

	// Find key attributes
	attrs, err := s.findKeyAttributes(ks, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Export the key
	wrapped, err := importExportBackend.ExportKey(attrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to export key: %v", err)
	}

	return &pb.ExportKeyResponse{
		WrappedKey:  wrapped.WrappedKey,
		Algorithm:   string(wrapped.Algorithm),
		ImportToken: wrapped.ImportToken,
		Metadata:    wrapped.Metadata,
	}, nil
}

// CopyKey copies a key from one backend to another using export/import
func (s *Service) CopyKey(ctx context.Context, req *pb.CopyKeyRequest) (*pb.CopyKeyResponse, error) {
	if req.SourceBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "source_backend is required")
	}
	if req.SourceKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "source_key_id is required")
	}
	if req.DestBackend == "" {
		return nil, status.Error(codes.InvalidArgument, "dest_backend is required")
	}
	if req.DestKeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "dest_key_id is required")
	}
	if req.WrappingAlgorithm == "" {
		return nil, status.Error(codes.InvalidArgument, "wrapping_algorithm is required")
	}

	// Get source keystore
	sourceKs, err := keychain.Backend(req.SourceBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source backend not found: %v", err)
	}

	// Get destination keystore
	destKs, err := keychain.Backend(req.DestBackend)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "destination backend not found: %v", err)
	}

	// Verify source backend supports export
	sourceBackend := sourceKs.Backend()
	sourceImportExport, ok := sourceBackend.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "source backend %s does not support export operations", req.SourceBackend)
	}

	// Verify destination backend supports import
	destBackend := destKs.Backend()
	destImportExport, ok := destBackend.(backend.ImportExportBackend)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "destination backend %s does not support import operations", req.DestBackend)
	}

	// Find source key attributes
	sourceAttrs, err := s.findKeyAttributes(sourceKs, req.SourceKeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "source key not found: %v", err)
	}

	// Parse wrapping algorithm
	wrappingAlg := backend.WrappingAlgorithm(req.WrappingAlgorithm)

	// Step 1: Export the key from source backend
	wrapped, err := sourceImportExport.ExportKey(sourceAttrs, wrappingAlg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to export key from source backend: %v", err)
	}

	// Step 2: Create destination key attributes (copy from source but with new ID)
	destAttrs := &types.KeyAttributes{
		CN:                 sourceAttrs.CN,
		KeyType:            sourceAttrs.KeyType,
		KeyAlgorithm:       sourceAttrs.KeyAlgorithm,
		Hash:               sourceAttrs.Hash,
		StoreType:          types.StoreType(req.DestBackend),
		Partition:          sourceAttrs.Partition,
		RSAAttributes:      sourceAttrs.RSAAttributes,
		ECCAttributes:      sourceAttrs.ECCAttributes,
		SymmetricAlgorithm: sourceAttrs.SymmetricAlgorithm,
	}
	// Update CN to destination key ID
	destAttrs.CN = req.DestKeyId

	// Step 3: Import the key into destination backend
	err = destImportExport.ImportKey(destAttrs, wrapped)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to import key into destination backend: %v", err)
	}

	return &pb.CopyKeyResponse{
		Success:   true,
		Message:   fmt.Sprintf("key %s copied from %s to %s as %s", req.SourceKeyId, req.SourceBackend, req.DestBackend, req.DestKeyId),
		DestKeyId: req.DestKeyId,
	}, nil
}

// Helper functions

func (s *Service) findKeyAttributes(ks keychain.KeyStore, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, fmt.Errorf("key %s not found", keyID)
}

// getAlgorithmString returns the algorithm name as a string, handling both
// symmetric and asymmetric key types.
func getAlgorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}

func parseHashAlgorithm(hash string) crypto.Hash {
	if hash == "" {
		return crypto.SHA256 // Default
	}
	h := types.ParseHash(hash)
	if h == 0 {
		return crypto.SHA256 // Default if unknown
	}
	return h
}

func extractPublicKeyPEM(privKey crypto.PrivateKey) (string, error) {
	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		// Handle OpaqueKey and other Signer implementations
		pubKey = k.Public()
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func parseCertFromPEM(certPem string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func encodeCertToPEM(cert *x509.Certificate) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func encodePrivateKeyToPEM(privKey crypto.PrivateKey) (string, error) {
	var pemType string
	var keyBytes []byte
	var err error

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		pemType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA key: %v", err)
		}
	case ed25519.PrivateKey:
		pemType = "PRIVATE KEY"
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", fmt.Errorf("failed to marshal Ed25519 key: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", privKey)
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}
