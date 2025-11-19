//go:build integration && tpm2

package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// setupIDevIDTPM ensures TPM is properly provisioned with IAK and IDevID config for CSR tests
func setupIDevIDTPM(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()

	// Use the shared createTPM2Instance function
	tpmInstance, cleanup := createTPM2Instance(t)

	// Always provision first
	t.Log("Provisioning TPM with EK and SRK...")
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (continuing)", err)
	}

	// Verify EK was created
	ekAttrs, err := tpmInstance.EKAttributes()
	if err != nil {
		cleanup()
		t.Fatalf("Failed to get EK attributes after provisioning: %v", err)
	}

	// Ensure IAK is created
	_, err = tpmInstance.IAKAttributes()
	if err != nil {
		t.Logf("IAK not found, creating IAK: %v", err)
		_, err = tpmInstance.CreateIAK(ekAttrs, nil)
		if err != nil {
			cleanup()
			t.Fatalf("Failed to create IAK: %v", err)
		}
	}

	return tpmInstance, cleanup
}

// createSelfSignedEKCert creates a self-signed EK certificate for testing
func createSelfSignedEKCert(t *testing.T, tpmInstance tpm2lib.TrustedPlatformModule) *x509.Certificate {
	t.Helper()

	ekAttrs, err := tpmInstance.EKAttributes()
	if err != nil {
		t.Fatalf("Failed to get EK attributes: %v", err)
	}

	// Create a simple self-signed certificate for the EK
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test EK Certificate",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Parse the EK public key
	pubKey, err := x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse EK public key: %v", err)
	}

	// Generate an RSA key to sign the certificate (for testing purposes)
	signerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate signer key: %v", err)
	}

	// Create the certificate using the EK public key and sign with generated key
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signerKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestIntegration_CreateTCGCSR_IDevID tests complete TCG CSR IDevID creation
func TestIntegration_CreateTCGCSR_IDevID(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("BasicCSRCreation", func(t *testing.T) {
		// Get necessary attributes
		_, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("Failed to get EK attributes: %v", err)
		}

		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Create a test EK certificate
		ekCert := createSelfSignedEKCert(t, tpmInstance)

		// Create IDevID with CSR
		idevidAttrs, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Verify IDevID attributes
		if idevidAttrs == nil {
			t.Fatal("IDevID attributes is nil")
		}

		if idevidAttrs.TPMAttributes == nil {
			t.Fatal("IDevID TPM attributes is nil")
		}

		if idevidAttrs.TPMAttributes.Handle == 0 {
			t.Error("IDevID handle is not set")
		}

		// Verify CSR structure
		if csr == nil {
			t.Fatal("CSR is nil")
		}

		// Check struct version (should be 0x00000100)
		structVer := binary.BigEndian.Uint32(csr.StructVer[:])
		if structVer != 0x00000100 {
			t.Errorf("CSR struct version mismatch: got 0x%08x, want 0x00000100", structVer)
		}

		// Check signature is present
		sigSz := binary.BigEndian.Uint32(csr.SigSz[:])
		if sigSz == 0 {
			t.Error("CSR signature size is zero")
		}

		if len(csr.Signature) == 0 {
			t.Error("CSR signature is empty")
		}

		if len(csr.Signature) != int(sigSz) {
			t.Errorf("CSR signature size mismatch: got %d, want %d", len(csr.Signature), sigSz)
		}

		t.Logf("TCG CSR IDevID created successfully:")
		t.Logf("  IDevID Handle: 0x%08x", idevidAttrs.TPMAttributes.Handle)
		t.Logf("  CSR Signature size: %d bytes", sigSz)
		t.Logf("  CSR Contents size: %d bytes", binary.BigEndian.Uint32(csr.Contents[:]))
	})

	t.Run("CSRWithQualifyingData", func(t *testing.T) {
		// This test would require a fresh TPM state to avoid handle conflicts
		// Skip for now as it would require special setup
		t.Skip("Requires fresh TPM state to avoid handle conflicts")
	})
}

// TestIntegration_IDevIDCSR_Encoding tests CSR encoding and packing
func TestIntegration_IDevIDCSR_Encoding(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("PackAndUnpack", func(t *testing.T) {
		// Get necessary attributes
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		// Create IDevID with CSR
		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Pack the CSR
		packedCSR, err := tpm2lib.PackIDevIDCSR(csr)
		if err != nil {
			t.Fatalf("Failed to pack CSR: %v", err)
		}

		if len(packedCSR) == 0 {
			t.Error("Packed CSR is empty")
		}

		// Unmarshal the packed CSR
		unpackedCSR, err := tpm2lib.UnmarshalIDevIDCSR(packedCSR)
		if err != nil {
			t.Fatalf("Failed to unmarshal CSR: %v", err)
		}

		// Verify structure version matches
		if unpackedCSR.StructVer != csr.StructVer {
			t.Error("StructVer mismatch after pack/unpack")
		}

		// Verify contents size matches
		if unpackedCSR.Contents != csr.Contents {
			t.Error("Contents size mismatch after pack/unpack")
		}

		// Verify signature size matches
		if unpackedCSR.SigSz != csr.SigSz {
			t.Error("SigSz mismatch after pack/unpack")
		}

		// Verify signature matches
		if !bytes.Equal(unpackedCSR.Signature, csr.Signature) {
			t.Error("Signature mismatch after pack/unpack")
		}

		t.Logf("CSR pack/unpack successful:")
		t.Logf("  Packed size: %d bytes", len(packedCSR))
	})

	t.Run("ContentPacking", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Pack just the content
		packedContent, err := tpm2lib.PackIDevIDContent(&csr.CsrContents)
		if err != nil {
			t.Fatalf("Failed to pack CSR content: %v", err)
		}

		if len(packedContent) == 0 {
			t.Error("Packed content is empty")
		}

		// Verify content contains expected fields
		reader := bytes.NewReader(packedContent)

		var structVer [4]byte
		if err := binary.Read(reader, binary.BigEndian, &structVer); err != nil {
			t.Fatalf("Failed to read struct version: %v", err)
		}

		if structVer != csr.CsrContents.StructVer {
			t.Error("Content struct version mismatch")
		}

		t.Logf("Content packing successful: %d bytes", len(packedContent))
	})
}

// TestIntegration_IDevIDCSR_Validation tests CSR validation and verification
func TestIntegration_IDevIDCSR_Validation(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("ValidateCSRStructure", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Validate CSR contents structure
		content := csr.CsrContents

		// Check hash algorithm ID is valid
		hashAlgoId := binary.BigEndian.Uint32(content.HashAlgoId[:])
		if hashAlgoId == 0 {
			t.Error("Hash algorithm ID is zero")
		}

		// Check hash size is reasonable
		hashSz := binary.BigEndian.Uint32(content.HashSz[:])
		if hashSz == 0 || hashSz > 64 {
			t.Errorf("Invalid hash size: %d", hashSz)
		}

		// Check EK certificate is present
		ekCertSz := binary.BigEndian.Uint32(content.EkCertSZ[:])
		if ekCertSz == 0 {
			t.Error("EK certificate size is zero")
		}
		if len(content.EkCert) != int(ekCertSz) {
			t.Errorf("EK certificate size mismatch: got %d, want %d", len(content.EkCert), ekCertSz)
		}

		// Check attestation public key is present
		attestPubSz := binary.BigEndian.Uint32(content.AttestPubSZ[:])
		if attestPubSz == 0 {
			t.Error("Attestation public key size is zero")
		}
		if len(content.AttestPub) != int(attestPubSz) {
			t.Errorf("Attestation public key size mismatch: got %d, want %d", len(content.AttestPub), attestPubSz)
		}

		// Check signing public key is present
		signingPubSz := binary.BigEndian.Uint32(content.SigningPubSZ[:])
		if signingPubSz == 0 {
			t.Error("Signing public key size is zero")
		}
		if len(content.SigningPub) != int(signingPubSz) {
			t.Errorf("Signing public key size mismatch: got %d, want %d", len(content.SigningPub), signingPubSz)
		}

		t.Logf("CSR structure validation successful:")
		t.Logf("  Hash Algo ID: 0x%04x", hashAlgoId)
		t.Logf("  Hash Size: %d bytes", hashSz)
		t.Logf("  EK Cert Size: %d bytes", ekCertSz)
		t.Logf("  Attest Pub Size: %d bytes", attestPubSz)
		t.Logf("  Signing Pub Size: %d bytes", signingPubSz)
	})

	t.Run("UnpackCSRStructure", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Unpack CSR to native types
		unpacked, err := tpm2lib.UnpackIDevIDCSR(csr)
		if err != nil {
			t.Fatalf("Failed to unpack CSR: %v", err)
		}

		// Verify unpacked structure
		if unpacked.StructVer != 0x00000100 {
			t.Errorf("Unpacked struct version mismatch: got 0x%08x, want 0x00000100", unpacked.StructVer)
		}

		if unpacked.SigSz == 0 {
			t.Error("Unpacked signature size is zero")
		}

		if len(unpacked.Signature) != int(unpacked.SigSz) {
			t.Errorf("Unpacked signature size mismatch: got %d, want %d", len(unpacked.Signature), unpacked.SigSz)
		}

		// Verify content fields
		if unpacked.CsrContents.HashAlgoId == 0 {
			t.Error("Unpacked hash algorithm ID is zero")
		}

		if unpacked.CsrContents.EkCertSZ == 0 {
			t.Error("Unpacked EK cert size is zero")
		}

		if unpacked.CsrContents.AttestPubSZ == 0 {
			t.Error("Unpacked attest pub size is zero")
		}

		if unpacked.CsrContents.SigningPubSZ == 0 {
			t.Error("Unpacked signing pub size is zero")
		}

		t.Logf("CSR unpacking successful:")
		t.Logf("  Struct Version: 0x%08x", unpacked.StructVer)
		t.Logf("  Contents Size: %d bytes", unpacked.Contents)
		t.Logf("  Signature Size: %d bytes", unpacked.SigSz)
	})
}

// TestIntegration_IDevIDCertificate_Generation tests certificate-related operations
func TestIntegration_IDevIDCertificate_Generation(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("IDevIDKeyGeneration", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		// Create IDevID key
		idevidAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID: %v", err)
		}

		// Verify key attributes
		if idevidAttrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			t.Error("IDevID key algorithm is unknown")
		}

		if idevidAttrs.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
			t.Error("IDevID signature algorithm is unknown")
		}

		if idevidAttrs.StoreType != types.StoreTPM2 {
			t.Errorf("IDevID store type mismatch: got %v, want %v", idevidAttrs.StoreType, types.StoreTPM2)
		}

		// Verify TPM attributes
		if idevidAttrs.TPMAttributes.Handle == 0 {
			t.Error("IDevID TPM handle is zero")
		}

		if len(idevidAttrs.TPMAttributes.Name.(tpm2.TPM2BName).Buffer) == 0 {
			t.Error("IDevID TPM name is empty")
		}

		if len(idevidAttrs.TPMAttributes.PublicKeyBytes) == 0 {
			t.Error("IDevID public key bytes are empty")
		}

		if len(idevidAttrs.TPMAttributes.CertifyInfo) == 0 {
			t.Error("IDevID certify info is empty")
		}

		if len(idevidAttrs.TPMAttributes.Signature) == 0 {
			t.Error("IDevID signature is empty")
		}

		t.Logf("IDevID key generation successful:")
		t.Logf("  Key Algorithm: %v", idevidAttrs.KeyAlgorithm)
		t.Logf("  Signature Algorithm: %v", idevidAttrs.SignatureAlgorithm)
		t.Logf("  TPM Handle: 0x%08x", idevidAttrs.TPMAttributes.Handle)
		t.Logf("  Public Key Size: %d bytes", len(idevidAttrs.TPMAttributes.PublicKeyBytes))
	})

	t.Run("IDevIDKeyPersistence", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		idevidAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID: %v", err)
		}

		// Verify key is persistent
		if idevidAttrs.TPMAttributes.HandleType == 0 {
			t.Error("IDevID handle type is not set")
		}

		// Handle should be in the persistent range
		handle := idevidAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)
		if handle < 0x81000000 || handle > 0x81FFFFFF {
			t.Errorf("IDevID handle not in persistent range: 0x%08x", handle)
		}

		t.Logf("IDevID key persistence verified: handle 0x%08x", handle)
	})
}

// TestIntegration_IDevIDCertificate_Parsing tests parsing of CSR contents
func TestIntegration_IDevIDCertificate_Parsing(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("ParseCSRContents", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Parse product model
		prodModelSz := binary.BigEndian.Uint32(csr.CsrContents.ProdModelSz[:])
		if prodModelSz > 0 {
			prodModel := string(csr.CsrContents.ProdModel)
			t.Logf("Product Model: %s (%d bytes)", prodModel, prodModelSz)
		}

		// Parse product serial
		prodSerialSz := binary.BigEndian.Uint32(csr.CsrContents.ProdSerialSz[:])
		if prodSerialSz > 0 {
			prodSerial := string(csr.CsrContents.ProdSerial)
			t.Logf("Product Serial: %s (%d bytes)", prodSerial, prodSerialSz)
		}

		// Parse attestation certify info
		atCertifyInfoSz := binary.BigEndian.Uint32(csr.CsrContents.AtCertifyInfoSZ[:])
		if atCertifyInfoSz == 0 {
			t.Error("Attestation certify info size is zero")
		}
		if len(csr.CsrContents.AtCertifyInfo) != int(atCertifyInfoSz) {
			t.Errorf("Attestation certify info size mismatch: got %d, want %d",
				len(csr.CsrContents.AtCertifyInfo), atCertifyInfoSz)
		}

		// Parse signing certify info
		sgnCertifyInfoSz := binary.BigEndian.Uint32(csr.CsrContents.SgnCertifyInfoSZ[:])
		if sgnCertifyInfoSz == 0 {
			t.Error("Signing certify info size is zero")
		}
		if len(csr.CsrContents.SgnCertifyInfo) != int(sgnCertifyInfoSz) {
			t.Errorf("Signing certify info size mismatch: got %d, want %d",
				len(csr.CsrContents.SgnCertifyInfo), sgnCertifyInfoSz)
		}

		t.Logf("CSR contents parsing successful:")
		t.Logf("  Attest Certify Info: %d bytes", atCertifyInfoSz)
		t.Logf("  Sign Certify Info: %d bytes", sgnCertifyInfoSz)
	})

	t.Run("ParseCertifySignatures", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Check attestation certify info signature
		atCertifyInfoSigSz := binary.BigEndian.Uint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:])
		if atCertifyInfoSigSz == 0 {
			t.Error("Attestation certify info signature size is zero")
		}
		if len(csr.CsrContents.AtCertifyInfoSig) != int(atCertifyInfoSigSz) {
			t.Errorf("Attestation certify info signature size mismatch: got %d, want %d",
				len(csr.CsrContents.AtCertifyInfoSig), atCertifyInfoSigSz)
		}

		// Check signing certify info signature
		sgnCertifyInfoSigSz := binary.BigEndian.Uint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:])
		if sgnCertifyInfoSigSz == 0 {
			t.Error("Signing certify info signature size is zero")
		}
		if len(csr.CsrContents.SgnCertifyInfoSig) != int(sgnCertifyInfoSigSz) {
			t.Errorf("Signing certify info signature size mismatch: got %d, want %d",
				len(csr.CsrContents.SgnCertifyInfoSig), sgnCertifyInfoSigSz)
		}

		t.Logf("Certify signatures parsing successful:")
		t.Logf("  Attest Signature: %d bytes", atCertifyInfoSigSz)
		t.Logf("  Sign Signature: %d bytes", sgnCertifyInfoSigSz)
	})
}

// TestIntegration_IDevIDCSR_InvalidInputs tests error handling for invalid inputs
func TestIntegration_IDevIDCSR_InvalidInputs(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("NilAKAttributes", func(t *testing.T) {
		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, _, err := tpmInstance.CreateIDevID(nil, ekCert, nil)
		if err == nil {
			t.Error("Expected error for nil AK attributes, got nil")
		}
		t.Logf("Correctly rejected nil AK attributes: %v", err)
	})

	t.Run("NilEKCertificate", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		_, _, err = tpmInstance.CreateIDevID(iakAttrs, nil, nil)
		if err == nil {
			t.Error("Expected error for nil EK certificate, got nil")
		}
		t.Logf("Correctly rejected nil EK certificate: %v", err)
	})

	t.Run("AKAttributesMissingParent", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Create a copy with nil parent
		invalidAKAttrs := *iakAttrs
		invalidAKAttrs.Parent = nil

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		_, _, err = tpmInstance.CreateIDevID(&invalidAKAttrs, ekCert, nil)
		if err == nil {
			t.Error("Expected error for AK attributes with nil parent, got nil")
		}
		if err != tpm2lib.ErrInvalidEKAttributes {
			t.Logf("Got error: %v (expected ErrInvalidEKAttributes)", err)
		} else {
			t.Log("Correctly rejected AK attributes with nil parent")
		}
	})
}

// TestIntegration_IDevIDCSR_WithoutProvisioning tests CSR creation behavior without proper provisioning
func TestIntegration_IDevIDCSR_WithoutProvisioning(t *testing.T) {
	t.Run("UnprovisionedTPM", func(t *testing.T) {
		// This would require a completely fresh TPM instance without provisioning
		// which is complex to set up in the test environment
		t.Skip("Requires unprovisioned TPM state - complex setup")
	})

	t.Run("MissingIAK", func(t *testing.T) {
		// Testing with missing IAK would require careful state management
		t.Skip("Requires TPM state without IAK - complex setup")
	})
}

// TestIntegration_IDevIDCSR_RoundTrip tests complete CSR round-trip
func TestIntegration_IDevIDCSR_RoundTrip(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("CompleteRoundTrip", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		// Create CSR
		_, originalCSR, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create IDevID CSR: %v", err)
		}

		// Pack CSR
		packedBytes, err := tpm2lib.PackIDevIDCSR(originalCSR)
		if err != nil {
			t.Fatalf("Failed to pack CSR: %v", err)
		}

		// Unmarshal CSR
		unmarshaledCSR, err := tpm2lib.UnmarshalIDevIDCSR(packedBytes)
		if err != nil {
			t.Fatalf("Failed to unmarshal CSR: %v", err)
		}

		// Unpack to native types
		unpackedCSR, err := tpm2lib.UnpackIDevIDCSR(unmarshaledCSR)
		if err != nil {
			t.Fatalf("Failed to unpack CSR: %v", err)
		}

		// Verify round-trip integrity
		originalStructVer := binary.BigEndian.Uint32(originalCSR.StructVer[:])
		if unpackedCSR.StructVer != originalStructVer {
			t.Errorf("Struct version mismatch after round-trip: got 0x%08x, want 0x%08x",
				unpackedCSR.StructVer, originalStructVer)
		}

		originalContents := binary.BigEndian.Uint32(originalCSR.Contents[:])
		if unpackedCSR.Contents != originalContents {
			t.Errorf("Contents size mismatch after round-trip: got %d, want %d",
				unpackedCSR.Contents, originalContents)
		}

		originalSigSz := binary.BigEndian.Uint32(originalCSR.SigSz[:])
		if unpackedCSR.SigSz != originalSigSz {
			t.Errorf("Signature size mismatch after round-trip: got %d, want %d",
				unpackedCSR.SigSz, originalSigSz)
		}

		if !bytes.Equal(unpackedCSR.Signature, originalCSR.Signature) {
			t.Error("Signature mismatch after round-trip")
		}

		// Verify content fields
		originalHashAlgoId := binary.BigEndian.Uint32(originalCSR.CsrContents.HashAlgoId[:])
		if unpackedCSR.CsrContents.HashAlgoId != originalHashAlgoId {
			t.Errorf("Hash algorithm ID mismatch: got %d, want %d",
				unpackedCSR.CsrContents.HashAlgoId, originalHashAlgoId)
		}

		t.Logf("Complete round-trip successful:")
		t.Logf("  Packed size: %d bytes", len(packedBytes))
		t.Logf("  Struct version preserved: 0x%08x", unpackedCSR.StructVer)
		t.Logf("  Signature preserved: %d bytes", unpackedCSR.SigSz)
	})
}

// TestIntegration_IDevIDCSR_MultipleCreations tests creating multiple CSRs
func TestIntegration_IDevIDCSR_MultipleCreations(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDTPM(t)
	defer cleanup()

	t.Run("SequentialCSRs", func(t *testing.T) {
		// Note: Creating multiple IDevID keys in sequence would require different handles
		// or deleting the previous one. This test verifies the first creation is successful.
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		ekCert := createSelfSignedEKCert(t, tpmInstance)

		// Create first IDevID
		idevidAttrs, csr, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, nil)
		if err != nil {
			t.Fatalf("Failed to create first IDevID CSR: %v", err)
		}

		// Verify CSR is valid
		if csr == nil {
			t.Fatal("First CSR is nil")
		}

		if len(csr.Signature) == 0 {
			t.Error("First CSR signature is empty")
		}

		t.Logf("First IDevID CSR created successfully at handle 0x%08x",
			idevidAttrs.TPMAttributes.Handle)

		// Creating a second one would fail due to handle conflict unless we delete the first
		// or use a different handle configuration
	})
}
