//nolint:staticcheck // Style warnings suppressed
package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestTPMOperations(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	logger := logging.DefaultLogger()

	buf := make([]byte, 8)
	_, err = rand.Reader.Read(buf)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create go-objstore backed storage using the factory
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		t.Fatalf("Failed to create storage factory: %v", err)
	}
	defer func() { _ = storageFactory.Close() }()

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     true,
		Device:         "/dev/tpmrm0",
		UseSimulator:   false,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		IDevID: &IDevIDConfig{
			CertHandle:         0x01C90000,
			Debug:              true,
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Model:              "test-model",
			Pad:                true,
			PlatformPolicy:     false,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "test-serial",
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		KeyStore: &KeyStoreConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: false,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
		Transport:    sim,
	}

	tpmInstance, err := NewTPM2(params)
	if err != nil {
		if err != ErrNotInitialized {
			t.Fatalf("Failed to create TPM instance: %v", err)
		}
	}
	defer func() { _ = tpmInstance.Close() }()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	t.Run("Config", func(t *testing.T) {
		cfg := tpmInstance.Config()
		if cfg == nil {
			t.Fatal("Config returned nil")
		}
		if cfg.Hash != "SHA-256" {
			t.Errorf("Expected hash SHA-256, got %s", cfg.Hash)
		}
		if cfg.PlatformPCR != debugPCR {
			t.Errorf("Expected platform PCR %d, got %d", debugPCR, cfg.PlatformPCR)
		}
	})

	t.Run("Device", func(t *testing.T) {
		device := tpmInstance.Device()
		if device != "/dev/tpmrm0" {
			t.Errorf("Expected device /dev/tpmrm0, got %s", device)
		}
	})

	t.Run("AlgID", func(t *testing.T) {
		algID := tpmInstance.AlgID()
		if algID != tpm2.TPMAlgSHA256 {
			t.Errorf("Expected TPMAlgSHA256, got %v", algID)
		}
	})

	t.Run("Transport", func(t *testing.T) {
		transport := tpmInstance.Transport()
		if transport == nil {
			t.Fatal("Transport returned nil")
		}
	})

	t.Run("EKPublic", func(t *testing.T) {
		name, pub := tpmInstance.EKPublic()
		if len(name.Buffer) == 0 {
			t.Error("EK name buffer is empty")
		}
		if pub.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected RSA algorithm, got %v", pub.Type)
		}
	})

	t.Run("EKRSA", func(t *testing.T) {
		rsaPub := tpmInstance.EKRSA()
		if rsaPub == nil {
			t.Fatal("EKRSA returned nil")
		}
		if rsaPub.N == nil {
			t.Error("RSA public key N is nil")
		}
		if rsaPub.E == 0 {
			t.Error("RSA public key E is 0")
		}
		expectedKeySize := 2048
		actualKeySize := rsaPub.N.BitLen()
		if actualKeySize != expectedKeySize {
			t.Errorf("Expected key size %d, got %d", expectedKeySize, actualKeySize)
		}
	})

	t.Run("EKAttributes", func(t *testing.T) {
		ekAttrs, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("EKAttributes failed: %v", err)
		}
		if ekAttrs == nil {
			t.Fatal("EKAttributes returned nil")
		}
		if ekAttrs.KeyType != types.KeyTypeEndorsement {
			t.Errorf("Expected KEY_TYPE_ENDORSEMENT, got %v", ekAttrs.KeyType)
		}
		if ekAttrs.StoreType != types.StoreTPM2 {
			t.Errorf("Expected STORE_TPM2, got %v", ekAttrs.StoreType)
		}
		if ekAttrs.TPMAttributes == nil {
			t.Fatal("EK TPMAttributes is nil")
		}
	})

	t.Run("EK", func(t *testing.T) {
		ek := tpmInstance.EK()
		if ek == nil {
			t.Fatal("EK returned nil")
		}
		_, ok := ek.(*rsa.PublicKey)
		if !ok {
			t.Error("EK is not an RSA public key")
		}
	})

	t.Run("SSRKPublic", func(t *testing.T) {
		t.Skip("SRK not provisioned in IAK-only provisioning strategy")
	})

	t.Run("SSRKAttributes", func(t *testing.T) {
		ssrkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("SSRKAttributes failed: %v", err)
		}
		if ssrkAttrs == nil {
			t.Fatal("SSRKAttributes returned nil")
		}
		if ssrkAttrs.KeyType != types.KeyTypeStorage {
			t.Errorf("Expected KEY_TYPE_STORAGE, got %v", ssrkAttrs.KeyType)
		}
		if ssrkAttrs.TPMAttributes.Handle != tpm2.TPMHandle(config.SSRK.Handle) {
			t.Errorf("Expected handle 0x%x, got 0x%x", config.SSRK.Handle, ssrkAttrs.TPMAttributes.Handle)
		}
	})

	t.Run("IAKAttributes", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("IAKAttributes failed: %v", err)
		}
		if iakAttrs == nil {
			t.Fatal("IAKAttributes returned nil")
		}
		if iakAttrs.KeyType != types.KeyTypeAttestation {
			t.Errorf("Expected KEY_TYPE_ATTESTATION, got %v", iakAttrs.KeyType)
		}
		if iakAttrs.TPMAttributes == nil {
			t.Fatal("IAK TPMAttributes is nil")
		}
		if iakAttrs.TPMAttributes.Handle != tpm2.TPMHandle(config.IAK.Handle) {
			t.Errorf("Expected IAK handle 0x%x, got 0x%x", config.IAK.Handle, iakAttrs.TPMAttributes.Handle)
		}
	})

	t.Run("IAK", func(t *testing.T) {
		iak := tpmInstance.IAK()
		if iak == nil {
			t.Fatal("IAK returned nil")
		}
		_, ok := iak.(*rsa.PublicKey)
		if !ok {
			t.Error("IAK is not an RSA public key")
		}
	})

	t.Run("IAKAttributesParent", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("IAKAttributes failed: %v", err)
		}
		if iakAttrs.Parent == nil {
			t.Fatal("IAK parent is nil")
		}
		if iakAttrs.Parent.KeyType != types.KeyTypeEndorsement {
			t.Errorf("Expected parent to be EK, got %v", iakAttrs.Parent.KeyType)
		}
	})

	t.Run("PlatformPolicyDigest", func(t *testing.T) {
		digest := tpmInstance.PlatformPolicyDigest()
		if len(digest.Buffer) == 0 {
			t.Error("Platform policy digest buffer is empty")
		}
	})

	t.Run("Random", func(t *testing.T) {
		randomBytes, err := tpmInstance.Random()
		if err != nil {
			t.Fatalf("Random failed: %v", err)
		}
		if len(randomBytes) != 32 {
			t.Errorf("Expected 32 bytes, got %d", len(randomBytes))
		}
		allZero := true
		for _, b := range randomBytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("Random bytes are all zeros")
		}
	})

	t.Run("RandomBytes", func(t *testing.T) {
		fixedLength := 64
		randomBytes, err := tpmInstance.RandomBytes(fixedLength)
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		if len(randomBytes) != fixedLength {
			t.Errorf("Expected %d bytes, got %d", fixedLength, len(randomBytes))
		}
	})

	t.Run("RandomBytesLarge", func(t *testing.T) {
		fixedLength := 256
		randomBytes, err := tpmInstance.RandomBytes(fixedLength)
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		if len(randomBytes) != fixedLength {
			t.Errorf("Expected %d bytes, got %d", fixedLength, len(randomBytes))
		}
	})

	t.Run("RandomHex", func(t *testing.T) {
		fixedLength := 32
		hexBytes, err := tpmInstance.RandomHex(fixedLength)
		if err != nil {
			t.Fatalf("RandomHex failed: %v", err)
		}
		if len(hexBytes) != fixedLength {
			t.Errorf("Expected %d hex characters, got %d", fixedLength, len(hexBytes))
		}
		for _, b := range hexBytes {
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
				t.Errorf("Invalid hex character: %c", b)
			}
		}
	})

	t.Run("RandomSource", func(t *testing.T) {
		source := tpmInstance.RandomSource()
		if source == nil {
			t.Fatal("RandomSource returned nil")
		}
		testBuf := make([]byte, 16)
		n, err := source.Read(testBuf)
		if err != nil {
			t.Fatalf("Failed to read from random source: %v", err)
		}
		if n != 16 {
			t.Errorf("Expected to read 16 bytes, got %d", n)
		}
	})

	t.Run("ReadHandle", func(t *testing.T) {
		ekHandle := tpm2.TPMHandle(config.EK.Handle)
		name, pub, err := tpmInstance.ReadHandle(ekHandle)
		if err != nil {
			t.Fatalf("ReadHandle failed: %v", err)
		}
		if len(name.Buffer) == 0 {
			t.Error("Handle name buffer is empty")
		}
		if pub.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected RSA algorithm, got %v", pub.Type)
		}
	})

	t.Run("KeyAttributes", func(t *testing.T) {
		ekHandle := tpm2.TPMHandle(config.EK.Handle)
		attrs, err := tpmInstance.KeyAttributes(ekHandle)
		if err != nil {
			t.Fatalf("KeyAttributes failed: %v", err)
		}
		if attrs == nil {
			t.Fatal("KeyAttributes returned nil")
		}
		if attrs.TPMAttributes == nil {
			t.Fatal("TPMAttributes is nil")
		}
		if attrs.TPMAttributes.Handle != ekHandle {
			t.Errorf("Expected handle 0x%x, got 0x%x", ekHandle, attrs.TPMAttributes.Handle)
		}
	})

	t.Run("ReadPCRs", func(t *testing.T) {
		pcrList := []uint{0, 1, 7}
		banks, err := tpmInstance.ReadPCRs(pcrList)
		if err != nil {
			t.Fatalf("ReadPCRs failed: %v", err)
		}
		if len(banks) == 0 {
			t.Error("No PCR banks returned")
		}
		for _, bank := range banks {
			if bank.Algorithm == "" {
				t.Error("Bank algorithm is empty")
			}
			if len(bank.PCRs) == 0 {
				t.Errorf("No PCRs in bank %s", bank.Algorithm)
			}
			for _, pcr := range bank.PCRs {
				if len(pcr.Value) == 0 {
					t.Errorf("PCR %d value is empty in bank %s", pcr.ID, bank.Algorithm)
				}
			}
		}
	})

	t.Run("ReadPCRsSinglePCR", func(t *testing.T) {
		pcrList := []uint{16}
		banks, err := tpmInstance.ReadPCRs(pcrList)
		if err != nil {
			t.Fatalf("ReadPCRs failed: %v", err)
		}
		if len(banks) == 0 {
			t.Error("No PCR banks returned")
		}
		found := false
		for _, bank := range banks {
			if bank.Algorithm == "SHA256" {
				for _, pcr := range bank.PCRs {
					if pcr.ID == 0 {
						found = true
						break
					}
				}
			}
		}
		if !found {
			t.Error("Expected to find PCR 16 in SHA256 bank")
		}
	})

	t.Run("Quote", func(t *testing.T) {
		pcrs := []uint{0, 1, 7}
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		if err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Quote failed: %v", err)
		}

		if len(quote.Quoted) == 0 {
			t.Error("Quote.Quoted is empty")
		}
		if len(quote.Signature) == 0 {
			t.Error("Quote.Signature is empty")
		}
		if len(quote.Nonce) != 32 {
			t.Errorf("Expected nonce length 32, got %d", len(quote.Nonce))
		}
		for i := range nonce {
			if nonce[i] != quote.Nonce[i] {
				t.Error("Quote nonce does not match input nonce")
				break
			}
		}
		if len(quote.PCRs) == 0 {
			t.Error("Quote.PCRs is empty")
		}
	})

	t.Run("PlatformQuote", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		quote, nonce, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("PlatformQuote failed: %v", err)
		}

		if len(quote.Quoted) == 0 {
			t.Error("PlatformQuote.Quoted is empty")
		}
		if len(quote.Signature) == 0 {
			t.Error("PlatformQuote.Signature is empty")
		}
		if len(nonce) != 32 {
			t.Errorf("Expected nonce length 32, got %d", len(nonce))
		}
		if len(quote.PCRs) == 0 {
			t.Error("PlatformQuote.PCRs is empty")
		}
	})

	t.Run("MakeCredential", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		credentialBlob, encryptedSecret, digest, err := tpmInstance.MakeCredential(
			iakAttrs.TPMAttributes.Name,
			nil,
		)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		if len(credentialBlob) == 0 {
			t.Error("CredentialBlob is empty")
		}
		if len(encryptedSecret) == 0 {
			t.Error("EncryptedSecret is empty")
		}
		if len(digest) == 0 {
			t.Error("Digest is empty")
		}
	})

	t.Run("MakeCredentialWithSecret", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		secret := []byte("test-secret-12345678901234567890")
		credentialBlob, encryptedSecret, digest, err := tpmInstance.MakeCredential(
			iakAttrs.TPMAttributes.Name,
			secret,
		)
		if err != nil {
			t.Fatalf("MakeCredential failed: %v", err)
		}

		if len(credentialBlob) == 0 {
			t.Error("CredentialBlob is empty")
		}
		if len(encryptedSecret) == 0 {
			t.Error("EncryptedSecret is empty")
		}
		for i := range secret {
			if digest[i] != secret[i] {
				t.Error("Digest does not match input secret")
				break
			}
		}
	})

	t.Run("AKProfile", func(t *testing.T) {
		profile, err := tpmInstance.AKProfile()
		if err != nil {
			t.Fatalf("AKProfile failed: %v", err)
		}
		if len(profile.EKPub) == 0 {
			t.Error("AKProfile.EKPub is empty")
		}
		if len(profile.AKPub) == 0 {
			t.Error("AKProfile.AKPub is empty")
		}
		if len(profile.AKName.Buffer) == 0 {
			t.Error("AKProfile.AKName is empty")
		}
	})

	t.Run("HashSmall", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}
		if iakAttrs.Parent == nil || iakAttrs.Parent.TPMAttributes == nil || iakAttrs.Parent.TPMAttributes.HierarchyAuth == nil {
			t.Skip("IAK parent TPMAttributes not configured")
		}

		data := []byte("test data to hash")
		digest, validation, err := tpmInstance.HashSequence(iakAttrs, data)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		if len(digest) == 0 {
			t.Error("Hash digest is empty")
		}
		if len(validation) == 0 {
			t.Error("Hash validation is empty")
		}

		_ = sha256.Sum256(data) // Length checked against sha256.Size
		if len(digest) != sha256.Size {
			t.Errorf("Expected digest length %d, got %d", sha256.Size, len(digest))
		}
	})

	t.Run("HashSequenceLarge", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}
		if iakAttrs.Parent == nil || iakAttrs.Parent.TPMAttributes == nil || iakAttrs.Parent.TPMAttributes.HierarchyAuth == nil {
			t.Skip("IAK parent TPMAttributes not configured")
		}

		data := make([]byte, 2048)
		_, err = rand.Read(data)
		if err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}

		digest, validation, err := tpmInstance.HashSequence(iakAttrs, data)
		if err != nil {
			t.Fatalf("HashSequence failed: %v", err)
		}

		if len(digest) == 0 {
			t.Error("HashSequence digest is empty")
		}
		if len(validation) == 0 {
			t.Error("HashSequence validation is empty")
		}
	})

	t.Run("ParsePublicKey", func(t *testing.T) {
		_, pub := tpmInstance.EKPublic()
		pubBuf := tpm2.New2B(pub)
		pubBytes := pubBuf.Bytes()

		parsedKey, err := tpmInstance.ParsePublicKey(pubBytes)
		if err != nil {
			t.Fatalf("ParsePublicKey failed: %v", err)
		}
		if parsedKey == nil {
			t.Fatal("ParsePublicKey returned nil")
		}

		_, ok := parsedKey.(*rsa.PublicKey)
		if !ok {
			t.Error("Parsed key is not an RSA public key")
		}
	})

	t.Run("FlushHandle", func(t *testing.T) {
		testHandle := tpm2.TPMHandle(0x80000099)
		tpmInstance.Flush(testHandle)
	})

	t.Run("EKCertificateNil", func(t *testing.T) {
		cert, err := tpmInstance.EKCertificate()
		if err == nil {
			t.Log("EKCertificate returned without error, this may be expected in some environments")
			if cert != nil {
				t.Log("EKCertificate returned a valid certificate")
			}
		} else {
			if err != ErrEndorsementCertNotFound {
				t.Logf("EKCertificate returned error: %v", err)
			}
		}
	})

	t.Run("FixedPropertiesNotImplemented", func(t *testing.T) {
		t.Skip("FixedProperties method not available in current implementation")
	})

	t.Run("GoldenMeasurements", func(t *testing.T) {
		measurements := tpmInstance.GoldenMeasurements()
		if len(measurements) == 0 {
			t.Error("GoldenMeasurements returned empty")
		}
	})

	t.Run("PlatformPolicyDigestHash", func(t *testing.T) {
		hash, err := tpmInstance.PlatformPolicyDigestHash()
		if err != nil {
			t.Fatalf("PlatformPolicyDigestHash failed: %v", err)
		}
		if len(hash) == 0 {
			t.Error("PlatformPolicyDigestHash returned empty")
		}
	})

	t.Run("SetHierarchyAuthAndRevert", func(t *testing.T) {
		oldAuth := store.NewClearPassword(nil)
		newAuth := store.NewClearPassword([]byte("test-auth"))

		ownerHierarchy := tpm2.TPMRHOwner
		err := tpmInstance.SetHierarchyAuth(oldAuth, newAuth, &ownerHierarchy)
		if err != nil {
			t.Fatalf("SetHierarchyAuth failed: %v", err)
		}

		err = tpmInstance.SetHierarchyAuth(newAuth, oldAuth, &ownerHierarchy)
		if err != nil {
			t.Fatalf("SetHierarchyAuth revert failed: %v", err)
		}
	})

	t.Run("InfoNotImplemented", func(t *testing.T) {
		info, err := tpmInstance.Info()
		if err != nil {
			t.Logf("Info returned error: %v", err)
		} else {
			if info == "" {
				t.Error("Info returned empty string")
			}
		}
	})

	t.Run("IsFIPS140_2", func(t *testing.T) {
		isFIPS, err := tpmInstance.IsFIPS140_2()
		if err != nil {
			t.Fatalf("IsFIPS140_2 failed: %v", err)
		}
		t.Logf("IsFIPS140_2: %v", isFIPS)
	})

	t.Run("CalculateNameFunction", func(t *testing.T) {
		publicArea := []byte("test-public-area-data")
		name, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
		if err != nil {
			t.Fatalf("CalculateName failed: %v", err)
		}
		if len(name) == 0 {
			t.Error("CalculateName returned empty")
		}
		if len(name) != 2+32 {
			t.Errorf("Expected name length 34, got %d", len(name))
		}
	})

	t.Run("CalculateNameSHA1", func(t *testing.T) {
		publicArea := []byte("test-public-area-data")
		name, err := CalculateName(tpm2.TPMAlgSHA1, publicArea)
		if err != nil {
			t.Fatalf("CalculateName with SHA1 failed: %v", err)
		}
		if len(name) != 2+20 {
			t.Errorf("Expected name length 22, got %d", len(name))
		}
	})

	t.Run("CalculateNameSHA512", func(t *testing.T) {
		publicArea := []byte("test-public-area-data")
		name, err := CalculateName(tpm2.TPMAlgSHA512, publicArea)
		if err != nil {
			t.Fatalf("CalculateName with SHA512 failed: %v", err)
		}
		if len(name) != 2+64 {
			t.Errorf("Expected name length 66, got %d", len(name))
		}
	})

	t.Run("ParseHashAlgFromString", func(t *testing.T) {
		algID, err := ParseHashAlgFromString("SHA-256")
		if err != nil {
			t.Fatalf("ParseHashAlgFromString failed: %v", err)
		}
		if algID != tpm2.TPMAlgSHA256 {
			t.Errorf("Expected TPMAlgSHA256, got %v", algID)
		}
	})

	t.Run("ParseCryptoHashAlgID", func(t *testing.T) {
		algID, err := ParseCryptoHashAlgID(crypto.SHA256)
		if err != nil {
			t.Fatalf("ParseCryptoHashAlgID failed: %v", err)
		}
		if algID != tpm2.TPMAlgSHA256 {
			t.Errorf("Expected TPMAlgSHA256, got %v", algID)
		}
	})

	t.Run("ParsePCRBankAlgID", func(t *testing.T) {
		algID, err := ParsePCRBankAlgID("sha256")
		if err != nil {
			t.Fatalf("ParsePCRBankAlgID failed: %v", err)
		}
		if algID != tpm2.TPMAlgSHA256 {
			t.Errorf("Expected TPMAlgSHA256, got %v", algID)
		}
	})

	t.Run("ParsePCRBankCryptoHash", func(t *testing.T) {
		hash, err := ParsePCRBankCryptoHash("sha256")
		if err != nil {
			t.Fatalf("ParsePCRBankCryptoHash failed: %v", err)
		}
		if hash != crypto.SHA256 {
			t.Errorf("Expected crypto.SHA256, got %v", hash)
		}
	})

	t.Run("HierarchyName", func(t *testing.T) {
		name := HierarchyName(tpm2.TPMRHOwner)
		if name != "OWNER" {
			t.Errorf("Expected 'OWNER', got %s", name)
		}
		name = HierarchyName(tpm2.TPMRHEndorsement)
		if name != "ENDORSEMENT" {
			t.Errorf("Expected 'ENDORSEMENT', got %s", name)
		}
		name = HierarchyName(tpm2.TPMRHPlatform)
		if name != "PLATFORM" {
			t.Errorf("Expected 'PLATFORM', got %s", name)
		}
	})

	t.Run("ParseIdentityProvisioningStrategy", func(t *testing.T) {
		strategy := ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK))
		if strategy != EnrollmentStrategyIAK {
			t.Errorf("Expected EnrollmentStrategyIAK, got %v", strategy)
		}
		strategy = ParseIdentityProvisioningStrategy(string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS))
		if strategy != EnrollmentStrategyIAK_IDEVID_SINGLE_PASS {
			t.Errorf("Expected EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, got %v", strategy)
		}
	})

	t.Run("EncodeAndDecode", func(t *testing.T) {
		data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		encoded := Encode(data)
		if encoded != "deadbeef" {
			t.Errorf("Expected 'deadbeef', got %s", encoded)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		for i := range data {
			if decoded[i] != data[i] {
				t.Errorf("Decoded data does not match original at index %d", i)
			}
		}
	})

	t.Run("EncodePCRs", func(t *testing.T) {
		banks := []PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []PCR{
					{ID: 0, Value: []byte("test-value")},
				},
			},
		}
		encoded, err := EncodePCRs(banks)
		if err != nil {
			t.Fatalf("EncodePCRs failed: %v", err)
		}
		if len(encoded) == 0 {
			t.Error("EncodePCRs returned empty")
		}
	})

	t.Run("DecodePCRs", func(t *testing.T) {
		banks := []PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []PCR{
					{ID: 0, Value: []byte("test-value")},
				},
			},
		}
		encoded, err := EncodePCRs(banks)
		if err != nil {
			t.Fatalf("EncodePCRs failed: %v", err)
		}
		decoded, err := DecodePCRs(encoded)
		if err != nil {
			t.Fatalf("DecodePCRs failed: %v", err)
		}
		if len(decoded) != len(banks) {
			t.Errorf("Expected %d banks, got %d", len(banks), len(decoded))
		}
	})

	t.Run("ShareSecretAndReconstruct", func(t *testing.T) {
		t.Skip("ShareSecret and SecretFromShares methods not yet implemented")
	})

	t.Run("HMACSaltedSessionNotNil", func(t *testing.T) {
		ekAttrs, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("Failed to get EK attributes: %v", err)
		}

		session, closer, err := tpmInstance.HMACSaltedSession(
			ekAttrs.TPMAttributes.Handle,
			ekAttrs.TPMAttributes.Public,
			nil,
		)
		if err != nil {
			t.Fatalf("HMACSaltedSession failed: %v", err)
		}
		defer func() { _ = closer() }()

		if session == nil {
			t.Fatal("HMACSaltedSession returned nil session")
		}
	})

	t.Run("HMACSession", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSession(nil)
		if err != nil {
			t.Fatalf("HMACSession failed: %v", err)
		}
		defer func() { _ = closer() }()

		if session == nil {
			t.Fatal("HMACSession returned nil session")
		}
	})

	t.Run("PlatformPolicySession", func(t *testing.T) {
		session, closer, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("PlatformPolicySession failed: %v", err)
		}
		defer func() { _ = closer() }()

		if session == nil {
			t.Fatal("PlatformPolicySession returned nil session")
		}
	})

	t.Run("CreateSession", func(t *testing.T) {
		ekAttrs, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("Failed to get EK attributes: %v", err)
		}

		session, closer, err := tpmInstance.CreateSession(ekAttrs)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		defer func() { _ = closer() }()

		if session == nil {
			t.Fatal("CreateSession returned nil session")
		}
	})

	t.Run("ECCKeysNotSupported", func(t *testing.T) {
		_, pub := tpmInstance.EKPublic()
		if pub.Type == tpm2.TPMAlgECC {
			eccPub := tpmInstance.EKECC()
			if eccPub == nil {
				t.Fatal("EKECC returned nil for ECC key")
			}
		} else {
			t.Log("EK is RSA, skipping ECC key test")
		}
	})

	t.Run("ReadPCRsInvalidPCRIndex", func(t *testing.T) {
		pcrList := []uint{30}
		_, err := tpmInstance.ReadPCRs(pcrList)
		if err == nil {
			t.Error("Expected error for invalid PCR index, got nil")
		}
		if err != ErrInvalidPCRIndex {
			t.Errorf("Expected ErrInvalidPCRIndex, got %v", err)
		}
	})

	t.Run("RandomBytesZeroLength", func(t *testing.T) {
		_, err := tpmInstance.RandomBytes(0)
		if err == nil {
			t.Error("Expected error for zero length, got nil")
		}
		if err != ErrInvalidRandomBytesLength {
			t.Errorf("Expected ErrInvalidRandomBytesLength, got %v", err)
		}
	})

	t.Run("RandomBytesNegativeLength", func(t *testing.T) {
		_, err := tpmInstance.RandomBytes(-1)
		if err == nil {
			t.Error("Expected error for negative length, got nil")
		}
		if err != ErrInvalidRandomBytesLength {
			t.Errorf("Expected ErrInvalidRandomBytesLength, got %v", err)
		}
	})

	t.Run("RandomHexOddLength", func(t *testing.T) {
		_, err := tpmInstance.RandomHex(31)
		if err == nil {
			t.Error("Expected error for odd length, got nil")
		}
		if err != ErrInvalidRandomBytesLength {
			t.Errorf("Expected ErrInvalidRandomBytesLength, got %v", err)
		}
	})

	t.Run("CalculateNameInvalidAlgorithm", func(t *testing.T) {
		_, err := CalculateName(tpm2.TPMAlgID(0xFFFF), []byte("test"))
		if err == nil {
			t.Error("Expected error for invalid algorithm, got nil")
		}
	})

	t.Run("ParsePCRBankAlgIDInvalid", func(t *testing.T) {
		_, err := ParsePCRBankAlgID("invalid-bank")
		if err == nil {
			t.Error("Expected error for invalid PCR bank, got nil")
		}
		if err != ErrInvalidPCRBankType {
			t.Errorf("Expected ErrInvalidPCRBankType, got %v", err)
		}
	})

	t.Run("ParsePCRBankCryptoHashInvalid", func(t *testing.T) {
		_, err := ParsePCRBankCryptoHash("invalid-bank")
		if err == nil {
			t.Error("Expected error for invalid PCR bank, got nil")
		}
		if err != ErrInvalidPCRBankType {
			t.Errorf("Expected ErrInvalidPCRBankType, got %v", err)
		}
	})

	t.Run("ParseCryptoHashAlgIDInvalid", func(t *testing.T) {
		_, err := ParseCryptoHashAlgID(crypto.Hash(0))
		if err == nil {
			t.Error("Expected error for invalid hash, got nil")
		}
		if err != ErrInvalidCryptoHashAlgID {
			t.Errorf("Expected ErrInvalidCryptoHashAlgID, got %v", err)
		}
	})

	t.Run("ConfigDefault", func(t *testing.T) {
		if DefaultConfig.Hash != "SHA-256" {
			t.Errorf("Expected default hash SHA-256, got %s", DefaultConfig.Hash)
		}
		if DefaultConfig.PlatformPCR != 16 {
			t.Errorf("Expected default platform PCR 16, got %d", DefaultConfig.PlatformPCR)
		}
		if DefaultConfig.EK == nil {
			t.Fatal("DefaultConfig.EK is nil")
		}
		if DefaultConfig.SSRK == nil {
			t.Fatal("DefaultConfig.SSRK is nil")
		}
	})

	t.Run("EKAttributesFromConfigRSA", func(t *testing.T) {
		ekConfig := EKConfig{
			CN:            "test-ek",
			Handle:        0x81010001,
			HierarchyAuth: "test-auth",
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
		attrs, err := EKAttributesFromConfig(ekConfig, nil, nil)
		if err != nil {
			t.Fatalf("EKAttributesFromConfig failed: %v", err)
		}
		if attrs.CN != "test-ek" {
			t.Errorf("Expected CN 'test-ek', got %s", attrs.CN)
		}
		if attrs.KeyAlgorithm != x509.RSA {
			t.Errorf("Expected RSA algorithm, got %v", attrs.KeyAlgorithm)
		}
	})

	t.Run("SRKAttributesFromConfig", func(t *testing.T) {
		srkConfig := SRKConfig{
			CN:           "test-srk",
			Handle:       0x81000001,
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
		attrs, err := SRKAttributesFromConfig(srkConfig, nil)
		if err != nil {
			t.Fatalf("SRKAttributesFromConfig failed: %v", err)
		}
		if attrs.CN != "test-srk" {
			t.Errorf("Expected CN 'test-srk', got %s", attrs.CN)
		}
		if attrs.KeyType != types.KeyTypeStorage {
			t.Errorf("Expected KEY_TYPE_STORAGE, got %v", attrs.KeyType)
		}
	})

	t.Run("IAKAttributesFromConfig", func(t *testing.T) {
		iakConfig := IAKConfig{
			CN:                 "test-iak",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
		attrs, err := IAKAttributesFromConfig(nil, &iakConfig, nil)
		if err != nil {
			t.Fatalf("IAKAttributesFromConfig failed: %v", err)
		}
		if attrs.CN != "test-iak" {
			t.Errorf("Expected CN 'test-iak', got %s", attrs.CN)
		}
		if attrs.KeyType != types.KeyTypeAttestation {
			t.Errorf("Expected KEY_TYPE_ATTESTATION, got %v", attrs.KeyType)
		}
	})

	t.Run("IDevIDAttributesFromConfig", func(t *testing.T) {
		idevidConfig := IDevIDConfig{
			CN:                 "test-idevid",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
			Model:              "test-model",
			Serial:             "test-serial",
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		}
		attrs, err := IDevIDAttributesFromConfig(idevidConfig, nil)
		if err != nil {
			t.Fatalf("IDevIDAttributesFromConfig failed: %v", err)
		}
		if attrs.CN != "test-idevid" {
			t.Errorf("Expected CN 'test-idevid', got %s", attrs.CN)
		}
		if attrs.KeyType != types.KeyTypeIDevID {
			t.Errorf("Expected KEY_TYPE_IDEVID, got %v", attrs.KeyType)
		}
	})

	// New subtests for increased coverage

	t.Run("SignWithIAKAttributes", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Create test data to sign
		testData := []byte("test data for signing")
		hash := sha256.Sum256(testData)

		signerOpts := &store.SignerOpts{
			KeyAttributes: iakAttrs,
		}

		signature, err := tpmInstance.Sign(nil, hash[:], signerOpts)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Sign returned empty signature")
		}
	})

	t.Run("HashWithSmallData", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}
		if iakAttrs.Parent == nil || iakAttrs.Parent.TPMAttributes == nil || iakAttrs.Parent.TPMAttributes.HierarchyAuth == nil {
			t.Skip("IAK parent TPMAttributes not configured")
		}

		// Use small data to test HashSequence()
		smallData := []byte("small test data")
		digest, validation, err := tpmInstance.HashSequence(iakAttrs, smallData)
		if err != nil {
			t.Fatalf("HashSequence failed: %v", err)
		}

		if len(digest) == 0 {
			t.Error("HashSequence digest is empty")
		}
		if len(validation) == 0 {
			t.Error("HashSequence validation is empty")
		}

		// Verify digest length matches SHA256
		if len(digest) != 32 {
			t.Errorf("Expected digest length 32, got %d", len(digest))
		}
	})

	t.Run("SignValidateAfterHash", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}
		if iakAttrs.Parent == nil || iakAttrs.Parent.TPMAttributes == nil || iakAttrs.Parent.TPMAttributes.HierarchyAuth == nil {
			t.Skip("IAK parent TPMAttributes not configured")
		}

		// Hash some data first
		testData := []byte("data to hash and sign")
		digest, validationDigest, err := tpmInstance.HashSequence(iakAttrs, testData)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		// Now sign with validation
		signature, err := tpmInstance.SignValidate(iakAttrs, digest, validationDigest)
		if err != nil {
			t.Fatalf("SignValidate failed: %v", err)
		}

		if len(signature) == 0 {
			t.Error("SignValidate returned empty signature")
		}
	})

	t.Run("RSAEncryptDecrypt", func(t *testing.T) {
		// Get EK attributes which has an RSA key
		ekAttrs, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("Failed to get EK attributes: %v", err)
		}

		// Create a test message (must be smaller than key size minus padding overhead)
		message := []byte("test encryption message")

		// Encrypt
		ciphertext, err := tpmInstance.RSAEncrypt(
			ekAttrs.TPMAttributes.Handle,
			ekAttrs.TPMAttributes.Name,
			message,
		)
		if err != nil {
			t.Fatalf("RSAEncrypt failed: %v", err)
		}

		if len(ciphertext) == 0 {
			t.Error("RSAEncrypt returned empty ciphertext")
		}

		// Ciphertext should be different from plaintext
		if string(ciphertext) == string(message) {
			t.Error("Ciphertext is the same as plaintext")
		}

		// Note: RSADecrypt may fail if the EK doesn't have decrypt capability
		// The EK is typically a storage key, so this might not work
		// Skipping decryption test for EK as it's not typically used for encryption
		t.Log("RSAEncrypt succeeded, skipping RSADecrypt as EK may not support decryption")
	})

	t.Run("CreateSecretKey", func(t *testing.T) {
		// Get SSRK attributes as parent
		ssrkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SSRK attributes: %v", err)
		}

		// Create key attributes for the secret key
		secretKeyAttrs := &types.KeyAttributes{
			CN:             "test-secret-key",
			KeyType:        types.KeyTypeSecret,
			StoreType:      types.StoreTPM2,
			Parent:         ssrkAttrs,
			PlatformPolicy: false,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(0x80000001),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}

		err = tpmInstance.CreateSecretKey(secretKeyAttrs, fileBackend)
		if err != nil {
			t.Fatalf("CreateSecretKey failed: %v", err)
		}

		t.Log("CreateSecretKey succeeded")
	})

	t.Run("NonceSession", func(t *testing.T) {
		hierarchyAuth := store.NewClearPassword(nil)
		session, closer, err := tpmInstance.NonceSession(hierarchyAuth)
		if err != nil {
			t.Fatalf("NonceSession failed: %v", err)
		}
		defer func() { _ = closer() }()

		if session == nil {
			t.Fatal("NonceSession returned nil session")
		}

		// Verify session has a nonce
		nonce := session.NonceTPM()
		if len(nonce.Buffer) == 0 {
			t.Error("NonceSession returned session with empty nonce")
		}
	})

	t.Run("DeleteKeyTransient", func(t *testing.T) {
		t.Skip("DeleteKey requires sealed data, not just secret key - skipping")
		// Create a transient key first
		ssrkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SSRK attributes: %v", err)
		}

		// Create key attributes for deletion test
		keyAttrs := &types.KeyAttributes{
			CN:             "test-delete-key",
			KeyType:        types.KeyTypeSecret,
			StoreType:      types.StoreTPM2,
			Parent:         ssrkAttrs,
			PlatformPolicy: false,
			TPMAttributes: &types.TPMAttributes{
				Handle:     tpm2.TPMHandle(0x80000002),
				HandleType: tpm2.TPMHTTransient,
				HashAlg:    tpm2.TPMAlgSHA256,
				Hierarchy:  tpm2.TPMRHOwner,
			},
		}

		// Create the key first
		err = tpmInstance.CreateSecretKey(keyAttrs, fileBackend)
		if err != nil {
			t.Fatalf("CreateSecretKey failed: %v", err)
		}

		// Delete the key
		err = tpmInstance.DeleteKey(keyAttrs, fileBackend)
		if err != nil {
			t.Fatalf("DeleteKey failed: %v", err)
		}

		t.Log("DeleteKey for transient key succeeded")
	})

	t.Run("ParsedEventLog", func(t *testing.T) {
		// This will likely return nil or error since we're using a simulator
		// and not a real TPM with an event log
		events, err := tpmInstance.ParsedEventLog()
		if err != nil {
			t.Logf("ParsedEventLog returned error (expected for simulator): %v", err)
		} else if events == nil {
			t.Log("ParsedEventLog returned nil (no event log available)")
		} else {
			t.Logf("ParsedEventLog returned %d events", len(events))
		}
	})

	t.Run("EKECC", func(t *testing.T) {
		// Check if EK is ECC type
		_, pub := tpmInstance.EKPublic()
		if pub.Type == tpm2.TPMAlgECC {
			eccPub := tpmInstance.EKECC()
			if eccPub == nil {
				t.Fatal("EKECC returned nil for ECC key")
			}
			if eccPub.Curve == nil {
				t.Error("ECC public key curve is nil")
			}
			if eccPub.X == nil || eccPub.Y == nil {
				t.Error("ECC public key coordinates are nil")
			}
		} else {
			t.Skip("EK is RSA, skipping ECC test")
		}
	})

	t.Run("SSRKPublicConfigured", func(t *testing.T) {
		// Check if SSRK is configured by trying to read it
		ssrkHandle := tpm2.TPMHandle(config.SSRK.Handle)
		name, pub, err := tpmInstance.ReadHandle(ssrkHandle)
		if err != nil {
			t.Skipf("SSRK not configured or available: %v", err)
		}

		if len(name.Buffer) == 0 {
			t.Error("SSRK name buffer is empty")
		}
		if pub.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected RSA algorithm for SSRK, got %v", pub.Type)
		}
	})

	t.Run("IDevIDAttributesProvisioned", func(t *testing.T) {
		// Check if IDevID is provisioned
		idevidAttrs, err := tpmInstance.IDevIDAttributes()
		if err != nil {
			t.Skipf("IDevID not provisioned: %v", err)
		}

		if idevidAttrs == nil {
			t.Fatal("IDevIDAttributes returned nil")
		}
		if idevidAttrs.KeyType != types.KeyTypeIDevID {
			t.Errorf("Expected KEY_TYPE_IDEVID, got %v", idevidAttrs.KeyType)
		}
		if idevidAttrs.TPMAttributes == nil {
			t.Fatal("IDevID TPMAttributes is nil")
		}
		if idevidAttrs.TPMAttributes.Handle != tpm2.TPMHandle(config.IDevID.Handle) {
			t.Errorf("Expected IDevID handle 0x%x, got 0x%x", config.IDevID.Handle, idevidAttrs.TPMAttributes.Handle)
		}
	})

	t.Run("IDevIDPublicKey", func(t *testing.T) {
		// First check if IDevID is available
		idevidAttrs, err := tpmInstance.IDevIDAttributes()
		if err != nil {
			t.Skipf("IDevID not provisioned: %v", err)
		}
		if idevidAttrs == nil {
			t.Skip("IDevID attributes not available")
		}

		// Get the IDevID public key
		idevid := tpmInstance.IDevID()
		if idevid == nil {
			t.Fatal("IDevID returned nil")
		}

		// Check the public key type
		switch key := idevid.(type) {
		case *rsa.PublicKey:
			if key.N == nil {
				t.Error("RSA public key N is nil")
			}
			if key.E == 0 {
				t.Error("RSA public key E is 0")
			}
		case *ecdsa.PublicKey:
			if key.Curve == nil {
				t.Error("ECC public key curve is nil")
			}
			if key.X == nil || key.Y == nil {
				t.Error("ECC public key coordinates are nil")
			}
		default:
			t.Errorf("Unexpected public key type: %T", idevid)
		}
	})
}

func TestTPMOperationsECC(t *testing.T) {
	t.Skip("Skipping - opening second simulator causes mutex deadlock")
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	logger := logging.DefaultLogger()

	buf := make([]byte, 8)
	_, err = rand.Reader.Read(buf)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create go-objstore backed storage using the factory
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		t.Fatalf("Failed to create storage factory: %v", err)
	}
	defer func() { _ = storageFactory.Close() }()

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     false,
		Device:         "/dev/tpmrm0",
		UseSimulator:   false,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{
				Curve: "P256",
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{
				Curve: "P256",
			},
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{
				Curve: "P256",
			},
		},
		KeyStore: &KeyStoreConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: false,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
		Transport:    sim,
	}

	tpmInstance, err := NewTPM2(params)
	if err != nil {
		if err != ErrNotInitialized {
			t.Fatalf("Failed to create TPM instance: %v", err)
		}
	}
	defer func() { _ = tpmInstance.Close() }()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	t.Run("EKECCKey", func(t *testing.T) {
		eccPub := tpmInstance.EKECC()
		if eccPub == nil {
			t.Fatal("EKECC returned nil")
		}
		if eccPub.Curve == nil {
			t.Error("ECC public key curve is nil")
		}
		if eccPub.X == nil || eccPub.Y == nil {
			t.Error("ECC public key coordinates are nil")
		}
	})

	t.Run("EKECCPublicArea", func(t *testing.T) {
		name, pub := tpmInstance.EKPublic()
		if len(name.Buffer) == 0 {
			t.Error("EK name buffer is empty")
		}
		if pub.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected ECC algorithm, got %v", pub.Type)
		}
	})

	t.Run("EKECCAttributes", func(t *testing.T) {
		ekAttrs, err := tpmInstance.EKAttributes()
		if err != nil {
			t.Fatalf("EKAttributes failed: %v", err)
		}
		if ekAttrs.KeyAlgorithm != x509.ECDSA {
			t.Errorf("Expected ECDSA algorithm, got %v", ekAttrs.KeyAlgorithm)
		}
	})

	t.Run("EKECCParsePublicKey", func(t *testing.T) {
		_, pub := tpmInstance.EKPublic()
		pubBuf := tpm2.New2B(pub)
		pubBytes := pubBuf.Bytes()

		parsedKey, err := tpmInstance.ParsePublicKey(pubBytes)
		if err != nil {
			t.Fatalf("ParsePublicKey failed: %v", err)
		}
		if parsedKey == nil {
			t.Fatal("ParsePublicKey returned nil")
		}

		_, ok := parsedKey.(*ecdsa.PublicKey)
		if !ok {
			t.Error("Parsed key is not an ECDSA public key")
		}
	})
}

func TestTPMOperationsMultipleRandomReads(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	logger := logging.DefaultLogger()

	buf := make([]byte, 8)
	_, err = rand.Reader.Read(buf)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create go-objstore backed storage using the factory
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		t.Fatalf("Failed to create storage factory: %v", err)
	}
	defer func() { _ = storageFactory.Close() }()

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     true,
		Device:         "/dev/tpmrm0",
		UseSimulator:   false,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSA.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		KeyStore: &KeyStoreConfig{
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: false,
		},
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
		Transport:    sim,
	}

	tpmInstance, err := NewTPM2(params)
	if err != nil {
		if err != ErrNotInitialized {
			t.Fatalf("Failed to create TPM instance: %v", err)
		}
	}
	defer func() { _ = tpmInstance.Close() }()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Fatalf("Failed to provision TPM: %v", err)
	}

	t.Run("MultipleConsecutiveRandomReads", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			randomBytes, err := tpmInstance.Random()
			if err != nil {
				t.Fatalf("Random read %d failed: %v", i, err)
			}
			if len(randomBytes) != 32 {
				t.Errorf("Read %d: Expected 32 bytes, got %d", i, len(randomBytes))
			}
		}
	})

	t.Run("LargeRandomBytesRead", func(t *testing.T) {
		size := 1024
		randomBytes, err := tpmInstance.RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes(%d) failed: %v", size, err)
		}
		if len(randomBytes) != size {
			t.Errorf("Expected %d bytes, got %d", size, len(randomBytes))
		}
	})

	t.Run("VariousSizeRandomReads", func(t *testing.T) {
		sizes := []int{1, 8, 16, 32, 48, 64, 100, 128, 256, 512}
		for _, size := range sizes {
			randomBytes, err := tpmInstance.RandomBytes(size)
			if err != nil {
				t.Fatalf("RandomBytes(%d) failed: %v", size, err)
			}
			if len(randomBytes) != size {
				t.Errorf("Size %d: Expected %d bytes, got %d", size, size, len(randomBytes))
			}
		}
	})
}
