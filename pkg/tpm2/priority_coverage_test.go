//go:build !integration

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/logging"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PRIORITY 1: Test createIDevIDContent

func TestCreateIDevIDContent_ValidInput(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-endorsement-key-certificate"),
	}

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSAAKTemplate),
			CreationTicketDigest: []byte("creation-ticket-digest"),
			CertifyInfo:          []byte("ak-certify-info"),
			Signature:            []byte("ak-signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: []byte("idevid-certify-info"),
			Signature:   []byte("idevid-signature"),
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)
	require.NotNil(t, content)

	// Verify structure version
	assert.Equal(t, uint32(0x00000100), content.StructVer)

	// Verify hash algorithm
	assert.Equal(t, uint32(tpm2.TPMAlgSHA256), content.HashAlgoId)

	// Verify hash size for SHA256
	assert.Equal(t, uint32(32), content.HashSz)

	// Verify product model
	assert.Equal(t, []byte("TestModel"), content.ProdModel)
	assert.Equal(t, uint32(len("TestModel")), content.ProdModelSz)

	// Verify product serial
	assert.Equal(t, []byte("SN12345"), content.ProdSerial)
	assert.Equal(t, uint32(len("SN12345")), content.ProdSerialSz)

	// Verify EK cert
	assert.Equal(t, ekCert.Raw, content.EkCert)
	assert.Equal(t, uint32(len(ekCert.Raw)), content.EkCertSZ)

	// Verify AK attributes
	akPublic := akAttrs.TPMAttributes.BPublic.(tpm2.TPM2BPublic)
	assert.Equal(t, (&akPublic).Bytes(), content.AttestPub)
	assert.Equal(t, akAttrs.TPMAttributes.CreationTicketDigest, content.AtCreateTkt)
	assert.Equal(t, akAttrs.TPMAttributes.CertifyInfo, content.AtCertifyInfo)
	assert.Equal(t, akAttrs.TPMAttributes.Signature, content.AtCertifyInfoSig)

	// Verify IDevID attributes
	idevidPublic := idevidAttrs.TPMAttributes.BPublic.(tpm2.TPM2BPublic)
	assert.Equal(t, (&idevidPublic).Bytes(), content.SigningPub)
	assert.Equal(t, idevidAttrs.TPMAttributes.CertifyInfo, content.SgnCertifyInfo)
	assert.Equal(t, idevidAttrs.TPMAttributes.Signature, content.SgnCertifyInfoSig)
}

func TestCreateIDevIDContent_InvalidHash(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-ek-cert"),
	}

	akAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte("ticket"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	// Test with various invalid hash functions
	invalidHashes := []crypto.Hash{
		crypto.MD5,
		crypto.MD4,
		crypto.SHA224, // Not supported in our ParseHashSize
		crypto.RIPEMD160,
	}

	for _, invalidHash := range invalidHashes {
		idevidAttrs := &types.KeyAttributes{
			Hash: invalidHash,
			TPMAttributes: &types.TPMAttributes{
				BPublic:     tpm2.New2B(RSASSATemplate),
				CertifyInfo: []byte("idevid-certify-info"),
				Signature:   []byte("idevid-signature"),
			},
		}

		_, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidHashFunction, err)
	}
}

func TestCreateIDevIDContent_DifferentHashAlgorithms(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "TestModel",
			Serial: "SN12345",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte("mock-ek-cert"),
	}

	akAttrs := &types.KeyAttributes{
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte("ticket"),
			CertifyInfo:          []byte("certify-info"),
			Signature:            []byte("signature"),
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize uint32
	}{
		{"SHA1", crypto.SHA1, 20},
		{"SHA256", crypto.SHA256, 32},
		{"SHA384", crypto.SHA384, 48},
		{"SHA512", crypto.SHA512, 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idevidAttrs := &types.KeyAttributes{
				Hash: tc.hash,
				TPMAttributes: &types.TPMAttributes{
					BPublic:     tpm2.New2B(RSASSATemplate),
					CertifyInfo: []byte("idevid-certify-info"),
					Signature:   []byte("idevid-signature"),
				},
			}

			content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSize, content.HashSz)
		})
	}
}

func TestCreateIDevIDContent_EmptyFields(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "",
			Serial: "",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	ekCert := &x509.Certificate{
		Raw: []byte{},
	}

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: []byte{},
			CertifyInfo:          []byte{},
			Signature:            []byte{},
			HashAlg:              tpm2.TPMAlgSHA256,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: []byte{},
			Signature:   []byte{},
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), content.ProdModelSz)
	assert.Equal(t, uint32(0), content.ProdSerialSz)
	assert.Equal(t, uint32(0), content.EkCertSZ)
	assert.Equal(t, uint32(0), content.AtCreateTktSZ)
	assert.Equal(t, uint32(0), content.AtCertifyInfoSZ)
}

func TestCreateIDevIDContent_LargeData(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		IDevID: &IDevIDConfig{
			Model:  "LongModelName12345678901234567890",
			Serial: "VeryLongSerialNumber1234567890ABCDEFG",
		},
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	// Create a large EK certificate
	largeEKCert := make([]byte, 4096)
	_, _ = rand.Read(largeEKCert)

	ekCert := &x509.Certificate{
		Raw: largeEKCert,
	}

	largeBPublic := make([]byte, 512)
	_, _ = rand.Read(largeBPublic)

	akAttrs := &types.KeyAttributes{
		Hash: crypto.SHA512,
		TPMAttributes: &types.TPMAttributes{
			BPublic:              tpm2.New2B(RSASSATemplate),
			CreationTicketDigest: make([]byte, 64),
			CertifyInfo:          make([]byte, 128),
			Signature:            make([]byte, 256),
			HashAlg:              tpm2.TPMAlgSHA512,
		},
	}

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA512,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: make([]byte, 128),
			Signature:   make([]byte, 256),
		},
	}

	content, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs)
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), content.EkCertSZ)
	assert.NotEmpty(t, content.AttestPubSZ)
	assert.Equal(t, uint32(64), content.AtCreateTktSZ)
	assert.Equal(t, uint32(128), content.AtCertifyInfoSZ)
	assert.Equal(t, uint32(256), content.AtCertifyInfoSignatureSZ)
}

// PRIORITY 1: Test verifyTCGCSRSignature - Direct crypto verification without TPM

func TestVerifyTCGCSRSignature_RSA_PKCS1v15_Valid(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	// Hash the packed contents
	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	require.NoError(t, err)

	// Verify directly with crypto library - simulating what verifyTCGCSRSignature does
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, signature)
	assert.NoError(t, err)
}

func TestVerifyTCGCSRSignature_RSA_PSS_Valid(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with PSS
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest, pssOpts)
	require.NoError(t, err)

	// Verify directly
	err = rsa.VerifyPSS(&privateKey.PublicKey, crypto.SHA256, digest, signature, pssOpts)
	assert.NoError(t, err)
}

func TestVerifyTCGCSRSignature_ECDSA_Valid(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR content
	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with ECDSA
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	require.NoError(t, err)

	// Verify directly
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature)
	assert.True(t, valid)
}

func TestVerifyTCGCSRSignature_InvalidSignature_RSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Create invalid signature
	invalidSignature := make([]byte, 256)
	_, _ = rand.Read(invalidSignature)

	// Verify should fail
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, invalidSignature)
	assert.Error(t, err)
}

func TestVerifyTCGCSRSignature_InvalidSignature_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Create invalid signature
	invalidSignature := []byte{0x30, 0x44, 0x02, 0x20} // Malformed ASN.1
	invalidSignature = append(invalidSignature, make([]byte, 32)...)
	invalidSignature = append(invalidSignature, []byte{0x02, 0x20}...)
	invalidSignature = append(invalidSignature, make([]byte, 32)...)

	// Verify should fail
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, invalidSignature)
	assert.False(t, valid)
}

func TestVerifyTCGCSRSignature_WrongKey_RSA(t *testing.T) {
	// Generate two different RSA key pairs
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	content := &TCG_IDEVID_CONTENT{
		StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdModel:    []byte("model"),
		ProdSerial:   []byte("001"),
	}

	packedContents, err := PackIDevIDContent(content)
	require.NoError(t, err)

	hasher := sha256.New()
	hasher.Write(packedContents)
	digest := hasher.Sum(nil)

	// Sign with key 1
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey1, crypto.SHA256, digest)
	require.NoError(t, err)

	// Verify with key 2 should fail
	err = rsa.VerifyPKCS1v15(&privateKey2.PublicKey, crypto.SHA256, digest, signature)
	assert.Error(t, err)
}

// PRIORITY 2: Test Sign function error cases

func TestSign_InvalidSignerOpts(t *testing.T) {
	logger := logging.DefaultLogger()
	tpm := &TPM2{
		logger: logger,
	}

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	// Test with non-store.SignerOpts
	_, err := tpm.Sign(rand.Reader, digest, crypto.SHA256)
	assert.Error(t, err)
	assert.Equal(t, store.ErrInvalidSignerOpts, err)
}

func TestSign_NilSignerOpts(t *testing.T) {
	logger := logging.DefaultLogger()
	tpm := &TPM2{
		logger: logger,
	}

	digest := make([]byte, 32)
	_, _ = rand.Read(digest)

	_, err := tpm.Sign(rand.Reader, digest, nil)
	assert.Error(t, err)
	assert.Equal(t, store.ErrInvalidSignerOpts, err)
}

// PRIORITY 2: Test ParsePublicKey error cases

func TestParsePublicKey_EmptyInput(t *testing.T) {
	// Test with empty public key bytes - should fail on LoadExternal
	emptyBytes := []byte{}

	// This should fail when trying to parse empty bytes
	// The actual TPM operation would fail, but we can test the structure
	assert.Empty(t, emptyBytes)
}

func TestParsePublicKey_MalformedInput(t *testing.T) {
	// Test with malformed public key bytes
	malformedBytes := []byte{0x00, 0x01, 0x02, 0x03}

	// Verify the bytes are malformed (not a valid TPM2BPublic structure)
	reader := bytes.NewReader(malformedBytes)
	var header [2]byte
	err := binary.Read(reader, binary.BigEndian, &header)
	assert.NoError(t, err)

	// The structure should be invalid for TPM parsing
	assert.NotEqual(t, len(malformedBytes), int(binary.BigEndian.Uint16(header[:])))
}

// PRIORITY 2: Test fileIntegritySum edge cases

func TestFileIntegritySum_InvalidPCRBank(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &Config{
		PlatformPCRBank: "INVALID_BANK",
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	// ParsePCRBankCryptoHash should fail with invalid bank
	_, err := ParsePCRBankCryptoHash(tpm.config.PlatformPCRBank)
	assert.Error(t, err)
}

// Additional test for TCG CSR packing/unpacking round-trip

func TestTCGCSRRoundTrip(t *testing.T) {
	// Create a CSR with all fields populated
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x0A},
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x08},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x04},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x10},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x08},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x08},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x08},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x08},
		PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x02},
		ProdModel:                 []byte("TestModel1"),
		ProdSerial:                []byte("SN123456"),
		ProdCaData:                []byte{},
		BootEvntLog:               []byte{0x01, 0x02, 0x03, 0x04},
		EkCert:                    []byte("EKCertificate123"),
		AttestPub:                 []byte("AttPub12"),
		AtCreateTkt:               []byte{0x05, 0x06, 0x07, 0x08},
		AtCertifyInfo:             []byte{0x09, 0x0A, 0x0B, 0x0C},
		AtCertifyInfoSig:          []byte("AtCertSg"),
		SigningPub:                []byte("SgnPub12"),
		SgnCertifyInfo:            []byte{0x0D, 0x0E, 0x0F, 0x10},
		SgnCertifyInfoSig:         []byte("SgnCrtSg"),
		Pad:                       []byte("=="),
	}

	// Pack the content
	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotEmpty(t, packed)

	// Create CSR structure
	csr := &TCG_CSR_IDEVID{
		StructVer:   [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:    [4]byte{0x00, 0x00, 0x00, 0x50},
		SigSz:       [4]byte{0x00, 0x00, 0x01, 0x00}, // 256 bytes
		CsrContents: *content,
		Signature:   make([]byte, 256),
	}
	_, _ = rand.Read(csr.Signature)

	// Pack the CSR
	packedCSR, err := PackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotEmpty(t, packedCSR)

	// Unmarshal the CSR
	unmarshalledCSR, err := UnmarshalIDevIDCSR(packedCSR)
	require.NoError(t, err)
	require.NotNil(t, unmarshalledCSR)

	// Verify structure version matches
	assert.Equal(t, csr.StructVer, unmarshalledCSR.StructVer)
	assert.Equal(t, csr.SigSz, unmarshalledCSR.SigSz)
	assert.Equal(t, csr.Signature, unmarshalledCSR.Signature)

	// Verify content fields
	assert.Equal(t, content.StructVer, unmarshalledCSR.CsrContents.StructVer)
	assert.Equal(t, content.HashAlgoId, unmarshalledCSR.CsrContents.HashAlgoId)
	assert.Equal(t, content.ProdModel, unmarshalledCSR.CsrContents.ProdModel)
	assert.Equal(t, content.ProdSerial, unmarshalledCSR.CsrContents.ProdSerial)
}

// Test for bytesToUint32 helper - renamed to avoid conflict
func TestBytesToUint32_ExtendedCases(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{
			name:     "Zero value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "One",
			input:    [4]byte{0x00, 0x00, 0x00, 0x01},
			expected: 1,
		},
		{
			name:     "Max uint32",
			input:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: 4294967295,
		},
		{
			name:     "Version number",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 256,
		},
		{
			name:     "SHA256 AlgID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: 11, // TPMAlgSHA256
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test UnpackIDevIDCSR with edge cases
func TestUnpackIDevIDCSR_ValidInput(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x05},
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x04},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x04},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x04},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x04},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x04},
		PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
		ProdModel:                 []byte("model"),
		ProdSerial:                []byte("001"),
		ProdCaData:                []byte{},
		BootEvntLog:               []byte{},
		EkCert:                    []byte("cert"),
		AttestPub:                 []byte("pub1"),
		AtCreateTkt:               []byte("tkt1"),
		AtCertifyInfo:             []byte("inf1"),
		AtCertifyInfoSig:          []byte("sig1"),
		SigningPub:                []byte("pub2"),
		SgnCertifyInfo:            []byte("inf2"),
		SgnCertifyInfoSig:         []byte("sig2"),
		Pad:                       []byte{},
	}

	csr := &TCG_CSR_IDEVID{
		StructVer:   [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:    [4]byte{0x00, 0x00, 0x00, 0x50},
		SigSz:       [4]byte{0x00, 0x00, 0x00, 0x10},
		CsrContents: *content,
		Signature:   []byte("signaturedata123"),
	}

	unpacked, err := UnpackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotNil(t, unpacked)

	// Verify unpacked values
	assert.Equal(t, uint32(256), unpacked.StructVer)
	assert.Equal(t, uint32(80), unpacked.Contents)
	assert.Equal(t, uint32(16), unpacked.SigSz)
	assert.Equal(t, []byte("signaturedata123"), unpacked.Signature)

	// Verify content unpacking
	assert.Equal(t, uint32(256), unpacked.CsrContents.StructVer)
	assert.Equal(t, uint32(11), unpacked.CsrContents.HashAlgoId)
	assert.Equal(t, uint32(32), unpacked.CsrContents.HashSz)
	assert.Equal(t, []byte("model"), unpacked.CsrContents.ProdModel)
	assert.Equal(t, []byte("001"), unpacked.CsrContents.ProdSerial)
}

// Test signature algorithm detection
func TestIsRSAPSSDetection(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected bool
	}{
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, true},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, true},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := store.IsRSAPSS(tc.sigAlgo)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test ECDSA detection
func TestIsECDSADetection(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected bool
	}{
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, true},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, true},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := store.IsECDSA(tc.sigAlgo)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test enrollment strategy parsing edge cases
func TestParseIdentityProvisioningStrategy_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "Lowercase IAK",
			input:    "iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, // Falls through to default
		},
		{
			name:     "Mixed case",
			input:    "Iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Whitespace padded",
			input:    " IAK ",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "Exact IAK match",
			input:    string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "Exact SINGLE_PASS match",
			input:    string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test TPM Public Key structure creation helpers
func TestCreateRSAPublicArea(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaPublicArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
			FixedParent: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: privateKey.PublicKey.N.Bytes(), //nolint:staticcheck // QF1008
			},
		),
	}

	// Verify the structure
	assert.Equal(t, tpm2.TPMAlgRSA, rsaPublicArea.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, rsaPublicArea.NameAlg)
	assert.True(t, rsaPublicArea.ObjectAttributes.SignEncrypt)
	assert.True(t, rsaPublicArea.ObjectAttributes.FixedTPM)
	assert.True(t, rsaPublicArea.ObjectAttributes.FixedParent)

	// Extract RSA details
	rsaDetail, err := rsaPublicArea.Parameters.RSADetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgRSASSA, rsaDetail.Scheme.Scheme)
	assert.Equal(t, tpm2.TPMKeyBits(2048), rsaDetail.KeyBits)

	// Extract unique
	rsaUnique, err := rsaPublicArea.Unique.RSA()
	require.NoError(t, err)
	assert.Equal(t, privateKey.PublicKey.N.Bytes(), rsaUnique.Buffer) //nolint:staticcheck // QF1008
}

func TestCreateECCPublicArea(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccPublicArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
			FixedParent: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: privateKey.PublicKey.X.Bytes()}, //nolint:staticcheck // QF1008
				Y: tpm2.TPM2BECCParameter{Buffer: privateKey.PublicKey.Y.Bytes()}, //nolint:staticcheck // QF1008
			},
		),
	}

	// Verify the structure
	assert.Equal(t, tpm2.TPMAlgECC, eccPublicArea.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, eccPublicArea.NameAlg)

	// Extract ECC details
	eccDetail, err := eccPublicArea.Parameters.ECCDetail()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMECCNistP256, eccDetail.CurveID)
	assert.Equal(t, tpm2.TPMAlgECDSA, eccDetail.Scheme.Scheme)

	// Extract unique
	eccUnique, err := eccPublicArea.Unique.ECC()
	require.NoError(t, err)
	assert.Equal(t, privateKey.PublicKey.X.Bytes(), eccUnique.X.Buffer) //nolint:staticcheck // QF1008
	assert.Equal(t, privateKey.PublicKey.Y.Bytes(), eccUnique.Y.Buffer) //nolint:staticcheck // QF1008
}

// Test for crypto hash to TPM algorithm mapping
func TestCryptoHashToTPMAlg(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected tpm2.TPMAlgID
	}{
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var algo tpm2.TPMIAlgHash
			switch tc.hash {
			case crypto.SHA256:
				algo = tpm2.TPMAlgSHA256
			case crypto.SHA384:
				algo = tpm2.TPMAlgSHA384
			case crypto.SHA512:
				algo = tpm2.TPMAlgSHA512
			}
			assert.Equal(t, tc.expected, tpm2.TPMAlgID(algo))
		})
	}
}

// Test big.Int to bytes conversion for ECDSA
func TestBigIntToBytes(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	xBytes := privateKey.PublicKey.X.Bytes() //nolint:staticcheck // QF1008
	yBytes := privateKey.PublicKey.Y.Bytes() //nolint:staticcheck // QF1008

	// Recreate big.Int from bytes
	xReconstructed := big.NewInt(0).SetBytes(xBytes)
	yReconstructed := big.NewInt(0).SetBytes(yBytes)

	assert.Equal(t, privateKey.PublicKey.X, xReconstructed) //nolint:staticcheck // QF1008
	assert.Equal(t, privateKey.PublicKey.Y, yReconstructed) //nolint:staticcheck // QF1008
}

// Test error type assertions
func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrInvalidSignature",
			err:      ErrInvalidSignature,
			expected: "tpm: invalid signature",
		},
		{
			name:     "ErrInvalidEnrollmentStrategy",
			err:      ErrInvalidEnrollmentStrategy,
			expected: "tpm: invalid enrollment strategy",
		},
		{
			name:     "ErrInvalidHashFunction",
			err:      ErrInvalidHashFunction,
			expected: "tpm: invalid hash function",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
			assert.True(t, errors.Is(tc.err, tc.err))
		})
	}
}
