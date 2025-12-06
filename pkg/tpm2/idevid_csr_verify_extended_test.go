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
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ========================================
// Tests for CSR Packing/Unpacking Functions
// ========================================

func TestPackIDevIDContent_ValidContent(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	// Set version info
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Set sizes
	prodModel := []byte("TestModel")
	prodSerial := []byte("12345")
	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(content.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(content.PadSz[:], 0)

	// Set payload
	content.ProdModel = prodModel
	content.ProdSerial = prodSerial

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify the packed data size
	expectedSize := 16*4 + len(prodModel) + len(prodSerial) // 16 uint32 fields + payloads
	assert.Equal(t, expectedSize, len(packed))
}

func TestPackIDevIDContent_WithAllFields(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	// Set version info
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Create test data for all fields
	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial123")
	prodCaData := []byte("CA Data")
	bootEvntLog := []byte("Boot Event Log Data")
	ekCert := []byte("EK Certificate")
	attestPub := []byte("Attestation Public Key")
	atCreateTkt := []byte("Create Ticket")
	atCertifyInfo := []byte("Certify Info")
	atCertifyInfoSig := []byte("Certify Info Signature")
	signingPub := []byte("Signing Public Key")
	sgnCertifyInfo := []byte("Signing Certify Info")
	sgnCertifyInfoSig := []byte("Signing Certify Info Signature")
	pad := []byte("====")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

	content.ProdModel = prodModel
	content.ProdSerial = prodSerial
	content.ProdCaData = prodCaData
	content.BootEvntLog = bootEvntLog
	content.EkCert = ekCert
	content.AttestPub = attestPub
	content.AtCreateTkt = atCreateTkt
	content.AtCertifyInfo = atCertifyInfo
	content.AtCertifyInfoSig = atCertifyInfoSig
	content.SigningPub = signingPub
	content.SgnCertifyInfo = sgnCertifyInfo
	content.SgnCertifyInfoSig = sgnCertifyInfoSig
	content.Pad = pad

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify size
	expectedPayloadSize := len(prodModel) + len(prodSerial) + len(prodCaData) +
		len(bootEvntLog) + len(ekCert) + len(attestPub) + len(atCreateTkt) +
		len(atCertifyInfo) + len(atCertifyInfoSig) + len(signingPub) +
		len(sgnCertifyInfo) + len(sgnCertifyInfoSig) + len(pad)
	expectedSize := 16*4 + expectedPayloadSize
	assert.Equal(t, expectedSize, len(packed))
}

func TestPackAndUnpackIDevIDContent_RoundTrip(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Create test data for all fields
	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial123")
	prodCaData := []byte("CA Data")
	bootEvntLog := []byte("Boot Event Log Data")
	ekCert := []byte("EK Certificate")
	attestPub := []byte("Attestation Public Key")
	atCreateTkt := []byte("Create Ticket")
	atCertifyInfo := []byte("Certify Info")
	atCertifyInfoSig := []byte("Certify Info Signature")
	signingPub := []byte("Signing Public Key")
	sgnCertifyInfo := []byte("Signing Certify Info")
	sgnCertifyInfoSig := []byte("Signing Certify Info Signature")
	pad := []byte("====")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

	content.ProdModel = prodModel
	content.ProdSerial = prodSerial
	content.ProdCaData = prodCaData
	content.BootEvntLog = bootEvntLog
	content.EkCert = ekCert
	content.AttestPub = attestPub
	content.AtCreateTkt = atCreateTkt
	content.AtCertifyInfo = atCertifyInfo
	content.AtCertifyInfoSig = atCertifyInfoSig
	content.SigningPub = signingPub
	content.SgnCertifyInfo = sgnCertifyInfo
	content.SgnCertifyInfoSig = sgnCertifyInfoSig
	content.Pad = pad

	packed, err := PackIDevIDContent(content)
	require.NoError(t, err)

	reader := bytes.NewReader(packed)
	unpacked, err := UnpackIDevIDContent(reader)
	require.NoError(t, err)

	// Verify fields match
	assert.Equal(t, content.StructVer, unpacked.StructVer)
	assert.Equal(t, content.HashAlgoId, unpacked.HashAlgoId)
	assert.Equal(t, content.HashSz, unpacked.HashSz)
	assert.Equal(t, content.ProdModel, unpacked.ProdModel)
	assert.Equal(t, content.ProdSerial, unpacked.ProdSerial)
	assert.Equal(t, content.ProdCaData, unpacked.ProdCaData)
	assert.Equal(t, content.BootEvntLog, unpacked.BootEvntLog)
	assert.Equal(t, content.EkCert, unpacked.EkCert)
	assert.Equal(t, content.AttestPub, unpacked.AttestPub)
	assert.Equal(t, content.AtCreateTkt, unpacked.AtCreateTkt)
	assert.Equal(t, content.AtCertifyInfo, unpacked.AtCertifyInfo)
	assert.Equal(t, content.AtCertifyInfoSig, unpacked.AtCertifyInfoSig)
	assert.Equal(t, content.SigningPub, unpacked.SigningPub)
	assert.Equal(t, content.SgnCertifyInfo, unpacked.SgnCertifyInfo)
	assert.Equal(t, content.SgnCertifyInfoSig, unpacked.SgnCertifyInfoSig)
	assert.Equal(t, content.Pad, unpacked.Pad)
}

func TestUnpackIDevIDContent_EmptyReader(t *testing.T) {
	reader := bytes.NewReader([]byte{})
	_, err := UnpackIDevIDContent(reader)
	require.Error(t, err)
}

func TestUnpackIDevIDContent_TruncatedData(t *testing.T) {
	// Only provide partial header
	data := make([]byte, 10)
	reader := bytes.NewReader(data)
	_, err := UnpackIDevIDContent(reader)
	require.Error(t, err)
}

func TestPackIDevIDCSR_ValidCSR(t *testing.T) {
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 64)

	// Setup minimal content
	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.Signature = make([]byte, 64)

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)
	require.NotNil(t, packed)

	// Verify the packed size includes header (3*4) + content (16*4) + signature (64)
	expectedSize := 3*4 + 16*4 + 64
	assert.Equal(t, expectedSize, len(packed))
}

func TestUnmarshalIDevIDCSR_ValidData(t *testing.T) {
	// Create a valid CSR
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 32)

	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.Signature = make([]byte, 32)

	packed, err := PackIDevIDCSR(csr)
	require.NoError(t, err)

	unmarshalled, err := UnmarshalIDevIDCSR(packed)
	require.NoError(t, err)

	assert.Equal(t, csr.StructVer, unmarshalled.StructVer)
	assert.Equal(t, csr.Contents, unmarshalled.Contents)
	assert.Equal(t, csr.SigSz, unmarshalled.SigSz)
}

func TestUnmarshalIDevIDCSR_EmptyData(t *testing.T) {
	_, err := UnmarshalIDevIDCSR([]byte{})
	require.Error(t, err)
}

func TestUnmarshalIDevIDCSR_TruncatedHeader(t *testing.T) {
	data := make([]byte, 5) // Less than one uint32
	_, err := UnmarshalIDevIDCSR(data)
	require.Error(t, err)
}

func TestUnpackIDevIDCSR_WithPayload(t *testing.T) {
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 200)
	binary.BigEndian.PutUint32(csr.SigSz[:], 64)

	prodModel := []byte("TestModel")
	prodSerial := []byte("Serial999")

	binary.BigEndian.PutUint32(csr.CsrContents.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
	binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], 32)
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], uint32(len(prodSerial)))
	binary.BigEndian.PutUint32(csr.CsrContents.ProdCaDataSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.BootEvntLogSz[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.EkCertSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AttestPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCreateTktSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.AtCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SigningPubSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.SgnCertifyInfoSignatureSZ[:], 0)
	binary.BigEndian.PutUint32(csr.CsrContents.PadSz[:], 0)

	csr.CsrContents.ProdModel = prodModel
	csr.CsrContents.ProdSerial = prodSerial
	csr.Signature = make([]byte, 64)

	unpacked, err := UnpackIDevIDCSR(csr)
	require.NoError(t, err)

	assert.Equal(t, uint32(0x00000100), unpacked.StructVer)
	assert.Equal(t, uint32(200), unpacked.Contents)
	assert.Equal(t, uint32(64), unpacked.SigSz)
	assert.Equal(t, prodModel, unpacked.CsrContents.ProdModel)
	assert.Equal(t, prodSerial, unpacked.CsrContents.ProdSerial)
}

func TestBytesToUint32_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    [4]byte
		expected uint32
	}{
		{
			name:     "zero value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x00},
			expected: 0,
		},
		{
			name:     "max value",
			input:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			expected: 0xFFFFFFFF,
		},
		{
			name:     "version number",
			input:    [4]byte{0x00, 0x00, 0x01, 0x00},
			expected: 256,
		},
		{
			name:     "TPM algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B}, // SHA256
			expected: 11,
		},
		{
			name:     "handle value",
			input:    [4]byte{0x81, 0x01, 0x00, 0x01},
			expected: 0x81010001,
		},
		{
			name:     "certificate handle",
			input:    [4]byte{0x01, 0xC0, 0x00, 0x02},
			expected: 0x01C00002,
		},
		{
			name:     "single byte value",
			input:    [4]byte{0x00, 0x00, 0x00, 0x01},
			expected: 1,
		},
		{
			name:     "high byte only",
			input:    [4]byte{0x80, 0x00, 0x00, 0x00},
			expected: 0x80000000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ========================================
// Tests for Signature Verification Logic
// ========================================

func TestRSAPKCS1v15SignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (*rsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name: "valid signature",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name: "invalid signature - tampered",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				signature[0] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - wrong message",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				wrongMessage := []byte("wrong message")
				hash := sha256.Sum256(message)
				wrongHash := sha256.Sum256(wrongMessage)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
				return &privateKey.PublicKey, wrongHash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - different key",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey1, crypto.SHA256, hash[:])
				return &privateKey2.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup()
			err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
			if tc.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRSAPSSSignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (*rsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name: "valid signature",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message for PSS")
				hash := sha256.Sum256(message)
				opts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
				signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], opts)
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name: "invalid signature - tampered",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message for PSS")
				hash := sha256.Sum256(message)
				opts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
				signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], opts)
				signature[len(signature)-1] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name: "invalid signature - empty",
			setup: func() (*rsa.PublicKey, []byte, []byte) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				return &privateKey.PublicKey, hash[:], []byte{}
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup()
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA256,
			}
			err := rsa.VerifyPSS(pubKey, crypto.SHA256, digest, signature, opts)
			if tc.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestECDSASignatureVerification(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		setup       func(elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte)
		expectValid bool
	}{
		{
			name:  "valid P256 signature",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message for ECDSA")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name:  "valid P384 signature",
			curve: elliptic.P384(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message for ECDSA P384")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: true,
		},
		{
			name:  "invalid signature - tampered",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				signature[0] ^= 0xFF
				return &privateKey.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
		{
			name:  "invalid signature - wrong digest",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				wrongMessage := []byte("wrong message")
				hash := sha256.Sum256(message)
				wrongHash := sha256.Sum256(wrongMessage)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
				return &privateKey.PublicKey, wrongHash[:], signature
			},
			expectValid: false,
		},
		{
			name:  "invalid signature - different key",
			curve: elliptic.P256(),
			setup: func(curve elliptic.Curve) (*ecdsa.PublicKey, []byte, []byte) {
				privateKey1, _ := ecdsa.GenerateKey(curve, rand.Reader)
				privateKey2, _ := ecdsa.GenerateKey(curve, rand.Reader)
				message := []byte("test message")
				hash := sha256.Sum256(message)
				signature, _ := ecdsa.SignASN1(rand.Reader, privateKey1, hash[:])
				return &privateKey2.PublicKey, hash[:], signature
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubKey, digest, signature := tc.setup(tc.curve)
			valid := ecdsa.VerifyASN1(pubKey, digest, signature)
			assert.Equal(t, tc.expectValid, valid)
		})
	}
}

// ========================================
// Tests for KeyAttributes Validation Logic
// ========================================

func TestKeyAttributesObjectAttributes(t *testing.T) {
	tests := []struct {
		name          string
		attrs         tpm2.TPMAObject
		isAK          bool
		expectValid   bool
		expectedError string
	}{
		{
			name: "valid AK attributes",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:        true,
			expectValid: true,
		},
		{
			name: "AK missing Restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  false,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "Restricted",
		},
		{
			name: "AK missing FixedTPM",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    false,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "FixedTPM",
		},
		{
			name: "AK missing FixedParent",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: false,
				SignEncrypt: true,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "FixedParent",
		},
		{
			name: "AK missing SignEncrypt",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: false,
			},
			isAK:          true,
			expectValid:   false,
			expectedError: "SignEncrypt",
		},
		{
			name: "valid IDevID attributes - non-restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  false,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:        false,
			expectValid: true,
		},
		{
			name: "IDevID should not be restricted",
			attrs: tpm2.TPMAObject{
				Restricted:  true,
				FixedTPM:    true,
				FixedParent: true,
				SignEncrypt: true,
			},
			isAK:          false,
			expectValid:   false,
			expectedError: "Restricted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var valid bool
			var err error

			if tc.isAK {
				// AK validation
				if !tc.attrs.Restricted {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedTPM {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedParent {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.SignEncrypt {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else {
					valid = true
				}
			} else {
				// IDevID validation
				if tc.attrs.Restricted {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedTPM {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.FixedParent {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else if !tc.attrs.SignEncrypt {
					valid = false
					err = store.ErrInvalidKeyAttributes
				} else {
					valid = true
				}
			}

			if tc.expectValid {
				assert.True(t, valid)
				assert.NoError(t, err)
			} else {
				assert.False(t, valid)
				assert.Error(t, err)
			}
		})
	}
}

// ========================================
// Tests for Hash Algorithm Parsing in CSR
// ========================================

func TestParseHashAlgorithmFromCSR(t *testing.T) {
	tests := []struct {
		name        string
		algID       uint32
		expectError bool
	}{
		{
			name:        "SHA1",
			algID:       uint32(tpm2.TPMAlgSHA1),
			expectError: false,
		},
		{
			name:        "SHA256",
			algID:       uint32(tpm2.TPMAlgSHA256),
			expectError: false,
		},
		{
			name:        "SHA384",
			algID:       uint32(tpm2.TPMAlgSHA384),
			expectError: false,
		},
		{
			name:        "SHA512",
			algID:       uint32(tpm2.TPMAlgSHA512),
			expectError: false,
		},
		{
			name:        "invalid algorithm",
			algID:       0xFFFF,
			expectError: true,
		},
		{
			name:        "zero algorithm",
			algID:       0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hashAlgo := tpm2.TPMAlgID(tc.algID)
			_, err := hashAlgo.Hash()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ========================================
// Tests for Signature Algorithm Classification
// ========================================

func TestSignatureAlgorithmClassification(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		isRSAPSS bool
		isECDSA  bool
		isRSASSA bool
	}{
		{
			name:     "SHA256WithRSAPSS",
			sigAlgo:  x509.SHA256WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA384WithRSAPSS",
			sigAlgo:  x509.SHA384WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA512WithRSAPSS",
			sigAlgo:  x509.SHA512WithRSAPSS,
			isRSAPSS: true,
			isECDSA:  false,
			isRSASSA: false,
		},
		{
			name:     "SHA256WithRSA",
			sigAlgo:  x509.SHA256WithRSA,
			isRSAPSS: false,
			isECDSA:  false,
			isRSASSA: true,
		},
		{
			name:     "ECDSAWithSHA256",
			sigAlgo:  x509.ECDSAWithSHA256,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
		{
			name:     "ECDSAWithSHA384",
			sigAlgo:  x509.ECDSAWithSHA384,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
		{
			name:     "ECDSAWithSHA512",
			sigAlgo:  x509.ECDSAWithSHA512,
			isRSAPSS: false,
			isECDSA:  true,
			isRSASSA: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isRSAPSS, store.IsRSAPSS(tc.sigAlgo))
			assert.Equal(t, tc.isECDSA, store.IsECDSA(tc.sigAlgo))
		})
	}
}

// ========================================
// Tests for CSR Content Validation
// ========================================

func TestCSRContentFieldSizes(t *testing.T) {
	t.Run("maximum field size validation", func(t *testing.T) {
		content := &TCG_IDEVID_CONTENT{}

		// Test with very large field sizes
		maxSize := uint32(1 << 24) // 16MB
		binary.BigEndian.PutUint32(content.EkCertSZ[:], maxSize)

		result := bytesToUint32(content.EkCertSZ)
		assert.Equal(t, maxSize, result)
	})

	t.Run("empty fields are valid", func(t *testing.T) {
		content := &TCG_IDEVID_CONTENT{}
		// All fields default to zero
		assert.Equal(t, uint32(0), bytesToUint32(content.ProdModelSz))
		assert.Equal(t, uint32(0), bytesToUint32(content.ProdSerialSz))
	})
}

func TestCSRVersionValidation(t *testing.T) {
	tests := []struct {
		name        string
		version     uint32
		expectValid bool
	}{
		{
			name:        "valid version 1.0",
			version:     0x00000100,
			expectValid: true,
		},
		{
			name:        "zero version",
			version:     0x00000000,
			expectValid: false,
		},
		{
			name:        "future version 2.0",
			version:     0x00000200,
			expectValid: true, // May be forward compatible
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csr := &TCG_CSR_IDEVID{}
			binary.BigEndian.PutUint32(csr.StructVer[:], tc.version)

			unpacked, err := UnpackIDevIDCSR(csr)
			require.NoError(t, err)
			assert.Equal(t, tc.version, unpacked.StructVer)
		})
	}
}

// ========================================
// Tests for Error Conditions in CSR Processing
// ========================================

func TestUnpackIDevIDCSR_CorruptedCopy(t *testing.T) {
	// Test that copy operations are validated
	csr := &TCG_CSR_IDEVID{}

	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 100)
	binary.BigEndian.PutUint32(csr.SigSz[:], 32)

	// Set a size larger than actual data
	binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 100)
	csr.CsrContents.ProdModel = []byte("short") // Only 5 bytes but size says 100

	_, err := UnpackIDevIDCSR(csr)
	// Should fail on copy validation
	assert.Error(t, err)
}

// ========================================
// Tests for Different Key Sizes
// ========================================

func TestRSASignatureWithDifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(func() string { return "RSA-" + string(rune(keySize)) }(), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			require.NoError(t, err)

			message := []byte("test message for different key sizes")
			hash := sha256.Sum256(message)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
			require.NoError(t, err)

			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hash[:], signature)
			assert.NoError(t, err)

			// Verify signature size matches key size
			expectedSigSize := keySize / 8
			assert.Equal(t, expectedSigSize, len(signature))
		})
	}
}

// ========================================
// Tests for Hash Size Validation
// ========================================

func TestParseHashSize_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize uint32
		expectError  bool
	}{
		{
			name:         "SHA1",
			hash:         crypto.SHA1,
			expectedSize: 20,
			expectError:  false,
		},
		{
			name:         "SHA256",
			hash:         crypto.SHA256,
			expectedSize: 32,
			expectError:  false,
		},
		{
			name:         "SHA384",
			hash:         crypto.SHA384,
			expectedSize: 48,
			expectError:  false,
		},
		{
			name:         "SHA512",
			hash:         crypto.SHA512,
			expectedSize: 64,
			expectError:  false,
		},
		{
			name:         "MD5 - unsupported",
			hash:         crypto.MD5,
			expectedSize: 0,
			expectError:  true,
		},
		{
			name:         "invalid hash",
			hash:         crypto.Hash(0),
			expectedSize: 0,
			expectError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
			}
		})
	}
}

// ========================================
// Tests for Enrollment Strategy Parsing
// ========================================

func TestEnrollmentStrategyParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			input:    "IAK",
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			input:    "IAK_IDEVID_SINGLE_PASS",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "unknown defaults to single pass",
			input:    "UNKNOWN",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			input:    "",
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
