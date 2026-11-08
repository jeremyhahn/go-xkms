package tpm2

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create a minimal valid TCG_IDEVID_CONTENT
// Note: Uses non-empty byte slices for all fields to avoid Go's Reader.Read EOF behavior
func createTestIDevIDContent() *TCG_IDEVID_CONTENT {
	content := &TCG_IDEVID_CONTENT{}

	// Set structure version to 1.0
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)

	// Use SHA-256 (0x000B = 11)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], 0x0000000B)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)

	// Product info
	prodModel := []byte("TestModel")
	prodSerial := []byte("SN12345")

	binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(prodModel)))
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(prodSerial)))

	// CA Data (non-empty)
	prodCaData := []byte("mock-ca-data")
	binary.BigEndian.PutUint32(content.ProdCaDataSz[:], uint32(len(prodCaData)))

	// Boot event log (non-empty)
	bootEvntLog := []byte("mock-boot-log")
	binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(len(bootEvntLog)))

	// EK Certificate (mock)
	ekCert := []byte("mock-ek-cert")
	binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(len(ekCert)))

	// Attestation public key (mock)
	attestPub := []byte("mock-attest-pub-key")
	binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(len(attestPub)))

	// Creation ticket
	atCreateTkt := []byte("mock-create-ticket")
	binary.BigEndian.PutUint32(content.AtCreateTktSZ[:], uint32(len(atCreateTkt)))

	// Certify info
	atCertifyInfo := []byte("mock-certify-info")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSZ[:], uint32(len(atCertifyInfo)))

	// Certify info signature
	atCertifyInfoSig := []byte("mock-certify-sig")
	binary.BigEndian.PutUint32(content.AtCertifyInfoSignatureSZ[:], uint32(len(atCertifyInfoSig)))

	// Signing public key
	signingPub := []byte("mock-signing-pub")
	binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(len(signingPub)))

	// Signing certify info
	sgnCertifyInfo := []byte("mock-sgn-certify")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSZ[:], uint32(len(sgnCertifyInfo)))

	// Signing certify info signature
	sgnCertifyInfoSig := []byte("mock-sgn-sig")
	binary.BigEndian.PutUint32(content.SgnCertifyInfoSignatureSZ[:], uint32(len(sgnCertifyInfoSig)))

	// Padding (non-empty to avoid EOF)
	pad := []byte("==")
	binary.BigEndian.PutUint32(content.PadSz[:], uint32(len(pad)))

	// Set actual data
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

	return content
}

// Helper to create a minimal TCG_CSR_IDEVID structure for testing
func createMinimalTCGCSRIDevIDCoverage(hashAlgo uint32, signature []byte) *TCG_CSR_IDEVID {
	csr := &TCG_CSR_IDEVID{}
	binary.BigEndian.PutUint32(csr.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(csr.Contents[:], 0)
	binary.BigEndian.PutUint32(csr.SigSz[:], uint32(len(signature)))
	csr.Signature = signature

	content := &csr.CsrContents
	binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
	binary.BigEndian.PutUint32(content.HashAlgoId[:], hashAlgo)
	binary.BigEndian.PutUint32(content.HashSz[:], 32)
	binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
	binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
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

	content.ProdModel = []byte("test")
	content.ProdSerial = []byte("001")
	content.ProdCaData = []byte{}
	content.BootEvntLog = []byte{}
	content.EkCert = []byte{}
	content.AttestPub = []byte{}
	content.AtCreateTkt = []byte{}
	content.AtCertifyInfo = []byte{}
	content.AtCertifyInfoSig = []byte{}
	content.SigningPub = []byte{}
	content.SgnCertifyInfo = []byte{}
	content.SgnCertifyInfoSig = []byte{}
	content.Pad = []byte{}

	return csr
}

func TestUnmarshalIDevIDCSRCoverage(t *testing.T) {
	packed := func(t *testing.T, sigSize int) []byte {
		t.Helper()
		csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, sigSize))
		data, err := PackIDevIDCSR(csr)
		require.NoError(t, err)
		return data
	}

	tests := []struct {
		name        string
		setup       func(t *testing.T) []byte
		expectError bool
	}{
		{
			name:  "unmarshal packed CSR",
			setup: func(t *testing.T) []byte { return packed(t, 64) },
		},
		{
			name:  "unmarshal with different signature size",
			setup: func(t *testing.T) []byte { return packed(t, 128) },
		},
		{
			name:        "unmarshal truncated data",
			setup:       func(*testing.T) []byte { return make([]byte, 8) },
			expectError: true,
		},
		{
			name:        "unmarshal empty data",
			setup:       func(*testing.T) []byte { return []byte{} },
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csr, err := UnmarshalIDevIDCSR(tc.setup(t))
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, csr)
		})
	}
}

func TestCreateIDevIDContent_InvalidHash(t *testing.T) {
	logger := slog.Default()
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

	idevidAttrs := &types.KeyAttributes{
		Hash: crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			BPublic:     tpm2.New2B(RSASSATemplate),
			CertifyInfo: []byte("idevid-certify-info"),
			Signature:   []byte("idevid-signature"),
		},
	}

	// hashAlgoId and hashSz describe the signer's hash (section 13.1), so a
	// signer whose HashAlg is not a hash algorithm cannot produce a CSR.
	invalidSignerHashes := []tpm2.TPMAlgID{
		tpm2.TPMAlgID(0),
		tpm2.TPMAlgRSA,
		tpm2.TPMAlgAES,
		tpm2.TPMAlgNull,
	}

	for _, invalidHash := range invalidSignerHashes {
		signerAttrs := &types.KeyAttributes{
			TPMAttributes: &types.TPMAttributes{
				BPublic: tpm2.New2B(RSASSATemplate),
				HashAlg: invalidHash,
			},
		}

		_, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs, signerAttrs)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidHashFunction)
	}

	_, err := tpm.createIDevIDContent(ekCert, akAttrs, idevidAttrs, nil)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes, "a nil signer has no hash to describe")
}
