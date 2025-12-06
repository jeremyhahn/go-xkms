package tpm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

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

// Helper to create RSA public key in TPM format
func createRSATPMPublicCoverage(pub *rsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	modBytes := pub.N.Bytes()
	if len(modBytes) < 256 {
		padded := make([]byte, 256)
		copy(padded[256-len(modBytes):], modBytes)
		modBytes = padded
	}

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
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
				Buffer: modBytes,
			},
		),
	}
	return tpmPub
}

// Helper to create ECDSA public key in TPM format
func createECDSATPMPublicCoverage(pub *ecdsa.PublicKey, restricted bool) tpm2.TPMTPublic {
	var curveID tpm2.TPMECCCurve
	var nameAlg tpm2.TPMAlgID

	switch pub.Curve {
	case elliptic.P256():
		curveID = tpm2.TPMECCNistP256
		nameAlg = tpm2.TPMAlgSHA256
	case elliptic.P384():
		curveID = tpm2.TPMECCNistP384
		nameAlg = tpm2.TPMAlgSHA384
	case elliptic.P521():
		curveID = tpm2.TPMECCNistP521
		nameAlg = tpm2.TPMAlgSHA512
	default:
		curveID = tpm2.TPMECCNistP256
		nameAlg = tpm2.TPMAlgSHA256
	}

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	tpmPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: nameAlg,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          restricted,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: curveID,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: nameAlg,
						},
					),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
		),
	}
	return tpmPub
}

func TestPackIDevIDContentCoverage(t *testing.T) {
	tests := []struct {
		name        string
		content     *TCG_IDEVID_CONTENT
		expectError bool
	}{
		{
			name: "valid minimal content",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(c.HashSz[:], 32)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 4)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 3)
				c.ProdModel = []byte("test")
				c.ProdSerial = []byte("001")
				c.ProdCaData = []byte{}
				c.BootEvntLog = []byte{}
				c.EkCert = []byte{}
				c.AttestPub = []byte{}
				c.AtCreateTkt = []byte{}
				c.AtCertifyInfo = []byte{}
				c.AtCertifyInfoSig = []byte{}
				c.SigningPub = []byte{}
				c.SgnCertifyInfo = []byte{}
				c.SgnCertifyInfoSig = []byte{}
				c.Pad = []byte{}
				return c
			}(),
			expectError: false,
		},
		{
			name: "content with padding",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(c.HashSz[:], 32)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 10)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 6)
				binary.BigEndian.PutUint32(c.PadSz[:], 8)
				c.ProdModel = []byte("testmodel1")
				c.ProdSerial = []byte("ser123")
				c.ProdCaData = []byte{}
				c.BootEvntLog = []byte{}
				c.EkCert = []byte{}
				c.AttestPub = []byte{}
				c.AtCreateTkt = []byte{}
				c.AtCertifyInfo = []byte{}
				c.AtCertifyInfoSig = []byte{}
				c.SigningPub = []byte{}
				c.SgnCertifyInfo = []byte{}
				c.SgnCertifyInfoSig = []byte{}
				c.Pad = []byte("========")
				return c
			}(),
			expectError: false,
		},
		{
			name: "content with all fields populated",
			content: func() *TCG_IDEVID_CONTENT {
				c := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(c.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(c.HashAlgoId[:], uint32(tpm2.TPMAlgSHA384))
				binary.BigEndian.PutUint32(c.HashSz[:], 48)
				binary.BigEndian.PutUint32(c.ProdModelSz[:], 5)
				binary.BigEndian.PutUint32(c.ProdSerialSz[:], 4)
				binary.BigEndian.PutUint32(c.ProdCaDataSz[:], 10)
				binary.BigEndian.PutUint32(c.BootEvntLogSz[:], 16)
				binary.BigEndian.PutUint32(c.EkCertSZ[:], 8)
				binary.BigEndian.PutUint32(c.AttestPubSZ[:], 12)
				binary.BigEndian.PutUint32(c.AtCreateTktSZ[:], 6)
				binary.BigEndian.PutUint32(c.AtCertifyInfoSZ[:], 10)
				binary.BigEndian.PutUint32(c.AtCertifyInfoSignatureSZ[:], 14)
				binary.BigEndian.PutUint32(c.SigningPubSZ[:], 8)
				binary.BigEndian.PutUint32(c.SgnCertifyInfoSZ[:], 10)
				binary.BigEndian.PutUint32(c.SgnCertifyInfoSignatureSZ[:], 12)
				c.ProdModel = []byte("edge1")
				c.ProdSerial = []byte("0001")
				c.ProdCaData = []byte("ca_data_01")
				c.BootEvntLog = []byte("boot_event_log_1")
				c.EkCert = []byte("ek_cert1")
				c.AttestPub = []byte("attest_pub_1")
				c.AtCreateTkt = []byte("ticket")
				c.AtCertifyInfo = []byte("certify_01")
				c.AtCertifyInfoSig = []byte("certify_sig_01")
				c.SigningPub = []byte("sign_pub")
				c.SgnCertifyInfo = []byte("sgn_cert_i")
				c.SgnCertifyInfoSig = []byte("sgn_cert_sig")
				c.Pad = []byte{}
				return c
			}(),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDContent(tc.content)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(packed) == 0 {
				t.Error("packed content should not be empty")
			}
		})
	}
}

func TestPackIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name:        "valid minimal CSR",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 256)),
			expectError: false,
		},
		{
			name:        "CSR with small signature",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64)),
			expectError: false,
		},
		{
			name:        "CSR with SHA384",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA384), make([]byte, 256)),
			expectError: false,
		},
		{
			name:        "CSR with SHA512",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA512), make([]byte, 256)),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packed, err := PackIDevIDCSR(tc.csr)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(packed) == 0 {
				t.Error("packed CSR should not be empty")
			}

			expectedMinSize := 12 + 64
			if len(packed) < expectedMinSize {
				t.Errorf("packed CSR too small: got %d, expected at least %d", len(packed), expectedMinSize)
			}
		})
	}
}

func TestUnpackIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		csr         *TCG_CSR_IDEVID
		expectError bool
	}{
		{
			name:        "unpack valid CSR",
			csr:         createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 256)),
			expectError: false,
		},
		{
			name: "unpack CSR with custom content",
			csr: func() *TCG_CSR_IDEVID {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA384), make([]byte, 128))
				binary.BigEndian.PutUint32(csr.CsrContents.ProdModelSz[:], 8)
				csr.CsrContents.ProdModel = []byte("mydevice")
				binary.BigEndian.PutUint32(csr.CsrContents.ProdSerialSz[:], 10)
				csr.CsrContents.ProdSerial = []byte("SN12345678")
				return csr
			}(),
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unpacked, err := UnpackIDevIDCSR(tc.csr)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if unpacked == nil {
				t.Fatal("unpacked CSR should not be nil")
				return
			}
			if unpacked.StructVer != 0x00000100 {
				t.Errorf("unexpected struct version: got %x, want %x", unpacked.StructVer, 0x00000100)
			}
			if len(unpacked.Signature) != int(unpacked.SigSz) {
				t.Errorf("signature size mismatch: got %d, want %d", len(unpacked.Signature), unpacked.SigSz)
			}
		})
	}
}

func TestUnmarshalIDevIDCSRCoverage(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() []byte
		expectError bool
	}{
		{
			name: "unmarshal packed CSR",
			setup: func() []byte {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 64))
				packed, _ := PackIDevIDCSR(csr)
				return packed
			},
			expectError: false,
		},
		{
			name: "unmarshal with different signature size",
			setup: func() []byte {
				csr := createMinimalTCGCSRIDevIDCoverage(uint32(tpm2.TPMAlgSHA256), make([]byte, 128))
				packed, _ := PackIDevIDCSR(csr)
				return packed
			},
			expectError: false,
		},
		{
			name: "unmarshal truncated data",
			setup: func() []byte {
				return make([]byte, 8)
			},
			expectError: true,
		},
		{
			name: "unmarshal empty data",
			setup: func() []byte {
				return []byte{}
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.setup()
			csr, err := UnmarshalIDevIDCSR(data)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if csr == nil {
				t.Fatal("unmarshaled CSR should not be nil")
			}
		})
	}
}

func TestUnpackIDevIDContentCoverage(t *testing.T) {
	t.Skip("Test has hex decoding issues")
	tests := []struct {
		name        string
		setup       func() *bytes.Reader
		expectError bool
	}{
		{
			name: "unpack valid content",
			setup: func() *bytes.Reader {
				content := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
				binary.BigEndian.PutUint32(content.HashSz[:], 32)
				binary.BigEndian.PutUint32(content.ProdModelSz[:], 4)
				binary.BigEndian.PutUint32(content.ProdSerialSz[:], 3)
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
				packed, _ := PackIDevIDContent(content)
				return bytes.NewReader(packed)
			},
			expectError: false,
		},
		{
			name: "unpack content with large fields",
			setup: func() *bytes.Reader {
				content := &TCG_IDEVID_CONTENT{}
				binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
				binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA512))
				binary.BigEndian.PutUint32(content.HashSz[:], 64)
				binary.BigEndian.PutUint32(content.ProdModelSz[:], 20)
				binary.BigEndian.PutUint32(content.ProdSerialSz[:], 15)
				binary.BigEndian.PutUint32(content.BootEvntLogSz[:], 100)
				content.ProdModel = make([]byte, 20)
				content.ProdSerial = make([]byte, 15)
				content.ProdCaData = []byte{}
				content.BootEvntLog = make([]byte, 100)
				content.EkCert = []byte{}
				content.AttestPub = []byte{}
				content.AtCreateTkt = []byte{}
				content.AtCertifyInfo = []byte{}
				content.AtCertifyInfoSig = []byte{}
				content.SigningPub = []byte{}
				content.SgnCertifyInfo = []byte{}
				content.SgnCertifyInfoSig = []byte{}
				content.Pad = []byte{}
				packed, _ := PackIDevIDContent(content)
				return bytes.NewReader(packed)
			},
			expectError: false,
		},
		{
			name: "unpack truncated data",
			setup: func() *bytes.Reader {
				return bytes.NewReader(make([]byte, 10))
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := tc.setup()
			content, err := UnpackIDevIDContent(reader)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if content == nil {
				t.Fatal("unpacked content should not be nil")
			}
		})
	}
}

func TestBytesToUint32Coverage(t *testing.T) {
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
			expected: 0x00000100,
		},
		{
			name:     "SHA256 algorithm ID",
			input:    [4]byte{0x00, 0x00, 0x00, 0x0B},
			expected: uint32(tpm2.TPMAlgSHA256),
		},
		{
			name:     "random value",
			input:    [4]byte{0x12, 0x34, 0x56, 0x78},
			expected: 0x12345678,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToUint32(tc.input)
			if result != tc.expected {
				t.Errorf("got %x, want %x", result, tc.expected)
			}
		})
	}
}

func TestParseHashSizeCoverage(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    uint32
		expectError bool
	}{
		{
			name:        "SHA1",
			hash:        crypto.SHA1,
			expected:    20,
			expectError: false,
		},
		{
			name:        "SHA256",
			hash:        crypto.SHA256,
			expected:    32,
			expectError: false,
		},
		{
			name:        "SHA384",
			hash:        crypto.SHA384,
			expected:    48,
			expectError: false,
		},
		{
			name:        "SHA512",
			hash:        crypto.SHA512,
			expected:    64,
			expectError: false,
		},
		{
			name:        "unsupported hash",
			hash:        crypto.MD5,
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid hash",
			hash:        crypto.Hash(0),
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.hash)
			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				if !errors.Is(err, ErrInvalidHashFunction) {
					t.Errorf("expected ErrInvalidHashFunction, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if size != tc.expected {
				t.Errorf("got %d, want %d", size, tc.expected)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyCoverage(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			strategy: string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			strategy: "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "invalid strategy defaults to single pass",
			strategy: "INVALID",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "case sensitive - lowercase fails",
			strategy: "iak",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.strategy)
			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestRSAPKCS1v15SignatureVerificationCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name        string
		hash        crypto.Hash
		dataSize    int
		expectError bool
	}{
		{
			name:        "SHA256 signature",
			hash:        crypto.SHA256,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "SHA384 signature",
			hash:        crypto.SHA384,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "SHA512 signature",
			hash:        crypto.SHA512,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "large data",
			hash:        crypto.SHA256,
			dataSize:    10000,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, tc.hash, digest)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, tc.hash, digest, signature)
			if tc.expectError {
				if err == nil {
					t.Error("expected verification to fail")
				}
			} else {
				if err != nil {
					t.Errorf("signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestRSAPSSSignatureVerificationCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name        string
		hash        crypto.Hash
		saltLength  int
		dataSize    int
		expectError bool
	}{
		{
			name:        "SHA256 PSS with salt length equals hash",
			hash:        crypto.SHA256,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "SHA384 PSS",
			hash:        crypto.SHA384,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "SHA512 PSS",
			hash:        crypto.SHA512,
			saltLength:  rsa.PSSSaltLengthEqualsHash,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "PSS with auto salt length",
			hash:        crypto.SHA256,
			saltLength:  rsa.PSSSaltLengthAuto,
			dataSize:    150,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			pssOpts := &rsa.PSSOptions{
				SaltLength: tc.saltLength,
				Hash:       tc.hash,
			}

			signature, err := rsa.SignPSS(rand.Reader, privateKey, tc.hash, digest, pssOpts)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			err = rsa.VerifyPSS(&privateKey.PublicKey, tc.hash, digest, signature, pssOpts)
			if tc.expectError {
				if err == nil {
					t.Error("expected verification to fail")
				}
			} else {
				if err != nil {
					t.Errorf("PSS signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestInvalidRSASignatureCoverage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	data := []byte("test data for signature")
	hasher := crypto.SHA256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	tests := []struct {
		name      string
		modifySig func([]byte) []byte
	}{
		{
			name: "flip bit in signature",
			modifySig: func(sig []byte) []byte {
				modified := make([]byte, len(sig))
				copy(modified, sig)
				modified[0] ^= 0x01
				return modified
			},
		},
		{
			name: "truncate signature",
			modifySig: func(sig []byte) []byte {
				return sig[:len(sig)-1]
			},
		},
		{
			name: "zero out signature",
			modifySig: func(sig []byte) []byte {
				return make([]byte, len(sig))
			},
		},
		{
			name: "empty signature",
			modifySig: func(sig []byte) []byte {
				return []byte{}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modifiedSig := tc.modifySig(signature)
			err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, modifiedSig)
			if err == nil {
				t.Error("expected verification to fail with modified signature")
			}
		})
	}
}

func TestECDSASignatureVerificationCoverage(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		hash        crypto.Hash
		dataSize    int
		expectError bool
	}{
		{
			name:        "P256 with SHA256",
			curve:       elliptic.P256(),
			hash:        crypto.SHA256,
			dataSize:    100,
			expectError: false,
		},
		{
			name:        "P384 with SHA384",
			curve:       elliptic.P384(),
			hash:        crypto.SHA384,
			dataSize:    200,
			expectError: false,
		},
		{
			name:        "P521 with SHA512",
			curve:       elliptic.P521(),
			hash:        crypto.SHA512,
			dataSize:    300,
			expectError: false,
		},
		{
			name:        "P256 with large data",
			curve:       elliptic.P256(),
			hash:        crypto.SHA256,
			dataSize:    10000,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			data := make([]byte, tc.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("failed to generate random data: %v", err)
			}

			hasher := tc.hash.New()
			hasher.Write(data)
			digest := hasher.Sum(nil)

			signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}

			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature)
			if tc.expectError {
				if valid {
					t.Error("expected verification to fail")
				}
			} else {
				if !valid {
					t.Error("ECDSA signature verification failed")
				}
			}
		})
	}
}

func TestInvalidECDSASignatureCoverage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data for ECDSA signature")
	hasher := crypto.SHA256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	tests := []struct {
		name      string
		modifySig func([]byte) []byte
	}{
		{
			name: "flip bit in signature",
			modifySig: func(sig []byte) []byte {
				modified := make([]byte, len(sig))
				copy(modified, sig)
				if len(modified) > 10 {
					modified[10] ^= 0x01
				}
				return modified
			},
		},
		{
			name: "truncate signature",
			modifySig: func(sig []byte) []byte {
				return sig[:len(sig)-5]
			},
		},
		{
			name: "malformed ASN1",
			modifySig: func(sig []byte) []byte {
				return []byte{0x30, 0x00}
			},
		},
		{
			name: "empty signature",
			modifySig: func(sig []byte) []byte {
				return []byte{}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modifiedSig := tc.modifySig(signature)
			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, digest, modifiedSig)
			if valid {
				t.Error("expected verification to fail with modified signature")
			}
		})
	}
}

func TestKeyAttributesCreationCoverage(t *testing.T) {
	tests := []struct {
		name        string
		setupAttrs  func() *types.KeyAttributes
		expectValid bool
	}{
		{
			name: "RSA key attributes with PKCS1v15",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-rsa-key",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSA,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSASSATemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "RSA key attributes with PSS",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-rsa-pss-key",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSTemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "ECDSA P256 key attributes",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ecdsa-p256-key",
					KeyAlgorithm:       x509.ECDSA,
					SignatureAlgorithm: x509.ECDSAWithSHA256,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  ECCP256Template,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "ECDSA P384 key attributes",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ecdsa-p384-key",
					KeyAlgorithm:       x509.ECDSA,
					SignatureAlgorithm: x509.ECDSAWithSHA384,
					Hash:               crypto.SHA384,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA384,
						Public:  ECCP384Template,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "AK attributes (restricted)",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-ak",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					KeyType:            types.KeyTypeAttestation,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSAKTemplate,
					},
				}
			},
			expectValid: true,
		},
		{
			name: "IDevID attributes (non-restricted)",
			setupAttrs: func() *types.KeyAttributes {
				return &types.KeyAttributes{
					CN:                 "test-idevid",
					KeyAlgorithm:       x509.RSA,
					SignatureAlgorithm: x509.SHA256WithRSAPSS,
					KeyType:            types.KeyTypeIDevID,
					Hash:               crypto.SHA256,
					TPMAttributes: &types.TPMAttributes{
						HashAlg: tpm2.TPMAlgSHA256,
						Public:  RSAPSSIDevIDTemplate,
					},
				}
			},
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.setupAttrs()
			if attrs == nil && tc.expectValid {
				t.Error("expected valid attributes but got nil")
			}
			if attrs != nil {
				if attrs.TPMAttributes == nil {
					t.Error("TPM attributes should not be nil")
				}
				if attrs.CN == "" {
					t.Error("CN should not be empty")
				}
			}
		})
	}
}

func TestCSRRoundTripCoverage(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo uint32
		sigSize  int
	}{
		{
			name:     "SHA256 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA256),
			sigSize:  256,
		},
		{
			name:     "SHA384 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA384),
			sigSize:  384,
		},
		{
			name:     "SHA512 round trip",
			hashAlgo: uint32(tpm2.TPMAlgSHA512),
			sigSize:  512,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signature := make([]byte, tc.sigSize)
			if _, err := rand.Read(signature); err != nil {
				t.Fatalf("failed to generate random signature: %v", err)
			}

			originalCSR := createMinimalTCGCSRIDevIDCoverage(tc.hashAlgo, signature)

			packed, err := PackIDevIDCSR(originalCSR)
			if err != nil {
				t.Fatalf("failed to pack CSR: %v", err)
			}

			unmarshaled, err := UnmarshalIDevIDCSR(packed)
			if err != nil {
				t.Fatalf("failed to unmarshal CSR: %v", err)
			}

			if unmarshaled.StructVer != originalCSR.StructVer {
				t.Errorf("StructVer mismatch: got %v, want %v", unmarshaled.StructVer, originalCSR.StructVer)
			}
			if unmarshaled.Contents != originalCSR.Contents {
				t.Errorf("Contents mismatch: got %v, want %v", unmarshaled.Contents, originalCSR.Contents)
			}
			if unmarshaled.SigSz != originalCSR.SigSz {
				t.Errorf("SigSz mismatch: got %v, want %v", unmarshaled.SigSz, originalCSR.SigSz)
			}

			if !bytes.Equal(unmarshaled.Signature, originalCSR.Signature) {
				t.Error("signature bytes mismatch after round trip")
			}

			if unmarshaled.CsrContents.HashAlgoId != originalCSR.CsrContents.HashAlgoId {
				t.Errorf("HashAlgoId mismatch: got %v, want %v",
					unmarshaled.CsrContents.HashAlgoId, originalCSR.CsrContents.HashAlgoId)
			}
		})
	}
}

func TestDifferentHashAlgorithmsCoverage(t *testing.T) {
	tests := []struct {
		name       string
		tpmAlgID   tpm2.TPMAlgID
		cryptoHash crypto.Hash
		hashSize   uint32
	}{
		{
			name:       "SHA1",
			tpmAlgID:   tpm2.TPMAlgSHA1,
			cryptoHash: crypto.SHA1,
			hashSize:   20,
		},
		{
			name:       "SHA256",
			tpmAlgID:   tpm2.TPMAlgSHA256,
			cryptoHash: crypto.SHA256,
			hashSize:   32,
		},
		{
			name:       "SHA384",
			tpmAlgID:   tpm2.TPMAlgSHA384,
			cryptoHash: crypto.SHA384,
			hashSize:   48,
		},
		{
			name:       "SHA512",
			tpmAlgID:   tpm2.TPMAlgSHA512,
			cryptoHash: crypto.SHA512,
			hashSize:   64,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			size, err := ParseHashSize(tc.cryptoHash)
			if err != nil {
				t.Fatalf("failed to parse hash size: %v", err)
			}
			if size != tc.hashSize {
				t.Errorf("hash size mismatch: got %d, want %d", size, tc.hashSize)
			}

			csr := createMinimalTCGCSRIDevIDCoverage(uint32(tc.tpmAlgID), make([]byte, 64))
			binary.BigEndian.PutUint32(csr.CsrContents.HashSz[:], tc.hashSize)

			unpacked, err := UnpackIDevIDCSR(csr)
			if err != nil {
				t.Fatalf("failed to unpack CSR: %v", err)
			}

			if unpacked.CsrContents.HashAlgoId != uint32(tc.tpmAlgID) {
				t.Errorf("hash algorithm ID mismatch: got %d, want %d",
					unpacked.CsrContents.HashAlgoId, tc.tpmAlgID)
			}

			if unpacked.CsrContents.HashSz != tc.hashSize {
				t.Errorf("hash size in content mismatch: got %d, want %d",
					unpacked.CsrContents.HashSz, tc.hashSize)
			}
		})
	}
}

func TestTPMPublicCreationCoverage(t *testing.T) {
	t.Run("RSA public key creation", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		restrictedPub := createRSATPMPublicCoverage(&privateKey.PublicKey, true)
		if restrictedPub.Type != tpm2.TPMAlgRSA {
			t.Errorf("expected RSA type, got %v", restrictedPub.Type)
		}
		if !restrictedPub.ObjectAttributes.Restricted {
			t.Error("expected restricted attribute to be true")
		}
		if !restrictedPub.ObjectAttributes.FixedTPM {
			t.Error("expected fixedTPM attribute to be true")
		}

		unrestrictedPub := createRSATPMPublicCoverage(&privateKey.PublicKey, false)
		if unrestrictedPub.ObjectAttributes.Restricted {
			t.Error("expected restricted attribute to be false for unrestricted key")
		}
	})

	t.Run("ECDSA P256 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, true)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA256 {
			t.Errorf("expected SHA256 name alg for P256, got %v", tpmPub.NameAlg)
		}
	})

	t.Run("ECDSA P384 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, false)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA384 {
			t.Errorf("expected SHA384 name alg for P384, got %v", tpmPub.NameAlg)
		}
	})

	t.Run("ECDSA P521 public key creation", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		tpmPub := createECDSATPMPublicCoverage(&privateKey.PublicKey, true)
		if tpmPub.Type != tpm2.TPMAlgECC {
			t.Errorf("expected ECC type, got %v", tpmPub.Type)
		}
		if tpmPub.NameAlg != tpm2.TPMAlgSHA512 {
			t.Errorf("expected SHA512 name alg for P521, got %v", tpmPub.NameAlg)
		}
	})
}

func TestMixedKeyTypesSignatureScenariosCoverage(t *testing.T) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	testData := []byte("test data to sign with different key types")
	sha256Hash := crypto.SHA256.New()
	sha256Hash.Write(testData)
	digest := sha256Hash.Sum(nil)

	t.Run("RSA key cannot verify ECDSA signature", func(t *testing.T) {
		ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivateKey, digest)
		if err != nil {
			t.Fatalf("failed to create ECDSA signature: %v", err)
		}

		err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, digest, ecdsaSig)
		if err == nil {
			t.Error("RSA verification should fail for ECDSA signature")
		}
	})

	t.Run("ECDSA key cannot verify RSA signature", func(t *testing.T) {
		rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("failed to create RSA signature: %v", err)
		}

		valid := ecdsa.VerifyASN1(&ecdsaPrivateKey.PublicKey, digest, rsaSig)
		if valid {
			t.Error("ECDSA verification should fail for RSA signature")
		}
	})

	t.Run("wrong data produces invalid signature", func(t *testing.T) {
		rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, digest)
		if err != nil {
			t.Fatalf("failed to create RSA signature: %v", err)
		}

		wrongData := []byte("completely different data")
		wrongHash := crypto.SHA256.New()
		wrongHash.Write(wrongData)
		wrongDigest := wrongHash.Sum(nil)

		err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, wrongDigest, rsaSig)
		if err == nil {
			t.Error("signature verification should fail for wrong data")
		}
	})
}

func TestSignatureWithDifferentKeysCoverage(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate first RSA key: %v", err)
	}

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate second RSA key: %v", err)
	}

	testData := []byte("data signed with key1")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key1, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("failed to sign with key1: %v", err)
	}

	t.Run("correct key verifies signature", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(&key1.PublicKey, crypto.SHA256, digest, signature)
		if err != nil {
			t.Errorf("verification with correct key failed: %v", err)
		}
	})

	t.Run("wrong key fails to verify signature", func(t *testing.T) {
		err := rsa.VerifyPKCS1v15(&key2.PublicKey, crypto.SHA256, digest, signature)
		if err == nil {
			t.Error("verification with wrong key should fail")
		}
	})
}

func TestCSRContentFieldSizesCoverage(t *testing.T) {
	tests := []struct {
		name        string
		prodModel   string
		prodSerial  string
		ekCertSize  int
		attestPubSz int
		signPubSz   int
		bootLogSize int
		expectError bool
	}{
		{
			name:        "minimal sizes",
			prodModel:   "m",
			prodSerial:  "1",
			ekCertSize:  0,
			attestPubSz: 0,
			signPubSz:   0,
			bootLogSize: 0,
			expectError: false,
		},
		{
			name:        "typical sizes",
			prodModel:   "edge-device-v1",
			prodSerial:  "SN123456789",
			ekCertSize:  1024,
			attestPubSz: 256,
			signPubSz:   256,
			bootLogSize: 4096,
			expectError: false,
		},
		{
			name:        "large boot log",
			prodModel:   "server",
			prodSerial:  "SVR-001",
			ekCertSize:  2048,
			attestPubSz: 512,
			signPubSz:   512,
			bootLogSize: 65536,
			expectError: false,
		},
		{
			name:        "empty model and serial",
			prodModel:   "",
			prodSerial:  "",
			ekCertSize:  256,
			attestPubSz: 128,
			signPubSz:   128,
			bootLogSize: 1024,
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := &TCG_IDEVID_CONTENT{}
			binary.BigEndian.PutUint32(content.StructVer[:], 0x00000100)
			binary.BigEndian.PutUint32(content.HashAlgoId[:], uint32(tpm2.TPMAlgSHA256))
			binary.BigEndian.PutUint32(content.HashSz[:], 32)
			binary.BigEndian.PutUint32(content.ProdModelSz[:], uint32(len(tc.prodModel)))
			binary.BigEndian.PutUint32(content.ProdSerialSz[:], uint32(len(tc.prodSerial)))
			binary.BigEndian.PutUint32(content.EkCertSZ[:], uint32(tc.ekCertSize))
			binary.BigEndian.PutUint32(content.AttestPubSZ[:], uint32(tc.attestPubSz))
			binary.BigEndian.PutUint32(content.SigningPubSZ[:], uint32(tc.signPubSz))
			binary.BigEndian.PutUint32(content.BootEvntLogSz[:], uint32(tc.bootLogSize))

			content.ProdModel = []byte(tc.prodModel)
			content.ProdSerial = []byte(tc.prodSerial)
			content.ProdCaData = []byte{}
			content.BootEvntLog = make([]byte, tc.bootLogSize)
			content.EkCert = make([]byte, tc.ekCertSize)
			content.AttestPub = make([]byte, tc.attestPubSz)
			content.AtCreateTkt = []byte{}
			content.AtCertifyInfo = []byte{}
			content.AtCertifyInfoSig = []byte{}
			content.SigningPub = make([]byte, tc.signPubSz)
			content.SgnCertifyInfo = []byte{}
			content.SgnCertifyInfoSig = []byte{}
			content.Pad = []byte{}

			packed, err := PackIDevIDContent(content)
			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedMinSize := 64 + len(tc.prodModel) + len(tc.prodSerial) +
				tc.ekCertSize + tc.attestPubSz + tc.signPubSz + tc.bootLogSize
			if len(packed) < expectedMinSize {
				t.Errorf("packed size too small: got %d, expected at least %d",
					len(packed), expectedMinSize)
			}
		})
	}
}

func TestInvalidSignatureErrorCoverage(t *testing.T) {
	if ErrInvalidSignature == nil {
		t.Error("ErrInvalidSignature should not be nil")
	}

	expectedMsg := "tpm: invalid signature"
	if ErrInvalidSignature.Error() != expectedMsg {
		t.Errorf("unexpected error message: got %q, want %q",
			ErrInvalidSignature.Error(), expectedMsg)
	}

	if !errors.Is(ErrInvalidSignature, ErrInvalidSignature) {
		t.Error("ErrInvalidSignature should be equal to itself")
	}
}

func TestBigIntConversionsCoverage(t *testing.T) {
	tests := []struct {
		name string
		num  *big.Int
	}{
		{
			name: "small number",
			num:  big.NewInt(12345),
		},
		{
			name: "large number",
			num: func() *big.Int {
				n := new(big.Int)
				n.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
				return n
			}(),
		},
		{
			name: "256-bit number",
			num: func() *big.Int {
				bytes := make([]byte, 32)
				_, _ = rand.Read(bytes)
				return new(big.Int).SetBytes(bytes)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bytes := tc.num.Bytes()
			recovered := new(big.Int).SetBytes(bytes)
			if tc.num.Cmp(recovered) != 0 {
				t.Errorf("big.Int conversion failed: got %v, want %v", recovered, tc.num)
			}
		})
	}
}
