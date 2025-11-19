package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"

	tpmlib "github.com/google/go-tpm/tpm2"
)

func TestBytesToUint32Unit(t *testing.T) {
	tests := []struct {
		name string
		b    [4]byte
		want uint32
	}{
		{
			name: "zero",
			b:    [4]byte{0x00, 0x00, 0x00, 0x00},
			want: 0,
		},
		{
			name: "one",
			b:    [4]byte{0x00, 0x00, 0x00, 0x01},
			want: 1,
		},
		{
			name: "max uint32",
			b:    [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			want: 0xFFFFFFFF,
		},
		{
			name: "version number",
			b:    [4]byte{0x00, 0x00, 0x01, 0x00},
			want: 0x00000100,
		},
		{
			name: "arbitrary value",
			b:    [4]byte{0x12, 0x34, 0x56, 0x78},
			want: 0x12345678,
		},
		{
			name: "high byte set",
			b:    [4]byte{0x80, 0x00, 0x00, 0x00},
			want: 0x80000000,
		},
		{
			name: "alternating bytes",
			b:    [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
			want: 0xAABBCCDD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToUint32(tt.b)
			if got != tt.want {
				t.Errorf("bytesToUint32() = %d (0x%x), want %d (0x%x)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestPackIDevIDContentUnit(t *testing.T) {
	tests := []struct {
		name    string
		content *TCG_IDEVID_CONTENT
		wantErr bool
	}{
		{
			name: "valid content with all fields",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
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
				ProdModel:                 []byte("test"),
				ProdSerial:                []byte("001"),
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{1, 2, 3, 4},
				AttestPub:                 []byte{5, 6, 7, 8},
				AtCreateTkt:               []byte{9, 10, 11, 12},
				AtCertifyInfo:             []byte{13, 14, 15, 16},
				AtCertifyInfoSig:          []byte{17, 18, 19, 20},
				SigningPub:                []byte{21, 22, 23, 24},
				SgnCertifyInfo:            []byte{25, 26, 27, 28},
				SgnCertifyInfoSig:         []byte{29, 30, 31, 32},
				Pad:                       []byte{},
			},
			wantErr: false,
		},
		{
			name: "empty content",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{},
				ProdSerialSz:              [4]byte{},
				ProdCaDataSz:              [4]byte{},
				BootEvntLogSz:             [4]byte{},
				EkCertSZ:                  [4]byte{},
				AttestPubSZ:               [4]byte{},
				AtCreateTktSZ:             [4]byte{},
				AtCertifyInfoSZ:           [4]byte{},
				AtCertifyInfoSignatureSZ:  [4]byte{},
				SigningPubSZ:              [4]byte{},
				SgnCertifyInfoSZ:          [4]byte{},
				SgnCertifyInfoSignatureSZ: [4]byte{},
				PadSz:                     [4]byte{},
				ProdModel:                 []byte{},
				ProdSerial:                []byte{},
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{},
				AttestPub:                 []byte{},
				AtCreateTkt:               []byte{},
				AtCertifyInfo:             []byte{},
				AtCertifyInfoSig:          []byte{},
				SigningPub:                []byte{},
				SgnCertifyInfo:            []byte{},
				SgnCertifyInfoSig:         []byte{},
				Pad:                       []byte{},
			},
			wantErr: false,
		},
		{
			name: "content with padding",
			content: &TCG_IDEVID_CONTENT{
				StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
				HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
				ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
				ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
				ProdCaDataSz:              [4]byte{},
				BootEvntLogSz:             [4]byte{},
				EkCertSZ:                  [4]byte{},
				AttestPubSZ:               [4]byte{},
				AtCreateTktSZ:             [4]byte{},
				AtCertifyInfoSZ:           [4]byte{},
				AtCertifyInfoSignatureSZ:  [4]byte{},
				SigningPubSZ:              [4]byte{},
				SgnCertifyInfoSZ:          [4]byte{},
				SgnCertifyInfoSignatureSZ: [4]byte{},
				PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x08},
				ProdModel:                 []byte("edge"),
				ProdSerial:                []byte("001"),
				ProdCaData:                []byte{},
				BootEvntLog:               []byte{},
				EkCert:                    []byte{},
				AttestPub:                 []byte{},
				AtCreateTkt:               []byte{},
				AtCertifyInfo:             []byte{},
				AtCertifyInfoSig:          []byte{},
				SigningPub:                []byte{},
				SgnCertifyInfo:            []byte{},
				SgnCertifyInfoSig:         []byte{},
				Pad:                       []byte("========"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PackIDevIDContent(tt.content)

			if tt.wantErr {
				if err == nil {
					t.Error("PackIDevIDContent() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("PackIDevIDContent() unexpected error: %v", err)
				return
			}

			// Verify minimum size (16 size fields * 4 bytes)
			minSize := 16 * 4
			if len(result) < minSize {
				t.Errorf("PackIDevIDContent() result too short: got %d, want at least %d", len(result), minSize)
			}

			// Verify header fields
			if !bytes.Equal(result[0:4], tt.content.StructVer[:]) {
				t.Error("PackIDevIDContent() StructVer mismatch")
			}
			if !bytes.Equal(result[4:8], tt.content.HashAlgoId[:]) {
				t.Error("PackIDevIDContent() HashAlgoId mismatch")
			}
			if !bytes.Equal(result[8:12], tt.content.HashSz[:]) {
				t.Error("PackIDevIDContent() HashSz mismatch")
			}
		})
	}
}

func TestPackIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		csr     *TCG_CSR_IDEVID
		wantErr bool
	}{
		{
			name: "valid CSR",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x10},
				SigSz:     [4]byte{0x00, 0x00, 0x00, 0x08},
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:    [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId:   [4]byte{0x00, 0x00, 0x00, 0x0b},
					HashSz:       [4]byte{0x00, 0x00, 0x00, 0x20},
					ProdModelSz:  [4]byte{0x00, 0x00, 0x00, 0x04},
					ProdSerialSz: [4]byte{0x00, 0x00, 0x00, 0x03},
					ProdModel:    []byte("test"),
					ProdSerial:   []byte("001"),
				},
				Signature: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := PackIDevIDCSR(tt.csr)

			if tt.wantErr {
				if err == nil {
					t.Error("PackIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("PackIDevIDCSR() unexpected error: %v", err)
				return
			}

			// Verify structure starts with StructVer
			if !bytes.Equal(result[0:4], tt.csr.StructVer[:]) {
				t.Error("PackIDevIDCSR() StructVer mismatch")
			}

			// Verify signature at the end
			sigSize := binary.BigEndian.Uint32(tt.csr.SigSz[:])
			sigStart := len(result) - int(sigSize)
			if !bytes.Equal(result[sigStart:], tt.csr.Signature) {
				t.Error("PackIDevIDCSR() signature mismatch at end")
			}
		})
	}
}

func TestUnpackIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		csr     *TCG_CSR_IDEVID
		wantErr bool
	}{
		{
			name: "unpack valid CSR",
			csr: &TCG_CSR_IDEVID{
				StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
				Contents:  [4]byte{0x00, 0x00, 0x00, 0x64},
				SigSz:     [4]byte{0x00, 0x00, 0x00, 0x10},
				CsrContents: TCG_IDEVID_CONTENT{
					StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
					HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0b},
					HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
					ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
					ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
					ProdCaDataSz:              [4]byte{},
					BootEvntLogSz:             [4]byte{},
					EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x04},
					AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x04},
					AtCreateTktSZ:             [4]byte{},
					AtCertifyInfoSZ:           [4]byte{},
					AtCertifyInfoSignatureSZ:  [4]byte{},
					SigningPubSZ:              [4]byte{},
					SgnCertifyInfoSZ:          [4]byte{},
					SgnCertifyInfoSignatureSZ: [4]byte{},
					PadSz:                     [4]byte{},
					ProdModel:                 []byte("test"),
					ProdSerial:                []byte("001"),
					EkCert:                    []byte{1, 2, 3, 4},
					AttestPub:                 []byte{5, 6, 7, 8},
				},
				Signature: make([]byte, 16),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unpacked, err := UnpackIDevIDCSR(tt.csr)

			if tt.wantErr {
				if err == nil {
					t.Error("UnpackIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnpackIDevIDCSR() unexpected error: %v", err)
				return
			}

			// Verify unpacked values match
			expectedStructVer := binary.BigEndian.Uint32(tt.csr.StructVer[:])
			if unpacked.StructVer != expectedStructVer {
				t.Errorf("UnpackIDevIDCSR() StructVer = %d, want %d", unpacked.StructVer, expectedStructVer)
			}

			expectedContents := binary.BigEndian.Uint32(tt.csr.Contents[:])
			if unpacked.Contents != expectedContents {
				t.Errorf("UnpackIDevIDCSR() Contents = %d, want %d", unpacked.Contents, expectedContents)
			}

			// Verify content fields
			if !bytes.Equal(unpacked.CsrContents.ProdModel, tt.csr.CsrContents.ProdModel) {
				t.Error("UnpackIDevIDCSR() ProdModel mismatch")
			}
		})
	}
}

func TestUnmarshalIDevIDCSRUnit(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() []byte
		wantErr bool
	}{
		{
			name: "valid marshalled CSR",
			setup: func() []byte {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x10}) // Contents
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x04}) // SigSz
				// CSR Contents
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x0b}) // HashAlgoId
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x20}) // HashSz
				// Size fields (all zeros)
				for i := 0; i < 13; i++ {
					_ = binary.Write(&buf, binary.BigEndian, [4]byte{})
				}
				// Signature
				_ = binary.Write(&buf, binary.BigEndian, []byte{1, 2, 3, 4})
				return buf.Bytes()
			},
			wantErr: false,
		},
		{
			name: "truncated header",
			setup: func() []byte {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00})
				return buf.Bytes()
			},
			wantErr: true,
		},
		{
			name: "empty data",
			setup: func() []byte {
				return []byte{}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrBytes := tt.setup()
			result, err := UnmarshalIDevIDCSR(csrBytes)

			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalIDevIDCSR() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnmarshalIDevIDCSR() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("UnmarshalIDevIDCSR() returned nil")
			}
		})
	}
}

func TestUnpackIDevIDContentUnit(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *bytes.Reader
		wantErr bool
	}{
		{
			name: "valid content with zero size fields",
			setup: func() *bytes.Reader {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00}) // StructVer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x0b}) // HashAlgoId
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x20}) // HashSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x04}) // ProdModelSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x00, 0x03}) // ProdSerialSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // ProdCaDataSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // BootEvntLogSz
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // EkCertSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AttestPubSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCreateTktSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCertifyInfoSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // AtCertifyInfoSignatureSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SigningPubSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SgnCertifyInfoSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // SgnCertifyInfoSignatureSZ
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{})                       // PadSz
				return bytes.NewReader(buf.Bytes())
			},
			wantErr: true, // Reader insufficient data for variable fields
		},
		{
			name: "partial header",
			setup: func() *bytes.Reader {
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.BigEndian, [4]byte{0x00, 0x00, 0x01, 0x00})
				return bytes.NewReader(buf.Bytes())
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := tt.setup()
			result, err := UnpackIDevIDContent(reader)

			if tt.wantErr {
				if err == nil {
					t.Error("UnpackIDevIDContent() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("UnpackIDevIDContent() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Fatal("UnpackIDevIDContent() returned nil")
			}

			// Verify parsed values
			if bytesToUint32(result.StructVer) != uint32(0x00000100) {
				t.Errorf("UnpackIDevIDContent() StructVer = 0x%x, want 0x00000100", result.StructVer)
			}

			if bytesToUint32(result.HashAlgoId) != uint32(11) {
				t.Errorf("UnpackIDevIDContent() HashAlgoId = %d, want 11", result.HashAlgoId)
			}
		})
	}
}

func TestQuoteStructure(t *testing.T) {
	quote := Quote{
		Quoted:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x05, 0x06},
		Nonce:     []byte{0x07, 0x08, 0x09},
		PCRs:      []byte{0x0A, 0x0B, 0x0C},
		EventLog:  []byte{0x0D, 0x0E, 0x0F},
	}

	if len(quote.Quoted) != 3 {
		t.Errorf("Quote.Quoted length = %d, want 3", len(quote.Quoted))
	}

	if len(quote.Signature) != 3 {
		t.Errorf("Quote.Signature length = %d, want 3", len(quote.Signature))
	}

	if len(quote.Nonce) != 3 {
		t.Errorf("Quote.Nonce length = %d, want 3", len(quote.Nonce))
	}
}

func TestPCRBankStructure(t *testing.T) {
	bank := PCRBank{
		Algorithm: "SHA256",
		PCRs: []PCR{
			{ID: 0, Value: []byte{0x01}},
			{ID: 7, Value: []byte{0x02}},
			{ID: 16, Value: []byte{0x03}},
		},
	}

	if bank.Algorithm != "SHA256" {
		t.Errorf("PCRBank.Algorithm = %s, want SHA256", bank.Algorithm)
	}

	if len(bank.PCRs) != 3 {
		t.Errorf("PCRBank.PCRs length = %d, want 3", len(bank.PCRs))
	}

	if bank.PCRs[0].ID != 0 {
		t.Errorf("PCRBank.PCRs[0].ID = %d, want 0", bank.PCRs[0].ID)
	}

	if bank.PCRs[1].ID != 7 {
		t.Errorf("PCRBank.PCRs[1].ID = %d, want 7", bank.PCRs[1].ID)
	}
}

func TestAKProfileStructure(t *testing.T) {
	profile := AKProfile{
		EKPub:  []byte{0x01, 0x02},
		AKPub:  []byte{0x03, 0x04},
		AKName: tpmlib.TPM2BName{Buffer: []byte{0x05, 0x06}},
	}

	if len(profile.EKPub) != 2 {
		t.Errorf("AKProfile.EKPub length = %d, want 2", len(profile.EKPub))
	}

	if len(profile.AKPub) != 2 {
		t.Errorf("AKProfile.AKPub length = %d, want 2", len(profile.AKPub))
	}

	if len(profile.AKName.Buffer) != 2 {
		t.Errorf("AKProfile.AKName.Buffer length = %d, want 2", len(profile.AKName.Buffer))
	}
}
