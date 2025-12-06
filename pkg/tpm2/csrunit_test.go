package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCSR_PackIDevIDContent_Success(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{
		StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
		HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
		HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
		ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
		ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
		ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
		BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
		EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
		AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
		AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
		AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
		AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
		SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
		SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
		SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
		PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
		ProdModel:                 []byte("edge"),
		ProdSerial:                []byte("001"),
	}

	packed, err := PackIDevIDContent(content)
	if err != nil {
		t.Fatalf("PackIDevIDContent() unexpected error: %v", err)
	}

	if packed == nil {
		t.Fatal("PackIDevIDContent() returned nil")
	}

	expectedHeader := []byte{0x00, 0x00, 0x01, 0x00}
	if !bytes.HasPrefix(packed, expectedHeader) {
		t.Errorf("PackIDevIDContent() header mismatch, got %v", packed[:4])
	}

	expectedSizes := []uint32{
		0x00000100,
		0x0000000B,
		0x00000020,
		0x00000004,
		0x00000003,
	}

	reader := bytes.NewReader(packed)
	for i, expected := range expectedSizes {
		var val uint32
		err := binary.Read(reader, binary.BigEndian, &val)
		if err != nil {
			t.Fatalf("Failed to read field %d: %v", i, err)
		}
		if val != expected {
			t.Errorf("Field %d = %#x, want %#x", i, val, expected)
		}
	}
}

func TestCSR_PackIDevIDContent_Empty(t *testing.T) {
	content := &TCG_IDEVID_CONTENT{}

	packed, err := PackIDevIDContent(content)
	if err != nil {
		t.Fatalf("PackIDevIDContent() with empty content unexpected error: %v", err)
	}

	expectedMinSize := 16 * 4
	if len(packed) < expectedMinSize {
		t.Errorf("PackIDevIDContent() packed size = %d, want at least %d", len(packed), expectedMinSize)
	}
}

func TestCSR_PackIDevIDCSR_Success(t *testing.T) {
	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x64},
		SigSz:     [4]byte{0x00, 0x00, 0x01, 0x00},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
		},
		Signature: make([]byte, 256),
	}

	packed, err := PackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("PackIDevIDCSR() unexpected error: %v", err)
	}

	if packed == nil {
		t.Fatal("PackIDevIDCSR() returned nil")
	}

	expectedCSRHeader := []byte{0x00, 0x00, 0x01, 0x00}
	if !bytes.HasPrefix(packed, expectedCSRHeader) {
		t.Errorf("PackIDevIDCSR() header mismatch, got %v", packed[:4])
	}

	sigStart := len(packed) - 256
	if sigStart < 0 {
		t.Errorf("PackIDevIDCSR() packed size too small for signature")
	}
}

func TestCSR_UnpackIDevIDCSR_Success(t *testing.T) {
	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x40},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x40},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x04},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x03},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdModel:                 []byte("edge"),
			ProdSerial:                []byte("001"),
		},
		Signature: make([]byte, 64),
	}

	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("UnpackIDevIDCSR() unexpected error: %v", err)
	}

	if unpacked == nil {
		t.Fatal("UnpackIDevIDCSR() returned nil")
		return
	}

	if unpacked.StructVer != 0x00000100 {
		t.Errorf("UnpackIDevIDCSR().StructVer = %#x, want %#x", unpacked.StructVer, 0x00000100)
	}

	if unpacked.SigSz != 64 {
		t.Errorf("UnpackIDevIDCSR().SigSz = %d, want 64", unpacked.SigSz)
	}

	if unpacked.CsrContents.HashAlgoId != 0x0000000B {
		t.Errorf("UnpackIDevIDCSR().CsrContents.HashAlgoId = %#x, want %#x", unpacked.CsrContents.HashAlgoId, 0x0000000B)
	}

	if unpacked.CsrContents.HashSz != 32 {
		t.Errorf("UnpackIDevIDCSR().CsrContents.HashSz = %d, want 32", unpacked.CsrContents.HashSz)
	}

	if string(unpacked.CsrContents.ProdModel) != "edge" {
		t.Errorf("UnpackIDevIDCSR().CsrContents.ProdModel = %q, want %q", string(unpacked.CsrContents.ProdModel), "edge")
	}

	if string(unpacked.CsrContents.ProdSerial) != "001" {
		t.Errorf("UnpackIDevIDCSR().CsrContents.ProdSerial = %q, want %q", string(unpacked.CsrContents.ProdSerial), "001")
	}

	if len(unpacked.Signature) != 64 {
		t.Errorf("UnpackIDevIDCSR().Signature length = %d, want 64", len(unpacked.Signature))
	}
}

func TestCSR_UnmarshalIDevIDCSR_Valid(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000100))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000040))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000020))

	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000100))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x0000000B))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000020))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000004))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000003))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))
	_ = binary.Write(&buf, binary.BigEndian, uint32(0x00000000))

	buf.WriteString("edge")
	buf.WriteString("001")
	buf.Write(make([]byte, 32))

	csr, err := UnmarshalIDevIDCSR(buf.Bytes())
	if err != nil {
		t.Fatalf("UnmarshalIDevIDCSR() unexpected error: %v", err)
	}

	if csr == nil {
		t.Fatal("UnmarshalIDevIDCSR() returned nil")
		return
	}

	if bytesToUint32(csr.StructVer) != 0x00000100 {
		t.Errorf("UnmarshalIDevIDCSR().StructVer = %#x, want %#x", bytesToUint32(csr.StructVer), 0x00000100)
	}

	if bytesToUint32(csr.SigSz) != 32 {
		t.Errorf("UnmarshalIDevIDCSR().SigSz = %d, want 32", bytesToUint32(csr.SigSz))
	}

	if string(csr.CsrContents.ProdModel) != "edge" {
		t.Errorf("UnmarshalIDevIDCSR().CsrContents.ProdModel = %q, want %q", string(csr.CsrContents.ProdModel), "edge")
	}

	if len(csr.Signature) != 32 {
		t.Errorf("UnmarshalIDevIDCSR().Signature length = %d, want 32", len(csr.Signature))
	}
}

func TestCSR_UnmarshalIDevIDCSR_Truncated(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01}

	csr, err := UnmarshalIDevIDCSR(data)
	if err == nil {
		t.Error("UnmarshalIDevIDCSR() with truncated header expected error, got nil")
	}
	if csr != nil {
		t.Errorf("UnmarshalIDevIDCSR() with truncated header expected nil, got %v", csr)
	}
}

func TestCSR_UnmarshalIDevIDCSR_Empty(t *testing.T) {
	data := []byte{}

	csr, err := UnmarshalIDevIDCSR(data)
	if err == nil {
		t.Error("UnmarshalIDevIDCSR() with empty input expected error, got nil")
	}
	if csr != nil {
		t.Errorf("UnmarshalIDevIDCSR() with empty input expected nil, got %v", csr)
	}
}

func TestCSR_PackUnpackRoundTrip(t *testing.T) {
	original := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x01, 0x00},
		SigSz:     [4]byte{0x00, 0x00, 0x00, 0x40},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0C},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x30},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x06},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x05},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x02},
			ProdModel:                 []byte("device"),
			ProdSerial:                []byte("12345"),
			Pad:                       []byte("=="),
		},
		Signature: make([]byte, 64),
	}

	for i := range original.Signature {
		original.Signature[i] = byte(i % 256)
	}

	packed, err := PackIDevIDCSR(original)
	if err != nil {
		t.Fatalf("PackIDevIDCSR() unexpected error: %v", err)
	}

	unpacked, err := UnpackIDevIDCSR(original)
	if err != nil {
		t.Fatalf("UnpackIDevIDCSR() unexpected error: %v", err)
	}

	if unpacked.StructVer != bytesToUint32(original.StructVer) {
		t.Errorf("Round trip StructVer mismatch: got %#x, want %#x", unpacked.StructVer, bytesToUint32(original.StructVer))
	}

	if unpacked.SigSz != bytesToUint32(original.SigSz) {
		t.Errorf("Round trip SigSz mismatch: got %d, want %d", unpacked.SigSz, bytesToUint32(original.SigSz))
	}

	if unpacked.CsrContents.HashAlgoId != bytesToUint32(original.CsrContents.HashAlgoId) {
		t.Errorf("Round trip HashAlgoId mismatch: got %#x, want %#x", unpacked.CsrContents.HashAlgoId, bytesToUint32(original.CsrContents.HashAlgoId))
	}

	if string(unpacked.CsrContents.ProdModel) != string(original.CsrContents.ProdModel) {
		t.Errorf("Round trip ProdModel mismatch: got %q, want %q", string(unpacked.CsrContents.ProdModel), string(original.CsrContents.ProdModel))
	}

	if string(unpacked.CsrContents.ProdSerial) != string(original.CsrContents.ProdSerial) {
		t.Errorf("Round trip ProdSerial mismatch: got %q, want %q", string(unpacked.CsrContents.ProdSerial), string(original.CsrContents.ProdSerial))
	}

	if !bytes.Equal(unpacked.Signature, original.Signature) {
		t.Error("Round trip Signature mismatch")
	}

	expectedSize := 12 + 16*4 + 6 + 5 + 2 + 64
	if len(packed) != expectedSize {
		t.Errorf("Packed size = %d, want %d", len(packed), expectedSize)
	}
}

func TestCSR_UnpackIDevIDContent_Truncated(t *testing.T) {
	data := make([]byte, 10)
	reader := bytes.NewReader(data)

	content, err := UnpackIDevIDContent(reader)
	if err == nil {
		t.Error("UnpackIDevIDContent() with truncated input expected error, got nil")
	}
	if content != nil {
		t.Errorf("UnpackIDevIDContent() with truncated input expected nil, got %v", content)
	}
}

func TestCSR_LargeSignature(t *testing.T) {
	sigSize := 512
	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x00, 0x40},
		SigSz:     [4]byte{0x00, 0x00, 0x02, 0x00},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0D},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x40},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x00},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x00, 0x00},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
		},
		Signature: make([]byte, sigSize),
	}

	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("UnpackIDevIDCSR() with large signature unexpected error: %v", err)
	}

	if unpacked.SigSz != uint32(sigSize) {
		t.Errorf("UnpackIDevIDCSR().SigSz = %d, want %d", unpacked.SigSz, sigSize)
	}

	if len(unpacked.Signature) != sigSize {
		t.Errorf("UnpackIDevIDCSR().Signature length = %d, want %d", len(unpacked.Signature), sigSize)
	}
}

func TestCSR_PackIDevIDContent_AllHashAlgos(t *testing.T) {
	tests := []struct {
		name       string
		hashAlgoId [4]byte
		hashSz     [4]byte
	}{
		{"SHA1", [4]byte{0x00, 0x00, 0x00, 0x04}, [4]byte{0x00, 0x00, 0x00, 0x14}},
		{"SHA256", [4]byte{0x00, 0x00, 0x00, 0x0B}, [4]byte{0x00, 0x00, 0x00, 0x20}},
		{"SHA384", [4]byte{0x00, 0x00, 0x00, 0x0C}, [4]byte{0x00, 0x00, 0x00, 0x30}},
		{"SHA512", [4]byte{0x00, 0x00, 0x00, 0x0D}, [4]byte{0x00, 0x00, 0x00, 0x40}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := &TCG_IDEVID_CONTENT{
				StructVer:  [4]byte{0x00, 0x00, 0x01, 0x00},
				HashAlgoId: tt.hashAlgoId,
				HashSz:     tt.hashSz,
			}

			packed, err := PackIDevIDContent(content)
			if err != nil {
				t.Fatalf("PackIDevIDContent() unexpected error: %v", err)
			}

			reader := bytes.NewReader(packed)
			var structVer, hashAlgoId uint32
			_ = binary.Read(reader, binary.BigEndian, &structVer)
			_ = binary.Read(reader, binary.BigEndian, &hashAlgoId)

			expectedHashAlgoId := bytesToUint32(tt.hashAlgoId)
			if hashAlgoId != expectedHashAlgoId {
				t.Errorf("Packed HashAlgoId = %#x, want %#x", hashAlgoId, expectedHashAlgoId)
			}
		})
	}
}

func TestCSR_UnpackIDevIDCSR_VariableFields(t *testing.T) {
	bootEvntLog := make([]byte, 100)
	ekCert := make([]byte, 500)
	attestPub := make([]byte, 256)

	csr := &TCG_CSR_IDEVID{
		StructVer: [4]byte{0x00, 0x00, 0x01, 0x00},
		Contents:  [4]byte{0x00, 0x00, 0x03, 0x5C},
		SigSz:     [4]byte{0x00, 0x00, 0x01, 0x00},
		CsrContents: TCG_IDEVID_CONTENT{
			StructVer:                 [4]byte{0x00, 0x00, 0x01, 0x00},
			HashAlgoId:                [4]byte{0x00, 0x00, 0x00, 0x0B},
			HashSz:                    [4]byte{0x00, 0x00, 0x00, 0x20},
			ProdModelSz:               [4]byte{0x00, 0x00, 0x00, 0x08},
			ProdSerialSz:              [4]byte{0x00, 0x00, 0x00, 0x06},
			ProdCaDataSz:              [4]byte{0x00, 0x00, 0x00, 0x00},
			BootEvntLogSz:             [4]byte{0x00, 0x00, 0x00, 0x64},
			EkCertSZ:                  [4]byte{0x00, 0x00, 0x01, 0xF4},
			AttestPubSZ:               [4]byte{0x00, 0x00, 0x01, 0x00},
			AtCreateTktSZ:             [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSZ:           [4]byte{0x00, 0x00, 0x00, 0x00},
			AtCertifyInfoSignatureSZ:  [4]byte{0x00, 0x00, 0x00, 0x00},
			SigningPubSZ:              [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSZ:          [4]byte{0x00, 0x00, 0x00, 0x00},
			SgnCertifyInfoSignatureSZ: [4]byte{0x00, 0x00, 0x00, 0x00},
			PadSz:                     [4]byte{0x00, 0x00, 0x00, 0x00},
			ProdModel:                 []byte("testdevx"),
			ProdSerial:                []byte("SN0001"),
			BootEvntLog:               bootEvntLog,
			EkCert:                    ekCert,
			AttestPub:                 attestPub,
		},
		Signature: make([]byte, 256),
	}

	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		t.Fatalf("UnpackIDevIDCSR() unexpected error: %v", err)
	}

	if unpacked.CsrContents.BootEvntLogSz != 100 {
		t.Errorf("BootEvntLogSz = %d, want 100", unpacked.CsrContents.BootEvntLogSz)
	}

	if unpacked.CsrContents.EkCertSZ != 500 {
		t.Errorf("EkCertSZ = %d, want 500", unpacked.CsrContents.EkCertSZ)
	}

	if unpacked.CsrContents.AttestPubSZ != 256 {
		t.Errorf("AttestPubSZ = %d, want 256", unpacked.CsrContents.AttestPubSZ)
	}

	if len(unpacked.CsrContents.BootEvntLog) != 100 {
		t.Errorf("BootEvntLog length = %d, want 100", len(unpacked.CsrContents.BootEvntLog))
	}

	if len(unpacked.CsrContents.EkCert) != 500 {
		t.Errorf("EkCert length = %d, want 500", len(unpacked.CsrContents.EkCert))
	}

	if len(unpacked.CsrContents.AttestPub) != 256 {
		t.Errorf("AttestPub length = %d, want 256", len(unpacked.CsrContents.AttestPub))
	}
}
