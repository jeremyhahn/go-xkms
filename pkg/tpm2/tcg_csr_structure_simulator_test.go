//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spec131Field is one entry of the TCG_IDEVID_CONTENT payload list of TCG
// "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12, section 13.1,
// in the order the specification prints it. The test walks this list, not the
// product's struct, so a field the product forgets or reorders is caught.
type spec131Field struct {
	name string
	size uint32
	data []byte
}

// spec131CSR is a TCG-CSR-IDEVID as read back by a reader that knows only
// section 13.1: the outer header, the content header, the payloads in order,
// the pad, then the signature.
type spec131CSR struct {
	structVer  uint32
	contents   uint32
	sigSz      uint32
	content    []byte // the csrContents bytes, exactly `contents` long
	cStructVer uint32
	hashAlgoId uint32
	hashSz     uint32
	fields     []spec131Field
	padSz      uint32
	pad        []byte
	signature  []byte
}

// spec131PayloadNames is the payload order of section 13.1, transcribed from
// the specification's typedef -- prodModel[] through sgnCertifyInfoSig[].
var spec131PayloadNames = []string{
	"prodModel", "prodSerial", "prodCaData", "bootEvntLog", "ekCert",
	"attestPub", "atCreateTkt", "atCertifyInfo", "atCertifyInfoSig",
	"signingPub", "sgnCertifyInfo", "sgnCertifyInfoSig",
}

// parseSpec131 reads a packed TCG-CSR-IDEVID exactly as section 13.1 lays it
// out: big-endian, every size four bytes, sizes first, payloads after, no
// delimiters. It is deliberately independent of UnmarshalIDevIDCSR.
func parseSpec131(t *testing.T, raw []byte) spec131CSR {
	t.Helper()

	r := bytes.NewReader(raw)
	u32 := func(what string) uint32 {
		var b [4]byte
		_, err := r.Read(b[:])
		require.NoError(t, err, "reading %s", what)
		return binary.BigEndian.Uint32(b[:])
	}
	take := func(what string, n uint32) []byte {
		b := make([]byte, n)
		if n == 0 {
			return b
		}
		_, err := r.Read(b)
		require.NoError(t, err, "reading %d bytes of %s", n, what)
		return b
	}

	var csr spec131CSR
	csr.structVer = u32("structVer")
	csr.contents = u32("contents")
	csr.sigSz = u32("sigSz")

	require.GreaterOrEqual(t, len(raw), 12+int(csr.contents)+int(csr.sigSz),
		"the message must hold the csrContents and signature the header declares")
	csr.content = raw[12 : 12+csr.contents]

	csr.cStructVer = u32("csrContents.structVer")
	csr.hashAlgoId = u32("csrContents.hashAlgoId")
	csr.hashSz = u32("csrContents.hashSz")
	sizes := make([]uint32, len(spec131PayloadNames))
	for i, name := range spec131PayloadNames {
		sizes[i] = u32(name + "Sz")
	}
	csr.padSz = u32("padSz")
	for i, name := range spec131PayloadNames {
		csr.fields = append(csr.fields, spec131Field{name: name, size: sizes[i], data: take(name, sizes[i])})
	}
	csr.pad = take("pad", csr.padSz)
	csr.signature = take("signature", csr.sigSz)
	require.Zero(t, r.Len(), "nothing may follow the signature")
	return csr
}

// TestTCGCSR_Structure_MatchesSection13_1 is the byte-exact conformance test
// for the TCG-CSR-IDEVID the device emits. Every value it checks is taken
// from the specification's typedef or from the harness, never from the
// packer under test.
func TestTCGCSR_Structure_MatchesSection13_1(t *testing.T) {
	for _, tc := range []struct {
		name     string
		strategy EnrollmentStrategy
		pad      bool
	}{
		{"IAK signs, padded", EnrollmentStrategyIAK, true},
		{"IAK signs, unpadded", EnrollmentStrategyIAK, false},
		{"IDevID signs (single pass), padded", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newIdentityHarness(t, tc.strategy, tc.pad)
			built := h.csr(t)
			raw, err := built.Marshal()
			require.NoError(t, err)

			csr := parseSpec131(t, raw)

			t.Run("headers", func(t *testing.T) {
				assert.Equal(t, uint32(0x01000100), csr.structVer,
					"TCG_CSR_IDEVID.structVer: Version 1.0 = 0x01000100; the first byte (0x01) says IDevID CSR")
				assert.Equal(t, uint32(0x00000100), csr.cStructVer,
					"TCG_IDEVID_CONTENT.structVer: Version 1.0 = 0x00000100")
				assert.Equal(t, uint32(0x000B), csr.hashAlgoId,
					"hashAlgoId is the TCG algorithm identifier of the CSR hash: TPM_ALG_SHA256")
				assert.Equal(t, uint32(32), csr.hashSz, "hashSz is the size in bytes of the hash used")
				assert.Equal(t, len(csr.signature), int(csr.sigSz), "sigSz is the size in bytes of the signature")
			})

			t.Run("contents is the size of csrContents", func(t *testing.T) {
				const headerFields = 16 // structVer, hashAlgoId, hashSz, 12 payload sizes, padSz
				var sum uint32
				for _, f := range csr.fields {
					sum += f.size
				}
				assert.Equal(t, headerFields*4+sum+csr.padSz, csr.contents)
				assert.Equal(t, 12+int(csr.contents)+int(csr.sigSz), len(raw),
					"the message is exactly the outer header, csrContents and signature")
			})

			t.Run("payloads follow the sizes in the order of section 13.1", func(t *testing.T) {
				want := map[string][]byte{
					"prodModel":  []byte("xkms-test-device"),
					"prodSerial": []byte("SN-0000-0001"),
					"ekCert":     h.EKCert.Raw,
					"attestPub":  h.IAK.TPMAttributes.BPublic.Bytes(),
					"signingPub": h.IDevID.TPMAttributes.BPublic.Bytes(),
				}
				for _, f := range csr.fields {
					assert.Equal(t, int(f.size), len(f.data), "%sSz must equal the %s payload length", f.name, f.name)
					if expected, ok := want[f.name]; ok {
						assert.Equal(t, expected, f.data, "%s payload", f.name)
					}
				}
				byName := func(name string) spec131Field {
					for _, f := range csr.fields {
						if f.name == name {
							return f
						}
					}
					t.Fatalf("no field %q", name)
					return spec131Field{}
				}
				assert.NotZero(t, byName("prodCaData").size,
					"the CA-specific data carries the platform quote; a simulator has a transport to quote over")
				assert.NotZero(t, byName("atCertifyInfo").size, "the IAK's TPM2_Certify info must be present")
				assert.NotZero(t, byName("atCertifyInfoSig").size)
				assert.NotZero(t, byName("sgnCertifyInfo").size, "the IDevID's TPM2_Certify info must be present")
				assert.NotZero(t, byName("sgnCertifyInfoSig").size)
			})

			t.Run("pad", func(t *testing.T) {
				assert.Equal(t, int(csr.padSz), len(csr.pad), "padSz bytes of pad follow the payload")
				if tc.pad {
					assert.Zero(t, csr.contents%16, "the padded structure size is a multiple of 16 bytes")
					assert.Less(t, csr.padSz, uint32(16), "the pad is the shortest that aligns the structure")
					if csr.padSz >= 4 {
						assert.NotEqual(t, bytes.Repeat([]byte{'='}, int(csr.padSz)), csr.pad,
							"the pad is random data, not a filler byte")
					}
				} else {
					assert.Zero(t, csr.padSz)
				}
			})

			t.Run("signature is over csrContents with the hash the header names", func(t *testing.T) {
				signer := h.IAK
				if tc.strategy == EnrollmentStrategyIAK_IDEVID_SINGLE_PASS {
					signer = h.IDevID
				}
				pub, err := ExtractPublicKeyFromTPMPublic(signer.TPMAttributes.BPublic.Bytes())
				require.NoError(t, err)
				rsaPub, ok := pub.(*rsa.PublicKey)
				require.True(t, ok, "the harness keys are RSA")

				hash := crypto.Hash(0)
				switch csr.hashAlgoId {
				case 0x000B:
					hash = crypto.SHA256
				default:
					t.Fatalf("unexpected hashAlgoId 0x%04X", csr.hashAlgoId)
				}
				d := hash.New()
				d.Write(csr.content)
				require.NoError(t, rsa.VerifyPSS(rsaPub, hash, d.Sum(nil), csr.signature,
					&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}),
					"the signer's public key must verify the signature over the csrContents bytes")

				tampered := append([]byte{}, csr.content...)
				tampered[len(tampered)-1] ^= 0x01
				d = hash.New()
				d.Write(tampered)
				assert.Error(t, rsa.VerifyPSS(rsaPub, hash, d.Sum(nil), csr.signature,
					&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}),
					"a one-bit change to csrContents must break the signature")
			})

			t.Run("the product's parser agrees with the specification's reader", func(t *testing.T) {
				decoded, err := UnmarshalIDevIDCSR(raw)
				require.NoError(t, err)
				assert.Equal(t, csr.structVer, bytesToUint32(decoded.StructVer))
				assert.Equal(t, csr.contents, bytesToUint32(decoded.Contents))
				assert.Equal(t, csr.signature, decoded.Signature)
				assert.Equal(t, csr.pad, decoded.CsrContents.Pad)
			})
		})
	}
}
