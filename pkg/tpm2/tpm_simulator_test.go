//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test NV Define and Delete operations
func TestNVDefineAndDelete_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	nvIndex := tpm2.TPMHandle(0x01500020)
	dataSize := uint16(32)

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	// Define NV space
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err = defs.Execute(tpmImpl.transport)
	require.NoError(t, err)

	// Verify NV index is defined by reading its public area
	nvPub, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
	assert.NotNil(t, nvPub)

	// Get NV name for undefine operation
	nvName := nvPub.NVName

	// Undefine (delete) NV space - requires NamedHandle
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvIndex, Name: nvName},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	// Verify NV index is deleted
	_, err = tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpmImpl.transport)
	assert.Error(t, err)
}

// Test NV Write and Read operations
func TestNVWriteAndRead_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	nvIndex := tpm2.TPMHandle(0x01500021)
	testData := []byte("test-secret-data-12345678901234")
	dataSize := uint16(len(testData))

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	// Define NV space
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err = defs.Execute(tpmImpl.transport)
	require.NoError(t, err)

	nvPub, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	// Write data to NV
	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   nvPub.NVName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: testData,
		},
		Offset: 0,
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	// Read data from NV
	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: nvIndex,
			Name:   nvPub.NVName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Size:   dataSize,
		Offset: 0,
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	assert.Equal(t, testData, readRsp.Data.Buffer)

	// Cleanup
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvIndex, Name: nvPub.NVName},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
}

// Test NVReadPublic operation
func TestNVReadPublic_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	nvIndex := tpm2.TPMHandle(0x01500022)
	dataSize := uint16(64)

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
				},
				DataSize: dataSize,
			}),
	}

	_, err = defs.Execute(tpmImpl.transport)
	require.NoError(t, err)

	nvPub, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
	assert.NotNil(t, nvPub)

	pubContents, err := nvPub.NVPublic.Contents()
	require.NoError(t, err)
	assert.Equal(t, nvIndex, pubContents.NVIndex)
	assert.Equal(t, dataSize, pubContents.DataSize)
	assert.Equal(t, tpm2.TPMAlgSHA256, pubContents.NameAlg)

	assert.NotEmpty(t, nvPub.NVName.Buffer)

	// Cleanup
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{Handle: nvIndex, Name: nvPub.NVName},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
}

// Test PCR Read operations
func TestReadPCRs_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	pcrs := []uint{0, 1, 2, 3, 7, 16}
	banks, err := tpm.ReadPCRs(pcrs)
	require.NoError(t, err)
	require.NotNil(t, banks)

	assert.GreaterOrEqual(t, len(banks), 2)

	for _, bank := range banks {
		assert.Equal(t, len(pcrs), len(bank.PCRs))
		for _, pcr := range bank.PCRs {
			assert.NotEmpty(t, pcr.Value)
		}
	}
}

// Test PCR Extend operation
func TestPCRExtend_Simulator(t *testing.T) {
	t.Skip("Test isolation issue - passes alone but fails in suite")
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	pcrIndex := uint(16)

	initialBanks, err := tpm.ReadPCRs([]uint{pcrIndex})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(initialBanks), 1)
	initialValue := initialBanks[0].PCRs[0].Value

	extendData := make([]byte, 32)
	_, err = rand.Read(extendData)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcrIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  extendData,
				},
			},
		},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	finalBanks, err := tpm.ReadPCRs([]uint{pcrIndex})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(finalBanks), 1)
	finalValue := finalBanks[0].PCRs[0].Value

	assert.NotEqual(t, initialValue, finalValue)
}

// Test IsPlatformPCRExtended method
// Note: createSim() provisions the TPM which calls CreatePlatformPolicy(),
// so PCR 16 is already extended when this test runs.
// This test verifies the method correctly detects the extended state.
func TestIsPlatformPCRExtended_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// After provisioning, PCR 16 should be extended (provisioning calls CreatePlatformPolicy)
	extended, err := tpm.IsPlatformPCRExtended()
	require.NoError(t, err)
	assert.True(t, extended, "PCR should be extended after provisioning")

	// Verify the method returns no errors and consistent results
	extended2, err := tpm.IsPlatformPCRExtended()
	require.NoError(t, err)
	assert.True(t, extended2, "PCR extended state should be consistent")
	assert.Equal(t, extended, extended2, "Multiple calls should return same result")
}

// Test Random Number Generation
func TestRandomBytes_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	testSizes := []int{16, 32, 48, 64}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			randomBytes, err := tpm.RandomBytes(size)
			require.NoError(t, err)
			assert.Len(t, randomBytes, size)

			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros)

			randomBytes2, err := tpm.RandomBytes(size)
			require.NoError(t, err)
			assert.NotEqual(t, randomBytes, randomBytes2)
		})
	}
}

// Test Large Random Byte Generation
func TestRandomBytes_LargeSize_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	largeSizes := []int{100, 256, 512, 1024}

	for _, size := range largeSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			randomBytes, err := tpm.RandomBytes(size)
			require.NoError(t, err)
			assert.Len(t, randomBytes, size)

			uniqueBytes := make(map[byte]struct{})
			for _, b := range randomBytes {
				uniqueBytes[b] = struct{}{}
			}
			if size >= 256 {
				assert.Greater(t, len(uniqueBytes), 100)
			}
		})
	}
}

// Test Random with invalid length
func TestRandomBytes_InvalidLength_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, err := tpm.RandomBytes(0)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	_, err = tpm.RandomBytes(-1)
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)
}

// Test Random() default 32 bytes
func TestRandom_Default32Bytes_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	randomBytes, err := tpm.Random()
	require.NoError(t, err)
	assert.Len(t, randomBytes, 32)

	allZeros := true
	for _, b := range randomBytes {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros)
}

// Test RandomHex encoding
func TestRandomHex_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	hexBytes, err := tpm.RandomHex(32)
	require.NoError(t, err)
	assert.Len(t, hexBytes, 32)

	_, err = hex.DecodeString(string(hexBytes))
	require.NoError(t, err)
}

// Test TPM Info
func TestInfo_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	info, err := tpm.Info()
	require.NoError(t, err)
	assert.NotEmpty(t, info)
}

// Test Fixed Properties
func TestFixedProperties_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err)
	assert.NotNil(t, props)

	assert.NotEmpty(t, props.Manufacturer)
	assert.NotEmpty(t, props.VendorID)
	assert.NotEmpty(t, props.Family)
}

// Test PCR operations with invalid index
func TestReadPCRs_InvalidIndex_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	_, err := tpm.ReadPCRs([]uint{24})
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPCRIndex, err)

	_, err = tpm.ReadPCRs([]uint{100})
	assert.Error(t, err)
}

// Test Multiple PCR Extend operations
func TestPCRExtend_Multiple_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	pcrIndex := uint(16)

	values := make([][]byte, 4)

	// Helper function to find SHA256 bank value
	getSHA256Value := func(banks []PCRBank) []byte {
		for _, bank := range banks {
			if bank.Algorithm == "SHA256" {
				return bank.PCRs[0].Value
			}
		}
		return nil
	}

	initialBanks, err := tpm.ReadPCRs([]uint{pcrIndex})
	require.NoError(t, err)
	values[0] = getSHA256Value(initialBanks)
	require.NotNil(t, values[0], "SHA256 bank not found")

	for i := 1; i < 4; i++ {
		extendData := make([]byte, 32)
		_, err = rand.Read(extendData)
		require.NoError(t, err)

		_, err = tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(pcrIndex),
				Auth:   tpm2.PasswordAuth(nil),
			},
			Digests: tpm2.TPMLDigestValues{
				Digests: []tpm2.TPMTHA{
					{
						HashAlg: tpm2.TPMAlgSHA256,
						Digest:  extendData,
					},
				},
			},
		}.Execute(tpmImpl.transport)
		require.NoError(t, err)

		banks, err := tpm.ReadPCRs([]uint{pcrIndex})
		require.NoError(t, err)
		values[i] = getSHA256Value(banks)
		require.NotNil(t, values[i], "SHA256 bank not found")
	}

	for i := 0; i < len(values)-1; i++ {
		for j := i + 1; j < len(values); j++ {
			assert.NotEqual(t, values[i], values[j])
		}
	}
}

// Test ReadHandle operation
func TestReadHandle_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekHandle := tpm2.TPMHandle(tpm.Config().EK.Handle)

	name, pub, err := tpm.ReadHandle(ekHandle)
	require.NoError(t, err)
	assert.NotEmpty(t, name.Buffer)
	assert.NotNil(t, pub)

	assert.Equal(t, tpm2.TPMAlgRSA, pub.Type)
}

// Test capabilities with encrypted session
func TestCapabilities_EncryptedSession_Simulator(t *testing.T) {
	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err)
	assert.NotNil(t, props)
	assert.NotEmpty(t, props.Manufacturer)
}

// Test random bytes with entropy mode
func TestRandomBytes_EntropyMode_Simulator(t *testing.T) {
	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	randomBytes, err := tpm.RandomBytes(64)
	require.NoError(t, err)
	assert.Len(t, randomBytes, 64)

	uniqueBytes := make(map[byte]struct{})
	for _, b := range randomBytes {
		uniqueBytes[b] = struct{}{}
	}
	assert.Greater(t, len(uniqueBytes), 20)
}

// Test simultaneous PCR bank reads
func TestReadPCRs_AllBanks_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	allPCRs := make([]uint, 24)
	for i := uint(0); i < 24; i++ {
		allPCRs[i] = i
	}

	banks, err := tpm.ReadPCRs(allPCRs)
	require.NoError(t, err)
	require.NotEmpty(t, banks)

	assert.GreaterOrEqual(t, len(banks), 2)

	for _, bank := range banks {
		assert.Equal(t, 24, len(bank.PCRs))
	}
}

// Benchmark random byte generation
func BenchmarkRandomBytes_Simulator(b *testing.B) {
	logger := logging.DefaultLogger()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		b.Fatal(err)
	}
	hexVal := hex.EncodeToString(buf)
	_ = fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	// Create storage backend
	storageFactory, err := store.NewStorageFactory(logger, "")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = storageFactory.Close() }()

	blobStore := storageFactory.BlobStore()
	fileBackend := storageFactory.KeyBackend()

	config := &Config{
		EncryptSession: false,
		UseEntropy:     false,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: store.DEFAULT_PASSWORD,
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity:                []string{},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
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
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       logging.DefaultLogger(),
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				b.Fatal(err)
			}
		} else {
			b.Fatal(err)
		}
	}
	defer func() { _ = tpm.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tpm.RandomBytes(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test io.Reader interface implementation
func TestRead_Interface_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	data := make([]byte, 128)
	n, err := tpm.Read(data)
	require.NoError(t, err)
	assert.Equal(t, 128, n)

	hasNonZero := false
	for _, b := range data {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	assert.True(t, hasNonZero)
}

// Test PCR extend with multiple hash algorithms
func TestPCRExtend_MultipleAlgorithms_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)
	pcrIndex := uint(16)

	sha1Data := make([]byte, 20)
	sha256Data := make([]byte, 32)
	_, err := rand.Read(sha1Data)
	require.NoError(t, err)
	_, err = rand.Read(sha256Data)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcrIndex),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA1,
					Digest:  sha1Data,
				},
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  sha256Data,
				},
			},
		},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	banks, err := tpm.ReadPCRs([]uint{pcrIndex})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(banks), 2)
}

// Test NV operations with different data sizes
func TestNVWriteAndRead_VariableSizes_Simulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl := tpm.(*TPM2)

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	var hierarchyAuth []byte
	if ekAttrs.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
	}

	testCases := []struct {
		name  string
		size  int
		nvIdx uint32
	}{
		{"Small_16bytes", 16, 0x01500030},
		{"Medium_128bytes", 128, 0x01500031},
		{"Large_512bytes", 512, 0x01500032},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nvIndex := tpm2.TPMHandle(tc.nvIdx)
			testData := make([]byte, tc.size)
			_, err := rand.Read(testData)
			require.NoError(t, err)

			defs := tpm2.NVDefineSpace{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(hierarchyAuth),
				},
				PublicInfo: tpm2.New2B(
					tpm2.TPMSNVPublic{
						NVIndex: nvIndex,
						NameAlg: tpm2.TPMAlgSHA256,
						Attributes: tpm2.TPMANV{
							AuthRead:   true,
							AuthWrite:  true,
							NT:         tpm2.TPMNTOrdinary,
							NoDA:       true,
							OwnerRead:  true,
							OwnerWrite: true,
						},
						DataSize: uint16(tc.size),
					}),
			}

			_, err = defs.Execute(tpmImpl.transport)
			require.NoError(t, err)

			nvPub, err := tpm2.NVReadPublic{
				NVIndex: nvIndex,
			}.Execute(tpmImpl.transport)
			require.NoError(t, err)

			_, err = tpm2.NVWrite{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(hierarchyAuth),
				},
				NVIndex: tpm2.AuthHandle{
					Handle: nvIndex,
					Name:   nvPub.NVName,
					Auth:   tpm2.PasswordAuth(nil),
				},
				Data: tpm2.TPM2BMaxNVBuffer{
					Buffer: testData,
				},
				Offset: 0,
			}.Execute(tpmImpl.transport)
			require.NoError(t, err)

			readRsp, err := tpm2.NVRead{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(hierarchyAuth),
				},
				NVIndex: tpm2.AuthHandle{
					Handle: nvIndex,
					Name:   nvPub.NVName,
					Auth:   tpm2.PasswordAuth(nil),
				},
				Size:   uint16(tc.size),
				Offset: 0,
			}.Execute(tpmImpl.transport)
			require.NoError(t, err)

			assert.True(t, bytes.Equal(testData, readRsp.Data.Buffer))

			_, err = tpm2.NVUndefineSpace{
				AuthHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(hierarchyAuth),
				},
				NVIndex: tpm2.NamedHandle{Handle: nvIndex, Name: nvPub.NVName},
			}.Execute(tpmImpl.transport)
			require.NoError(t, err)
		})
	}
}
