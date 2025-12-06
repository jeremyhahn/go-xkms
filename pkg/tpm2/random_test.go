package tpm2

import (
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/logging"
	"github.com/stretchr/testify/assert"
)

func TestRandBytes(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	randomBytes := make([]byte, 32)

	n, err := tpm.Read(randomBytes)
	assert.Nil(t, err)
	assert.Equal(t, 32, n)
	assert.Equal(t, len(randomBytes), 32)
}

func TestRandBytesEncrypted(t *testing.T) {

	_, tpm := createSim(true, true)
	defer func() { _ = tpm.Close() }()

	randomBytes := make([]byte, 32)

	n, err := tpm.Read(randomBytes)
	assert.Nil(t, err)
	assert.Equal(t, 32, n)
	assert.Equal(t, len(randomBytes), 32)
}

func TestRandom(t *testing.T) {

	logger := logging.DefaultLogger()

	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	random, err := tpm.Random()
	assert.Nil(t, err)
	assert.NotNil(t, random)
	assert.Equal(t, 32, len(random))

	encoded := hex.EncodeToString(random)

	logger.Debugf("%+s", encoded)
}

func TestRandomBytes_SmallChunk(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test reading less than maxRandomBytesPerRequest
	randomBytes, err := tpm.RandomBytes(16)
	assert.Nil(t, err)
	assert.Equal(t, 16, len(randomBytes))
}

func TestRandomBytes_ExactChunkSize(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test reading exactly maxRandomBytesPerRequest
	randomBytes, err := tpm.RandomBytes(maxRandomBytesPerRequest)
	assert.Nil(t, err)
	assert.Equal(t, maxRandomBytesPerRequest, len(randomBytes))
}

func TestRandomBytes_MultipleChunks(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test reading more than maxRandomBytesPerRequest (requires chunking)
	size := 128
	randomBytes, err := tpm.RandomBytes(size)
	assert.Nil(t, err)
	assert.Equal(t, size, len(randomBytes))

	// Verify bytes are not all zeros
	allZeros := true
	for _, b := range randomBytes {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "Random bytes should not be all zeros")
}

func TestRandomBytes_LargeRequest(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test a large request that requires many chunks
	size := 256
	randomBytes, err := tpm.RandomBytes(size)
	assert.Nil(t, err)
	assert.Equal(t, size, len(randomBytes))
}

func TestRandomBytes_VeryLargeRequest(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test a very large request
	size := 1024
	randomBytes, err := tpm.RandomBytes(size)
	assert.Nil(t, err)
	assert.Equal(t, size, len(randomBytes))
}

func TestRandomBytes_InvalidLength(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test with zero length
	_, err := tpm.RandomBytes(0)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	// Test with negative length
	_, err = tpm.RandomBytes(-1)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)
}

func TestRandomHex_ValidLength(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test valid hex encoding
	hexBytes, err := tpm.RandomHex(32)
	assert.Nil(t, err)
	assert.Equal(t, 32, len(hexBytes))

	// Verify it's valid hex
	_, err = hex.DecodeString(string(hexBytes))
	assert.Nil(t, err)
}

func TestRandomHex_InvalidLength(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test with odd length (must be even)
	_, err := tpm.RandomHex(31)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	// Test with zero length
	_, err = tpm.RandomHex(0)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	// Test with negative length
	_, err = tpm.RandomHex(-2)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)
}

func TestRandomBytes_Uniqueness(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test that multiple reads produce different results
	bytes1, err := tpm.RandomBytes(32)
	assert.Nil(t, err)

	bytes2, err := tpm.RandomBytes(32)
	assert.Nil(t, err)

	// Should not be equal (extremely unlikely for true random)
	assert.NotEqual(t, bytes1, bytes2, "Random bytes should be unique")
}

func TestRead_ChunkedBehavior(t *testing.T) {

	_, tpm := createSim(false, true)
	defer func() { _ = tpm.Close() }()

	// Test that Read correctly fills buffer for sizes requiring multiple chunks
	testCases := []int{
		1,                               // Single byte
		maxRandomBytesPerRequest - 1,    // Just under chunk size
		maxRandomBytesPerRequest,        // Exact chunk size
		maxRandomBytesPerRequest + 1,    // Just over chunk size
		maxRandomBytesPerRequest * 2,    // Two chunks
		maxRandomBytesPerRequest*2 + 10, // Two chunks plus extra
		maxRandomBytesPerRequest * 3,    // Three chunks
		maxRandomBytesPerRequest*5 + 17, // Multiple chunks plus remainder
	}

	for _, size := range testCases {
		data := make([]byte, size)
		n, err := tpm.Read(data)
		assert.Nil(t, err, "Size %d should succeed", size)
		assert.Equal(t, size, n, "Should read exactly %d bytes", size)
		assert.Equal(t, size, len(data), "Buffer should have %d bytes", size)
	}
}

func TestRandomBytes_EncryptedSession(t *testing.T) {

	_, tpm := createSim(true, true)
	defer func() { _ = tpm.Close() }()

	// Test chunked reading with encrypted session
	size := 128
	randomBytes, err := tpm.RandomBytes(size)
	assert.Nil(t, err)
	assert.Equal(t, size, len(randomBytes))
}
