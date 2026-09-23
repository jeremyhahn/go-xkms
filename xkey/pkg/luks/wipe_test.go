// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package luks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-enclave"
)

func TestWipeStandard_String(t *testing.T) {
	tests := []struct {
		name     string
		standard WipeStandard
		expected string
	}{
		{name: "custom", standard: StandardCustom, expected: "custom"},
		{name: "nist", standard: StandardNIST, expected: "nist"},
		{name: "dod3", standard: StandardDoD3Pass, expected: "dod3"},
		{name: "dod7", standard: StandardDoD7Pass, expected: "dod7"},
		{name: "unknown", standard: WipeStandard(99), expected: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.standard.String())
		})
	}
}

func TestWipeStandard_GetPatternSequence(t *testing.T) {
	tests := []struct {
		name     string
		standard WipeStandard
		expected []WipePattern
	}{
		{
			name:     "nist single pass",
			standard: StandardNIST,
			expected: []WipePattern{PatternRandom},
		},
		{
			name:     "dod3 three pass",
			standard: StandardDoD3Pass,
			expected: []WipePattern{PatternZeros, PatternOnes, PatternRandom},
		},
		{
			name:     "dod7 seven pass",
			standard: StandardDoD7Pass,
			expected: []WipePattern{
				PatternZeros, PatternOnes, PatternRandom,
				PatternRandom,
				PatternZeros, PatternOnes, PatternRandom,
			},
		},
		{
			name:     "custom returns nil",
			standard: StandardCustom,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.standard.GetPatternSequence()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFillBufferWithPattern(t *testing.T) {
	t.Run("zeros pattern", func(t *testing.T) {
		buf := make([]byte, 100)
		for i := range buf {
			buf[i] = 0xFF // Pre-fill with ones
		}

		err := fillBufferWithPattern(buf, PatternZeros)
		require.NoError(t, err)

		for i, b := range buf {
			assert.Equal(t, byte(0x00), b, "byte %d should be 0x00", i)
		}
	})

	t.Run("ones pattern", func(t *testing.T) {
		buf := make([]byte, 100)
		for i := range buf {
			buf[i] = 0x00 // Pre-fill with zeros
		}

		err := fillBufferWithPattern(buf, PatternOnes)
		require.NoError(t, err)

		for i, b := range buf {
			assert.Equal(t, byte(0xFF), b, "byte %d should be 0xFF", i)
		}
	})

	t.Run("random pattern", func(t *testing.T) {
		buf := make([]byte, 100)
		zeros := make([]byte, 100)

		err := fillBufferWithPattern(buf, PatternRandom)
		require.NoError(t, err)

		// Random data shouldn't be all zeros (statistically improbable)
		allZeros := true
		for _, b := range buf {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "random pattern should not produce all zeros")
		assert.NotEqual(t, zeros, buf)
	})

	t.Run("unknown pattern", func(t *testing.T) {
		buf := make([]byte, 100)
		err := fillBufferWithPattern(buf, WipePattern(99))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown pattern")
	})
}

// wipePass wipes its scratch buffer via enclave.Wipe (go-xkms#623: the local
// clearBytes loop was retired in favor of go-enclave). This exercises that
// dependency the way wipePass uses it.
func TestWipePass_ScratchBufferWiped(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	enclave.Wipe(buf)

	for i, b := range buf {
		assert.Equal(t, byte(0x00), b, "byte %d should be cleared", i)
	}
}

func TestWipe_FileNotFound(t *testing.T) {
	opts := WipeOptions{
		Path:     "/non/existent/file",
		Standard: StandardNIST,
	}

	err := Wipe(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat file")
}

func TestWipe_NIST(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_wipe_nist.dat")

	// Create test file with known content
	content := make([]byte, 1024*10) // 10KB
	for i := range content {
		content[i] = 0xAA
	}
	err := os.WriteFile(testFile, content, 0600)
	require.NoError(t, err)

	// Wipe with NIST standard (1 pass of random)
	opts := WipeOptions{
		Path:     testFile,
		Standard: StandardNIST,
	}
	err = Wipe(opts)
	require.NoError(t, err)

	// Verify file content is changed (not all 0xAA)
	wiped, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Len(t, wiped, len(content))

	// Check that at least some bytes changed
	changed := false
	for _, b := range wiped {
		if b != 0xAA {
			changed = true
			break
		}
	}
	assert.True(t, changed, "file content should be different after wipe")
}

func TestWipe_DoD3(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_wipe_dod3.dat")

	// Create test file with known content
	content := make([]byte, 1024*10) // 10KB
	for i := range content {
		content[i] = 0xAA
	}
	err := os.WriteFile(testFile, content, 0600)
	require.NoError(t, err)

	// Wipe with DoD 3-pass standard
	opts := WipeOptions{
		Path:     testFile,
		Standard: StandardDoD3Pass,
	}
	err = Wipe(opts)
	require.NoError(t, err)

	// Verify file exists and content is changed
	wiped, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Len(t, wiped, len(content))

	// Final pass is random, so should be different from original
	changed := false
	for _, b := range wiped {
		if b != 0xAA {
			changed = true
			break
		}
	}
	assert.True(t, changed, "file content should be different after wipe")
}

func TestWipe_DoD7(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_wipe_dod7.dat")

	// Create test file with known content (smaller for speed)
	content := make([]byte, 1024*5) // 5KB
	for i := range content {
		content[i] = 0xAA
	}
	err := os.WriteFile(testFile, content, 0600)
	require.NoError(t, err)

	// Wipe with DoD 7-pass standard
	opts := WipeOptions{
		Path:     testFile,
		Standard: StandardDoD7Pass,
	}
	err = Wipe(opts)
	require.NoError(t, err)

	// Verify file exists and content is changed
	wiped, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Len(t, wiped, len(content))

	// Final pass is random, so should be different from original
	changed := false
	for _, b := range wiped {
		if b != 0xAA {
			changed = true
			break
		}
	}
	assert.True(t, changed, "file content should be different after wipe")
}

func TestWipe_EmptyPatternSequence(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_wipe_custom.dat")

	// Create test file
	content := make([]byte, 1024)
	err := os.WriteFile(testFile, content, 0600)
	require.NoError(t, err)

	// Wipe with custom standard (nil patterns defaults to zeros)
	opts := WipeOptions{
		Path:     testFile,
		Standard: StandardCustom,
	}
	err = Wipe(opts)
	require.NoError(t, err)

	// Verify file exists and is zeroed
	wiped, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Len(t, wiped, len(content))

	// All bytes should be zero (default pattern)
	for i, b := range wiped {
		assert.Equal(t, byte(0x00), b, "byte %d should be 0x00", i)
	}
}

func TestWipeConstants(t *testing.T) {
	assert.Equal(t, WipeStandard(0), StandardCustom)
	assert.Equal(t, WipeStandard(1), StandardNIST)
	assert.Equal(t, WipeStandard(2), StandardDoD3Pass)
	assert.Equal(t, WipeStandard(3), StandardDoD7Pass)

	assert.Equal(t, WipePattern(0), PatternZeros)
	assert.Equal(t, WipePattern(1), PatternOnes)
	assert.Equal(t, WipePattern(2), PatternRandom)
}

// TestWipe_OpenFailure covers the open-for-write failure branch using a
// directory, which cannot be opened O_WRONLY at any privilege level.
func TestWipe_OpenFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := Wipe(WipeOptions{Path: dir, Standard: StandardNIST})
	require.Error(t, err)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to open file", wrapped.Msg)
}

// TestWipePass_WriteFailure verifies a failing write aborts the pass with a
// wrapped error instead of silently reporting a successful wipe.
func TestWipePass_WriteFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "data.bin")
	require.NoError(t, os.WriteFile(path, []byte("sensitive data"), 0600))

	// Opened read-only: every write must fail.
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	err = wipePass(f, 14, PatternZeros)
	require.Error(t, err)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "write error", wrapped.Msg)

	// The file content must be untouched by the failed pass.
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "sensitive data", string(data))
}

// TestWipePass_UnknownPattern verifies an unsupported pattern aborts the pass
// rather than writing whatever happens to be in the buffer.
func TestWipePass_UnknownPattern(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "data.bin")
	require.NoError(t, os.WriteFile(path, []byte("sensitive data"), 0600))

	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	err = wipePass(f, 14, WipePattern(200))
	require.Error(t, err)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, "unknown pattern")

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "sensitive data", string(data), "an unsupported pattern must not modify the file")
}

// TestWipe_LargerThanBuffer exercises the multi-iteration write loop with a
// file larger than the 1 MiB wipe buffer.
func TestWipe_LargerThanBuffer(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "big.bin")
	original := bytes.Repeat([]byte{0xAA}, (1024*1024)+4096)
	require.NoError(t, os.WriteFile(path, original, 0600))

	require.NoError(t, Wipe(WipeOptions{Path: path, Standard: StandardCustom}))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, data, len(original), "wiping must not change the file size")
	assert.Equal(t, bytes.Repeat([]byte{0x00}, len(original)), data,
		"every byte past the buffer boundary must be overwritten")
}
