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
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// WipeStandard defines a named wipe methodology.
type WipeStandard uint8

const (
	StandardCustom   WipeStandard = iota // Legacy/custom configuration
	StandardNIST                         // NIST SP 800-88 Rev 1
	StandardDoD3Pass                     // DoD 5220.22-M 3-pass
	StandardDoD7Pass                     // DoD 5220.22-M ECE 7-pass
)

// WipePattern defines the data pattern for a wipe pass.
type WipePattern uint8

const (
	PatternZeros  WipePattern = iota // 0x00
	PatternOnes                      // 0xFF
	PatternRandom                    // crypto/rand
)

// String returns the string representation of a WipeStandard.
func (s WipeStandard) String() string {
	switch s {
	case StandardCustom:
		return "custom"
	case StandardNIST:
		return "nist"
	case StandardDoD3Pass:
		return "dod3"
	case StandardDoD7Pass:
		return "dod7"
	default:
		return "unknown"
	}
}

// GetPatternSequence returns the pattern sequence for a standard.
func (s WipeStandard) GetPatternSequence() []WipePattern {
	switch s {
	case StandardNIST:
		// NIST SP 800-88: Single pass of random data
		return []WipePattern{PatternRandom}
	case StandardDoD3Pass:
		// DoD 5220.22-M 3-pass: Zeros -> Ones -> Random
		return []WipePattern{PatternZeros, PatternOnes, PatternRandom}
	case StandardDoD7Pass:
		// DoD 5220.22-M ECE 7-pass: (Z->O->R) + R + (Z->O->R)
		return []WipePattern{
			PatternZeros, PatternOnes, PatternRandom,
			PatternRandom,
			PatternZeros, PatternOnes, PatternRandom,
		}
	default:
		return nil
	}
}

// WipeOptions contains options for wiping a file.
type WipeOptions struct {
	Path     string       // Path to the file to wipe
	Standard WipeStandard // Named standard
}

// Wipe securely wipes a file using the specified standard.
func Wipe(opts WipeOptions) error {
	patterns := opts.Standard.GetPatternSequence()
	if len(patterns) == 0 {
		// Default to single zeros pass
		patterns = []WipePattern{PatternZeros}
	}

	// Get file size
	info, err := os.Stat(opts.Path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	size := info.Size()

	// Open file for writing
	f, err := os.OpenFile(opts.Path, os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Perform wipe passes
	for i, pattern := range patterns {
		if err := wipePass(f, size, pattern); err != nil {
			return fmt.Errorf("wipe pass %d failed: %w", i+1, err)
		}
	}

	// Sync to ensure writes are flushed
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	return nil
}

// wipePass performs one wipe pass over the file.
func wipePass(f *os.File, size int64, pattern WipePattern) error {
	const bufferSize = 1024 * 1024 // 1MB buffer

	buffer := make([]byte, bufferSize)
	defer clearBytes(buffer)

	// Seek to beginning
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	remaining := size
	for remaining > 0 {
		writeSize := int64(bufferSize)
		if remaining < writeSize {
			writeSize = remaining
		}

		// Fill buffer with pattern
		if err := fillBufferWithPattern(buffer[:writeSize], pattern); err != nil {
			return err
		}

		// Write buffer
		n, err := f.Write(buffer[:writeSize])
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}

		remaining -= int64(n)
	}

	return nil
}

// fillBufferWithPattern fills a buffer with the specified pattern.
func fillBufferWithPattern(buf []byte, pattern WipePattern) error {
	switch pattern {
	case PatternZeros:
		for i := range buf {
			buf[i] = 0x00
		}
	case PatternOnes:
		for i := range buf {
			buf[i] = 0xFF
		}
	case PatternRandom:
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}
	default:
		return fmt.Errorf("unknown pattern: %d", pattern)
	}
	return nil
}

// clearBytes securely clears a byte slice.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
