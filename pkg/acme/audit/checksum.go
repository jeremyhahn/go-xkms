// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package audit

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"sync"
)

// Checksum error types.
var (
	// ErrInvalidChecksumFormat indicates the line does not have the expected checksum format.
	ErrInvalidChecksumFormat = errors.New("audit: invalid checksum format")

	// ErrChecksumMismatch indicates the computed checksum does not match the stored checksum.
	ErrChecksumMismatch = errors.New("audit: checksum mismatch")

	// ErrEmptyLine indicates an empty line was encountered.
	ErrEmptyLine = errors.New("audit: empty line")
)

// LogLineChecksum computes CRC32 checksum for a log line and returns it as
// base64 URL-safe encoded string. The checksum uses the IEEE polynomial.
func LogLineChecksum(line string) string {
	crc := crc32.ChecksumIEEE([]byte(line))
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, crc)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// FormatChecksummedLine creates a checksummed log line in the format:
// <checksum> <original-log-line>
func FormatChecksummedLine(line string) string {
	checksum := LogLineChecksum(line)
	return checksum + " " + line
}

// ChecksumWriter wraps an io.Writer to prepend CRC32 checksums to each line.
// It is safe for concurrent use.
type ChecksumWriter struct {
	w   io.Writer
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewChecksumWriter creates a new ChecksumWriter that wraps the given writer.
func NewChecksumWriter(w io.Writer) *ChecksumWriter {
	return &ChecksumWriter{w: w}
}

// Write prepends CRC32 checksum to each complete line in the input.
// Lines are identified by newline characters. Partial lines at the end
// are buffered until the next Write call completes them.
func (c *ChecksumWriter) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Add new data to buffer
	c.buf.Write(p)

	// Process complete lines
	for {
		line, err := c.buf.ReadString('\n')
		if err != nil {
			// No complete line yet, put back what we read
			if line != "" {
				// Create new buffer with remaining content
				remaining := line
				c.buf.Reset()
				c.buf.WriteString(remaining)
			}
			break
		}

		// Remove the trailing newline for checksum computation
		content := strings.TrimSuffix(line, "\n")
		if content == "" {
			// Empty line - write as-is
			if _, err := c.w.Write([]byte("\n")); err != nil {
				return len(p), err
			}
			continue
		}

		// Write checksummed line
		checksummed := FormatChecksummedLine(content) + "\n"
		if _, err := c.w.Write([]byte(checksummed)); err != nil {
			return len(p), err
		}
	}

	return len(p), nil
}

// Flush writes any remaining buffered content. Should be called before
// closing the writer to ensure all content is written.
func (c *ChecksumWriter) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	remaining := c.buf.String()
	if remaining == "" {
		return nil
	}

	c.buf.Reset()
	checksummed := FormatChecksummedLine(remaining) + "\n"
	_, err := c.w.Write([]byte(checksummed))
	return err
}

// VerifyLogLine verifies a checksummed log line and extracts the content.
// The line format is: <checksum> <original-content>
// Returns the original content, whether it's valid, and any error.
func VerifyLogLine(line string) (content string, valid bool, err error) {
	// Handle empty lines
	if line == "" || line == "\n" {
		return "", false, ErrEmptyLine
	}

	// Remove trailing newline if present
	line = strings.TrimSuffix(line, "\n")
	if line == "" {
		return "", false, ErrEmptyLine
	}

	// Find the first space separator
	idx := strings.Index(line, " ")
	if idx == -1 {
		return "", false, ErrInvalidChecksumFormat
	}

	storedChecksum := line[:idx]
	content = line[idx+1:]

	// Compute expected checksum
	expectedChecksum := LogLineChecksum(content)

	if storedChecksum != expectedChecksum {
		return content, false, ErrChecksumMismatch
	}

	return content, true, nil
}

// VerificationResult contains the results of verifying a log file.
type VerificationResult struct {
	// TotalLines is the total number of lines processed.
	TotalLines int

	// ValidLines is the number of lines with valid checksums.
	ValidLines int

	// InvalidLines contains details about lines with invalid checksums.
	InvalidLines []InvalidLine

	// EmptyLines is the count of empty lines encountered.
	EmptyLines int
}

// IsValid returns true if all non-empty lines have valid checksums.
func (r *VerificationResult) IsValid() bool {
	return len(r.InvalidLines) == 0
}

// InvalidLine contains information about a line that failed verification.
type InvalidLine struct {
	// LineNumber is the 1-based line number in the file.
	LineNumber int

	// Expected is the expected checksum.
	Expected string

	// Actual is the checksum that was stored in the line.
	Actual string

	// Content is the content portion of the line.
	Content string

	// Error is the specific error that occurred.
	Error error
}

// VerifyLogFile verifies all lines in a log file and returns a summary.
func VerifyLogFile(r io.Reader) (*VerificationResult, error) {
	result := &VerificationResult{
		InvalidLines: make([]InvalidLine, 0),
	}

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		content, valid, err := VerifyLogLine(line)
		result.TotalLines++

		if err == ErrEmptyLine {
			result.EmptyLines++
			continue
		}

		if err == ErrInvalidChecksumFormat {
			result.InvalidLines = append(result.InvalidLines, InvalidLine{
				LineNumber: lineNum,
				Content:    line,
				Error:      err,
			})
			continue
		}

		if !valid {
			// Extract stored checksum for reporting
			idx := strings.Index(line, " ")
			storedChecksum := ""
			if idx > 0 {
				storedChecksum = line[:idx]
			}
			expectedChecksum := LogLineChecksum(content)

			result.InvalidLines = append(result.InvalidLines, InvalidLine{
				LineNumber: lineNum,
				Expected:   expectedChecksum,
				Actual:     storedChecksum,
				Content:    content,
				Error:      ErrChecksumMismatch,
			})
			continue
		}

		result.ValidLines++
	}

	if err := scanner.Err(); err != nil {
		return result, err
	}

	return result, nil
}
