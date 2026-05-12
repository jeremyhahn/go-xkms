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
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogLineChecksum(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantLen int
	}{
		{
			name:    "simple log line",
			line:    "2024-01-15T10:30:00Z INFO certificate issued serial=abc123",
			wantLen: 6, // Base64 URL encoding of 4 bytes without padding
		},
		{
			name:    "empty string",
			line:    "",
			wantLen: 6,
		},
		{
			name:    "unicode characters",
			line:    "2024-01-15T10:30:00Z INFO user=用户 action=登录",
			wantLen: 6,
		},
		{
			name:    "special characters",
			line:    `{"timestamp":"2024-01-15T10:30:00Z","level":"INFO","msg":"test\n\t"}`,
			wantLen: 6,
		},
		{
			name:    "long line",
			line:    strings.Repeat("a", 10000),
			wantLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checksum := LogLineChecksum(tt.line)
			assert.Len(t, checksum, tt.wantLen)

			// Verify same input produces same checksum (deterministic)
			checksum2 := LogLineChecksum(tt.line)
			assert.Equal(t, checksum, checksum2)
		})
	}
}

func TestLogLineChecksum_Uniqueness(t *testing.T) {
	// Different inputs should produce different checksums
	lines := []string{
		"2024-01-15T10:30:00Z INFO message1",
		"2024-01-15T10:30:00Z INFO message2",
		"2024-01-15T10:30:01Z INFO message1",
		"different format entirely",
	}

	checksums := make(map[string]bool)
	for _, line := range lines {
		checksum := LogLineChecksum(line)
		assert.False(t, checksums[checksum], "checksum collision for: %s", line)
		checksums[checksum] = true
	}
}

func TestFormatChecksummedLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantFmt string
	}{
		{
			name:    "simple line",
			line:    "test content",
			wantFmt: `^[A-Za-z0-9_-]{6} test content$`,
		},
		{
			name:    "json content",
			line:    `{"event":"test"}`,
			wantFmt: `^[A-Za-z0-9_-]{6} \{"event":"test"\}$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatChecksummedLine(tt.line)

			// Should have format: <checksum> <content>
			parts := strings.SplitN(result, " ", 2)
			require.Len(t, parts, 2)
			assert.Len(t, parts[0], 6)
			assert.Equal(t, tt.line, parts[1])
		})
	}
}

func TestChecksumWriter_Write(t *testing.T) {
	tests := []struct {
		name   string
		writes []string
		want   int // number of checksummed lines expected
	}{
		{
			name:   "single line",
			writes: []string{"log line one\n"},
			want:   1,
		},
		{
			name:   "multiple lines in one write",
			writes: []string{"line one\nline two\nline three\n"},
			want:   3,
		},
		{
			name:   "partial lines across writes",
			writes: []string{"part", "ial line\n"},
			want:   1,
		},
		{
			name:   "multiple writes with newlines",
			writes: []string{"line one\n", "line two\n"},
			want:   2,
		},
		{
			name:   "empty line",
			writes: []string{"\n"},
			want:   0, // empty lines are written as-is
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := NewChecksumWriter(&buf)

			for _, w := range tt.writes {
				n, err := writer.Write([]byte(w))
				require.NoError(t, err)
				assert.Equal(t, len(w), n)
			}

			output := buf.String()
			if tt.want > 0 {
				lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
				checksummedCount := 0
				for _, line := range lines {
					if strings.Contains(line, " ") {
						checksummedCount++
					}
				}
				assert.Equal(t, tt.want, checksummedCount)
			}
		})
	}
}

func TestChecksumWriter_Flush(t *testing.T) {
	var buf bytes.Buffer
	writer := NewChecksumWriter(&buf)

	// Write partial line without newline
	_, err := writer.Write([]byte("partial line without newline"))
	require.NoError(t, err)

	// Buffer should be empty since no complete line
	assert.Empty(t, buf.String())

	// Flush should write the remaining content
	err = writer.Flush()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "partial line without newline")
	// Should have checksum prefix
	parts := strings.SplitN(strings.TrimSuffix(output, "\n"), " ", 2)
	require.Len(t, parts, 2)
	assert.Len(t, parts[0], 6)
}

func TestChecksumWriter_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	writer := NewChecksumWriter(&buf)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				line := strings.Repeat("x", 50) + "\n"
				_, err := writer.Write([]byte(line))
				assert.NoError(t, err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic and should have written lines
	output := buf.String()
	assert.NotEmpty(t, output)
}

func TestVerifyLogLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantValid bool
		wantErr   error
	}{
		{
			name:      "valid checksummed line",
			line:      FormatChecksummedLine("test content"),
			wantValid: true,
			wantErr:   nil,
		},
		{
			name:      "valid with newline",
			line:      FormatChecksummedLine("test content") + "\n",
			wantValid: true,
			wantErr:   nil,
		},
		{
			name:      "empty line",
			line:      "",
			wantValid: false,
			wantErr:   ErrEmptyLine,
		},
		{
			name:      "newline only",
			line:      "\n",
			wantValid: false,
			wantErr:   ErrEmptyLine,
		},
		{
			name:      "no space separator",
			line:      "invalidlinewithoutspace",
			wantValid: false,
			wantErr:   ErrInvalidChecksumFormat,
		},
		{
			name:      "wrong checksum",
			line:      "WRONG! actual content",
			wantValid: false,
			wantErr:   ErrChecksumMismatch,
		},
		{
			name:      "corrupted content",
			line:      strings.Replace(FormatChecksummedLine("original"), "original", "modified", 1),
			wantValid: false,
			wantErr:   ErrChecksumMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, valid, err := VerifyLogLine(tt.line)

			assert.Equal(t, tt.wantValid, valid)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, content)
			}
		})
	}
}

func TestVerifyLogFile(t *testing.T) {
	t.Run("all valid lines", func(t *testing.T) {
		lines := []string{
			FormatChecksummedLine("line one"),
			FormatChecksummedLine("line two"),
			FormatChecksummedLine("line three"),
		}
		input := strings.Join(lines, "\n") + "\n"

		result, err := VerifyLogFile(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, 3, result.TotalLines)
		assert.Equal(t, 3, result.ValidLines)
		assert.Empty(t, result.InvalidLines)
		assert.True(t, result.IsValid())
	})

	t.Run("mixed valid and invalid", func(t *testing.T) {
		lines := []string{
			FormatChecksummedLine("valid line one"),
			"BADCS! invalid line",
			FormatChecksummedLine("valid line two"),
		}
		input := strings.Join(lines, "\n") + "\n"

		result, err := VerifyLogFile(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, 3, result.TotalLines)
		assert.Equal(t, 2, result.ValidLines)
		assert.Len(t, result.InvalidLines, 1)
		assert.False(t, result.IsValid())

		// Check invalid line details
		invalid := result.InvalidLines[0]
		assert.Equal(t, 2, invalid.LineNumber)
		assert.Equal(t, "BADCS!", invalid.Actual)
		assert.ErrorIs(t, invalid.Error, ErrChecksumMismatch)
	})

	t.Run("with empty lines", func(t *testing.T) {
		lines := []string{
			FormatChecksummedLine("line one"),
			"",
			FormatChecksummedLine("line two"),
		}
		input := strings.Join(lines, "\n") + "\n"

		result, err := VerifyLogFile(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, 3, result.TotalLines)
		assert.Equal(t, 2, result.ValidLines)
		assert.Equal(t, 1, result.EmptyLines)
		assert.True(t, result.IsValid())
	})

	t.Run("line without separator", func(t *testing.T) {
		input := "linewithoutseparator\n"

		result, err := VerifyLogFile(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, 1, result.TotalLines)
		assert.Equal(t, 0, result.ValidLines)
		assert.Len(t, result.InvalidLines, 1)
		assert.ErrorIs(t, result.InvalidLines[0].Error, ErrInvalidChecksumFormat)
	})

	t.Run("empty file", func(t *testing.T) {
		result, err := VerifyLogFile(strings.NewReader(""))
		require.NoError(t, err)

		assert.Equal(t, 0, result.TotalLines)
		assert.Equal(t, 0, result.ValidLines)
		assert.Empty(t, result.InvalidLines)
		assert.True(t, result.IsValid())
	})

	t.Run("special characters", func(t *testing.T) {
		lines := []string{
			FormatChecksummedLine(`{"event":"CERTIFICATE_ISSUED","actor":"account:123"}`),
			FormatChecksummedLine("unicode: 日本語 한국어"),
			FormatChecksummedLine("tab\tseparated\tvalues"),
		}
		input := strings.Join(lines, "\n") + "\n"

		result, err := VerifyLogFile(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, 3, result.TotalLines)
		assert.Equal(t, 3, result.ValidLines)
		assert.True(t, result.IsValid())
	})
}

func TestVerificationResult_IsValid(t *testing.T) {
	t.Run("empty result is valid", func(t *testing.T) {
		result := &VerificationResult{
			InvalidLines: make([]InvalidLine, 0),
		}
		assert.True(t, result.IsValid())
	})

	t.Run("result with invalid lines is not valid", func(t *testing.T) {
		result := &VerificationResult{
			InvalidLines: []InvalidLine{
				{LineNumber: 1, Error: ErrChecksumMismatch},
			},
		}
		assert.False(t, result.IsValid())
	})
}

func TestChecksumWriter_RoundTrip(t *testing.T) {
	originalLines := []string{
		`{"timestamp":"2024-01-15T10:30:00Z","event_type":"CERTIFICATE_ISSUED"}`,
		`{"timestamp":"2024-01-15T10:31:00Z","event_type":"ACCOUNT_CREATED"}`,
		`{"timestamp":"2024-01-15T10:32:00Z","event_type":"ORDER_FINALIZED"}`,
	}

	// Write with checksums
	var buf bytes.Buffer
	writer := NewChecksumWriter(&buf)

	for _, line := range originalLines {
		_, err := writer.Write([]byte(line + "\n"))
		require.NoError(t, err)
	}

	// Verify the output
	result, err := VerifyLogFile(strings.NewReader(buf.String()))
	require.NoError(t, err)

	assert.Equal(t, len(originalLines), result.TotalLines)
	assert.Equal(t, len(originalLines), result.ValidLines)
	assert.True(t, result.IsValid())

	// Verify we can extract original content
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	for i, line := range lines {
		content, valid, err := VerifyLogLine(line)
		require.NoError(t, err)
		assert.True(t, valid)
		assert.Equal(t, originalLines[i], content)
	}
}

func TestChecksumWriter_WriteError(t *testing.T) {
	// Test with a writer that fails
	failingWriter := &failWriter{failAfter: 1}
	writer := NewChecksumWriter(failingWriter)

	// First line should succeed
	_, err := writer.Write([]byte("line one\n"))
	require.NoError(t, err)

	// Second line should fail
	_, err = writer.Write([]byte("line two\n"))
	require.Error(t, err)
	assert.Equal(t, errWriteFailed, err)
}

type failWriter struct {
	count     int
	failAfter int
}

var errWriteFailed = assert.AnError

func (w *failWriter) Write(p []byte) (n int, err error) {
	w.count++
	if w.count > w.failAfter {
		return 0, errWriteFailed
	}
	return len(p), nil
}
