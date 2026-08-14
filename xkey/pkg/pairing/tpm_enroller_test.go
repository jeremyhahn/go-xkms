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

package pairing

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedLog is one structured record emitted during a test.
type capturedLog struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Device  string `json:"device"`
	Error   string `json:"error"`
}

// captureLogger returns a logger writing JSON into buf so tests can assert on
// the level and fields of the single line OpenTPMEnroller emits.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// decodeLogs parses every record written to buf.
func decodeLogs(t *testing.T, buf *bytes.Buffer) []capturedLog {
	t.Helper()

	var records []capturedLog
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec capturedLog
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line must be JSON: %s", line)
		records = append(records, rec)
	}
	return records
}

// findLog returns the first record whose message contains substr.
func findLog(records []capturedLog, substr string) (capturedLog, bool) {
	for _, rec := range records {
		if strings.Contains(rec.Message, substr) {
			return rec, true
		}
	}
	return capturedLog{}, false
}

// listeningSocket creates a Unix socket that accepts connections but speaks no
// TPM protocol, so opening it as a TPM gets past connect and fails afterwards.
func listeningSocket(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "swtpm.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	return path
}

// TestOpenTPMEnroller_ReportsTheThreeHostStates proves the distinction that
// makes enrollment diagnosable: a host with no TPM is a capability gap
// reported at INFO, while a host whose TPM will not open is a fault reported
// at WARN with the device path and the underlying cause. Neither returns an
// enroller, because the bridge must keep working without one.
func TestOpenTPMEnroller_ReportsTheThreeHostStates(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-tpm")

	// A directory is a node that exists but cannot be opened read-write, which
	// is exactly the shape of the /dev/tpmrm0 permission failure.
	unopenable := t.TempDir()

	tests := []struct {
		name         string
		device       string
		wantSentinel error
		wantLevel    string
		wantMessage  string
		wantCause    bool
	}{
		{
			name:         "no TPM on this host",
			device:       missing,
			wantSentinel: ErrTPMNotConfigured,
			wantLevel:    slog.LevelInfo.String(),
			wantMessage:  "no TPM on this host",
		},
		{
			name:         "TPM node present but not openable",
			device:       unopenable,
			wantSentinel: ErrTPMUnavailable,
			wantLevel:    slog.LevelWarn.String(),
			wantMessage:  "cannot reach it",
			wantCause:    true,
		},
		{
			name:         "TPM socket present but not speaking TPM",
			device:       listeningSocket(t),
			wantSentinel: ErrTPMUnavailable,
			wantLevel:    slog.LevelWarn.String(),
			wantMessage:  "cannot reach it",
			wantCause:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			enroller, err := OpenTPMEnroller(&TPMEnrollerConfig{
				Device: tt.device,
				Logger: captureLogger(&buf),
			})

			assert.Nil(t, enroller, "an unavailable TPM must yield no enroller")
			require.ErrorIs(t, err, tt.wantSentinel)

			rec, ok := findLog(decodeLogs(t, &buf), tt.wantMessage)
			require.True(t, ok, "the outcome must be reported once; got %q", buf.String())
			assert.Equal(t, tt.wantLevel, rec.Level)
			assert.Equal(t, tt.device, rec.Device, "the report must name the device path")
			if tt.wantCause {
				assert.NotEmpty(t, rec.Error, "an unreachable TPM must report its cause")
			}
		})
	}
}

// TestOpenTPMEnroller_MissingTPMIsNotAFault pins the level: reporting an
// absent TPM at WARN or ERROR would make every laptop without one look broken.
func TestOpenTPMEnroller_MissingTPMIsNotAFault(t *testing.T) {
	var buf bytes.Buffer

	_, err := OpenTPMEnroller(&TPMEnrollerConfig{
		Device: filepath.Join(t.TempDir(), "absent"),
		Logger: captureLogger(&buf),
	})
	require.ErrorIs(t, err, ErrTPMNotConfigured)

	for _, rec := range decodeLogs(t, &buf) {
		assert.NotEqual(t, slog.LevelWarn.String(), rec.Level)
		assert.NotEqual(t, slog.LevelError.String(), rec.Level)
	}
}

// TestOpenTPMEnroller_UnreachableIsDistinguishableFromAbsent is the whole
// point of ErrTPMUnavailable: the phone must be able to tell the user that the
// laptop has a TPM xkey cannot reach, rather than that it has none.
func TestOpenTPMEnroller_UnreachableIsDistinguishableFromAbsent(t *testing.T) {
	var buf bytes.Buffer

	_, err := OpenTPMEnroller(&TPMEnrollerConfig{
		Device: t.TempDir(),
		Logger: captureLogger(&buf),
	})

	require.ErrorIs(t, err, ErrTPMUnavailable)
	assert.NotErrorIs(t, err, ErrTPMNotConfigured)
}

// TestOpenTPMEnroller_Defaults covers the zero-value config path: no device
// means the platform TPM node, and no logger means the default logger rather
// than a nil dereference.
func TestOpenTPMEnroller_Defaults(t *testing.T) {
	if _, err := os.Stat(DefaultTPMEnrollerDevice); err == nil {
		t.Skipf("this host has %s; the default path is exercised by hardware runs", DefaultTPMEnrollerDevice)
	}

	var buf bytes.Buffer

	enroller, err := OpenTPMEnroller(&TPMEnrollerConfig{Logger: captureLogger(&buf)})
	assert.Nil(t, enroller)
	require.ErrorIs(t, err, ErrTPMNotConfigured)

	rec, ok := findLog(decodeLogs(t, &buf), "no TPM on this host")
	require.True(t, ok)
	assert.Equal(t, DefaultTPMEnrollerDevice, rec.Device)
}

// TestOpenTPMEnroller_NilConfig proves a nil config is usable rather than a
// panic; callers that have nothing to configure should not have to say so.
func TestOpenTPMEnroller_NilConfig(t *testing.T) {
	if _, err := os.Stat(DefaultTPMEnrollerDevice); err == nil {
		t.Skipf("this host has %s; the default path is exercised by hardware runs", DefaultTPMEnrollerDevice)
	}

	enroller, err := OpenTPMEnroller(nil)
	assert.Nil(t, enroller)
	assert.ErrorIs(t, err, ErrTPMNotConfigured)
}
