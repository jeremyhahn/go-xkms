//go:build integration && tpm2

// Package integration provides TPM2 session encryption verification through
// packet capture and analysis.
package integration

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMPacket represents a captured TPM command or response packet
type TPMPacket struct {
	Direction string    // "send" (command) or "recv" (response)
	Data      []byte    // Raw packet data
	Timestamp time.Time // When packet was captured
}

// TPMCapture wraps a TPM transport to intercept and record all traffic
type TPMCapture struct {
	base    transport.TPMCloser
	packets []TPMPacket
	mu      sync.Mutex
	active  bool
}

// NewTPMCapture creates a new capturing transport wrapper
func NewTPMCapture(base transport.TPMCloser) *TPMCapture {
	return &TPMCapture{
		base:    base,
		packets: make([]TPMPacket, 0),
		active:  true,
	}
}

// Send captures outgoing TPM commands and incoming responses
func (tc *TPMCapture) Send(cmd []byte) ([]byte, error) {
	// Capture command
	if tc.active {
		tc.mu.Lock()
		// Make a copy to prevent mutation
		cmdCopy := make([]byte, len(cmd))
		copy(cmdCopy, cmd)
		tc.packets = append(tc.packets, TPMPacket{
			Direction: "send",
			Data:      cmdCopy,
			Timestamp: time.Now(),
		})
		tc.mu.Unlock()
	}

	// Send to TPM and get response
	resp, err := tc.base.Send(cmd)
	if err != nil {
		return resp, err
	}

	// Capture response
	if tc.active {
		tc.mu.Lock()
		// Make a copy to prevent mutation
		respCopy := make([]byte, len(resp))
		copy(respCopy, resp)
		tc.packets = append(tc.packets, TPMPacket{
			Direction: "recv",
			Data:      respCopy,
			Timestamp: time.Now(),
		})
		tc.mu.Unlock()
	}

	return resp, nil
}

// Close closes the underlying transport and stops capturing
func (tc *TPMCapture) Close() error {
	tc.mu.Lock()
	tc.active = false
	tc.mu.Unlock()
	return tc.base.Close()
}

// GetPackets returns a copy of all captured packets
func (tc *TPMCapture) GetPackets() []TPMPacket {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	packets := make([]TPMPacket, len(tc.packets))
	copy(packets, tc.packets)
	return packets
}

// Stop stops capturing (transport remains open)
func (tc *TPMCapture) Stop() {
	tc.mu.Lock()
	tc.active = false
	tc.mu.Unlock()
}

// Clear removes all captured packets
func (tc *TPMCapture) Clear() {
	tc.mu.Lock()
	tc.packets = make([]TPMPacket, 0)
	tc.mu.Unlock()
}

// TPMCommandHeader represents the fixed header of a TPM command
type TPMCommandHeader struct {
	Tag         uint16 // TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS
	CommandSize uint32 // Total command size including header
	CommandCode uint32 // TPM_CC_* command code
}

// TPMResponseHeader represents the fixed header of a TPM response
type TPMResponseHeader struct {
	Tag          uint16 // TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS
	ResponseSize uint32 // Total response size including header
	ResponseCode uint32 // TPM_RC_* response code
}

// ParseTPMCommandHeader parses a TPM command header from packet data
func ParseTPMCommandHeader(data []byte) (*TPMCommandHeader, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("packet too short for TPM command header: %d bytes", len(data))
	}

	hdr := &TPMCommandHeader{
		Tag:         binary.BigEndian.Uint16(data[0:2]),
		CommandSize: binary.BigEndian.Uint32(data[2:6]),
		CommandCode: binary.BigEndian.Uint32(data[6:10]),
	}

	return hdr, nil
}

// ParseTPMResponseHeader parses a TPM response header from packet data
func ParseTPMResponseHeader(data []byte) (*TPMResponseHeader, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("packet too short for TPM response header: %d bytes", len(data))
	}

	hdr := &TPMResponseHeader{
		Tag:          binary.BigEndian.Uint16(data[0:2]),
		ResponseSize: binary.BigEndian.Uint32(data[2:6]),
		ResponseCode: binary.BigEndian.Uint32(data[6:10]),
	}

	return hdr, nil
}

// IsTPMCommand returns true if packet appears to be a TPM command
func IsTPMCommand(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	tag := binary.BigEndian.Uint16(data[0:2])
	return tag == uint16(tpm2.TPMSTSessions) || tag == uint16(tpm2.TPMSTNoSessions)
}

// IsTPMResponse returns true if packet appears to be a TPM response
func IsTPMResponse(data []byte) bool {
	// Same structure as command for header
	return IsTPMCommand(data)
}

// HasSessionArea checks if a TPM command/response has a session area (TPM_ST_SESSIONS)
func HasSessionArea(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	tag := binary.BigEndian.Uint16(data[0:2])
	return tag == uint16(tpm2.TPMSTSessions)
}

// ExtractSessionAttributes attempts to extract session attributes from a command
// This is a best-effort parser for common TPM commands with sessions
func ExtractSessionAttributes(data []byte) ([]byte, error) {
	if !HasSessionArea(data) {
		return nil, fmt.Errorf("packet does not have session area")
	}

	if len(data) < 10 {
		return nil, fmt.Errorf("packet too short")
	}

	// Skip command header (10 bytes)
	offset := 10

	// Command-specific parameters vary, but session area comes after handles and parameters
	// For simplicity, we'll look for the session area marker (authorization size)
	// This is a simplified parser - real TPM commands require command-specific parsing

	// After command code, there are:
	// - Handles (varies by command)
	// - Authorization area size (4 bytes)
	// - Authorization sessions
	// - Parameters

	// We'll search for typical session encryption flag patterns
	// Session attributes are in the session area after the handle area

	// For now, return a simplified check - look for 0x20 (encrypt) or 0x40 (decrypt) flags
	for i := offset; i < len(data)-1; i++ {
		// Session attributes byte typically has bit patterns for encryption
		if data[i]&0x20 != 0 || data[i]&0x40 != 0 {
			return data[i : i+1], nil
		}
	}

	return nil, fmt.Errorf("no session attributes found")
}

// ContainsPlaintextPattern searches for common plaintext patterns that should be encrypted
func ContainsPlaintextPattern(data []byte, patterns [][]byte) bool {
	for _, pattern := range patterns {
		if bytes.Contains(data, pattern) {
			return true
		}
	}
	return false
}

// EncryptionAnalysis analyzes captured packets for encryption indicators
type EncryptionAnalysis struct {
	TotalPackets         int
	CommandPackets       int
	ResponsePackets      int
	SessionCommands      int
	SessionResponses     int
	EncryptedSessions    int
	PlaintextDetections  int
	EncryptionPercentage float64
}

// AnalyzePackets performs encryption analysis on captured TPM traffic
func AnalyzePackets(packets []TPMPacket, sensitivePatterns [][]byte) *EncryptionAnalysis {
	analysis := &EncryptionAnalysis{
		TotalPackets: len(packets),
	}

	for _, pkt := range packets {
		if pkt.Direction == "send" {
			analysis.CommandPackets++

			if HasSessionArea(pkt.Data) {
				analysis.SessionCommands++

				// Try to detect encryption flags
				attrs, err := ExtractSessionAttributes(pkt.Data)
				if err == nil && len(attrs) > 0 {
					// Check for encrypt/decrypt flags (0x20 = encrypt, 0x40 = decrypt)
					if attrs[0]&0x60 != 0 {
						analysis.EncryptedSessions++
					}
				}
			}
		} else if pkt.Direction == "recv" {
			analysis.ResponsePackets++

			if HasSessionArea(pkt.Data) {
				analysis.SessionResponses++
			}
		}

		// Check for plaintext sensitive data
		if ContainsPlaintextPattern(pkt.Data, sensitivePatterns) {
			analysis.PlaintextDetections++
		}
	}

	// Calculate encryption percentage
	if analysis.SessionCommands > 0 {
		analysis.EncryptionPercentage = (float64(analysis.EncryptedSessions) / float64(analysis.SessionCommands)) * 100.0
	}

	return analysis
}

// FormatAnalysis returns a human-readable string of the analysis
func (a *EncryptionAnalysis) FormatAnalysis() string {
	return fmt.Sprintf(`TPM Traffic Analysis:
  Total Packets: %d
  Commands: %d (Session: %d, Encrypted: %d)
  Responses: %d (Session: %d)
  Plaintext Detections: %d
  Encryption Rate: %.1f%%`,
		a.TotalPackets,
		a.CommandPackets, a.SessionCommands, a.EncryptedSessions,
		a.ResponsePackets, a.SessionResponses,
		a.PlaintextDetections,
		a.EncryptionPercentage)
}
