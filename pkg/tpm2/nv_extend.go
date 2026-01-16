package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// nvExtendExecute executes the TPM2_NV_Extend command.
// This is a manual implementation since go-tpm does not expose NV_Extend.
// TPM2_NV_Extend extends data into an NV index with NT=Extend attribute.
//
// Command structure (TPM 2.0 Part 3, section 31.9):
// - AuthHandle: authorization handle for the NV index
// - NVIndex: handle of the NV location
// - Data: data to be extended
func nvExtendExecute(
	t transport.TPM,
	hierarchy tpm2.TPMHandle,
	nvIndex tpm2.TPMHandle,
	nvName tpm2.TPM2BName,
	hierarchyAuth []byte,
	data []byte,
) error {
	// Build the command buffer manually
	// Command format:
	// - Header: tag (2) + size (4) + command code (4) = 10 bytes
	// - AuthHandle (4 bytes)
	// - NVIndex (4 bytes)
	// - AuthArea size (4 bytes) + AuthArea
	// - Data size (2 bytes) + Data

	// Calculate sizes
	// For password session (TPM_RS_PW), we need:
	// - Session handle (4 bytes)
	// - Nonce size (2 bytes) + empty nonce (0 bytes) for password auth
	// - Session attributes (1 byte)
	// - Auth value size (2 bytes) + auth value
	authAreaSize := 4 + // session handle
		2 + 0 + // nonce size (2) + empty nonce for password auth
		1 + // session attributes
		2 + len(hierarchyAuth) // auth value size + auth value

	paramsSize := 2 + len(data) // size (2 bytes) + data

	// Total size = header (10) + handles (8) + authArea size field (4) + authArea + params
	totalSize := 10 + 8 + 4 + authAreaSize + paramsSize

	buf := new(bytes.Buffer)

	// Write header
	// Tag: TPM_ST_SESSIONS (0x8002) - indicates command has authorization area
	if err := binary.Write(buf, binary.BigEndian, uint16(0x8002)); err != nil {
		return err
	}
	// Size
	if err := binary.Write(buf, binary.BigEndian, uint32(totalSize)); err != nil {
		return err
	}
	// Command code: TPM_CC_NV_Extend (0x00000136)
	if err := binary.Write(buf, binary.BigEndian, uint32(tpm2.TPMCCNVExtend)); err != nil {
		return err
	}

	// Write handles
	// AuthHandle (hierarchy)
	if err := binary.Write(buf, binary.BigEndian, uint32(hierarchy)); err != nil {
		return err
	}
	// NVIndex
	if err := binary.Write(buf, binary.BigEndian, uint32(nvIndex)); err != nil {
		return err
	}

	// Write authorization area size
	if err := binary.Write(buf, binary.BigEndian, uint32(authAreaSize)); err != nil {
		return err
	}

	// Write authorization area
	// Session handle: TPM_RS_PW (0x40000009) for password authorization
	if err := binary.Write(buf, binary.BigEndian, uint32(0x40000009)); err != nil {
		return err
	}
	// Nonce size: 0 for password session
	if err := binary.Write(buf, binary.BigEndian, uint16(0)); err != nil {
		return err
	}
	// Session attributes: continueSession = 1
	if err := buf.WriteByte(0x01); err != nil {
		return err
	}
	// Auth value size + auth value
	if err := binary.Write(buf, binary.BigEndian, uint16(len(hierarchyAuth))); err != nil {
		return err
	}
	if len(hierarchyAuth) > 0 {
		if _, err := buf.Write(hierarchyAuth); err != nil {
			return err
		}
	}

	// Write parameters
	// Data size
	if err := binary.Write(buf, binary.BigEndian, uint16(len(data))); err != nil {
		return err
	}
	// Data
	if _, err := buf.Write(data); err != nil {
		return err
	}

	// Send command
	cmd := buf.Bytes()

	// Read response
	rsp, err := t.Send(cmd)
	if err != nil {
		return fmt.Errorf("failed to send NV_Extend command: %w", err)
	}

	// Parse response header
	if len(rsp) < 10 {
		return fmt.Errorf("response too short: %d bytes", len(rsp))
	}

	// Check response tag
	respTag := binary.BigEndian.Uint16(rsp[0:2])
	if respTag != 0x8002 && respTag != 0x8001 {
		return fmt.Errorf("unexpected response tag: 0x%04x", respTag)
	}

	// Check response size
	respSize := binary.BigEndian.Uint32(rsp[2:6])
	if uint32(len(rsp)) < respSize {
		return fmt.Errorf("response truncated: got %d, expected %d", len(rsp), respSize)
	}

	// Check response code
	respCode := binary.BigEndian.Uint32(rsp[6:10])
	if respCode != 0 {
		return tpm2.TPMRC(respCode)
	}

	return nil
}
