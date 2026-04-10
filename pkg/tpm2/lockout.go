package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// DictionaryAttackLockoutReset executes TPM2_DictionaryAttackLockReset to
// reset the DA lockout counter. Authorization is provided via the Lockout
// hierarchy using password-based session authentication.
//
// Per TCG TPM 2.0 Part 3 - Commands, Section 25.3:
// This command cancels the effect of a TPM lockout due to a number of
// successive authorization failures.
func (tpm *TPM2) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	if tpm.transport == nil {
		return ErrTransportNotInitialized
	}

	// TPM2_DictionaryAttackLockReset is not wrapped in go-tpm v0.9.x,
	// so we construct the command buffer manually.
	//
	// Command structure (TPM 2.0 Part 3, Section 25.3):
	//   tag         (2 bytes): TPM_ST_SESSIONS (0x8002)
	//   commandSize (4 bytes): total size
	//   commandCode (4 bytes): TPM_CC_DictionaryAttackLockReset (0x00000139)
	//   lockoutHandle (4 bytes): TPM_RH_LOCKOUT (0x4000000A)
	//   authorizationSize (4 bytes) + authorization area

	authAreaSize := 4 + // session handle (TPM_RS_PW)
		2 + // nonce size (0 for password session)
		1 + // session attributes
		2 + len(lockoutAuth) // auth value size + auth value

	totalSize := 10 + 4 + 4 + authAreaSize // header + handle + authArea size field + authArea

	buf := new(bytes.Buffer)

	// Header
	if err := binary.Write(buf, binary.BigEndian, uint16(0x8002)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(totalSize)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(tpm2.TPMCCDictionaryAttackLockReset)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Lockout handle
	if err := binary.Write(buf, binary.BigEndian, uint32(tpm2.TPMRHLockout)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Authorization area size
	if err := binary.Write(buf, binary.BigEndian, uint32(authAreaSize)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Session handle: TPM_RS_PW (0x40000009)
	if err := binary.Write(buf, binary.BigEndian, uint32(0x40000009)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Nonce size: 0 for password session
	if err := binary.Write(buf, binary.BigEndian, uint16(0)); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Session attributes: continueSession = 1
	if err := buf.WriteByte(0x01); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}

	// Auth value size + auth value
	if err := binary.Write(buf, binary.BigEndian, uint16(len(lockoutAuth))); err != nil {
		return fmt.Errorf("tpm: lockout reset: %w", err)
	}
	if len(lockoutAuth) > 0 {
		if _, err := buf.Write(lockoutAuth); err != nil {
			return fmt.Errorf("tpm: lockout reset: %w", err)
		}
	}

	// Send command
	rsp, err := tpm.transport.Send(buf.Bytes())
	if err != nil {
		return fmt.Errorf("tpm: lockout reset send: %w", err)
	}

	// Parse response
	if len(rsp) < 10 {
		return fmt.Errorf("tpm: lockout reset: response too short: %d bytes", len(rsp))
	}

	respCode := binary.BigEndian.Uint32(rsp[6:10])
	if respCode != 0 {
		return tpm2.TPMRC(respCode)
	}

	tpm.logger.Info("dictionary attack lockout reset successful")
	return nil
}
