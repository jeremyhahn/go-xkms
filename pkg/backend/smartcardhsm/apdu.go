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

//go:build smartcardhsm

package smartcardhsm

// SmartCard-HSM APDU command definitions.
// These are proprietary commands specific to the SmartCard-HSM device.
// Reference: https://github.com/CardContact/sc-hsm-embedded/wiki/APDU-Reference

const (
	// CLA is the instruction class for SmartCard-HSM proprietary commands.
	CLA = 0x80

	// INS codes for SmartCard-HSM commands.
	INSInitialize      = 0x50 // Initialize device
	INSImportDKEKShare = 0x52 // Import DKEK share
	INSReadDKEKStatus  = 0x54 // Query DKEK status
	INSWrapKey         = 0x72 // Wrap/export key with DKEK
	INSUnwrapKey       = 0x74 // Unwrap/import key with DKEK
	INSGenerateKey     = 0x46 // Generate asymmetric key pair
	INSDeviceAuth      = 0x82 // Device authentication

	// P1/P2 values for Initialize command.
	P1InitRetryCounter = 0x00 // Initialize with retry counter
	P1InitDKEK         = 0x01 // Initialize with DKEK

	// Status words.
	SW_SUCCESS            = 0x9000
	SW_WRONG_LENGTH       = 0x6700
	SW_SECURITY_NOT_SAT   = 0x6982
	SW_AUTH_BLOCKED       = 0x6983
	SW_CONDITIONS_NOT_SAT = 0x6985
	SW_WRONG_DATA         = 0x6A80
	SW_WRONG_P1P2         = 0x6A86
	SW_INS_NOT_SUPPORTED  = 0x6D00
	SW_CLA_NOT_SUPPORTED  = 0x6E00

	// DKEK share status values (returned in response to INSReadDKEKStatus).
	DKEKStatusNotInitialized = 0x00
	DKEKStatusPartialShares  = 0x01 // Some shares imported, more needed
	DKEKStatusComplete       = 0x02 // All shares imported, DKEK ready

	// Key types for wrap/unwrap operations.
	KeyTypeRSA2048 = 0x00
	KeyTypeRSA4096 = 0x01
	KeyTypeECP256  = 0x10
	KeyTypeECP384  = 0x11
	KeyTypeECP521  = 0x12
	KeyTypeAES128  = 0x18
	KeyTypeAES192  = 0x19
	KeyTypeAES256  = 0x1A
)

// APDU represents a command APDU for SmartCard-HSM.
type APDU struct {
	CLA  byte   // Instruction class
	INS  byte   // Instruction code
	P1   byte   // Parameter 1
	P2   byte   // Parameter 2
	Data []byte // Command data (optional)
	Le   int    // Expected response length (-1 for none, 0 for any)
}

// Bytes serializes the APDU to bytes for transmission.
func (a *APDU) Bytes() []byte {
	cmd := []byte{a.CLA, a.INS, a.P1, a.P2}

	if len(a.Data) > 0 {
		if len(a.Data) <= 255 {
			// Short length encoding
			cmd = append(cmd, byte(len(a.Data)))
		} else {
			// Extended length encoding
			cmd = append(cmd, 0x00)
			cmd = append(cmd, byte(len(a.Data)>>8))
			cmd = append(cmd, byte(len(a.Data)&0xFF))
		}
		cmd = append(cmd, a.Data...)
	}

	if a.Le >= 0 {
		if a.Le == 0 {
			cmd = append(cmd, 0x00) // Any length
		} else if a.Le <= 256 {
			if a.Le == 256 {
				cmd = append(cmd, 0x00)
			} else {
				cmd = append(cmd, byte(a.Le))
			}
		} else {
			// Extended Le
			cmd = append(cmd, 0x00)
			cmd = append(cmd, byte(a.Le>>8))
			cmd = append(cmd, byte(a.Le&0xFF))
		}
	}

	return cmd
}

// Response represents a response from the SmartCard-HSM.
type Response struct {
	Data []byte // Response data
	SW1  byte   // Status word 1
	SW2  byte   // Status word 2
}

// StatusWord returns the combined status word.
func (r *Response) StatusWord() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// IsSuccess returns true if the command succeeded.
func (r *Response) IsSuccess() bool {
	return r.StatusWord() == SW_SUCCESS
}

// ParseResponse parses a raw response into Response struct.
func ParseResponse(raw []byte) *Response {
	if len(raw) < 2 {
		return &Response{SW1: 0x6F, SW2: 0x00} // Unknown error
	}
	return &Response{
		Data: raw[:len(raw)-2],
		SW1:  raw[len(raw)-2],
		SW2:  raw[len(raw)-1],
	}
}

// BuildInitializeAPDU creates an APDU for device initialization.
// Parameters:
//   - retryCounter: Number of PIN retry attempts
//   - options: Device configuration options
//   - dkekShares: Number of DKEK shares (0 for no DKEK)
//   - dkekThreshold: Minimum shares required to reconstruct DKEK
func BuildInitializeAPDU(retryCounter byte, options byte, dkekShares, dkekThreshold byte) *APDU {
	data := []byte{retryCounter, options}
	if dkekShares > 0 {
		data = append(data, dkekShares, dkekThreshold)
	}
	return &APDU{
		CLA:  CLA,
		INS:  INSInitialize,
		P1:   P1InitRetryCounter,
		P2:   0x00,
		Data: data,
		Le:   -1,
	}
}

// BuildImportDKEKShareAPDU creates an APDU for importing a DKEK share.
// The share should be a 32-byte AES-256 key share.
func BuildImportDKEKShareAPDU(share []byte) *APDU {
	return &APDU{
		CLA:  CLA,
		INS:  INSImportDKEKShare,
		P1:   0x00,
		P2:   0x00,
		Data: share,
		Le:   0, // Expect response with status
	}
}

// BuildReadDKEKStatusAPDU creates an APDU to query DKEK initialization status.
func BuildReadDKEKStatusAPDU() *APDU {
	return &APDU{
		CLA: CLA,
		INS: INSReadDKEKStatus,
		P1:  0x00,
		P2:  0x00,
		Le:  0,
	}
}

// BuildWrapKeyAPDU creates an APDU to wrap/export a key with DKEK.
// keyRef is the key reference (slot) on the card.
func BuildWrapKeyAPDU(keyRef byte) *APDU {
	return &APDU{
		CLA: CLA,
		INS: INSWrapKey,
		P1:  keyRef,
		P2:  0x00,
		Le:  0, // Variable response length
	}
}

// BuildUnwrapKeyAPDU creates an APDU to unwrap/import a key with DKEK.
// keyRef is the target key reference (slot) on the card.
// wrappedKey is the DKEK-wrapped key blob.
func BuildUnwrapKeyAPDU(keyRef byte, wrappedKey []byte) *APDU {
	return &APDU{
		CLA:  CLA,
		INS:  INSUnwrapKey,
		P1:   keyRef,
		P2:   0x00,
		Data: wrappedKey,
		Le:   -1,
	}
}
