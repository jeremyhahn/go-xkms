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

package ccid

// ISO 7816-4 status words.
const (
	// SW_SUCCESS indicates the command completed successfully.
	SW_SUCCESS uint16 = 0x9000

	// SW_FILE_NOT_FOUND indicates the referenced file or object was not found.
	SW_FILE_NOT_FOUND uint16 = 0x6A82

	// SW_WRONG_LENGTH indicates the APDU length is incorrect.
	SW_WRONG_LENGTH uint16 = 0x6700

	// SW_WRONG_DATA indicates the command data is invalid.
	SW_WRONG_DATA uint16 = 0x6A80

	// SW_INS_NOT_SUPPORTED indicates the instruction is not supported.
	SW_INS_NOT_SUPPORTED uint16 = 0x6D00

	// SW_CLA_NOT_SUPPORTED indicates the class byte is not supported.
	SW_CLA_NOT_SUPPORTED uint16 = 0x6E00

	// SW_INTERNAL_ERROR indicates an internal processing error.
	SW_INTERNAL_ERROR uint16 = 0x6F00

	// SW_SECURITY_STATUS indicates the security condition is not satisfied.
	SW_SECURITY_STATUS uint16 = 0x6982

	// SW_CONDITIONS_NOT_SATISFIED indicates the conditions of use are not satisfied.
	SW_CONDITIONS_NOT_SATISFIED uint16 = 0x6985

	// SW_WRONG_P1P2 indicates incorrect parameters P1-P2.
	SW_WRONG_P1P2 uint16 = 0x6A86
)

// ISO 7816-4 instruction bytes.
const (
	// INS_SELECT selects an application or file (0xA4).
	INS_SELECT byte = 0xA4

	// INS_VERIFY performs PIN verification (0x20).
	INS_VERIFY byte = 0x20

	// INS_PSO performs a security operation: sign, verify, encrypt,
	// or decrypt (0x2A).
	INS_PSO byte = 0x2A

	// INS_READ_BINARY reads binary data from a selected file (0xB0).
	INS_READ_BINARY byte = 0xB0

	// INS_GENERATE_ASYMMETRIC generates an asymmetric key pair (0x47).
	INS_GENERATE_ASYMMETRIC byte = 0x47

	// INS_GET_DATA retrieves a data object (0xCA).
	INS_GET_DATA byte = 0xCA

	// INS_PUT_DATA stores a data object (0xDA).
	INS_PUT_DATA byte = 0xDA

	// INS_GET_RESPONSE retrieves pending response data (0xC0).
	INS_GET_RESPONSE byte = 0xC0
)

// PSO sub-instructions encoded in P1/P2.
const (
	// PSO_SIGN: P1=0x9E, P2=0x9A (Compute Digital Signature).
	PSO_SIGN_P1 byte = 0x9E
	PSO_SIGN_P2 byte = 0x9A

	// PSO_VERIFY: P1=0x00, P2=0xA8 (Verify Digital Signature).
	PSO_VERIFY_P1 byte = 0x00
	PSO_VERIFY_P2 byte = 0xA8

	// PSO_ENCIPHER: P1=0x86, P2=0x80 (Encipher).
	PSO_ENCIPHER_P1 byte = 0x86
	PSO_ENCIPHER_P2 byte = 0x80

	// PSO_DECIPHER: P1=0x80, P2=0x86 (Decipher).
	PSO_DECIPHER_P1 byte = 0x80
	PSO_DECIPHER_P2 byte = 0x86
)

// Maximum APDU sizes.
const (
	// MaxAPDUDataLength is the maximum data field length for a
	// short-form APDU (256 bytes for Le=0).
	MaxAPDUDataLength = 65535

	// MinAPDULength is the minimum APDU length (CLA + INS + P1 + P2).
	MinAPDULength = 4
)

// CommandAPDU represents an ISO 7816-4 command APDU.
type CommandAPDU struct {
	// CLA is the class byte.
	CLA byte

	// INS is the instruction byte.
	INS byte

	// P1 is parameter 1.
	P1 byte

	// P2 is parameter 2.
	P2 byte

	// Data is the command data field (optional).
	Data []byte

	// Le is the expected response length.
	// -1 means Le is not present.
	// 0 means expect up to 256 bytes.
	Le int
}

// ResponseAPDU represents an ISO 7816-4 response APDU.
type ResponseAPDU struct {
	// Data is the response data field (optional).
	Data []byte

	// SW1 is status word byte 1.
	SW1 byte

	// SW2 is status word byte 2.
	SW2 byte
}

// StatusWord returns the combined 16-bit status word.
func (r *ResponseAPDU) StatusWord() uint16 {
	return uint16(r.SW1)<<8 | uint16(r.SW2)
}

// IsSuccess returns true if the status word indicates success (0x9000).
func (r *ResponseAPDU) IsSuccess() bool {
	return r.StatusWord() == SW_SUCCESS
}

// Serialize encodes the ResponseAPDU into its wire format.
// The format is: [Data...] [SW1] [SW2].
func (r *ResponseAPDU) Serialize() []byte {
	result := make([]byte, 0, len(r.Data)+2)
	result = append(result, r.Data...)
	result = append(result, r.SW1, r.SW2)
	return result
}

// NewSuccessResponse creates a ResponseAPDU with status 0x9000 and
// optional response data.
func NewSuccessResponse(data []byte) *ResponseAPDU {
	return &ResponseAPDU{
		Data: data,
		SW1:  byte(SW_SUCCESS >> 8),
		SW2:  byte(SW_SUCCESS & 0xFF),
	}
}

// NewErrorResponse creates a ResponseAPDU with the given status word
// and no data.
func NewErrorResponse(sw uint16) *ResponseAPDU {
	return &ResponseAPDU{
		SW1: byte(sw >> 8),
		SW2: byte(sw & 0xFF),
	}
}

// ParseCommandAPDU parses raw bytes into a CommandAPDU.
//
// ISO 7816-4 APDU encoding:
//
//	Case 1: [CLA INS P1 P2]                         (no data, no Le)
//	Case 2: [CLA INS P1 P2 Le]                      (no data, Le present)
//	Case 3: [CLA INS P1 P2 Lc Data...]              (data, no Le)
//	Case 4: [CLA INS P1 P2 Lc Data... Le]           (data and Le)
//
// Extended length APDUs (3-byte Lc/Le) are also supported when
// the first length byte is 0x00 and the total length supports it.
func ParseCommandAPDU(data []byte) (*CommandAPDU, error) {
	if len(data) < MinAPDULength {
		return nil, ErrAPDUMalformed
	}

	if len(data) > MaxAPDUDataLength+MinAPDULength+3 {
		return nil, ErrAPDUTooLong
	}

	cmd := &CommandAPDU{
		CLA: data[0],
		INS: data[1],
		P1:  data[2],
		P2:  data[3],
		Le:  -1, // Not present by default
	}

	remaining := data[4:]

	// Case 1: No body at all.
	if len(remaining) == 0 {
		return cmd, nil
	}

	// Case 2: Le only (single byte).
	if len(remaining) == 1 {
		le := int(remaining[0])
		if le == 0 {
			le = 256 // Le=0 means "up to 256"
		}
		cmd.Le = le
		return cmd, nil
	}

	// Extended length: first byte is 0x00 and there are at least 3 bytes.
	if remaining[0] == 0x00 && len(remaining) >= 3 {
		return parseExtendedAPDU(cmd, remaining)
	}

	// Short form: Lc followed by data and optional Le.
	return parseShortAPDU(cmd, remaining)
}

// parseShortAPDU handles standard short-form APDU parsing.
//
// This function is called from ParseCommandAPDU when len(remaining) >= 2
// and either remaining[0] != 0x00 or len(remaining) < 3.
func parseShortAPDU(cmd *CommandAPDU, remaining []byte) (*CommandAPDU, error) {
	lc := int(remaining[0])
	remaining = remaining[1:]

	if lc == 0 {
		// Lc=0 with one remaining byte: treat as Le.
		// Note: The lc==0 && len(remaining)==0 case is unreachable here because
		// ParseCommandAPDU handles single-byte remaining as Case 2 before
		// calling parseShortAPDU. Similarly, lc==0 && len(remaining)>1 is
		// unreachable because remaining[0]==0x00 with len>=3 routes to
		// parseExtendedAPDU, leaving only the len==2 case (lc byte consumed,
		// one remaining = Le byte).
		le := int(remaining[0])
		if le == 0 {
			le = 256
		}
		cmd.Le = le
		return cmd, nil
	}

	// Case 3/4: Lc bytes of data.
	if len(remaining) < lc {
		return nil, ErrAPDUMalformed
	}

	cmd.Data = make([]byte, lc)
	copy(cmd.Data, remaining[:lc])
	remaining = remaining[lc:]

	// Case 3: no Le.
	if len(remaining) == 0 {
		return cmd, nil
	}

	// Case 4: Le byte.
	if len(remaining) == 1 {
		le := int(remaining[0])
		if le == 0 {
			le = 256
		}
		cmd.Le = le
		return cmd, nil
	}

	// Extended Le (2 bytes) following short Lc data.
	if len(remaining) == 2 {
		le := int(remaining[0])<<8 | int(remaining[1])
		if le == 0 {
			le = 65536
		}
		cmd.Le = le
		return cmd, nil
	}

	return nil, ErrAPDUMalformed
}

// parseExtendedAPDU handles extended length APDU parsing.
//
// This function is called from ParseCommandAPDU when remaining[0]==0x00
// and len(remaining) >= 3, so len(remaining) is always >= 3 on entry.
func parseExtendedAPDU(cmd *CommandAPDU, remaining []byte) (*CommandAPDU, error) {
	// Extended Le only: [0x00 Le1 Le2].
	if len(remaining) == 3 {
		le := int(remaining[1])<<8 | int(remaining[2])
		if le == 0 {
			le = 65536
		}
		cmd.Le = le
		return cmd, nil
	}

	// Extended Lc + data: [0x00 Lc1 Lc2 Data... (Le1 Le2)?].
	lc := int(remaining[1])<<8 | int(remaining[2])
	remaining = remaining[3:]

	if lc == 0 {
		return nil, ErrAPDUMalformed
	}

	if len(remaining) < lc {
		return nil, ErrAPDUMalformed
	}

	cmd.Data = make([]byte, lc)
	copy(cmd.Data, remaining[:lc])
	remaining = remaining[lc:]

	if len(remaining) == 0 {
		return cmd, nil
	}

	// Extended Le.
	if len(remaining) == 2 {
		le := int(remaining[0])<<8 | int(remaining[1])
		if le == 0 {
			le = 65536
		}
		cmd.Le = le
		return cmd, nil
	}

	return nil, ErrAPDUMalformed
}

// Serialize encodes the CommandAPDU into its wire format.
//
// Short form is used when data length fits in a single byte (<=255).
// Extended form is used for larger payloads.
func (c *CommandAPDU) Serialize() []byte {
	// Pre-calculate size.
	size := 4 // CLA INS P1 P2
	hasData := len(c.Data) > 0
	hasLe := c.Le >= 0
	extended := len(c.Data) > 255 || c.Le > 256

	if extended {
		if hasData {
			size += 3 + len(c.Data) // 0x00 + 2-byte Lc + data
		}
		if hasLe {
			if !hasData {
				size += 1 // 0x00 prefix
			}
			size += 2 // 2-byte Le
		}
	} else {
		if hasData {
			size += 1 + len(c.Data) // 1-byte Lc + data
		}
		if hasLe {
			size += 1 // 1-byte Le
		}
	}

	buf := make([]byte, 0, size)
	buf = append(buf, c.CLA, c.INS, c.P1, c.P2)

	if extended {
		if hasData {
			buf = append(buf, 0x00)
			buf = append(buf, byte(len(c.Data)>>8), byte(len(c.Data)&0xFF))
			buf = append(buf, c.Data...)
		}
		if hasLe {
			if !hasData {
				buf = append(buf, 0x00) // Extended Le prefix
			}
			le := c.Le
			if le == 65536 {
				le = 0
			}
			buf = append(buf, byte(le>>8), byte(le&0xFF))
		}
	} else {
		if hasData {
			buf = append(buf, byte(len(c.Data)))
			buf = append(buf, c.Data...)
		}
		if hasLe {
			le := c.Le
			if le == 256 {
				le = 0
			}
			buf = append(buf, byte(le))
		}
	}

	return buf
}
