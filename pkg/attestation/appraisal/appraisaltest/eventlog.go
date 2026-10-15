// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package attestationtest

import (
	"crypto/sha256"
	"encoding/binary"
)

// TCG PC Client event types and the Spec ID header a crypto-agile log
// starts with (TCG PC Client Platform Firmware Profile, section 10).
const (
	evNoAction   uint32 = 0x00000003
	evPostCode   uint32 = 0x00000001
	algSHA256    uint16 = 0x000B
	specIDHeader        = "Spec ID Event03\x00"
)

// LogEvent is one measurement a boot event log records: Digest is the
// SHA-256 digest the firmware extended into PCR.
type LogEvent struct {
	PCR    uint32
	Digest []byte
}

// BootEventLog builds a TCG PC Client crypto-agile event log with a SHA-256
// bank, recording events in order, as firmware does. It returns the log and
// the SHA-256 PCR values replaying it produces, for the registers it touches.
func BootEventLog(events []LogEvent) ([]byte, map[uint32][]byte) {
	var log []byte

	// The Spec ID header is a SHA-1 format TCG_PCClientPCREvent.
	spec := []byte(specIDHeader)
	spec = binary.LittleEndian.AppendUint32(spec, 0) // platform class
	spec = append(spec, 0, 2, 0, 2)                  // spec 2.0 errata 0, UINTN size 2
	spec = binary.LittleEndian.AppendUint32(spec, 1) // one algorithm
	spec = binary.LittleEndian.AppendUint16(spec, algSHA256)
	spec = binary.LittleEndian.AppendUint16(spec, sha256.Size)
	spec = append(spec, 0) // no vendor info
	log = binary.LittleEndian.AppendUint32(log, 0)
	log = binary.LittleEndian.AppendUint32(log, evNoAction)
	log = append(log, make([]byte, 20)...)
	log = binary.LittleEndian.AppendUint32(log, uint32(len(spec))) // #nosec G115 -- a fixed-size header
	log = append(log, spec...)

	pcrs := make(map[uint32][]byte)
	for _, ev := range events {
		data := []byte("boot component")
		log = binary.LittleEndian.AppendUint32(log, ev.PCR)
		log = binary.LittleEndian.AppendUint32(log, evPostCode)
		log = binary.LittleEndian.AppendUint32(log, 1) // one digest
		log = binary.LittleEndian.AppendUint16(log, algSHA256)
		log = append(log, ev.Digest...)
		log = binary.LittleEndian.AppendUint32(log, uint32(len(data))) // #nosec G115 -- a fixed-size event
		log = append(log, data...)

		current, ok := pcrs[ev.PCR]
		if !ok {
			current = make([]byte, sha256.Size)
		}
		pcrs[ev.PCR] = ExtendSHA256(current, ev.Digest)
	}
	return log, pcrs
}

// ExtendSHA256 returns the SHA-256 PCR value after extending digest into
// current, as TPM2_PCR_Extend computes it.
func ExtendSHA256(current, digest []byte) []byte {
	h := sha256.New()
	h.Write(current)
	h.Write(digest)
	return h.Sum(nil)
}
