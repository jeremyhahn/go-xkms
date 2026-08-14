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

package uhid

import (
	"encoding/binary"
	"fmt"
)

// This file holds the UHID wire-format codec. It is deliberately untagged:
// packing a uhid_event is pure byte manipulation with no OS dependency, so it
// compiles and behaves identically on every platform. The Linux device
// implementation (uhid_linux.go) writes exactly these buffers to /dev/uhid,
// which means the cross-platform tests here cover the production encoding
// rather than a parallel test-only copy.

// SerializeCreate2Request serializes a CreateConfig into a UHID_CREATE2
// request buffer, ready to be written to /dev/uhid.
//
// Layout (Linux uhid_event with a uhid_create2_req payload, little endian):
//
//	0..4     __u32 type = UHID_CREATE2
//	4..132   __u8  name[128]
//	132..196 __u8  phys[64]
//	196..260 __u8  uniq[64]
//	260..262 __u16 rd_size
//	262..264 __u16 bus
//	264..268 __u32 vendor
//	268..272 __u32 product
//	272..276 __u32 version
//	276..280 __u32 country
//	280..    __u8  rd_data[HID_MAX_DESCRIPTOR_SIZE]
//
// A nil cfg selects DefaultCreateConfig. Over-long name/phys/uniq strings and
// an over-long report descriptor are truncated to the sizes the kernel
// structure allows.
func SerializeCreate2Request(cfg *CreateConfig) []byte {
	if cfg == nil {
		cfg = DefaultCreateConfig()
	}

	buf := make([]byte, uhidEventHeaderSize+uhidCreate2ReqSize)

	binary.LittleEndian.PutUint32(buf[0:4], UHID_CREATE2)

	offset := uhidEventHeaderSize
	offset += copyPadded(buf[offset:offset+128], cfg.Name, 127)
	offset += copyPadded(buf[offset:offset+64], cfg.Phys, 63)
	offset += copyPadded(buf[offset:offset+64], cfg.Uniq, 63)

	rdesc := cfg.ReportDescriptor
	if rdesc == nil {
		rdesc = FIDO2HIDReportDescriptor
	}
	if len(rdesc) > MaxReportDescriptorSize {
		rdesc = rdesc[:MaxReportDescriptorSize]
	}

	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(rdesc)))
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:offset+2], BUS_USB)
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.VendorID))
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.ProductID))
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.Version))
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0) // country
	offset += 4

	copy(buf[offset:], rdesc)

	return buf
}

// copyPadded writes up to max bytes of s into field (which is already zeroed,
// so the remainder acts as the NUL terminator and padding) and reports the
// number of bytes the field occupies.
func copyPadded(field []byte, s string, max int) int {
	b := []byte(s)
	if len(b) > max {
		b = b[:max]
	}
	copy(field, b)
	return len(field)
}

// SerializeInput2Request serializes a HID input report into a UHID_INPUT2
// request buffer (device → host).
//
// Layout (little endian):
//
//	0..4    __u32 type = UHID_INPUT2
//	4..6    __u16 size
//	6..     __u8  data[HID_MAX_DESCRIPTOR_SIZE]
//
// Data longer than MaxReportDescriptorSize is truncated so the returned buffer
// always matches the kernel structure; callers that must reject over-long
// reports (Device.WriteInput does) validate before calling.
func SerializeInput2Request(data []byte) []byte {
	if len(data) > MaxReportDescriptorSize {
		data = data[:MaxReportDescriptorSize]
	}

	buf := make([]byte, uhidEventHeaderSize+uhidInput2ReqSize)

	binary.LittleEndian.PutUint32(buf[0:4], UHID_INPUT2)
	binary.LittleEndian.PutUint16(buf[uhidEventHeaderSize:uhidEventHeaderSize+2], uint16(len(data)))
	copy(buf[uhidEventHeaderSize+2:], data)

	return buf
}

// ParseOutputEvent parses a raw UHID_OUTPUT event buffer and returns the HID
// report the host sent.
//
// Layout of the packed uhid_output_req payload (little endian):
//
//	0..4      __u32 type = UHID_OUTPUT
//	4..4100   __u8  data[HID_MAX_DESCRIPTOR_SIZE] — data comes FIRST
//	4100..4102 __u16 size — the significant length of data
//	4102       __u8  rtype — report type
//
// When the HID report descriptor defines no explicit report IDs the kernel
// prepends a report-ID byte to the data. For FIDO2 HID that means 65 bytes
// (1 report ID + a 64-byte packet), so the report ID is stripped and the raw
// 64-byte packet is returned.
func ParseOutputEvent(buf []byte) ([]byte, error) {
	if len(buf) < uhidEventHeaderSize {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: ": buffer too short"}
	}

	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_OUTPUT {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: fmt.Sprintf(": not an output event (type=%d)", eventType)}
	}

	// Need the header + data[4096] + size[2] before size can be read.
	minLen := uhidEventHeaderSize + MaxReportDescriptorSize + 2
	if len(buf) < minLen {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: fmt.Sprintf(": output event too short (%d, need %d)", len(buf), minLen)}
	}

	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	dataSize := binary.LittleEndian.Uint16(buf[sizeOffset : sizeOffset+2])
	if dataSize > MaxReportDescriptorSize {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: fmt.Sprintf(": data size too large (%d)", dataSize)}
	}
	if dataSize == 0 {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: ": zero data size"}
	}

	dataStart := uhidEventHeaderSize
	actualSize := int(dataSize)
	if dataSize == HIDReportSize+1 {
		dataStart++ // skip the kernel-prepended report ID
		actualSize = HIDReportSize
	}

	data := make([]byte, actualSize)
	copy(data, buf[dataStart:dataStart+actualSize])
	return data, nil
}
