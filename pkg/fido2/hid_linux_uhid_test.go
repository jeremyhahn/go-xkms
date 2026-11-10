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

//go:build linux

package fido2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/uhid"
	"github.com/stretchr/testify/require"
)

// uhidRoundTripTimeout bounds every wait in the UHID round trip, so a framing
// fault fails the test instead of hanging it.
const uhidRoundTripTimeout = 2 * time.Second

// TestLinuxHIDDevice_UHIDRoundTrip drives LinuxHIDDevice through a real hidraw
// node backed by a kernel UHID device (#2052). It proves that Write hands the
// kernel the report ID byte followed by the whole 64-byte frame, also when the
// frame's CID starts with 0x00, and that Read returns the 64-byte input report
// unchanged. It skips when /dev/uhid cannot be opened.
func TestLinuxHIDDevice_UHIDRoundTrip(t *testing.T) {
	kernel, err := uhid.Open()
	if err != nil {
		t.Skipf("skipped: %s cannot be opened: %v", uhid.UHIDDevicePath, err)
	}
	t.Cleanup(func() { _ = kernel.Close() })

	cfg := uhid.DefaultCreateConfig()
	cfg.Uniq = fmt.Sprintf("hid2052-%d", os.Getpid())
	require.NoError(t, kernel.Create(cfg))

	path := findUHIDHidrawNode(t, cfg.Uniq)
	opened, err := NewLinuxHIDDeviceEnumerator().Open(path)
	require.NoError(t, err)
	dev := opened.(*LinuxHIDDevice)
	t.Cleanup(func() { _ = dev.Close() })

	initFrame := func(cid uint32) []byte {
		frame := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(frame[0:4], cid)
		frame[4] = CTAPHID_INIT
		binary.BigEndian.PutUint16(frame[5:7], 8)
		copy(frame[7:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
		return frame
	}

	for _, cid := range []uint32{0x00112233, 0xFFFFFFFF} {
		t.Run(fmt.Sprintf("write CID %08X", cid), func(t *testing.T) {
			frame := initFrame(cid)
			n, err := dev.Write(frame)
			require.NoError(t, err)
			require.Equal(t, HIDPacketSize, n)

			// The raw UHID_OUTPUT payload is read, not uhid.ReadOutput,
			// because ReadOutput drops a leading report ID and so would
			// hide a missing one.
			raw := readRawUHIDOutput(t, kernel)
			require.Len(t, raw, HIDPacketSize+1, "the kernel must get the report ID and the whole frame")
			require.Equal(t, hidrawUnnumberedReportID, raw[0], "first byte must be the report ID")
			require.Equal(t, frame, raw[1:], "the frame must follow the report ID unchanged")
		})
	}

	t.Run("read frame starting with 0x00", func(t *testing.T) {
		frame := initFrame(0x00112233)
		require.NoError(t, kernel.WriteInput(frame))

		type result struct {
			data []byte
			err  error
		}
		done := make(chan result, 1)
		go func() {
			buf := make([]byte, HIDPacketSize+1)
			n, err := dev.Read(buf)
			done <- result{data: buf[:max(n, 0)], err: err}
		}()
		select {
		case r := <-done:
			require.NoError(t, r.err)
			require.Equal(t, frame, r.data, "Read must return the 64-byte input report unchanged")
		case <-time.After(uhidRoundTripTimeout):
			t.Fatalf("Read returned nothing within %s", uhidRoundTripTimeout)
		}
	})
}

// findUHIDHidrawNode returns the /dev/hidrawN node whose HID device carries
// uniq, retrying for at most uhidRoundTripTimeout while the kernel creates it.
func findUHIDHidrawNode(t *testing.T, uniq string) string {
	t.Helper()
	want := "HID_UNIQ=" + uniq
	deadline := time.Now().Add(uhidRoundTripTimeout)
	for {
		entries, _ := os.ReadDir(hidrawClassDir)
		for _, entry := range entries {
			uevent, err := os.ReadFile(filepath.Join(hidrawClassDir, entry.Name(), "device", "uevent"))
			if err != nil || !strings.Contains(string(uevent), want) {
				continue
			}
			node := filepath.Join(devDir, entry.Name())
			if _, err := os.Stat(node); err == nil {
				return node
			}
			if time.Now().After(deadline) {
				t.Skipf("skipped: %s exists in sysfs but %s was not created", entry.Name(), node)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no hidraw node for UHID device %q within %s", uniq, uhidRoundTripTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// readRawUHIDOutput returns the payload of the next UHID_OUTPUT event exactly
// as the kernel sized it, skipping other events, within uhidRoundTripTimeout.
func readRawUHIDOutput(t *testing.T, kernel *uhid.Device) []byte {
	t.Helper()
	const sizeOffset = 4 + uhid.MaxReportDescriptorSize
	buf := make([]byte, sizeOffset+3)
	deadline := time.Now().Add(uhidRoundTripTimeout)
	for time.Now().Before(deadline) {
		n, err := syscall.Read(kernel.Fd(), buf)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		require.NoError(t, err)
		if n < 4 || binary.LittleEndian.Uint32(buf[0:4]) != uhid.UHID_OUTPUT {
			continue
		}
		require.GreaterOrEqual(t, n, sizeOffset+2, "short UHID_OUTPUT event")
		size := int(binary.LittleEndian.Uint16(buf[sizeOffset : sizeOffset+2]))
		require.LessOrEqual(t, size, uhid.MaxReportDescriptorSize)
		return append([]byte(nil), buf[4:4+size]...)
	}
	t.Fatalf("no UHID_OUTPUT event within %s", uhidRoundTripTimeout)
	return nil
}
