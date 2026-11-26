//go:build integration && linux

// Package fido2hidraw proves, against a kernel UHID device, that the hidraw
// transport of pkg/fido2 frames CTAPHID packets as the kernel expects: every
// write is an unnumbered output report (report ID 0x00 followed by the
// packet) and reads return the input report unchanged.
package fido2hidraw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/fido2/uhid"
)

const (
	// uhidDataMax is UHID_DATA_MAX from linux/uhid.h.
	uhidDataMax = 4096
	// uhidOutputEventSize covers the type and struct uhid_output_req
	// (data[UHID_DATA_MAX], __u16 size, __u8 rtype).
	uhidOutputEventSize = 4 + uhidDataMax + 2 + 1
	ctaphidPacketSize   = 64
	hidrawClassDir      = "/sys/class/hidraw"
	waitTimeout         = 5 * time.Second
)

// TestHidrawWriteCarriesReportIDZero writes a CTAPHID packet through
// LinuxHIDDevice to a UHID device and checks the UHID_OUTPUT event carries a
// 65-byte report: report ID 0x00 followed by the 64-byte packet. It then
// injects an input report and checks LinuxHIDDevice.Read returns it as is.
func TestHidrawWriteCarriesReportIDZero(t *testing.T) {
	dev, err := uhid.Open()
	if err != nil {
		t.Fatalf("open /dev/uhid (root and the uhid module are required): %v", err)
	}
	defer dev.Close()

	uniq := fmt.Sprintf("HIDRAW%d", time.Now().UnixNano()%1_000_000_000)
	cfg := uhid.DefaultCreateConfig()
	cfg.Name = "xkms hidraw report id " + uniq
	cfg.Uniq = uniq
	if err := dev.Create(cfg); err != nil {
		t.Fatalf("create UHID device: %v", err)
	}

	node := findHidrawNode(t, uniq)
	path := hidrawDevPath(t, node)

	hid, err := fido2.NewLinuxHIDDeviceEnumerator().Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer hid.Close()

	cid := []byte{0x00, 0x11, 0x22, 0x33}

	// Write: a CTAPHID_INIT packet must reach the device with report ID 0x00.
	packet := make([]byte, ctaphidPacketSize)
	copy(packet, cid)
	packet[4] = 0x86 // CTAPHID_INIT
	packet[6] = 8    // BCNT low byte: 8-byte nonce
	for i := 0; i < 8; i++ {
		packet[7+i] = byte(0xA0 + i)
	}
	n, err := hid.Write(packet)
	if err != nil {
		t.Fatalf("hidraw write: %v", err)
	}
	if n != ctaphidPacketSize {
		t.Fatalf("hidraw write returned %d, want %d", n, ctaphidPacketSize)
	}

	ev := readOutputEvent(t, dev.Fd())
	size := binary.LittleEndian.Uint16(ev[4+uhidDataMax : 4+uhidDataMax+2])
	if size != ctaphidPacketSize+1 {
		t.Fatalf("UHID_OUTPUT size = %d, want %d (report ID 0x00 + %d-byte packet)",
			size, ctaphidPacketSize+1, ctaphidPacketSize)
	}
	if ev[4] != 0x00 {
		t.Fatalf("UHID_OUTPUT report ID = 0x%02x, want 0x00", ev[4])
	}
	if got := ev[5 : 5+ctaphidPacketSize]; !bytes.Equal(got, packet) {
		t.Fatalf("UHID_OUTPUT report data = %x, want %x", got, packet)
	}

	// Read: an input report comes back unchanged, with no report-ID byte.
	response := make([]byte, ctaphidPacketSize)
	copy(response, cid)
	response[4] = 0x86
	response[6] = 17
	for i := 7; i < ctaphidPacketSize; i++ {
		response[i] = byte(i)
	}
	if err := dev.WriteInput(response); err != nil {
		t.Fatalf("UHID WriteInput: %v", err)
	}

	type readResult struct {
		buf []byte
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, ctaphidPacketSize)
		n, err := hid.Read(buf)
		done <- readResult{buf: buf, n: n, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("hidraw read: %v", r.err)
		}
		if r.n != ctaphidPacketSize {
			t.Fatalf("hidraw read returned %d bytes, want %d", r.n, ctaphidPacketSize)
		}
		if !bytes.Equal(r.buf, response) {
			t.Fatalf("hidraw read = %x, want %x", r.buf, response)
		}
	case <-time.After(waitTimeout):
		t.Fatalf("hidraw read did not return within %s", waitTimeout)
	}
}

// findHidrawNode polls sysfs for the hidraw node whose HID device carries
// the given HID_UNIQ and returns its name (hidrawN).
func findHidrawNode(t *testing.T, uniq string) string {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(hidrawClassDir)
		for _, e := range entries {
			uevent, err := os.ReadFile(filepath.Join(hidrawClassDir, e.Name(), "device", "uevent"))
			if err != nil {
				continue
			}
			if ueventMatchesUniq(string(uevent), uniq) {
				return e.Name()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no hidraw node with HID_UNIQ=%s under %s within %s", uniq, hidrawClassDir, waitTimeout)
	return ""
}

// hidrawDevPath returns /dev/<node> when it exists, else a character device
// node created in a temp dir from the sysfs major:minor. The base name stays
// <node> so LinuxHIDDeviceEnumerator.Open finds the sysfs entry.
func hidrawDevPath(t *testing.T, node string) string {
	t.Helper()
	devPath := filepath.Join("/dev", node)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(devPath); err == nil {
			return devPath
		}
		time.Sleep(50 * time.Millisecond)
	}

	raw, err := os.ReadFile(filepath.Join(hidrawClassDir, node, "dev"))
	if err != nil {
		t.Fatalf("read major:minor of %s: %v", node, err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed %s/dev: %q", node, raw)
	}
	major, err1 := strconv.ParseUint(parts[0], 10, 32)
	minor, err2 := strconv.ParseUint(parts[1], 10, 32)
	if err1 != nil || err2 != nil {
		t.Fatalf("malformed %s/dev: %q", node, raw)
	}
	path := filepath.Join(t.TempDir(), node)
	rdev := int((major << 8) | (minor & 0xff) | ((minor &^ 0xff) << 12))
	if err := syscall.Mknod(path, syscall.S_IFCHR|0o600, rdev); err != nil {
		t.Fatalf("mknod %s (%d:%d): %v", path, major, minor, err)
	}
	return path
}

// readOutputEvent reads raw UHID events from fd until a UHID_OUTPUT event
// arrives, skipping lifecycle events (START, OPEN, STOP, CLOSE and others).
func readOutputEvent(t *testing.T, fd int) []byte {
	t.Helper()
	type result struct {
		ev  []byte
		err error
	}
	done := make(chan result, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			buf := make([]byte, uhidOutputEventSize)
			n, err := syscall.Read(fd, buf)
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if err != nil {
				done <- result{err: err}
				return
			}
			if n < 4 {
				continue
			}
			if binary.LittleEndian.Uint32(buf[0:4]) != uhid.UHID_OUTPUT {
				continue
			}
			if n < uhidOutputEventSize-1 {
				done <- result{err: fmt.Errorf("short UHID_OUTPUT event: %d bytes", n)}
				return
			}
			done <- result{ev: buf}
			return
		}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read UHID event: %v", r.err)
		}
		return r.ev
	case <-time.After(waitTimeout):
		t.Fatalf("no UHID_OUTPUT event within %s", waitTimeout)
		return nil
	}
}
