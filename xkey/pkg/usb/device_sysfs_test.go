package usb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeBlockDevice describes one entry of a fabricated /sys/block tree.
type fakeBlockDevice struct {
	name      string
	removable string // contents of the removable attribute; "" omits the file
	bus       string // directory the device link resolves into; "" omits the link
	model     string
	vendor    string
	sectors   string
}

// useFakeSysfs builds a /sys/block tree under a temp dir and points
// sysBlockDir at it for the duration of the test.
func useFakeSysfs(t *testing.T, devices ...fakeBlockDevice) string {
	t.Helper()
	root := t.TempDir()
	block := filepath.Join(root, "block")
	for _, d := range devices {
		dir := filepath.Join(block, d.name)
		writeSysFile(t, dir, "removable", d.removable)
		writeSysFile(t, dir, "size", d.sectors)
		if d.bus == "" {
			continue
		}
		target := filepath.Join(root, "devices", d.bus, d.name)
		writeSysFile(t, target, "model", d.model)
		writeSysFile(t, target, "vendor", d.vendor)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(block, 0o755); err != nil {
		t.Fatal(err)
	}

	orig := sysBlockDir
	sysBlockDir = block
	t.Cleanup(func() { sysBlockDir = orig })
	return block
}

func writeSysFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if content == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectUSBDevices_ListsOnlyRemovableUSBDisks(t *testing.T) {
	useFakeSysfs(t,
		fakeBlockDevice{name: "sdb", removable: "1", bus: "pci0000:00/usb1/1-1", model: "Flash Disk", vendor: "Kingston", sectors: "2048"},
		fakeBlockDevice{name: "sda", removable: "0", bus: "pci0000:00/usb1/1-2", sectors: "4096"},
		fakeBlockDevice{name: "sdc", removable: "1", bus: "pci0000:00/ata1/host0", sectors: "4096"},
		fakeBlockDevice{name: "sdd", removable: "1", sectors: "4096"},
		fakeBlockDevice{name: "loop0"},
	)

	devices, err := DetectUSBDevices()
	if err != nil {
		t.Fatalf("DetectUSBDevices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("found %d devices, want only the removable USB disk: %+v", len(devices), devices)
	}
	want := USBDevice{Path: "/dev/sdb", Model: "Flash Disk", Vendor: "Kingston", Size: 2048 * 512}
	if devices[0] != want {
		t.Errorf("device = %+v, want %+v", devices[0], want)
	}
}

func TestDetectUSBDevices_UnreadableAttributesAreEmpty(t *testing.T) {
	useFakeSysfs(t,
		fakeBlockDevice{name: "sde", removable: "1", bus: "usb2/2-1", sectors: "not-a-number"},
	)

	devices, err := DetectUSBDevices()
	if err != nil {
		t.Fatalf("DetectUSBDevices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("found %d devices, want 1", len(devices))
	}
	if d := devices[0]; d.Model != "" || d.Vendor != "" || d.Size != 0 {
		t.Errorf("missing model/vendor and a malformed size must read as empty, got %+v", d)
	}
}

func TestDetectUSBDevices_NoSysfsIsAScanError(t *testing.T) {
	orig := sysBlockDir
	sysBlockDir = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { sysBlockDir = orig })

	_, err := DetectUSBDevices()
	var usbErr *USBError
	if !errors.As(err, &usbErr) {
		t.Fatalf("error = %v, want *USBError", err)
	}
	if usbErr.Operation != "scan_devices" || usbErr.Path != sysBlockDir {
		t.Errorf("USBError = %+v, want scan_devices on %s", usbErr, sysBlockDir)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v does not wrap os.ErrNotExist", err)
	}
}

// A block device's size comes from sysfs (sectors × 512), not from stat,
// which reports zero for a device node.
func TestBlockDeviceSize_ReadsSysfsSectors(t *testing.T) {
	useFakeSysfs(t, fakeBlockDevice{name: "sdf", sectors: "8"})

	size, err := BlockDeviceSize("/dev/sdf")
	if err != nil {
		t.Fatalf("BlockDeviceSize: %v", err)
	}
	if size != 8*512 {
		t.Errorf("size = %d, want %d", size, 8*512)
	}
}
