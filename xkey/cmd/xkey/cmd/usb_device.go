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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ccid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gadget"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

// USB device command errors.
var (
	// ErrUSBDeviceStartFailed indicates the virtual USB device could not be started.
	ErrUSBDeviceStartFailed = errors.New("usb device: start failed")

	// ErrUSBDeviceCCIDCreateFailed indicates the CCID device could not be created.
	ErrUSBDeviceCCIDCreateFailed = errors.New("usb device: CCID device creation failed")

	// ErrUSBDeviceBridgeCreateFailed indicates the PKCS#11 bridge could not be created.
	ErrUSBDeviceBridgeCreateFailed = errors.New("usb device: PKCS#11 bridge creation failed")

	// ErrUSBDeviceTransportCreateFailed indicates the PKCS#11 transport could not be created.
	ErrUSBDeviceTransportCreateFailed = errors.New("usb device: PKCS#11 transport creation failed")
)

// Default USB device configuration values.
const (
	defaultUSBDeviceBackend   = "software"
	defaultUSBDeviceTransport = "uhid"
)

// usbDeviceCmd is the parent command for virtual USB device operations.
var usbDeviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Virtual USB device management",
	Long: `Create and manage virtual USB devices using Linux UHID.

xKey can present itself as a virtual USB composite device that appears
to the operating system as a CCID (Chip Card Interface Device) smartcard
reader with an inserted card. CCID messages are translated to PKCS#11
operations through the xKey backend.

Two transport modes are available:
  - uhid:   Software HID emulation via /dev/uhid (default, any Linux)
  - gadget: Real USB device via ConfigFS/FunctionFS (OTG hardware required)

In gadget mode, the device presents true USB CCID class (0x0B) and HID
interfaces. Any OS (Linux, macOS, Windows) auto-detects the device
without custom drivers.

This enables:
  - VM passthrough of xKey as a smartcard reader
  - PIV and OpenPGP applet emulation
  - Integration with smartcard-aware applications (OpenSC, GPG, etc.)
  - Cross-platform smartcard login (gadget mode)

Requirements:
  - uhid mode:   Linux kernel with UHID support (CONFIG_UHID)
  - gadget mode: OTG-capable hardware (Raspberry Pi Zero 2W, etc.)

Commands:
  start     Start the virtual CCID smartcard device
  stop      Stop a running virtual device (via signal)
  status    Show virtual device status

Examples:
  # Start with UHID transport (default)
  sudo xkey usb device start

  # Start with USB gadget transport (OTG hardware)
  sudo xkey usb device start --transport gadget

  # Start with explicit UDC controller
  sudo xkey usb device start --transport gadget --udc dummy_udc.0

  # Show device status
  xkey usb device status`,
}

// usbDeviceStartCmd starts the virtual CCID device.
var usbDeviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the virtual CCID smartcard device",
	Long: `Start a virtual CCID smartcard device using Linux UHID.

The device creates a virtual USB HID endpoint that carries CCID
(Chip Card Interface Device) messages. ISO 7816 APDU commands
received through the CCID transport are translated to PKCS#11
operations by the built-in bridge.

The device supports:
  - PIV applet (A000000308000010000100)
  - OpenPGP applet (D27600012401)
  - PIN verification via VERIFY APDU
  - Sign, verify, encrypt, decrypt via PSO APDUs
  - Key generation via GENERATE ASYMMETRIC KEY PAIR APDU

The device runs in the foreground until interrupted with Ctrl+C
or a SIGTERM signal.

Transport modes:
  uhid    Uses /dev/uhid for software HID emulation (default)
  gadget  Uses ConfigFS/FunctionFS for real USB CCID (requires OTG hardware)

Examples:
  # Start with UHID transport (default)
  sudo xkey usb device start

  # Start with USB gadget transport
  sudo xkey usb device start --transport gadget

  # Start with USB gadget and explicit UDC
  sudo xkey usb device start --transport gadget --udc dummy_udc.0

  # Start with TPM2 backend
  sudo xkey usb device start --device-backend tpm2`,
	RunE: runUSBDeviceStart,
}

// usbDeviceStopCmd provides instructions for stopping the device.
var usbDeviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the virtual CCID smartcard device",
	Long: `Stop a running virtual CCID device.

The virtual CCID device runs in the foreground and can be stopped by:
  - Pressing Ctrl+C in the terminal where it is running
  - Sending SIGTERM: kill -TERM <pid>
  - Sending SIGINT:  kill -INT <pid>

Examples:
  # Find the running device process
  pgrep -f "xkey usb device start"

  # Stop it with SIGTERM
  kill -TERM $(pgrep -f "xkey usb device start")`,
	RunE: runUSBDeviceStop,
}

// usbDeviceStatusCmd shows the virtual device status.
var usbDeviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show virtual CCID device status",
	Long: `Display information about the virtual CCID smartcard device.

Checks whether the UHID interface is available and whether a
virtual CCID device process is currently running.

Examples:
  xkey usb device status`,
	RunE: runUSBDeviceStatus,
}

func init() {
	usbCmd.AddCommand(usbDeviceCmd)
	usbDeviceCmd.AddCommand(usbDeviceStartCmd)
	usbDeviceCmd.AddCommand(usbDeviceStopCmd)
	usbDeviceCmd.AddCommand(usbDeviceStatusCmd)

	// Start command flags.
	usbDeviceStartCmd.Flags().String("device-backend", defaultUSBDeviceBackend,
		"PKCS#11 backend: software, tpm2, or pkcs11")
	usbDeviceStartCmd.Flags().String("transport", defaultUSBDeviceTransport,
		"USB transport: uhid or gadget")
	usbDeviceStartCmd.Flags().String("udc", "",
		"UDC controller name for gadget mode (auto-detect if empty)")

	// Bind to viper for unified config.
	_ = viper.BindPFlag("usb.device.backend", usbDeviceStartCmd.Flags().Lookup("device-backend"))
	_ = viper.BindPFlag("usb.device.transport", usbDeviceStartCmd.Flags().Lookup("transport"))
	_ = viper.BindPFlag("usb.device.udc", usbDeviceStartCmd.Flags().Lookup("udc"))

	// Add to LUKS exempt list.
	luksExemptCommands["device"] = true
	luksExemptCommands["start"] = true
	luksExemptCommands["stop"] = true
}

// runUSBDeviceStart starts the virtual CCID device.
func runUSBDeviceStart(_ *cobra.Command, _ []string) error {
	logger := slog.Default()

	backend := viper.GetString("usb.device.backend")
	if backend == "" {
		backend = defaultUSBDeviceBackend
	}

	transportMode := viper.GetString("usb.device.transport")
	if transportMode == "" {
		transportMode = defaultUSBDeviceTransport
	}

	logger.Info("starting virtual CCID device",
		slog.String("backend", backend),
		slog.String("transport", transportMode),
		slog.String("device_name", ccid.CCIDDeviceName),
		slog.String("serial", ccid.CCIDDeviceSerial),
	)

	// Create PKCS#11 embedded transport.
	pkcs11Transport, err := pkcs11.NewEmbeddedTransport()
	if err != nil {
		return errors.Join(ErrUSBDeviceTransportCreateFailed, err)
	}

	// Create the PKCS#11 bridge that translates APDUs to PKCS#11 operations.
	bridge, err := ccid.NewPKCS11Bridge(pkcs11Transport, logger)
	if err != nil {
		return errors.Join(ErrUSBDeviceBridgeCreateFailed, err)
	}
	bridge.SetDefaultBackend(backend)

	// Setup signal handling for graceful shutdown.
	ctx, cancel := setupUSBDeviceSignalHandler(logger)
	defer cancel()

	switch gadget.TransportType(transportMode) {
	case gadget.TransportGadget:
		return runUSBDeviceGadget(ctx, bridge, logger)
	default:
		return runUSBDeviceUHID(ctx, bridge, logger)
	}
}

// runUSBDeviceUHID starts the CCID device using UHID software HID emulation.
func runUSBDeviceUHID(ctx context.Context, bridge *ccid.PKCS11Bridge, logger *slog.Logger) error {
	uhidDev, err := uhid.Open()
	if err != nil {
		return errors.Join(ErrUSBDeviceStartFailed, err)
	}

	cfg := &uhid.CreateConfig{
		Name:             ccid.CCIDDeviceName,
		Phys:             ccid.CCIDDevicePhys,
		Uniq:             ccid.CCIDDeviceSerial,
		VendorID:         ccid.VendorIDCCID,
		ProductID:        ccid.ProductIDCCID,
		Version:          ccid.CCIDDeviceVersion,
		ReportDescriptor: ccid.CCIDHIDReportDescriptor,
	}
	if err := uhidDev.Create(cfg); err != nil {
		_ = uhidDev.Close()
		return errors.Join(ErrUSBDeviceStartFailed, err)
	}

	usbTransport, err := gadget.NewUHIDTransport(uhidDev, logger)
	if err != nil {
		_ = uhidDev.Close()
		return errors.Join(ErrUSBDeviceStartFailed, err)
	}
	defer usbTransport.Close()

	device, err := ccid.NewCCIDDevice(bridge, usbTransport, logger)
	if err != nil {
		return errors.Join(ErrUSBDeviceCCIDCreateFailed, err)
	}

	logger.Info("virtual CCID device starting (UHID), press Ctrl+C to stop")
	return runUSBDeviceLoop(ctx, device, bridge, logger)
}

// runUSBDeviceGadget starts the CCID device using the USB Gadget API
// for real USB device emulation on OTG-capable hardware.
func runUSBDeviceGadget(ctx context.Context, bridge *ccid.PKCS11Bridge, logger *slog.Logger) error {
	udc := viper.GetString("usb.device.udc")

	config := gadget.DefaultGadgetConfig()
	config.UDC = udc
	config.Functions = []gadget.FunctionConfig{
		{Type: gadget.FunctionCCID, MountDir: "/dev/ffs-ccid"},
	}

	g, err := gadget.New(config, logger)
	if err != nil {
		return errors.Join(ErrUSBDeviceStartFailed, err)
	}

	if err := g.Start(ctx); err != nil {
		return errors.Join(ErrUSBDeviceStartFailed, err)
	}
	defer g.Stop()

	ccidTransport := g.CCIDTransport()
	if ccidTransport == nil {
		return errors.Join(ErrUSBDeviceStartFailed, gadget.ErrTransportNotReady)
	}

	device, err := ccid.NewCCIDDevice(bridge, ccidTransport, logger)
	if err != nil {
		return errors.Join(ErrUSBDeviceCCIDCreateFailed, err)
	}

	logger.Info("virtual CCID device starting (USB Gadget), press Ctrl+C to stop",
		slog.String("udc", config.UDC),
	)
	return runUSBDeviceLoop(ctx, device, bridge, logger)
}

// runUSBDeviceLoop runs the CCID device event loop until context cancellation.
func runUSBDeviceLoop(ctx context.Context, device *ccid.CCIDDevice, bridge *ccid.PKCS11Bridge, logger *slog.Logger) error {
	if err := device.Start(ctx); err != nil {
		if ctx.Err() != nil {
			logger.Info("virtual CCID device stopped due to shutdown signal")
		} else {
			logger.Error("virtual CCID device error",
				slog.Any("error", err),
			)
			return errors.Join(ErrUSBDeviceStartFailed, err)
		}
	}

	bridge.CloseAllSessions()
	logger.Info("virtual CCID device stopped")
	return nil
}

// runUSBDeviceStop provides instructions for stopping the device.
func runUSBDeviceStop(cmd *cobra.Command, _ []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), "The virtual CCID device runs in the foreground.")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "To stop a running device:")
	fmt.Fprintln(cmd.OutOrStdout(), "  1. Press Ctrl+C in the terminal where it is running")
	fmt.Fprintln(cmd.OutOrStdout(), "  2. Or send SIGTERM: kill -TERM $(pgrep -f 'xkey usb device start')")
	return nil
}

// runUSBDeviceStatus shows the virtual device status.
func runUSBDeviceStatus(cmd *cobra.Command, _ []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), "Virtual CCID Device Status")
	fmt.Fprintln(cmd.OutOrStdout())

	// Check UHID availability.
	uhidAvailable := checkUHIDAvailable()
	uhidStatus := "available"
	if !uhidAvailable {
		uhidStatus = "not available"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  UHID interface:  %s\n", uhidStatus)

	// Check USB Gadget (ConfigFS) availability.
	gadgetAvailable := checkGadgetAvailable()
	gadgetStatus := "available"
	if !gadgetAvailable {
		gadgetStatus = "not available"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  USB Gadget:      %s\n", gadgetStatus)

	// Check UDC availability.
	udcName := detectUDCName()
	if udcName != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  UDC controller:  %s\n", udcName)
	}

	// Check if a device process appears to be running.
	running := checkUSBDeviceRunning()
	runStatus := "not running"
	if running {
		runStatus = "running"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  CCID device:     %s\n", runStatus)

	// Show device identification.
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "  Device name:     %s\n", ccid.CCIDDeviceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Serial:          %s\n", ccid.CCIDDeviceSerial)
	fmt.Fprintf(cmd.OutOrStdout(), "  Vendor ID:       0x%04X\n", ccid.VendorIDCCID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Product ID:      0x%04X\n", ccid.ProductIDCCID)

	return nil
}

// setupUSBDeviceSignalHandler creates a context that is cancelled on SIGTERM/SIGINT.
func setupUSBDeviceSignalHandler(logger *slog.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("received shutdown signal",
				slog.String("signal", sig.String()),
			)
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	return ctx, cancel
}

// checkGadgetAvailable checks if ConfigFS USB gadget support is available.
func checkGadgetAvailable() bool {
	_, err := os.Stat("/sys/kernel/config/usb_gadget")
	return err == nil
}

// detectUDCName returns the first available UDC controller name, or empty string.
func detectUDCName() string {
	entries, err := os.ReadDir("/sys/class/udc")
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[0].Name()
}

// checkUHIDAvailable checks if /dev/uhid exists and is accessible.
func checkUHIDAvailable() bool {
	_, err := os.Stat("/dev/uhid")
	return err == nil
}

// checkUSBDeviceRunning performs a best-effort check for a running
// CCID device process by looking for the UHID device file descriptor
// in /proc. This is a heuristic check and may not be accurate in
// all environments.
func checkUSBDeviceRunning() bool {
	// Look for processes with /dev/uhid open.
	// This is a best-effort heuristic.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only check numeric directories (PIDs).
		if len(entry.Name()) == 0 || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		fdPath := fmt.Sprintf("/proc/%s/fd", entry.Name())
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, fd.Name()))
			if err != nil {
				continue
			}
			if link == "/dev/uhid" {
				return true
			}
		}
	}

	return false
}
