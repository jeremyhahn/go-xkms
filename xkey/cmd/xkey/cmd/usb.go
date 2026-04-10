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
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/usb"
)

// USB command errors.
var (
	ErrUSBPassphraseRead = &USBCmdError{Operation: "read_passphrase", Message: "failed to read passphrase"}
	ErrUSBCreateFailed   = &USBCmdError{Operation: "create", Message: "failed to create USB image"}
	ErrUSBStatusFailed   = &USBCmdError{Operation: "status", Message: "failed to get USB status"}
	ErrUSBUpdateFailed   = &USBCmdError{Operation: "update", Message: "failed to update binaries"}
)

var (
	usbCreateSize string
	usbBinaries   []string
)

// usbCmd is the parent command for USB disk image operations.
var usbCmd = &cobra.Command{
	Use:   "usb",
	Short: "USB disk image management",
	Long: `Create and manage USB disk images for portable xKey deployments.

xKey USB images contain two partitions:
  Partition 1: FAT32 (512MB) - Contains xKey binaries, launcher script,
               and .xkey-home marker for automatic home detection.
  Partition 2: LUKS2 (remainder) - Encrypted data partition for
               credentials, keys, and configuration.

The image can be written to a USB flash drive or used directly with
QEMU for virtual deployments.

Commands:
  create    Create a new USB image or prepare a USB device
  status    Show status of an existing image or device
  update    Update xKey binaries on an existing image or device

Examples:
  # Create a 4GB USB image file
  sudo xkey usb create /tmp/xkey.img --size 4G

  # Create directly on a USB device
  sudo xkey usb create /dev/sdb --size 4G

  # Show image status
  xkey usb status /tmp/xkey.img

  # Update binaries on an existing image
  sudo xkey usb update /tmp/xkey.img`,
}

// usbCreateCmd creates a new USB image or prepares a device.
var usbCreateCmd = &cobra.Command{
	Use:   "create <device-or-image>",
	Short: "Create a USB image or prepare a USB device",
	Long: `Create a two-partition USB disk image or prepare a physical USB device.

The command creates:
  1. A FAT32 partition (512MB) with xKey binaries and launcher script
  2. A LUKS2 encrypted partition (remaining space) for data storage

Requires root privileges for partitioning and filesystem operations.

The --size flag is required for image files (ignored for block devices).
If --binary is not specified, the current xkey binary is used.

Examples:
  # Create a 4GB image file
  sudo xkey usb create /tmp/xkey.img --size 4G

  # Create with specific binaries
  sudo xkey usb create /tmp/xkey.img --size 4G \
    --binary ./xkey-linux-amd64 \
    --binary ./xkey-linux-arm64

  # Prepare a USB device (uses full device size)
  sudo xkey usb create /dev/sdb`,
	Args: cobra.ExactArgs(1),
	RunE: runUSBCreate,
}

// usbStatusCmd shows the status of an existing image or device.
var usbStatusCmd = &cobra.Command{
	Use:   "status [device-or-image]",
	Short: "Show status of a USB image or device",
	Long: `Display information about an existing USB image file or device.

Shows partition layout, sizes, LUKS mount status, and detected
xKey binaries on the FAT32 partition.

Examples:
  xkey usb status /tmp/xkey.img
  xkey usb status /dev/sdb`,
	Args: cobra.ExactArgs(1),
	RunE: runUSBStatus,
}

// usbUpdateCmd updates binaries on an existing image or device.
var usbUpdateCmd = &cobra.Command{
	Use:   "update <device-or-image>",
	Short: "Update xKey binaries on a USB image or device",
	Long: `Replace xKey binaries on the FAT32 partition of an existing USB
image or device. Also updates the launcher script.

Requires root privileges for mounting the FAT32 partition.

If --binary is not specified, the current xkey binary is used.

Examples:
  sudo xkey usb update /tmp/xkey.img
  sudo xkey usb update /tmp/xkey.img --binary ./xkey-linux-amd64
  sudo xkey usb update /dev/sdb`,
	Args: cobra.ExactArgs(1),
	RunE: runUSBUpdate,
}

func init() {
	RootCmd.AddCommand(usbCmd)
	usbCmd.AddCommand(usbCreateCmd)
	usbCmd.AddCommand(usbStatusCmd)
	usbCmd.AddCommand(usbUpdateCmd)

	usbCreateCmd.Flags().StringVar(&usbCreateSize, "size", "4G",
		"Total image size (e.g., 1G, 4G, 8G). Ignored for block devices.")
	usbCreateCmd.Flags().StringArrayVar(&usbBinaries, "binary", nil,
		"Path to xKey binary to include (repeatable). Defaults to current binary.")

	usbUpdateCmd.Flags().StringArrayVar(&usbBinaries, "binary", nil,
		"Path to xKey binary to include (repeatable). Defaults to current binary.")

	// Add usb to the LUKS exempt list so it runs without requiring
	// an unlocked LUKS volume.
	luksExemptCommands["usb"] = true
	luksExemptCommands["create"] = true
	luksExemptCommands["update"] = true
}

func runUSBCreate(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// Parse size.
	sizeBytes, err := usb.ParseSize(usbCreateSize)
	if err != nil {
		return &USBCmdError{Operation: "parse_size", Err: err}
	}

	// Resolve binaries. If none specified, use the current binary.
	binaries := usbBinaries
	if len(binaries) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return &USBCmdError{
				Operation: "resolve_binary",
				Message:   "cannot determine current binary path",
				Err:       err,
			}
		}
		binaries = []string{exe}
		fmt.Fprintf(cmd.OutOrStdout(), "Using current binary: %s\n", exe)
	}

	// Validate that all binaries exist before prompting for passphrase.
	for _, bin := range binaries {
		if _, statErr := os.Stat(bin); statErr != nil {
			return &USBCmdError{
				Operation: "validate_binary",
				Message:   fmt.Sprintf("binary not found: %s", bin),
				Err:       statErr,
			}
		}
	}

	// Prompt for passphrase.
	passphrase, err := readUSBPassphrase(cmd)
	if err != nil {
		return err
	}

	cfg := usb.ImageConfig{
		Path:       targetPath,
		SizeBytes:  sizeBytes,
		Passphrase: passphrase,
		Binaries:   binaries,
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Creating USB image at %s (%s)...\n", targetPath, usb.FormatSize(sizeBytes))
	fmt.Fprintf(cmd.OutOrStdout(), "  FAT32 partition: %s\n", usb.FormatSize(usb.FAT32PartitionSize))
	fmt.Fprintf(cmd.OutOrStdout(), "  LUKS2 partition: %s\n", usb.FormatSize(sizeBytes-usb.FAT32PartitionSize))
	fmt.Fprintf(cmd.OutOrStdout(), "  Binaries: %d\n", len(binaries))
	fmt.Fprintln(cmd.OutOrStdout())

	if err := usb.CreateImage(cfg); err != nil {
		return &USBCmdError{Operation: "create_image", Err: err}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "USB image created successfully!")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "  Path:     %s\n", targetPath)
	fmt.Fprintf(cmd.OutOrStdout(), "  Size:     %s\n", usb.FormatSize(sizeBytes))
	fmt.Fprintf(cmd.OutOrStdout(), "  Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(cmd.OutOrStdout())

	if usb.IsBlockDevice(targetPath) {
		fmt.Fprintln(cmd.OutOrStdout(), "USB device is ready. Safely eject and boot from it.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "To write to a USB drive:")
		fmt.Fprintf(cmd.OutOrStdout(), "  sudo dd if=%s of=/dev/sdX bs=4M status=progress\n", targetPath)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "To test with QEMU:")
		fmt.Fprintf(cmd.OutOrStdout(), "  qemu-system-x86_64 -drive file=%s,format=raw\n", targetPath)
	}

	return nil
}

func runUSBStatus(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	status, err := usb.Status(targetPath)
	if err != nil {
		return &USBCmdError{Operation: "get_status", Err: err}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "USB Image Status: %s\n\n", targetPath)

	deviceType := "Image file"
	if status.IsBlockDevice {
		deviceType = "Block device"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  Type:           %s\n", deviceType)
	fmt.Fprintf(cmd.OutOrStdout(), "  Total size:     %s\n", usb.FormatSize(status.TotalSize))
	fmt.Fprintf(cmd.OutOrStdout(), "  FAT32 size:     %s\n", usb.FormatSize(status.FAT32Size))
	fmt.Fprintf(cmd.OutOrStdout(), "  LUKS2 size:     %s\n", usb.FormatSize(status.LUKSSize))

	mountStatus := "Locked"
	if status.LUKSMounted {
		mountStatus = "Unlocked"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  LUKS status:    %s\n", mountStatus)

	if len(status.Binaries) > 0 {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), "  Binaries (%d):\n", len(status.Binaries))
		for _, bin := range status.Binaries {
			fmt.Fprintf(cmd.OutOrStdout(), "    - %s\n", bin)
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "  Binaries:       (not detected)\n")
	}

	return nil
}

func runUSBUpdate(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// Resolve binaries.
	binaries := usbBinaries
	if len(binaries) == 0 {
		exe, err := os.Executable()
		if err != nil {
			return &USBCmdError{
				Operation: "resolve_binary",
				Message:   "cannot determine current binary path",
				Err:       err,
			}
		}
		binaries = []string{exe}
		fmt.Fprintf(cmd.OutOrStdout(), "Using current binary: %s\n", exe)
	}

	// Validate binaries.
	for _, bin := range binaries {
		if _, statErr := os.Stat(bin); statErr != nil {
			return &USBCmdError{
				Operation: "validate_binary",
				Message:   fmt.Sprintf("binary not found: %s", bin),
				Err:       statErr,
			}
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Updating binaries on %s...\n", targetPath)

	if err := usb.UpdateBinaries(targetPath, binaries); err != nil {
		return &USBCmdError{Operation: "update_binaries", Err: err}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Binaries updated successfully!")
	for _, bin := range binaries {
		fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", bin)
	}

	return nil
}

// readUSBPassphrase reads a passphrase from the terminal with
// confirmation, or from stdin when piped.
func readUSBPassphrase(cmd *cobra.Command) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return readUSBPassphraseFromStdin()
	}

	fmt.Fprint(cmd.OutOrStdout(), "Enter passphrase for LUKS data partition: ")
	pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.OutOrStdout())
	if err != nil {
		return "", &USBCmdError{Operation: "read_passphrase", Err: err}
	}

	fmt.Fprint(cmd.OutOrStdout(), "Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.OutOrStdout())
	if err != nil {
		return "", &USBCmdError{Operation: "read_passphrase", Err: err}
	}

	if string(pass1) != string(pass2) {
		return "", &USBCmdError{
			Operation: "confirm_passphrase",
			Message:   "passphrases do not match",
		}
	}

	if len(pass1) == 0 {
		return "", &USBCmdError{
			Operation: "validate_passphrase",
			Message:   "passphrase cannot be empty",
		}
	}

	return string(pass1), nil
}

// readUSBPassphraseFromStdin reads passphrase from piped stdin.
func readUSBPassphraseFromStdin() (string, error) {
	var pass1, pass2 string

	if _, err := fmt.Scanln(&pass1); err != nil {
		return "", &USBCmdError{Operation: "read_passphrase", Err: err}
	}
	if _, err := fmt.Scanln(&pass2); err != nil {
		if !errors.Is(err, fmt.Errorf("")) {
			return "", &USBCmdError{Operation: "read_passphrase", Err: err}
		}
	}

	if pass1 != pass2 {
		return "", &USBCmdError{
			Operation: "confirm_passphrase",
			Message:   "passphrases do not match",
		}
	}

	if pass1 == "" {
		return "", &USBCmdError{
			Operation: "validate_passphrase",
			Message:   "passphrase cannot be empty",
		}
	}

	return pass1, nil
}

// USBCmdError represents a USB CLI command error.
type USBCmdError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *USBCmdError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("usb: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("usb: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("usb: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("usb: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *USBCmdError) Unwrap() error {
	return e.Err
}
