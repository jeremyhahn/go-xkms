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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivcertfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// PIV configuration constants.
const (
	defaultPIVStoragePath   = "./data/piv"
	defaultPIVBackend       = "software"
	defaultPIVTPMDevice     = "/dev/tpmrm0"
	defaultPIVExportFormat  = "pem"
	defaultPIVPKCS11Library = "/usr/lib/softhsm/libsofthsm2.so"
)

// PIV configuration keys for Viper.
const (
	viperKeyPIVBackend       = "piv.backend"
	viperKeyPIVStorage       = "piv.storage"
	viperKeyPIVStoragePath   = "piv.storage_path"
	viperKeyPIVTPMDevice     = "piv.tpm_device"
	viperKeyPIVPKCS11Library = "piv.pkcs11_library"
	viperKeyPIVPKCS11Token   = "piv.pkcs11_token"
	viperKeyPIVPKCS11PIN     = "piv.pkcs11_pin"
)

// PIV command errors.
var (
	// ErrPIVInvalidBackend indicates an unsupported backend type was specified.
	ErrPIVInvalidBackend = errors.New("piv: invalid backend type (must be 'software', 'tpm2', or 'pkcs11')")

	// ErrPIVInvalidStorageType indicates an unsupported storage type was specified.
	ErrPIVInvalidStorageType = errors.New("piv: invalid storage type (must be 'file', 'tpm2', or 'pkcs11')")

	// ErrPIVStoragePathRequired indicates storage path is required for file storage.
	ErrPIVStoragePathRequired = errors.New("piv: storage path required for file storage type")

	// ErrPIVInvalidSlot indicates an invalid PIV slot identifier.
	ErrPIVInvalidSlot = errors.New("piv: invalid slot identifier")

	// ErrPIVSlotRequired indicates a slot argument is required.
	ErrPIVSlotRequired = errors.New("piv: slot argument is required")

	// ErrPIVCertFileRequired indicates a certificate file argument is required.
	ErrPIVCertFileRequired = errors.New("piv: certificate file argument is required")

	// ErrPIVCertificateNotFound indicates no certificate exists in the slot.
	ErrPIVCertificateNotFound = errors.New("piv: certificate not found in slot")

	// ErrPIVInvalidFormat indicates an invalid certificate format.
	ErrPIVInvalidFormat = errors.New("piv: invalid certificate format (must be 'pem' or 'der')")

	// ErrPIVStorageCreationFailed indicates the storage backend could not be created.
	ErrPIVStorageCreationFailed = errors.New("piv: storage creation failed")

	// ErrPIVCertificateReadFailed indicates the certificate file could not be read.
	ErrPIVCertificateReadFailed = errors.New("piv: failed to read certificate file")

	// ErrPIVCertificateParseFailed indicates the certificate could not be parsed.
	ErrPIVCertificateParseFailed = errors.New("piv: failed to parse certificate")

	// ErrPIVStoreFailed indicates the certificate could not be stored.
	ErrPIVStoreFailed = errors.New("piv: failed to store certificate")

	// ErrPIVDeleteFailed indicates the certificate could not be deleted.
	ErrPIVDeleteFailed = errors.New("piv: failed to delete certificate")

	// ErrPIVExportFailed indicates the certificate could not be exported.
	ErrPIVExportFailed = errors.New("piv: failed to export certificate")

	// ErrPIVListFailed indicates the certificate list could not be retrieved.
	ErrPIVListFailed = errors.New("piv: failed to list certificates")

	// ErrPIVOutputFileRequired indicates an output file is required for export.
	ErrPIVOutputFileRequired = errors.New("piv: output file is required for export")

	// ErrPIVTPMDeviceRequired indicates TPM device path is required for tpm2 storage.
	ErrPIVTPMDeviceRequired = errors.New("piv: TPM device path required for tpm2 storage")

	// ErrPIVPKCS11LibraryRequired indicates PKCS#11 library is required for pkcs11 storage.
	ErrPIVPKCS11LibraryRequired = errors.New("piv: PKCS#11 library path required for pkcs11 storage")

	// ErrPIVPKCS11TokenRequired indicates PKCS#11 token label is required for pkcs11 storage.
	ErrPIVPKCS11TokenRequired = errors.New("piv: PKCS#11 token label required for pkcs11 storage")
)

// PIVStorageType represents the certificate storage backend type.
type PIVStorageType string

const (
	// PIVStorageTypeFile stores certificates on the filesystem.
	PIVStorageTypeFile PIVStorageType = "file"

	// PIVStorageTypeTPM2 stores certificates in TPM NV storage.
	PIVStorageTypeTPM2 PIVStorageType = "tpm2"

	// PIVStorageTypePKCS11 stores certificates in PKCS#11 token storage.
	PIVStorageTypePKCS11 PIVStorageType = "pkcs11"
)

// PIVBackendType represents the key backend type.
type PIVBackendType string

const (
	// PIVBackendSoftware uses software-based key operations.
	PIVBackendSoftware PIVBackendType = "software"

	// PIVBackendTPM2 uses TPM2 hardware for key operations.
	PIVBackendTPM2 PIVBackendType = "tpm2"

	// PIVBackendPKCS11 uses PKCS#11 tokens for key operations.
	PIVBackendPKCS11 PIVBackendType = "pkcs11"
)

// PIVSlot represents a PIV certificate slot identifier.
type PIVSlot string

// Standard PIV slots as defined by NIST SP 800-73-4.
const (
	PIVSlotAuthentication     PIVSlot = "9a" // PIV Authentication
	PIVSlotDigitalSignature   PIVSlot = "9c" // Digital Signature
	PIVSlotKeyManagement      PIVSlot = "9d" // Key Management
	PIVSlotCardAuthentication PIVSlot = "9e" // Card Authentication
)

// CertFormat specifies certificate encoding format.
type CertFormat string

const (
	// CertFormatPEM is PEM-encoded certificate format.
	CertFormatPEM CertFormat = "pem"

	// CertFormatDER is DER-encoded certificate format.
	CertFormatDER CertFormat = "der"
)

// PIVConfig holds the configuration for PIV certificate operations.
type PIVConfig struct {
	// Backend is the key backend type (software, tpm2, pkcs11).
	Backend PIVBackendType

	// StorageType is the certificate storage type.
	// If empty, defaults to match the backend.
	StorageType PIVStorageType

	// StoragePath is the path for file storage.
	StoragePath string

	// TPMDevice is the TPM device path for tpm2 backend/storage.
	TPMDevice string

	// PKCS11Library is the PKCS#11 library path.
	PKCS11Library string

	// PKCS11Token is the PKCS#11 token label.
	PKCS11Token string

	// PKCS11PIN is the PKCS#11 user PIN.
	PKCS11PIN string
}

// Validate checks the PIV configuration for errors.
func (c *PIVConfig) Validate() error {
	// Validate backend
	switch c.Backend {
	case PIVBackendSoftware, PIVBackendTPM2, PIVBackendPKCS11:
		// Valid
	default:
		return ErrPIVInvalidBackend
	}

	// Validate storage type
	switch c.StorageType {
	case PIVStorageTypeFile, PIVStorageTypeTPM2, PIVStorageTypePKCS11:
		// Valid
	default:
		return ErrPIVInvalidStorageType
	}

	// Validate storage-specific requirements
	switch c.StorageType {
	case PIVStorageTypeFile:
		if c.StoragePath == "" {
			return ErrPIVStoragePathRequired
		}
	case PIVStorageTypeTPM2:
		if c.TPMDevice == "" {
			return ErrPIVTPMDeviceRequired
		}
	case PIVStorageTypePKCS11:
		if c.PKCS11Library == "" {
			return ErrPIVPKCS11LibraryRequired
		}
		if c.PKCS11Token == "" {
			return ErrPIVPKCS11TokenRequired
		}
	}

	return nil
}

// PIVSlotInfo contains metadata about a certificate slot.
type PIVSlotInfo struct {
	Slot        PIVSlot
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Algorithm   string
	Fingerprint string
}

// validatePIVSlot checks if a slot identifier is valid.
func validatePIVSlot(slot string) (pivcert.PIVSlot, error) {
	s := pivcert.PIVSlot(strings.ToLower(slot))
	if err := pivcert.ValidateSlot(s); err != nil {
		return "", ErrPIVInvalidSlot
	}
	return s, nil
}

// PIVCmd represents the piv parent command.
var PIVCmd = &cobra.Command{
	Use:   "piv",
	Short: "PIV smart card certificate management",
	Long: `PIV (Personal Identity Verification) smart card certificate management.

Manage certificates stored in PIV-compatible slots for authentication,
digital signatures, key management, and card authentication.

Standard PIV Slots:
  9a  PIV Authentication      - Used for PIV card-based authentication
  9c  Digital Signature       - Used for signing documents and emails
  9d  Key Management          - Used for encryption/decryption operations
  9e  Card Authentication     - Used for physical access control

Certificate storage defaults to match the key backend:
  - software backend -> file storage
  - tpm2 backend     -> tpm2 storage
  - pkcs11 backend   -> pkcs11 storage

Use --piv-storage to override and use different storage (e.g., keys in TPM2,
certificates on filesystem).

Examples:
  # List all certificates
  xkey piv list

  # Show certificate details for authentication slot
  xkey piv show 9a

  # Store a certificate in the digital signature slot
  xkey piv store 9c /path/to/certificate.pem

  # Export certificate in PEM format
  xkey piv export 9a --format pem --output /tmp/cert.pem

  # Delete certificate from key management slot
  xkey piv delete 9d

  # Show PIV storage status
  xkey piv status

  # Use TPM2 backend with file storage for certificates
  xkey piv --backend tpm2 --piv-storage file list`,
}

// pivListCmd lists all certificates in PIV slots.
var pivListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List certificates in all slots",
	Long: `List all certificates stored in PIV slots.

Displays a summary of all certificates including slot, subject,
issuer, and expiration date.

Examples:
  # List all certificates
  xkey piv list

  # List with custom backend
  xkey piv --backend tpm2 list`,
	RunE: runPIVList,
}

// pivShowCmd shows certificate details for a slot.
var pivShowCmd = &cobra.Command{
	Use:   "show <slot>",
	Short: "Show certificate details for a slot",
	Long: `Show detailed certificate information for a specific PIV slot.

Displays comprehensive certificate details including subject, issuer,
validity period, key algorithm, and extensions.

Arguments:
  slot  PIV slot identifier (9a, 9c, 9d, or 9e)

Examples:
  # Show authentication certificate
  xkey piv show 9a

  # Show digital signature certificate
  xkey piv show 9c`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVShow,
}

// pivStoreCmd stores a certificate in a slot.
var pivStoreCmd = &cobra.Command{
	Use:   "store <slot> <cert-file>",
	Short: "Store certificate in slot",
	Long: `Store a certificate in a PIV slot.

Imports a certificate from a PEM or DER encoded file and stores it
in the specified PIV slot. The format is automatically detected.

Arguments:
  slot       PIV slot identifier (9a, 9c, 9d, or 9e)
  cert-file  Path to the certificate file (PEM or DER encoded)

Examples:
  # Store PEM certificate in authentication slot
  xkey piv store 9a /path/to/cert.pem

  # Store DER certificate in signature slot
  xkey piv store 9c /path/to/cert.der`,
	Args: cobra.ExactArgs(2),
	RunE: runPIVStore,
}

// pivDeleteCmd deletes a certificate from a slot.
var pivDeleteCmd = &cobra.Command{
	Use:     "delete <slot>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete certificate from slot",
	Long: `Delete a certificate from a PIV slot.

Removes the certificate from the specified PIV slot. This operation
cannot be undone.

Arguments:
  slot  PIV slot identifier (9a, 9c, 9d, or 9e)

Examples:
  # Delete certificate from authentication slot
  xkey piv delete 9a

  # Force delete without confirmation
  xkey piv delete --force 9c`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVDelete,
}

// pivExportCmd exports a certificate from a slot.
var pivExportCmd = &cobra.Command{
	Use:   "export <slot>",
	Short: "Export certificate from slot",
	Long: `Export a certificate from a PIV slot.

Exports the certificate in the specified format (PEM or DER).
Output can be written to a file or stdout.

Arguments:
  slot  PIV slot identifier (9a, 9c, 9d, or 9e)

Examples:
  # Export certificate to PEM file
  xkey piv export 9a --format pem --output /tmp/cert.pem

  # Export certificate to DER file
  xkey piv export 9a --format der --output /tmp/cert.der

  # Export to stdout (PEM format)
  xkey piv export 9a --format pem`,
	Args: cobra.ExactArgs(1),
	RunE: runPIVExport,
}

// pivStatusCmd shows PIV storage status.
var pivStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show PIV storage status",
	Long: `Show PIV certificate storage status.

Displays information about the configured storage backend,
available slots, and storage utilization.

Examples:
  # Show storage status
  xkey piv status

  # Show status for TPM2 backend
  xkey piv --backend tpm2 status`,
	RunE: runPIVStatus,
}

func init() {
	// Register piv command with root
	RootCmd.AddCommand(PIVCmd)

	// Add subcommands to piv command
	PIVCmd.AddCommand(pivListCmd)
	PIVCmd.AddCommand(pivShowCmd)
	PIVCmd.AddCommand(pivStoreCmd)
	PIVCmd.AddCommand(pivDeleteCmd)
	PIVCmd.AddCommand(pivExportCmd)
	PIVCmd.AddCommand(pivStatusCmd)

	// PIV parent command flags (inherited by subcommands)
	PIVCmd.PersistentFlags().String("backend", defaultPIVBackend,
		"Key backend: software, tpm2, or pkcs11")
	PIVCmd.PersistentFlags().String("piv-storage", "",
		"Certificate storage type override: file, tpm2, or pkcs11 (default: matches backend)")
	PIVCmd.PersistentFlags().String("storage-path", defaultPIVStoragePath,
		"Path for file storage")
	PIVCmd.PersistentFlags().String("tpm-device", defaultPIVTPMDevice,
		"TPM device path for tpm2 backend/storage")
	PIVCmd.PersistentFlags().String("pkcs11-library", defaultPIVPKCS11Library,
		"PKCS#11 library path")
	PIVCmd.PersistentFlags().String("pkcs11-token", "",
		"PKCS#11 token label")
	PIVCmd.PersistentFlags().String("pkcs11-pin", "",
		"PKCS#11 user PIN")

	// Bind PIV flags to viper
	_ = viper.BindPFlag(viperKeyPIVBackend, PIVCmd.PersistentFlags().Lookup("backend"))
	_ = viper.BindPFlag(viperKeyPIVStorage, PIVCmd.PersistentFlags().Lookup("piv-storage"))
	_ = viper.BindPFlag(viperKeyPIVStoragePath, PIVCmd.PersistentFlags().Lookup("storage-path"))
	_ = viper.BindPFlag(viperKeyPIVTPMDevice, PIVCmd.PersistentFlags().Lookup("tpm-device"))
	_ = viper.BindPFlag(viperKeyPIVPKCS11Library, PIVCmd.PersistentFlags().Lookup("pkcs11-library"))
	_ = viper.BindPFlag(viperKeyPIVPKCS11Token, PIVCmd.PersistentFlags().Lookup("pkcs11-token"))
	_ = viper.BindPFlag(viperKeyPIVPKCS11PIN, PIVCmd.PersistentFlags().Lookup("pkcs11-pin"))

	// Export command specific flags
	pivExportCmd.Flags().String("format", defaultPIVExportFormat,
		"Export format: pem or der")
	pivExportCmd.Flags().String("output", "",
		"Output file path (default: stdout)")

	// Delete command specific flags
	pivDeleteCmd.Flags().Bool("force", false,
		"Don't prompt for confirmation")
}

// buildPIVConfig creates a PIVConfig from Viper configuration.
func buildPIVConfig() *PIVConfig {
	backend := PIVBackendType(viper.GetString(viperKeyPIVBackend))
	storageType := PIVStorageType(viper.GetString(viperKeyPIVStorage))

	// If no storage override, default to match backend
	if storageType == "" {
		switch backend {
		case PIVBackendSoftware:
			storageType = PIVStorageTypeFile
		case PIVBackendTPM2:
			storageType = PIVStorageTypeTPM2
		case PIVBackendPKCS11:
			storageType = PIVStorageTypePKCS11
		default:
			storageType = PIVStorageTypeFile
		}
	}

	return &PIVConfig{
		Backend:       backend,
		StorageType:   storageType,
		StoragePath:   viper.GetString(viperKeyPIVStoragePath),
		TPMDevice:     viper.GetString(viperKeyPIVTPMDevice),
		PKCS11Library: viper.GetString(viperKeyPIVPKCS11Library),
		PKCS11Token:   viper.GetString(viperKeyPIVPKCS11Token),
		PKCS11PIN:     viper.GetString(viperKeyPIVPKCS11PIN),
	}
}

// createPIVStorage creates the appropriate certificate storage backend.
func createPIVStorage(cfg *PIVConfig, logger *slog.Logger) (pivcert.PIVCertificateStorage, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	logger.Info("creating PIV certificate storage",
		slog.String("type", string(cfg.StorageType)),
		slog.String("backend", string(cfg.Backend)),
	)

	switch cfg.StorageType {
	case PIVStorageTypeFile:
		// Create file storage backend
		backend, err := filestorage.New(cfg.StoragePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file storage backend: %w", err)
		}
		fileConfig := &pivcert.FileStorageConfig{
			Backend:    backend,
			DEREnabled: true,
			PEMEnabled: true,
		}
		return pivcertfile.NewFileBackend(fileConfig)

	case PIVStorageTypeTPM2:
		// TPM2 backend not yet implemented
		return nil, fmt.Errorf("piv: TPM2 storage backend not yet implemented")

	case PIVStorageTypePKCS11:
		// PKCS#11 backend not yet implemented
		return nil, fmt.Errorf("piv: PKCS#11 storage backend not yet implemented")

	default:
		return nil, ErrPIVInvalidStorageType
	}
}

// runPIVList executes the piv list command.
func runPIVList(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	slots, err := storage.List()
	if err != nil {
		return errors.Join(ErrPIVListFailed, err)
	}

	if len(slots) == 0 {
		fmt.Println("No certificates found in PIV slots.")
		return nil
	}

	fmt.Printf("PIV Certificates (%d):\n\n", len(slots))

	for _, slot := range slots {
		slotName := pivcert.SlotName(slot.Slot)
		fmt.Printf("  Slot:        %s (%s)\n", slot.Slot, slotName)
		fmt.Printf("  Subject:     %s\n", slot.Subject)
		fmt.Printf("  Issuer:      %s\n", slot.Issuer)
		fmt.Printf("  Not Before:  %s\n", slot.NotBefore)
		fmt.Printf("  Not After:   %s\n", slot.NotAfter)
		fmt.Printf("  Algorithm:   %s\n", slot.Algorithm)
		if slot.Fingerprint != "" {
			fmt.Printf("  Fingerprint: %s\n", slot.Fingerprint)
		}
		fmt.Println()
	}

	return nil
}

// runPIVShow executes the piv show command.
func runPIVShow(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrPIVCertificateNotFound, err)
	}

	slotName := pivcert.SlotName(slot)
	fmt.Printf("PIV Certificate - Slot %s (%s)\n", slot, slotName)
	fmt.Printf("========================================\n\n")

	fmt.Printf("Subject:       %s\n", cert.Subject.String())
	fmt.Printf("Issuer:        %s\n", cert.Issuer.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before:    %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:     %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
	fmt.Printf("Signature:     %s\n", cert.SignatureAlgorithm.String())

	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:     %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("Email:         %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if cert.KeyUsage != 0 {
		fmt.Printf("Key Usage:     %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("Ext Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	fmt.Printf("Is CA:         %t\n", cert.IsCA)

	return nil
}

// runPIVStore executes the piv store command.
func runPIVStore(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	certFile := args[1]

	// Read certificate file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return errors.Join(ErrPIVCertificateReadFailed, err)
	}

	// Parse certificate (auto-detect format)
	cert, format, err := parseCertificateAuto(certData)
	if err != nil {
		return errors.Join(ErrPIVCertificateParseFailed, err)
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	if err := storage.Store(slot, cert); err != nil {
		return errors.Join(ErrPIVStoreFailed, err)
	}

	slotName := pivcert.SlotName(slot)
	fmt.Printf("Certificate stored in slot %s (%s)\n", slot, slotName)
	fmt.Printf("  Subject:  %s\n", cert.Subject.CommonName)
	fmt.Printf("  Format:   %s\n", format)
	fmt.Printf("  Expires:  %s\n", cert.NotAfter.Format(time.RFC3339))

	return nil
}

// runPIVDelete executes the piv delete command.
func runPIVDelete(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()
	force, _ := cmd.Flags().GetBool("force")

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	// Check if certificate exists
	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrPIVCertificateNotFound, err)
	}

	slotName := pivcert.SlotName(slot)

	if !force {
		fmt.Printf("Delete certificate from slot %s (%s)?\n", slot, slotName)
		fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("  Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
		fmt.Print("\nConfirm deletion [y/N]: ")

		var confirm string
		if _, err := fmt.Scanln(&confirm); err != nil {
			return nil // User cancelled
		}
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	if err := storage.Delete(slot); err != nil {
		return errors.Join(ErrPIVDeleteFailed, err)
	}

	fmt.Printf("Certificate deleted from slot %s (%s)\n", slot, slotName)
	return nil
}

// runPIVExport executes the piv export command.
func runPIVExport(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	formatStr, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")

	format, err := parseCertFormat(formatStr)
	if err != nil {
		return err
	}

	// Convert to pivcert format
	var pivFormat pivcert.CertFormat
	switch format {
	case CertFormatPEM:
		pivFormat = pivcert.FormatPEM
	case CertFormatDER:
		pivFormat = pivcert.FormatDER
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	data, err := storage.Export(slot, pivFormat)
	if err != nil {
		return errors.Join(ErrPIVExportFailed, err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return errors.Join(ErrPIVExportFailed, err)
		}
		slotName := pivcert.SlotName(slot)
		fmt.Printf("Certificate exported from slot %s (%s) to %s\n", slot, slotName, outputPath)
	} else {
		// Write to stdout
		if _, err := os.Stdout.Write(data); err != nil {
			return errors.Join(ErrPIVExportFailed, err)
		}
	}

	return nil
}

// runPIVStatus executes the piv status command.
func runPIVStatus(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	fmt.Println("PIV Certificate Storage Status")
	fmt.Println("==============================")
	fmt.Println()

	fmt.Printf("Key Backend:       %s\n", cfg.Backend)
	fmt.Printf("Storage Type:      %s\n", cfg.StorageType)

	switch cfg.StorageType {
	case PIVStorageTypeFile:
		fmt.Printf("Storage Path:      %s\n", cfg.StoragePath)
	case PIVStorageTypeTPM2:
		fmt.Printf("TPM Device:        %s\n", cfg.TPMDevice)
	case PIVStorageTypePKCS11:
		fmt.Printf("PKCS#11 Library:   %s\n", cfg.PKCS11Library)
		fmt.Printf("PKCS#11 Token:     %s\n", cfg.PKCS11Token)
	}

	fmt.Println()

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		fmt.Printf("Storage Status:    Error - %v\n", err)
		return nil // Don't fail, just report status
	}
	defer func() { _ = storage.Close() }()

	slots, err := storage.List()
	if err != nil {
		fmt.Printf("Storage Status:    Error listing certificates - %v\n", err)
		return nil
	}

	fmt.Println("Slot Status:")
	fmt.Println()

	// Build map of occupied slots
	occupied := make(map[pivcert.PIVSlot]pivcert.PIVSlotInfo)
	for _, s := range slots {
		occupied[s.Slot] = s
	}

	// Display all slots
	allSlots := pivcert.PrimarySlots()

	for _, slot := range allSlots {
		slotName := pivcert.SlotName(slot)
		if info, ok := occupied[slot]; ok {
			fmt.Printf("  [%s] %s\n", slot, slotName)
			fmt.Printf("        Subject:  %s\n", info.Subject)
			fmt.Printf("        Expires:  %s\n", info.NotAfter)
		} else {
			fmt.Printf("  [%s] %s - Empty\n", slot, slotName)
		}
	}

	fmt.Printf("\nTotal Certificates: %d/4\n", len(slots))

	return nil
}

// parseCertificateAuto parses a certificate from PEM or DER format.
func parseCertificateAuto(data []byte) (*x509.Certificate, CertFormat, error) {
	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, "", fmt.Errorf("invalid PEM block type: %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		return cert, CertFormatPEM, nil
	}

	// Try DER
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, "", err
	}
	return cert, CertFormatDER, nil
}

// parseCertFormat parses a certificate format string.
func parseCertFormat(format string) (CertFormat, error) {
	switch strings.ToLower(format) {
	case "pem":
		return CertFormatPEM, nil
	case "der":
		return CertFormatDER, nil
	default:
		return "", ErrPIVInvalidFormat
	}
}

// formatKeyUsage converts x509.KeyUsage to a human-readable string.
func formatKeyUsage(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

// formatExtKeyUsage converts extended key usage to a human-readable string.
func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {
	var names []string
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageAny:
			names = append(names, "Any")
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		default:
			names = append(names, fmt.Sprintf("Unknown(%d)", usage))
		}
	}
	if len(names) == 0 {
		return "None"
	}
	return strings.Join(names, ", ")
}
