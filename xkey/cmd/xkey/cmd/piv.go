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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/spf13/cobra"
)

// PIV configuration constants.
const (
	defaultPIVBackend       = "software"
	defaultPIVTPMDevice     = "/dev/tpmrm0"
	defaultPIVExportFormat  = "pem"
	defaultPIVPKCS11Library = "/usr/lib/softhsm/libsofthsm2.so"

	// pivStorageFeature is the featureDataDir (datadir.go) subdirectory the
	// PIV file-storage path defaults to when --storage-path is not set:
	// <xkey data dir>/piv, resolved through the CLI's shared data-directory
	// chain (XKEY_HOME, XKEY_DATA_DIR, config data_dir, or ~/.xkey/data)
	// rather than a cwd-relative default (go-xkms#929).
	pivStorageFeature = "piv"
)

// pivPKCS11PINSource and pivPKCS11SOPINSource are the PKCS#11 hardware
// token's own user/Security Officer PIN -- a different secret from the xkey
// host PIN service's PIN (pin_input.go). They follow the identical
// stdin-flag-then-dedicated-environment-variable convention: there is no
// "--pkcs11-pin" value flag, for the same reason there is no "--pin" one
// (go-xkms#272) -- a value on the command line is visible to every other
// process on the host via 'ps'. Declared with addPersistentFlags on PIVCmd,
// so every "piv" subcommand inherits them; commands outside that tree (cert,
// device listen, provision, auth login --piv) do not declare the flag and so
// resolve the PIN from its environment variable only (go-xkms#871).
var (
	pivPKCS11PINSource = pinSource{
		label:      "PKCS#11 PIN",
		stdinFlag:  "pkcs11-pin-stdin",
		envVar:     "XKEY_PIV_PKCS11_PIN",
		stdinEmpty: ErrPIVPKCS11PINStdinEmpty,
	}
	pivPKCS11SOPINSource = pinSource{
		label:      "PKCS#11 Security Officer PIN",
		stdinFlag:  "pkcs11-so-pin-stdin",
		envVar:     "XKEY_PIV_PKCS11_SO_PIN",
		stdinEmpty: ErrPIVPKCS11SOPINStdinEmpty,
	}
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

	// ErrPIVPKCS11PINStdinEmpty indicates --pkcs11-pin-stdin was given but
	// standard input carried no PKCS#11 PIN.
	ErrPIVPKCS11PINStdinEmpty = errors.New("piv: --pkcs11-pin-stdin was given but standard input carried no PKCS#11 PIN")

	// ErrPIVPKCS11SOPINStdinEmpty indicates --pkcs11-so-pin-stdin was given
	// but standard input carried no PKCS#11 Security Officer PIN.
	ErrPIVPKCS11SOPINStdinEmpty = errors.New("piv: --pkcs11-so-pin-stdin was given but standard input carried no PKCS#11 Security Officer PIN")
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

	// PKCS11SOPIN is the PKCS#11 Security Officer PIN.
	PKCS11SOPIN string
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
func validatePIVSlot(slot string) (xkms.PIVSlot, error) {
	s := xkms.PIVSlot(strings.ToLower(slot))
	if err := xkms.ValidatePIVSlot(s); err != nil {
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
	PIVCmd.PersistentFlags().String("storage-path", "",
		"Path for file storage (default: ~/.xkey/data/piv, see XKEY_DATA_DIR)")
	PIVCmd.PersistentFlags().String("tpm-device", defaultPIVTPMDevice,
		"TPM device path for tpm2 backend/storage")
	PIVCmd.PersistentFlags().String("pkcs11-library", defaultPIVPKCS11Library,
		"PKCS#11 library path")
	PIVCmd.PersistentFlags().String("pkcs11-token", "",
		"PKCS#11 token label")
	pivPKCS11PINSource.addPersistentFlags(PIVCmd)
	pivPKCS11SOPINSource.addPersistentFlags(PIVCmd)

	// Export command specific flags
	pivExportCmd.Flags().String("format", defaultPIVExportFormat,
		"Export format: pem or der")
	pivExportCmd.Flags().String("output", "",
		"Output file path (default: stdout)")

	// Delete command specific flags
	pivDeleteCmd.Flags().Bool("force", false,
		"Don't prompt for confirmation")
}

// defaultPIVStorageTypeForBackend returns the certificate storage type that
// matches backend when no explicit override is given: software backends
// store certificates in a file, tpm2/pkcs11 backends store them in the
// hardware they came from.
func defaultPIVStorageTypeForBackend(backend PIVBackendType) PIVStorageType {
	switch backend {
	case PIVBackendTPM2:
		return PIVStorageTypeTPM2
	case PIVBackendPKCS11:
		return PIVStorageTypePKCS11
	case PIVBackendSoftware:
		return PIVStorageTypeFile
	default:
		return PIVStorageTypeFile
	}
}

// pivConfigString resolves one PIV setting with the same precedence
// resolveXKMSdURL uses for the xkmsd endpoint (xkmsd_client.go): an explicit
// flag on cmd beats the unified xkey config's piv.<field> value, which
// already merges the XKEY_PIV_* environment variable and the config file's
// piv: section -- every leaf pkg/config declares is registered for both by
// registerConfigKeys (pkg/config/load.go). cmd may be nil.
//
// It reads the flag through commandFlagChangedString, not
// commandFlagString: three of these settings (backend, tpm-device,
// pkcs11-library) declare a non-empty flag default, and
// commandFlagString's "current value" contract -- right for --tls-ca, whose
// only meaningful states are "empty" and "set" -- would make that default
// win over the config source on every invocation that does not pass the
// flag, since an unset flag's "current value" is indistinguishable from an
// explicitly-set one once the config already saw the same string. Only a
// flag pflag itself marks Changed may out-rank the config/environment
// source (go-xkms#871).
func pivConfigString(cmd *cobra.Command, flagName, cfgValue string) string {
	return firstNonEmpty(commandFlagChangedString(cmd, flagName), cfgValue)
}

// commandFlagChangedString returns the flag's value only when it was
// explicitly set on the command line (see commandFlagChanged), and "" otherwise.
// cmd may be nil.
func commandFlagChangedString(cmd *cobra.Command, name string) string {
	if !commandFlagChanged(cmd, name) {
		return ""
	}
	return commandFlagString(cmd, name)
}

// resolvePIVPKCS11Secret resolves source (the PKCS#11 PIN or Security
// Officer PIN) the same way pin_input.go's pinSource.resolve does when cmd
// declares the stdin flag, checked with commandFlagBool (xkmsd_client.go) so
// this works whether cmd is the executed subcommand (the stdin flag arrives
// merged into cmd.Flags() by cobra's own flag parsing) or PIVCmd itself
// (which carries it directly on PersistentFlags() and is never executed with
// a RunE of its own). Commands outside the "piv" tree (cert, device listen,
// provision, auth login --piv) declare neither flag, so only the environment
// variable is consulted there -- never a config file or a generic
// environment binding, so the secret is never written to disk by "xkey
// config init" and never appears in "xkey config show" (go-xkms#871). cmd
// may be nil.
func resolvePIVPKCS11Secret(cmd *cobra.Command, source pinSource) (string, error) {
	fromStdin, err := commandFlagBool(cmd, source.stdinFlag)
	if err != nil {
		return "", err
	}
	if fromStdin {
		data, readErr := stdinReader()
		if readErr != nil {
			return "", &SentinelCauseError{Sentinel: ErrPINInputStdinRead, Cause: readErr}
		}
		pin := strings.TrimRight(string(data), "\r\n")
		if pin == "" {
			return "", source.stdinEmpty
		}
		return pin, nil
	}
	return strings.TrimSpace(os.Getenv(source.envVar)), nil
}

// pivStorageOverride resolves the piv-storage setting (flag, then the
// unified config's piv.storage) without the backend-matched default
// buildPIVConfig applies for an unset one. It is shared with
// listenPIVStorageProvider (device_listen.go), which recomputes the storage
// type for a phone-requested backend unless the operator pinned one
// explicitly -- the same "" check buildPIVConfig itself uses.
func pivStorageOverride(cmd *cobra.Command) string {
	var cfgPIV xkeyconfig.PIVConfig
	if cfg := GetConfig(); cfg != nil {
		cfgPIV = cfg.PIV
	}
	return pivConfigString(cmd, "piv-storage", cfgPIV.Storage)
}

// buildPIVConfig resolves the PIV certificate storage configuration for cmd:
// an explicit flag beats the unified xkey config, which beats the
// backend-matched storage default (go-xkms#871). cmd may be nil --
// listenPIVStorageProvider builds one per phone request rather than per CLI
// invocation -- in which case every flag resolves empty and the PKCS#11
// secrets resolve from their environment variable only.
func buildPIVConfig(cmd *cobra.Command) (*PIVConfig, error) {
	var cfgPIV xkeyconfig.PIVConfig
	if cfg := GetConfig(); cfg != nil {
		cfgPIV = cfg.PIV
	}

	backend := PIVBackendType(pivConfigString(cmd, "backend", cfgPIV.Backend))
	if backend == "" {
		backend = PIVBackendSoftware
	}

	storageType := PIVStorageType(pivStorageOverride(cmd))
	if storageType == "" {
		storageType = defaultPIVStorageTypeForBackend(backend)
	}

	pkcs11PIN, err := resolvePIVPKCS11Secret(cmd, pivPKCS11PINSource)
	if err != nil {
		return nil, err
	}
	pkcs11SOPIN, err := resolvePIVPKCS11Secret(cmd, pivPKCS11SOPINSource)
	if err != nil {
		return nil, err
	}

	return &PIVConfig{
		Backend:       backend,
		StorageType:   storageType,
		StoragePath:   pivConfigString(cmd, "storage-path", cfgPIV.StoragePath),
		TPMDevice:     pivConfigString(cmd, "tpm-device", cfgPIV.TPMDevice),
		PKCS11Library: pivConfigString(cmd, "pkcs11-library", cfgPIV.PKCS11Library),
		PKCS11Token:   pivConfigString(cmd, "pkcs11-token", cfgPIV.PKCS11Token),
		PKCS11PIN:     pkcs11PIN,
		PKCS11SOPIN:   pkcs11SOPIN,
	}, nil
}

// resolvePIVStoragePath returns cfg.StoragePath if the operator set one
// (--storage-path, XKEY_DATA_DIR, or the config data_dir key), otherwise
// resolves the PIV file-storage default through the CLI's single
// data-directory chain (datadir.go), creating it if necessary
// (go-xkms#929). cfg.StoragePath is updated with the resolved value so
// later readers (e.g. `piv status`) observe the same path.
func resolvePIVStoragePath(cfg *PIVConfig) (string, error) {
	if cfg.StoragePath != "" {
		return cfg.StoragePath, nil
	}
	dir, err := featureDataDir(pivStorageFeature)
	if err != nil {
		return "", err
	}
	cfg.StoragePath = dir
	return dir, nil
}

// createPIVStorage creates the appropriate certificate storage backend.
func createPIVStorage(cfg *PIVConfig, logger *slog.Logger) (xkms.PIVCertificateStorage, error) {
	// Resolve the file-storage default before validating: an unset
	// --storage-path must resolve through the shared xkey data directory,
	// not fail closed as "required" (go-xkms#929).
	if cfg.StorageType == PIVStorageTypeFile {
		if _, err := resolvePIVStoragePath(cfg); err != nil {
			return nil, err
		}
	}

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
		backend, err := xkms.NewFileStorageBackend(cfg.StoragePath)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create file storage backend", Err: err}
		}
		fileConfig := &xkms.PIVFileStorageConfig{
			Backend:    backend,
			DEREnabled: true,
			PEMEnabled: true,
		}
		return xkms.NewPIVFileBackend(fileConfig)

	case PIVStorageTypeTPM2:
		return createTPM2PIVStorage(cfg, logger)

	case PIVStorageTypePKCS11:
		return createPKCS11PIVStorage(cfg, logger)

	default:
		return nil, ErrPIVInvalidStorageType
	}
}

// runPIVList executes the piv list command.
func runPIVList(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	slots, err := storage.List()
	if err != nil {
		return errors.Join(ErrPIVListFailed, err)
	}

	if len(slots) == 0 {
		_, _ = fmt.Fprintln(out, "No certificates found in PIV slots.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "PIV Certificates (%d):\n\n", len(slots))

	for _, slot := range slots {
		slotName := xkms.PIVSlotName(slot.Slot)
		_, _ = fmt.Fprintf(out, "  Slot:        %s (%s)\n", slot.Slot, slotName)
		_, _ = fmt.Fprintf(out, "  Subject:     %s\n", slot.Subject)
		_, _ = fmt.Fprintf(out, "  Issuer:      %s\n", slot.Issuer)
		_, _ = fmt.Fprintf(out, "  Not Before:  %s\n", slot.NotBefore)
		_, _ = fmt.Fprintf(out, "  Not After:   %s\n", slot.NotAfter)
		_, _ = fmt.Fprintf(out, "  Algorithm:   %s\n", slot.Algorithm)
		if slot.Fingerprint != "" {
			_, _ = fmt.Fprintf(out, "  Fingerprint: %s\n", slot.Fingerprint)
		}
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// runPIVShow executes the piv show command.
func runPIVShow(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrPIVCertificateNotFound, err)
	}

	slotName := xkms.PIVSlotName(slot)
	_, _ = fmt.Fprintf(out, "PIV Certificate - Slot %s (%s)\n", slot, slotName)
	_, _ = fmt.Fprintf(out, "========================================\n\n")

	_, _ = fmt.Fprintf(out, "Subject:       %s\n", cert.Subject.String())
	_, _ = fmt.Fprintf(out, "Issuer:        %s\n", cert.Issuer.String())
	_, _ = fmt.Fprintf(out, "Serial Number: %s\n", cert.SerialNumber.String())
	_, _ = fmt.Fprintf(out, "Not Before:    %s\n", cert.NotBefore.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "Not After:     %s\n", cert.NotAfter.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
	_, _ = fmt.Fprintf(out, "Signature:     %s\n", cert.SignatureAlgorithm.String())

	if len(cert.DNSNames) > 0 {
		_, _ = fmt.Fprintf(out, "DNS Names:     %s\n", strings.Join(cert.DNSNames, ", "))
	}

	if len(cert.EmailAddresses) > 0 {
		_, _ = fmt.Fprintf(out, "Email:         %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	if cert.KeyUsage != 0 {
		_, _ = fmt.Fprintf(out, "Key Usage:     %s\n", formatKeyUsage(cert.KeyUsage))
	}

	if len(cert.ExtKeyUsage) > 0 {
		_, _ = fmt.Fprintf(out, "Ext Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	}

	_, _ = fmt.Fprintf(out, "Is CA:         %t\n", cert.IsCA)

	return nil
}

// runPIVStore executes the piv store command.
func runPIVStore(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}

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
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := storage.Store(slot, cert); err != nil {
		return errors.Join(ErrPIVStoreFailed, err)
	}

	slotName := xkms.PIVSlotName(slot)
	_, _ = fmt.Fprintf(out, "Certificate stored in slot %s (%s)\n", slot, slotName)
	_, _ = fmt.Fprintf(out, "  Subject:  %s\n", cert.Subject.CommonName)
	_, _ = fmt.Fprintf(out, "  Format:   %s\n", format)
	_, _ = fmt.Fprintf(out, "  Expires:  %s\n", cert.NotAfter.Format(time.RFC3339))

	return nil
}

// runPIVDelete executes the piv delete command.
func runPIVDelete(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}
	force, _ := cmd.Flags().GetBool("force")

	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// Check if certificate exists
	cert, err := storage.Retrieve(slot)
	if err != nil {
		return errors.Join(ErrPIVCertificateNotFound, err)
	}

	slotName := xkms.PIVSlotName(slot)

	if !force {
		_, _ = fmt.Fprintf(out, "Delete certificate from slot %s (%s)?\n", slot, slotName)
		_, _ = fmt.Fprintf(out, "  Subject: %s\n", cert.Subject.CommonName)
		_, _ = fmt.Fprintf(out, "  Expires: %s\n", cert.NotAfter.Format(time.RFC3339))
		_, _ = fmt.Fprint(out, "\nConfirm deletion [y/N]: ")

		var confirm string
		if _, err := fmt.Scanln(&confirm); err != nil {
			return nil // User cancelled
		}
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "y" && confirm != "yes" {
			_, _ = fmt.Fprintln(out, "Deletion cancelled.")
			return nil
		}
	}

	if err := storage.Delete(slot); err != nil {
		return errors.Join(ErrPIVDeleteFailed, err)
	}

	_, _ = fmt.Fprintf(out, "Certificate deleted from slot %s (%s)\n", slot, slotName)
	return nil
}

// runPIVExport executes the piv export command.
func runPIVExport(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}

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
	var pivFormat xkms.PIVCertFormat
	switch format {
	case CertFormatPEM:
		pivFormat = xkms.PIVFormatPEM
	case CertFormatDER:
		pivFormat = xkms.PIVFormatDER
	}

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	data, err := storage.Export(slot, pivFormat)
	if err != nil {
		return errors.Join(ErrPIVExportFailed, err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, data, 0600); err != nil {
			return errors.Join(ErrPIVExportFailed, err)
		}
		slotName := xkms.PIVSlotName(slot)
		_, _ = fmt.Fprintf(out, "Certificate exported from slot %s (%s) to %s\n", slot, slotName, outputPath)
	} else {
		// Write to stdout
		if _, err := os.Stdout.Write(data); err != nil {
			return errors.Join(ErrPIVExportFailed, err)
		}
	}

	return nil
}

// runPIVStatus executes the piv status command.
func runPIVStatus(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	logger := slog.Default()
	cfg, err := buildPIVConfig(cmd)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(out, "PIV Certificate Storage Status")
	_, _ = fmt.Fprintln(out, "==============================")
	_, _ = fmt.Fprintln(out)

	_, _ = fmt.Fprintf(out, "Key Backend:       %s\n", cfg.Backend)
	_, _ = fmt.Fprintf(out, "Storage Type:      %s\n", cfg.StorageType)

	switch cfg.StorageType {
	case PIVStorageTypeFile:
		storagePath, err := resolvePIVStoragePath(cfg)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "Storage Path:      %s\n", storagePath)
	case PIVStorageTypeTPM2:
		_, _ = fmt.Fprintf(out, "TPM Device:        %s\n", cfg.TPMDevice)
	case PIVStorageTypePKCS11:
		_, _ = fmt.Fprintf(out, "PKCS#11 Library:   %s\n", cfg.PKCS11Library)
		_, _ = fmt.Fprintf(out, "PKCS#11 Token:     %s\n", cfg.PKCS11Token)
	}

	_, _ = fmt.Fprintln(out)

	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		_, _ = fmt.Fprintf(out, "Storage Status:    Error - %v\n", err)
		return nil // Don't fail, just report status
	}
	defer func() {
		// This command's job is to report status, not to fail -- see the
		// "Don't fail, just report status" returns above and below. A
		// storage-close failure doesn't change what was already reported,
		// so it's warned about rather than turned into a command failure.
		if closeErr := storage.Close(); closeErr != nil {
			_, _ = fmt.Fprintf(out, "Warning: could not close PIV storage: %v\n", closeErr)
		}
	}()

	slots, err := storage.List()
	if err != nil {
		_, _ = fmt.Fprintf(out, "Storage Status:    Error listing certificates - %v\n", err)
		return nil
	}

	_, _ = fmt.Fprintln(out, "Slot Status:")
	_, _ = fmt.Fprintln(out)

	// Build map of occupied slots
	occupied := make(map[xkms.PIVSlot]xkms.PIVSlotInfo)
	for _, s := range slots {
		occupied[s.Slot] = s
	}

	// Display all slots
	allSlots := xkms.PIVPrimarySlots()

	for _, slot := range allSlots {
		slotName := xkms.PIVSlotName(slot)
		if info, ok := occupied[slot]; ok {
			_, _ = fmt.Fprintf(out, "  [%s] %s\n", slot, slotName)
			_, _ = fmt.Fprintf(out, "        Subject:  %s\n", info.Subject)
			_, _ = fmt.Fprintf(out, "        Expires:  %s\n", info.NotAfter)
		} else {
			_, _ = fmt.Fprintf(out, "  [%s] %s - Empty\n", slot, slotName)
		}
	}

	_, _ = fmt.Fprintf(out, "\nTotal Certificates: %d/4\n", len(slots))

	return nil
}

// parseCertificateAuto parses a certificate from PEM or DER format.
func parseCertificateAuto(data []byte) (*x509.Certificate, CertFormat, error) {
	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, "", &MessageError{Msg: fmt.Sprintf("invalid PEM block type: %s", block.Type)}
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
