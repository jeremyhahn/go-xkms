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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/spf13/cobra"
)

// PIV certificate import command errors.
var (
	// ErrPIVCertImportFailed indicates the certificate import operation failed.
	ErrPIVCertImportFailed = errors.New("piv: certificate import failed")

	// ErrPIVCertReadFailed indicates the certificate file could not be read.
	ErrPIVCertReadFailed = errors.New("piv: failed to read certificate file")

	// ErrPIVCertParseFailed indicates the certificate could not be parsed.
	ErrPIVCertParseFailed = errors.New("piv: failed to parse certificate")

	// ErrPIVCertKeyMismatch indicates the certificate does not match the slot's public key.
	ErrPIVCertKeyMismatch = errors.New("piv: certificate does not match slot's public key")

	// ErrPIVNoCertificateInFile indicates no certificate was found in the file.
	ErrPIVNoCertificateInFile = errors.New("piv: no certificate found in file")

	// ErrPIVSlotKeyNotFound indicates no key exists in the specified slot for verification.
	ErrPIVSlotKeyNotFound = errors.New("piv: no key found in slot for verification")

	// ErrPIVVerificationFailed indicates certificate verification against slot key failed.
	ErrPIVVerificationFailed = errors.New("piv: certificate verification failed")
)

// pivImportCmd imports a certificate into a PIV slot.
var pivImportCmd = &cobra.Command{
	Use:   "import <slot> <cert-file>",
	Short: "Import a certificate into a PIV slot",
	Long: `Import a PEM-encoded certificate into the specified PIV slot.

The certificate must match the key already in the slot.
This command is typically used after receiving a signed certificate
from a Certificate Authority.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Example:
  xkey piv import 9a my-auth-cert.pem
  xkey piv import 9c signing-cert.crt --verify`,
	Args: cobra.ExactArgs(2),
	RunE: runPivImport,
}

func init() {
	// Add import command to PIV parent command
	PIVCmd.AddCommand(pivImportCmd)

	// Add flags
	pivImportCmd.Flags().Bool("verify", true, "Verify certificate matches slot's public key")
	pivImportCmd.Flags().BoolP("force", "f", false, "Import even if verification fails")
}

// runPivImport executes the piv import command.
func runPivImport(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	cfg := buildPIVConfig()

	// Parse slot argument
	slot, err := validatePIVSlot(args[0])
	if err != nil {
		return err
	}

	certFile := args[1]

	// Get flag values
	verify, _ := cmd.Flags().GetBool("verify")
	force, _ := cmd.Flags().GetBool("force")

	// Load certificate from file
	cert, err := loadCertificateFromFile(certFile)
	if err != nil {
		return err
	}

	logger.Info("importing certificate into PIV slot",
		slog.String("slot", string(slot)),
		slog.String("subject", cert.Subject.CommonName),
		slog.Bool("verify", verify),
	)

	// Create storage backend
	storage, err := createPIVStorage(cfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}
	defer func() { _ = storage.Close() }()

	// Verify certificate matches slot's public key if requested
	if verify {
		verifyErr := verifyCertMatchesSlotKey(storage, cert, slot)
		if verifyErr != nil {
			if force {
				logger.Warn("certificate verification failed, proceeding with --force",
					slog.String("error", verifyErr.Error()),
				)
			} else {
				return verifyErr
			}
		}
	}

	// Import certificate into the slot
	if err := storage.Store(slot, cert); err != nil {
		return errors.Join(ErrPIVCertImportFailed, err)
	}

	// Print success message with certificate info
	slotName := pivcert.SlotName(slot)
	fmt.Printf("Certificate imported into slot %s (%s)\n", slot, slotName)
	fmt.Print(formatCertInfo(cert))

	return nil
}

// loadCertificateFromFile reads and parses a certificate from a file.
// Supports both PEM and DER encoded certificates.
func loadCertificateFromFile(path string) (*x509.Certificate, error) {
	// Read certificate file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Join(ErrPIVCertReadFailed, err)
	}

	// Try PEM decoding first
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: invalid PEM block type: %s", ErrPIVCertParseFailed, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Join(ErrPIVCertParseFailed, err)
		}
		return cert, nil
	}

	// Try DER encoding
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, errors.Join(ErrPIVNoCertificateInFile, err)
	}

	return cert, nil
}

// verifyCertMatchesSlotKey verifies that the certificate's public key matches
// the public key stored in the PIV slot.
func verifyCertMatchesSlotKey(storage pivcert.PIVCertificateStorage, cert *x509.Certificate, slot pivcert.PIVSlot) error {
	// Retrieve existing certificate from slot to get its public key
	existingCert, err := storage.Retrieve(slot)
	if err != nil {
		if errors.Is(err, pivcert.ErrCertificateNotFound) {
			return errors.Join(ErrPIVSlotKeyNotFound, err)
		}
		return errors.Join(ErrPIVVerificationFailed, err)
	}

	// Compare public keys
	if !publicKeysEqual(cert.PublicKey, existingCert.PublicKey) {
		return ErrPIVCertKeyMismatch
	}

	return nil
}

// publicKeysEqual compares two public keys for equality.
func publicKeysEqual(pub1, pub2 crypto.PublicKey) bool {
	switch key1 := pub1.(type) {
	case *rsa.PublicKey:
		key2, ok := pub2.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return key1.N.Cmp(key2.N) == 0 && key1.E == key2.E

	case *ecdsa.PublicKey:
		key2, ok := pub2.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return key1.Curve == key2.Curve &&
			key1.X.Cmp(key2.X) == 0 &&
			key1.Y.Cmp(key2.Y) == 0

	default:
		// For other key types, marshal and compare bytes
		bytes1, err1 := x509.MarshalPKIXPublicKey(pub1)
		bytes2, err2 := x509.MarshalPKIXPublicKey(pub2)
		if err1 != nil || err2 != nil {
			return false
		}
		if len(bytes1) != len(bytes2) {
			return false
		}
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				return false
			}
		}
		return true
	}
}

// formatCertInfo returns a formatted string with certificate details.
func formatCertInfo(cert *x509.Certificate) string {
	var result string

	// Subject
	subject := cert.Subject.String()
	if subject == "" {
		subject = cert.Subject.CommonName
	}
	result += fmt.Sprintf("Subject: %s\n", subject)

	// Issuer
	issuer := cert.Issuer.String()
	if issuer == "" {
		issuer = cert.Issuer.CommonName
	}
	result += fmt.Sprintf("Issuer: %s\n", issuer)

	// Validity period
	result += fmt.Sprintf("Valid: %s to %s\n",
		cert.NotBefore.Format(time.DateOnly),
		cert.NotAfter.Format(time.DateOnly),
	)

	// Serial number
	result += fmt.Sprintf("Serial: %s\n", cert.SerialNumber.String())

	return result
}
