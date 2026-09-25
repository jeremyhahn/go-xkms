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

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// FIDO2 type aliases to avoid circular imports
type fido2Device = struct {
	Path         string
	VendorID     uint16
	ProductID    uint16
	Manufacturer string
	Product      string
	SerialNumber string
	Transport    string
}

type fido2EnrollmentResult = struct {
	CredentialID []byte
	PublicKey    []byte
	AAGUID       []byte
	SignCount    uint32
	RelyingParty fido2RelyingParty
	User         fido2User
	Salt         []byte
	Created      time.Time
}

type fido2User = struct {
	ID          []byte
	Name        string
	DisplayName string
	Icon        string
}

type fido2RelyingParty = struct {
	ID   string
	Name string
	Icon string
}

// OutputFormat defines the output format type
type OutputFormat string

const (
	OutputFormatText  OutputFormat = "text"
	OutputFormatJSON  OutputFormat = "json"
	OutputFormatTable OutputFormat = "table"
)

// Printer handles formatted output
type Printer struct {
	format OutputFormat
	writer *outputWriter
}

// NewPrinter creates a new Printer
func NewPrinter(format string, writer io.Writer) *Printer {
	return &Printer{
		format: OutputFormat(format),
		writer: newOutputWriter(writer),
	}
}

// Err returns the first output-write error recorded across every call made
// through this Printer, if any.
func (p *Printer) Err() error {
	return p.writer.Err()
}

// printf writes a formatted line, recording rather than returning a write
// failure. See outputWriter.
func (p *Printer) printf(format string, a ...any) {
	p.writer.printf(format, a...)
}

// println writes a, terminated by a newline, recording rather than
// returning a write failure. See outputWriter.
func (p *Printer) println(a ...any) {
	p.writer.println(a...)
}

// PrintBackendList prints a list of backends
func (p *Printer) PrintBackendList(backends []string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"backends": backends,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println("Available Backends:")
		for _, b := range backends {
			p.writer.printf("  - %s\n", b)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintBackendInfo prints detailed backend information
func (p *Printer) PrintBackendInfo(backendName string, caps client.Capabilities) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"backend": backendName,
			"capabilities": map[string]interface{}{
				"keys":            caps.Keys,
				"hardware_backed": caps.HardwareBacked,
				"signing":         caps.Signing,
				"decryption":      caps.Decryption,
				"key_rotation":    caps.KeyRotation,
			},
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.printf("Backend: %s\n", backendName)
		p.writer.println("Capabilities:")
		p.writer.printf("  Keys:            %t\n", caps.Keys)
		p.writer.printf("  Hardware Backed: %t\n", caps.HardwareBacked)
		p.writer.printf("  Signing:         %t\n", caps.Signing)
		p.writer.printf("  Decryption:      %t\n", caps.Decryption)
		p.writer.printf("  Key Rotation:    %t\n", caps.KeyRotation)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintKeyList prints a list of keys
func (p *Printer) PrintKeyList(keys []*client.KeyAttributes) error {
	switch p.format {
	case OutputFormatJSON:
		keyList := make([]map[string]interface{}, len(keys))
		for i, key := range keys {
			keyList[i] = map[string]interface{}{
				"cn":        key.CN,
				"type":      key.KeyType,
				"algorithm": key.KeyAlgorithm,
				"store":     key.StoreType,
			}
		}
		return p.printJSON(map[string]interface{}{
			"keys": keyList,
		})
	case OutputFormatTable:
		if len(keys) == 0 {
			p.writer.println("No keys found")
			return p.writer.Err()
		}
		p.writer.printf("%-30s %-15s %-15s %-10s\n", "CN", "TYPE", "ALGORITHM", "STORE")
		p.writer.println(strings.Repeat("-", 72))
		for _, key := range keys {
			p.writer.printf("%-30s %-15s %-15s %-10s\n",
				key.CN, key.KeyType, key.KeyAlgorithm, key.StoreType)
		}
		return p.writer.Err()
	case OutputFormatText:
		if len(keys) == 0 {
			p.writer.println("No keys found")
			return p.writer.Err()
		}
		p.writer.println("Keys:")
		for _, key := range keys {
			p.writer.printf("  - %s (%s, %s)\n", key.CN, key.KeyAlgorithm, key.KeyType)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintKeyInfo prints detailed key information
func (p *Printer) PrintKeyInfo(key *client.KeyAttributes) error {
	switch p.format {
	case OutputFormatJSON:
		info := map[string]interface{}{
			"cn":        key.CN,
			"type":      key.KeyType,
			"algorithm": key.KeyAlgorithm,
			"store":     key.StoreType,
			"hash":      key.Hash,
		}
		if key.Partition != "" {
			info["partition"] = key.Partition
		}
		if key.RSAAttributes != nil {
			info["rsa_key_size"] = key.RSAAttributes.KeySize
		}
		if key.ECCAttributes != nil {
			info["ecc_curve"] = key.ECCAttributes.Curve
		}
		return p.printJSON(info)
	case OutputFormatTable, OutputFormatText:
		p.writer.printf("Key Information:\n")
		p.writer.printf("  CN:        %s\n", key.CN)
		p.writer.printf("  Type:      %s\n", key.KeyType)
		p.writer.printf("  Algorithm: %s\n", key.KeyAlgorithm)
		p.writer.printf("  Store:     %s\n", key.StoreType)
		p.writer.printf("  Hash:      %s\n", key.Hash)
		if key.Partition != "" {
			p.writer.printf("  Partition: %s\n", key.Partition)
		}
		if key.RSAAttributes != nil {
			p.writer.printf("  RSA Size:  %d bits\n", key.RSAAttributes.KeySize)
		}
		if key.ECCAttributes != nil {
			p.writer.printf("  ECC Curve: %s\n", key.ECCAttributes.Curve)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintSuccess prints a success message
func (p *Printer) PrintSuccess(message string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"status":  "success",
			"message": message,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println(message)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintError prints an error message
func (p *Printer) PrintError(err error) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.printf("Error: %v\n", err)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintSignature prints a signature (base64 encoded)
func (p *Printer) PrintSignature(signature string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"signature": signature,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println(signature)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintDecryptedData prints decrypted data (base64 encoded)
func (p *Printer) PrintDecryptedData(plaintext string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"plaintext": plaintext,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println(plaintext)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintEncryptedData prints encrypted data (ciphertext, nonce, tag all base64 encoded)
func (p *Printer) PrintEncryptedData(data *client.EncryptedData) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(data.Ciphertext),
			"nonce":      base64.StdEncoding.EncodeToString(data.Nonce),
			"tag":        base64.StdEncoding.EncodeToString(data.Tag),
			"algorithm":  data.Algorithm,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(data.Ciphertext))
		p.writer.printf("Nonce:      %s\n", base64.StdEncoding.EncodeToString(data.Nonce))
		p.writer.printf("Tag:        %s\n", base64.StdEncoding.EncodeToString(data.Tag))
		p.writer.printf("Algorithm:  %s\n", data.Algorithm)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintCertificate prints a certificate in PEM format
func (p *Printer) PrintCertificate(cert *x509.Certificate) error {
	switch p.format {
	case OutputFormatJSON:
		certInfo := map[string]interface{}{
			"subject":       cert.Subject.String(),
			"issuer":        cert.Issuer.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before":    cert.NotBefore.String(),
			"not_after":     cert.NotAfter.String(),
			"dns_names":     cert.DNSNames,
		}
		return p.printJSON(certInfo)
	case OutputFormatTable, OutputFormatText:
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		p.writer.print(string(pemBytes))
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintCertList prints a list of certificate IDs
func (p *Printer) PrintCertList(certIDs []string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"certificates": certIDs,
		})
	case OutputFormatTable:
		if len(certIDs) == 0 {
			p.writer.println("No certificates found")
			return p.writer.Err()
		}
		p.writer.printf("%-50s\n", "CERTIFICATE ID")
		p.writer.println(strings.Repeat("-", 50))
		for _, id := range certIDs {
			p.writer.printf("%-50s\n", id)
		}
		return p.writer.Err()
	case OutputFormatText:
		if len(certIDs) == 0 {
			p.writer.println("No certificates found")
			return p.writer.Err()
		}
		p.writer.println("Certificates:")
		for _, id := range certIDs {
			p.writer.printf("  - %s\n", id)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintCertExists prints certificate existence status
func (p *Printer) PrintCertExists(keyID string, exists bool) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"key_id": keyID,
			"exists": exists,
		})
	case OutputFormatTable, OutputFormatText:
		if exists {
			p.writer.printf("Certificate exists for key: %s\n", keyID)
		} else {
			p.writer.printf("Certificate does not exist for key: %s\n", keyID)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintCertChain prints a certificate chain in PEM format
func (p *Printer) PrintCertChain(chain []*x509.Certificate) error {
	switch p.format {
	case OutputFormatJSON:
		chainInfo := make([]map[string]interface{}, len(chain))
		for i, cert := range chain {
			chainInfo[i] = map[string]interface{}{
				"subject":       cert.Subject.String(),
				"issuer":        cert.Issuer.String(),
				"serial_number": cert.SerialNumber.String(),
				"not_before":    cert.NotBefore.String(),
				"not_after":     cert.NotAfter.String(),
			}
		}
		return p.printJSON(map[string]interface{}{
			"chain": chainInfo,
		})
	case OutputFormatTable, OutputFormatText:
		for i, cert := range chain {
			if i > 0 {
				p.writer.println()
			}
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			pemBytes := pem.EncodeToMemory(pemBlock)
			p.writer.print(string(pemBytes))
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintTLSCertificate prints a TLS certificate and its chain. The private
// key is never included: it stays in the backend that holds it.
func (p *Printer) PrintTLSCertificate(cert *x509.Certificate, chain []*x509.Certificate) error {
	switch p.format {
	case OutputFormatJSON:
		certInfo := map[string]interface{}{
			"subject":       cert.Subject.String(),
			"issuer":        cert.Issuer.String(),
			"serial_number": cert.SerialNumber.String(),
			"not_before":    cert.NotBefore.String(),
			"not_after":     cert.NotAfter.String(),
			"dns_names":     cert.DNSNames,
		}
		result := map[string]interface{}{
			"certificate": certInfo,
		}
		if len(chain) > 0 {
			chainInfo := make([]map[string]interface{}, len(chain))
			for i, c := range chain {
				chainInfo[i] = map[string]interface{}{
					"subject": c.Subject.String(),
					"issuer":  c.Issuer.String(),
				}
			}
			result["chain_length"] = len(chain)
			result["chain"] = chainInfo
		}
		return p.printJSON(result)
	case OutputFormatTable, OutputFormatText:
		p.writer.println("TLS Certificate:")
		p.writer.printf("  Subject: %s\n", cert.Subject.String())
		p.writer.printf("  Issuer: %s\n", cert.Issuer.String())
		p.writer.printf("  Valid From: %s\n", cert.NotBefore.String())
		p.writer.printf("  Valid Until: %s\n", cert.NotAfter.String())
		if len(chain) > 0 {
			p.writer.printf("  Chain Length: %d\n", len(chain))
		}
		p.writer.println("\nCertificate PEM:")
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		p.writer.print(string(pemBytes))

		// Print chain if present
		if len(chain) > 0 {
			p.writer.println("\nCertificate Chain:")
			for i, chainCert := range chain {
				p.writer.printf("\nChain Certificate #%d:\n", i+1)
				pemBlock := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: chainCert.Raw,
				}
				pemBytes := pem.EncodeToMemory(pemBlock)
				p.writer.print(string(pemBytes))
			}
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintImportParameters prints import parameters
func (p *Printer) PrintImportParameters(params *client.ImportParameters) error {
	switch p.format {
	case OutputFormatJSON:
		// For JSON, we need to handle the crypto.PublicKey specially
		data := map[string]interface{}{
			"algorithm": params.Algorithm,
			"key_spec":  params.KeySpec,
		}
		if params.ExpiresAt != nil {
			data["expires_at"] = params.ExpiresAt.String()
		}
		if params.ImportToken != nil {
			data["import_token"] = base64.StdEncoding.EncodeToString(params.ImportToken)
		}
		return p.printJSON(data)

	case OutputFormatTable, OutputFormatText:
		p.writer.printf("Import Parameters:\n")
		p.writer.printf("  Algorithm:    %s\n", params.Algorithm)
		p.writer.printf("  Key Spec:     %s\n", params.KeySpec)
		if params.ExpiresAt != nil {
			p.writer.printf("  Expires At:   %s\n", params.ExpiresAt.String())
		}
		if params.ImportToken != nil {
			p.writer.printf("  Import Token: %d bytes\n", len(params.ImportToken))
		}
		if params.WrappingPublicKey != nil {
			p.writer.printf("  Wrapping Key: %T\n", params.WrappingPublicKey)
		}
		return p.writer.Err()

	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintEncryptedAsym prints asymmetrically encrypted data (base64 encoded)
func (p *Printer) PrintEncryptedAsym(ciphertext string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"ciphertext": ciphertext,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println(ciphertext)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintMessage prints a simple message
func (p *Printer) PrintMessage(message string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"message": message,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println(message)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintWarning prints a security warning. A warning is not data, so in JSON
// mode it goes to standard error rather than into the structured output
// stream, where it would corrupt the document; either way the operator sees
// it.
func (p *Printer) PrintWarning(message string) error {
	switch p.format {
	case OutputFormatJSON:
		if _, err := fmt.Fprintln(os.Stderr, "WARNING: "+message); err != nil {
			return err
		}
		return p.writer.Err()
	case OutputFormatTable, OutputFormatText:
		p.writer.println("WARNING: " + message)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintPrompt prints a user-facing prompt message.
// In JSON format, this is a no-op since prompts are not machine-readable data.
// In text/table format, the message is printed normally.
func (p *Printer) PrintPrompt(message string) error {
	switch p.format {
	case OutputFormatJSON:
		// Skip prompts in JSON mode - they're not structured data
		return p.writer.Err()
	case OutputFormatTable, OutputFormatText:
		p.writer.println(message)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintFIDO2Devices prints a list of FIDO2 devices
func (p *Printer) PrintFIDO2Devices(devices []fido2Device) error {
	switch p.format {
	case OutputFormatJSON:
		deviceList := make([]map[string]interface{}, len(devices))
		for i, dev := range devices {
			deviceList[i] = map[string]interface{}{
				"path":         dev.Path,
				"vendor_id":    fmt.Sprintf("0x%04X", dev.VendorID),
				"product_id":   fmt.Sprintf("0x%04X", dev.ProductID),
				"manufacturer": dev.Manufacturer,
				"product":      dev.Product,
				"transport":    dev.Transport,
			}
		}
		return p.printJSON(map[string]interface{}{
			"devices": deviceList,
		})
	case OutputFormatTable:
		p.writer.printf("%-20s %-10s %-10s %-25s %-25s\n",
			"PATH", "VENDOR", "PRODUCT", "MANUFACTURER", "NAME")
		p.writer.println(strings.Repeat("-", 92))
		for _, dev := range devices {
			p.writer.printf("%-20s 0x%04X     0x%04X     %-25s %-25s\n",
				dev.Path, dev.VendorID, dev.ProductID,
				truncateString(dev.Manufacturer, 25),
				truncateString(dev.Product, 25))
		}
		return p.writer.Err()
	case OutputFormatText:
		p.writer.println("FIDO2 Devices:")
		for _, dev := range devices {
			p.writer.printf("  - %s\n", dev.Path)
			p.writer.printf("    Product:      %s\n", dev.Product)
			p.writer.printf("    Manufacturer: %s\n", dev.Manufacturer)
			p.writer.printf("    Vendor ID:    0x%04X\n", dev.VendorID)
			p.writer.printf("    Product ID:   0x%04X\n", dev.ProductID)
			p.writer.printf("    Transport:    %s\n", dev.Transport)
		}
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintFIDO2DeviceInfo prints detailed information about a FIDO2 device
func (p *Printer) PrintFIDO2DeviceInfo(dev fido2Device) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"path":          dev.Path,
			"vendor_id":     fmt.Sprintf("0x%04X", dev.VendorID),
			"product_id":    fmt.Sprintf("0x%04X", dev.ProductID),
			"manufacturer":  dev.Manufacturer,
			"product":       dev.Product,
			"serial_number": dev.SerialNumber,
			"transport":     dev.Transport,
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println("FIDO2 Device Information:")
		p.writer.printf("  Path:          %s\n", dev.Path)
		p.writer.printf("  Product:       %s\n", dev.Product)
		p.writer.printf("  Manufacturer:  %s\n", dev.Manufacturer)
		p.writer.printf("  Vendor ID:     0x%04X\n", dev.VendorID)
		p.writer.printf("  Product ID:    0x%04X\n", dev.ProductID)
		if dev.SerialNumber != "" {
			p.writer.printf("  Serial Number: %s\n", dev.SerialNumber)
		}
		p.writer.printf("  Transport:     %s\n", dev.Transport)
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// PrintFIDO2Registration prints FIDO2 credential registration result
func (p *Printer) PrintFIDO2Registration(result *fido2EnrollmentResult) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"credential_id": base64.StdEncoding.EncodeToString(result.CredentialID),
			"public_key":    base64.StdEncoding.EncodeToString(result.PublicKey),
			"aaguid":        base64.StdEncoding.EncodeToString(result.AAGUID),
			"salt":          base64.StdEncoding.EncodeToString(result.Salt),
			"user_name":     result.User.Name,
			"user_display":  result.User.DisplayName,
			"relying_party": result.RelyingParty.ID,
			"created":       result.Created.Format("2006-01-02T15:04:05Z07:00"),
		})
	case OutputFormatTable, OutputFormatText:
		p.writer.println("FIDO2 Credential Registration Successful!")
		p.writer.println("")
		p.writer.println("Credential Information:")
		p.writer.printf("  User:          %s (%s)\n", result.User.Name, result.User.DisplayName)
		p.writer.printf("  Relying Party: %s\n", result.RelyingParty.ID)
		p.writer.printf("  Created:       %s\n", result.Created.Format("2006-01-02 15:04:05"))
		p.writer.println("")
		p.writer.println("Store these values securely for authentication:")
		p.writer.printf("  Credential ID: %s\n", base64.StdEncoding.EncodeToString(result.CredentialID))
		p.writer.printf("  Salt:          %s\n", base64.StdEncoding.EncodeToString(result.Salt))
		return p.writer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(p.format)}
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// PrintJSON prints data as JSON (public wrapper)
func (p *Printer) PrintJSON(data interface{}) error {
	return p.printJSON(data)
}

// printJSON prints data as JSON
func (p *Printer) printJSON(data interface{}) error {
	encoder := json.NewEncoder(p.writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return err
	}
	return p.writer.Err()
}
