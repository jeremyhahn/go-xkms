// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cli

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

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
	writer io.Writer
}

// NewPrinter creates a new Printer
func NewPrinter(format string, writer io.Writer) *Printer {
	return &Printer{
		format: OutputFormat(format),
		writer: writer,
	}
}

// PrintBackendList prints a list of backends
func (p *Printer) PrintBackendList(backends []string) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"backends": backends,
		})
	case OutputFormatTable, OutputFormatText:
		fmt.Fprintln(p.writer, "Available Backends:")
		for _, b := range backends {
			fmt.Fprintf(p.writer, "  - %s\n", b)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintBackendInfo prints detailed backend information
func (p *Printer) PrintBackendInfo(backendName string, caps types.Capabilities) error {
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
		fmt.Fprintf(p.writer, "Backend: %s\n", backendName)
		fmt.Fprintln(p.writer, "Capabilities:")
		fmt.Fprintf(p.writer, "  Keys:            %t\n", caps.Keys)
		fmt.Fprintf(p.writer, "  Hardware Backed: %t\n", caps.HardwareBacked)
		fmt.Fprintf(p.writer, "  Signing:         %t\n", caps.Signing)
		fmt.Fprintf(p.writer, "  Decryption:      %t\n", caps.Decryption)
		fmt.Fprintf(p.writer, "  Key Rotation:    %t\n", caps.KeyRotation)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintKeyList prints a list of keys
func (p *Printer) PrintKeyList(keys []*types.KeyAttributes) error {
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
			fmt.Fprintln(p.writer, "No keys found")
			return nil
		}
		fmt.Fprintf(p.writer, "%-30s %-15s %-15s %-10s\n", "CN", "TYPE", "ALGORITHM", "STORE")
		fmt.Fprintln(p.writer, strings.Repeat("-", 72))
		for _, key := range keys {
			fmt.Fprintf(p.writer, "%-30s %-15s %-15s %-10s\n",
				key.CN, key.KeyType, key.KeyAlgorithm, key.StoreType)
		}
		return nil
	case OutputFormatText:
		if len(keys) == 0 {
			fmt.Fprintln(p.writer, "No keys found")
			return nil
		}
		fmt.Fprintln(p.writer, "Keys:")
		for _, key := range keys {
			fmt.Fprintf(p.writer, "  - %s (%s, %s)\n", key.CN, key.KeyAlgorithm, key.KeyType)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintKeyInfo prints detailed key information
func (p *Printer) PrintKeyInfo(key *types.KeyAttributes) error {
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
		fmt.Fprintf(p.writer, "Key Information:\n")
		fmt.Fprintf(p.writer, "  CN:        %s\n", key.CN)
		fmt.Fprintf(p.writer, "  Type:      %s\n", key.KeyType)
		fmt.Fprintf(p.writer, "  Algorithm: %s\n", key.KeyAlgorithm)
		fmt.Fprintf(p.writer, "  Store:     %s\n", key.StoreType)
		fmt.Fprintf(p.writer, "  Hash:      %s\n", key.Hash)
		if key.Partition != "" {
			fmt.Fprintf(p.writer, "  Partition: %s\n", key.Partition)
		}
		if key.RSAAttributes != nil {
			fmt.Fprintf(p.writer, "  RSA Size:  %d bits\n", key.RSAAttributes.KeySize)
		}
		if key.ECCAttributes != nil {
			fmt.Fprintf(p.writer, "  ECC Curve: %s\n", key.ECCAttributes.Curve)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprintln(p.writer, message)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprintf(p.writer, "Error: %v\n", err)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprintln(p.writer, signature)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprintln(p.writer, plaintext)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintEncryptedData prints encrypted data (ciphertext, nonce, tag all base64 encoded)
func (p *Printer) PrintEncryptedData(data *types.EncryptedData) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(data.Ciphertext),
			"nonce":      base64.StdEncoding.EncodeToString(data.Nonce),
			"tag":        base64.StdEncoding.EncodeToString(data.Tag),
			"algorithm":  data.Algorithm,
		})
	case OutputFormatTable, OutputFormatText:
		fmt.Fprintf(p.writer, "Ciphertext: %s\n", base64.StdEncoding.EncodeToString(data.Ciphertext))
		fmt.Fprintf(p.writer, "Nonce:      %s\n", base64.StdEncoding.EncodeToString(data.Nonce))
		fmt.Fprintf(p.writer, "Tag:        %s\n", base64.StdEncoding.EncodeToString(data.Tag))
		fmt.Fprintf(p.writer, "Algorithm:  %s\n", data.Algorithm)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprint(p.writer, string(pemBytes))
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
			fmt.Fprintln(p.writer, "No certificates found")
			return nil
		}
		fmt.Fprintf(p.writer, "%-50s\n", "CERTIFICATE ID")
		fmt.Fprintln(p.writer, strings.Repeat("-", 50))
		for _, id := range certIDs {
			fmt.Fprintf(p.writer, "%-50s\n", id)
		}
		return nil
	case OutputFormatText:
		if len(certIDs) == 0 {
			fmt.Fprintln(p.writer, "No certificates found")
			return nil
		}
		fmt.Fprintln(p.writer, "Certificates:")
		for _, id := range certIDs {
			fmt.Fprintf(p.writer, "  - %s\n", id)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
			fmt.Fprintf(p.writer, "Certificate exists for key: %s\n", keyID)
		} else {
			fmt.Fprintf(p.writer, "Certificate does not exist for key: %s\n", keyID)
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
				fmt.Fprintln(p.writer)
			}
			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			pemBytes := pem.EncodeToMemory(pemBlock)
			fmt.Fprint(p.writer, string(pemBytes))
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintTLSCertificate prints a TLS certificate (key + cert + chain)
func (p *Printer) PrintTLSCertificate(key interface{}, cert *x509.Certificate, chain []*x509.Certificate) error {
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
			"key_type":    fmt.Sprintf("%T", key),
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
		fmt.Fprintln(p.writer, "TLS Certificate:")
		fmt.Fprintf(p.writer, "  Key Type: %T\n", key)
		fmt.Fprintf(p.writer, "  Subject: %s\n", cert.Subject.String())
		fmt.Fprintf(p.writer, "  Issuer: %s\n", cert.Issuer.String())
		fmt.Fprintf(p.writer, "  Valid From: %s\n", cert.NotBefore.String())
		fmt.Fprintf(p.writer, "  Valid Until: %s\n", cert.NotAfter.String())
		if len(chain) > 0 {
			fmt.Fprintf(p.writer, "  Chain Length: %d\n", len(chain))
		}
		fmt.Fprintln(p.writer, "\nCertificate PEM:")
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		fmt.Fprint(p.writer, string(pemBytes))

		// Print chain if present
		if len(chain) > 0 {
			fmt.Fprintln(p.writer, "\nCertificate Chain:")
			for i, chainCert := range chain {
				fmt.Fprintf(p.writer, "\nChain Certificate #%d:\n", i+1)
				pemBlock := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: chainCert.Raw,
				}
				pemBytes := pem.EncodeToMemory(pemBlock)
				fmt.Fprint(p.writer, string(pemBytes))
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// PrintImportParameters prints import parameters
func (p *Printer) PrintImportParameters(params *backend.ImportParameters) error {
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
		fmt.Fprintf(p.writer, "Import Parameters:\n")
		fmt.Fprintf(p.writer, "  Algorithm:    %s\n", params.Algorithm)
		fmt.Fprintf(p.writer, "  Key Spec:     %s\n", params.KeySpec)
		if params.ExpiresAt != nil {
			fmt.Fprintf(p.writer, "  Expires At:   %s\n", params.ExpiresAt.String())
		}
		if params.ImportToken != nil {
			fmt.Fprintf(p.writer, "  Import Token: %d bytes\n", len(params.ImportToken))
		}
		if params.WrappingPublicKey != nil {
			fmt.Fprintf(p.writer, "  Wrapping Key: %T\n", params.WrappingPublicKey)
		}
		return nil

	default:
		return fmt.Errorf("unknown output format: %s", p.format)
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
		fmt.Fprintln(p.writer, ciphertext)
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", p.format)
	}
}

// printJSON prints data as JSON
func (p *Printer) printJSON(data interface{}) error {
	encoder := json.NewEncoder(p.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}
