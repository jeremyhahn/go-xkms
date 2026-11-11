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

// Command certgen writes a throwaway self-signed certificate/key pair for the
// acme-tpm integration lane's dedicated ACME HTTPS listener
// (pkg/config.ACMEConfig.TLS requires pre-existing PEM files on disk; xkmsd
// does not generate them itself the way it does for its primary listener).
//
// With -ca it instead writes a self-signed CA certificate/key pair: the
// software-TPM EK root the acme-tpm suite signs every swtpm EK certificate
// with (swtpm_helper_test.go's swtpmTestEKIssuer) and the acme-server trusts
// (config.acme-tpm.yaml). The Makefile's integration-test-acme-tpm target
// generates it fresh on every run, before the stack starts, so no private
// key is ever committed (#1993).
//
// It is deliberately stdlib-only (crypto/*, encoding/pem) so the acme-server
// compose service can run it with `go run` against the source tree already
// baked into the image, with no external dependency fetch and no reliance on
// an `openssl` binary being present in the runtime image.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certPath := flag.String("cert", "", "output path for the PEM-encoded certificate (required)")
	keyPath := flag.String("key", "", "output path for the PEM-encoded private key (required)")
	commonName := flag.String("cn", "localhost", "certificate common name and primary DNS SAN")
	validDays := flag.Int("days", 1, "certificate validity, in days")
	ca := flag.Bool("ca", false, "write a self-signed CA certificate (the swtpm EK root) instead of a TLS server leaf")
	flag.Parse()

	if err := run(*certPath, *keyPath, *commonName, *validDays, *ca); err != nil {
		fmt.Fprintf(os.Stderr, "certgen: %v\n", err)
		os.Exit(1)
	}
}

func run(certPath, keyPath, commonName string, validDays int, ca bool) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("-cert and -key are required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName, "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	if ca {
		template.Subject = pkix.Name{Organization: []string{"swtpm-test"}, CommonName: commonName}
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = nil
		template.DNSNames = nil
		template.IPAddresses = nil
		template.BasicConstraintsValid = true
		template.IsCA = true
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}
