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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// deviceEnrollCmd enrolls this device with a master xKey instance.
var deviceEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll with a master xKey instance",
	Long: `Enroll this device as a remote agent with a master xKey instance.
On success, a client certificate is saved for mTLS authentication.

Examples:
  # Enroll with admin approval (requires admin to approve on master)
  xkey device enroll --server master.example.com:9443

  # Enroll with one-time code (code generated on master)
  xkey device enroll --server master.example.com:9443 --code ABCD1234`,
	RunE: runDeviceEnroll,
}

// deviceConnectCmd connects to a previously enrolled master.
var deviceConnectCmd = &cobra.Command{
	Use:   "connect <address>",
	Short: "Connect to a paired master",
	Long: `Connect to a previously enrolled master xKey instance using
the certificate obtained during enrollment.

Examples:
  xkey device connect master.example.com:9443`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceConnect,
}

// runDeviceEnroll enrolls this device with a master xKey instance.
func runDeviceEnroll(cmd *cobra.Command, args []string) error {
	serverAddr, _ := cmd.Flags().GetString("server")
	code, _ := cmd.Flags().GetString("code")
	name, _ := cmd.Flags().GetString("name")

	if serverAddr == "" {
		return fmt.Errorf("%w: --server is required", ErrAgentEnrollFailed)
	}

	if name == "" {
		hostname, err := os.Hostname()
		if err != nil {
			name = "agent"
		} else {
			name = hostname
		}
	}

	// Generate a key pair and CSR.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCSRFailed, err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"xKey Agent"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCSRFailed, err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Connect to master for enrollment.
	clientCfg := agent.DefaultClientConfig()
	clientCfg.MasterAddress = serverAddr
	clientCfg.ReconnectBackoffMax = 0

	logger := slog.Default()

	fmt.Printf("Enrolling with master at %s...\n", serverAddr)

	if code != "" {
		fmt.Printf("  Method: one-time code\n")
		fmt.Printf("  Code:   %s\n", code)
	} else {
		fmt.Printf("  Method: admin approval\n")
		fmt.Printf("  Name:   %s\n", name)
	}

	// For now, save the CSR and key locally. The actual enrollment over
	// gRPC will be implemented when the protobuf service definitions are
	// added.
	certDir := agentCertDir()
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCertWriteFailed, err)
	}

	// Save private key.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCSRFailed, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyPath := filepath.Join(certDir, "agent-key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCertWriteFailed, err)
	}

	// Save CSR.
	csrPath := filepath.Join(certDir, "agent-csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentCertWriteFailed, err)
	}

	_ = logger

	fmt.Printf("\nEnrollment request prepared:\n")
	fmt.Printf("  Key:  %s\n", keyPath)
	fmt.Printf("  CSR:  %s\n", csrPath)
	fmt.Printf("  Cert: (pending enrollment completion)\n")

	return nil
}

// runDeviceConnect connects to a previously enrolled master.
func runDeviceConnect(cmd *cobra.Command, args []string) error {
	masterAddr := args[0]
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	tlsCA, _ := cmd.Flags().GetString("tls-ca")

	// Use default cert paths if not specified.
	certDir := agentCertDir()
	if tlsCert == "" {
		tlsCert = filepath.Join(certDir, "agent-cert.pem")
	}
	if tlsKey == "" {
		tlsKey = filepath.Join(certDir, "agent-key.pem")
	}
	if tlsCA == "" {
		tlsCA = filepath.Join(certDir, "ca-cert.pem")
	}

	clientCfg := agent.DefaultClientConfig()
	clientCfg.MasterAddress = masterAddr
	clientCfg.TLSCertFile = tlsCert
	clientCfg.TLSKeyFile = tlsKey
	clientCfg.TLSCAFile = tlsCA

	logger := slog.Default()

	client, err := agent.NewClient(clientCfg, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentConnectFailed, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentConnectFailed, err)
	}

	fmt.Printf("Connected to master at %s\n", masterAddr)
	fmt.Printf("  TLS Cert: %s\n", tlsCert)

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	fmt.Println("\nDisconnecting...")

	return client.Disconnect()
}

func init() {
	deviceCmd.AddCommand(deviceEnrollCmd)
	deviceCmd.AddCommand(deviceConnectCmd)

	// Device enroll flags.
	deviceEnrollCmd.Flags().String("server", "", "Master server address (required)")
	deviceEnrollCmd.Flags().String("code", "", "One-time enrollment code")
	deviceEnrollCmd.Flags().String("name", "", "Agent name (default: hostname)")

	// Device connect flags.
	deviceConnectCmd.Flags().String("tls-cert", "", "TLS certificate file")
	deviceConnectCmd.Flags().String("tls-key", "", "TLS private key file")
	deviceConnectCmd.Flags().String("tls-ca", "", "TLS CA certificate file")
}
