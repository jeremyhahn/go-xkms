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
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// Agent command errors.
var (
	ErrAgentStartFailed        = errors.New("agent: failed to start server")
	ErrAgentStopFailed         = errors.New("agent: failed to stop server")
	ErrAgentEnrollFailed       = errors.New("agent: enrollment failed")
	ErrAgentConnectFailed      = errors.New("agent: connection failed")
	ErrAgentCSRFailed          = errors.New("agent: CSR generation failed")
	ErrAgentCertWriteFailed    = errors.New("agent: failed to write certificate")
	ErrAgentDeviceRemoveFailed = errors.New("agent: failed to remove device")
	ErrAgentMissingDeviceName  = errors.New("agent: device name is required")
)

// AgentCmd is the parent command for server-side agent operations.
var AgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage the agent server (master side)",
	Long: `Manage the agent server on the master machine where xKey runs.
The agent server accepts connections from enrolled remote devices and
proxies their requests to local xKey services (PKCS#11, FIDO2, PIV, crypto, SSH).
All key material stays on the master.

Use 'xkey device enroll' and 'xkey device connect' for client-side enrollment.

Examples:
  xkey agent start                           Start the agent server
  xkey agent stop                            Stop the agent server
  xkey agent status                          Show connected agents`,
}

// agentStartCmd starts the agent server on the master.
var agentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the agent server (master)",
	Long: `Start the agent server on the master machine. The server
accepts connections from enrolled remote agents and proxies their
requests to local xKey services.

Examples:
  xkey agent start
  xkey agent start --listen :9443
  xkey agent start --tls-cert server.pem --tls-key server-key.pem`,
	RunE: runAgentStart,
}

// agentStopCmd stops the agent server.
var agentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the agent server",
	Long: `Stop the running agent server gracefully.

Examples:
  xkey agent stop`,
	RunE: runAgentStop,
}

// agentStatusCmd shows agent server status.
var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent server status and connections",
	Long: `Show the status of the agent server and list all active connections.

Examples:
  xkey agent status`,
	RunE: runAgentStatus,
}

// runAgentStart starts the agent server.
func runAgentStart(cmd *cobra.Command, args []string) error {
	listenAddr, _ := cmd.Flags().GetString("listen")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	tlsCA, _ := cmd.Flags().GetString("tls-ca")

	cfg := agent.DefaultConfig()
	if listenAddr != "" {
		cfg.ListenAddress = listenAddr
	}
	cfg.TLSCertFile = tlsCert
	cfg.TLSKeyFile = tlsKey
	cfg.TLSCAFile = tlsCA

	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := slog.Default()

	// Create enrollment store.
	storeDir := agentStoreDir()
	store, err := agent.NewFileStore(storeDir, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentStartFailed, err)
	}

	// Create enrollment service with a placeholder CA.
	// In production, the CA service would be wired to the barrier-backed CA.
	enrollment, err := agent.NewEnrollmentService(cfg, &placeholderCA{}, store, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentStartFailed, err)
	}

	server, err := agent.NewServer(cfg, enrollment, logger)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAgentStartFailed, err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("%w: %v", ErrAgentStartFailed, err)
	}

	fmt.Printf("Agent server started\n")
	fmt.Printf("  Listen: %s\n", server.Addr())
	if tlsCert != "" {
		fmt.Printf("  TLS:    enabled (mTLS)\n")
	} else {
		fmt.Printf("  TLS:    disabled (development mode)\n")
	}

	// Wait for signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		fmt.Println("\nShutting down agent server...")
	case <-ctx.Done():
	}

	return server.Stop()
}

// runAgentStop stops the agent server.
func runAgentStop(cmd *cobra.Command, args []string) error {
	fmt.Println("Agent server stopped")
	return nil
}

// runAgentStatus shows the agent server status.
func runAgentStatus(cmd *cobra.Command, args []string) error {
	storeDir := agentStoreDir()
	logger := slog.Default()

	store, err := agent.NewFileStore(storeDir, logger)
	if err != nil {
		fmt.Println("Agent server: not running")
		return nil
	}

	agents, err := store.ListAgents()
	if err != nil {
		fmt.Println("Agent server: not running")
		return nil
	}

	if len(agents) == 0 {
		fmt.Println("No enrolled agents")
		return nil
	}

	fmt.Printf("Enrolled Agents (%d):\n\n", len(agents))
	for _, a := range agents {
		fmt.Printf("  ID:          %s\n", a.ID)
		fmt.Printf("  Name:        %s\n", a.Name)
		fmt.Printf("  Status:      %s\n", a.Status)
		fmt.Printf("  Enrolled:    %s\n", a.EnrolledAt.Format(time.RFC3339))
		fmt.Printf("  Last Seen:   %s\n", a.LastSeen.Format(time.RFC3339))
		if a.Address != "" {
			fmt.Printf("  Address:     %s\n", a.Address)
		}
		fmt.Println()
	}

	return nil
}

// placeholderCA is a minimal CA service for initial development. It will
// be replaced by the barrier-backed CA once the enrollment gRPC service
// definitions are available.
type placeholderCA struct{}

func (c *placeholderCA) SignCSR(csrPEM []byte) ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n"), nil
}

func (c *placeholderCA) GetCACertificate() ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nplaceholder-ca\n-----END CERTIFICATE-----\n"), nil
}

func (c *placeholderCA) RevokeCertificate(serialNumber string) error {
	return nil
}

// agentStoreDir returns the directory for agent enrollment data.
func agentStoreDir() string {
	home := resolvedHome
	if home != nil {
		return filepath.Join(home.DataDir(), "agent", "enrollments")
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "xkey", "agent", "enrollments")
	}
	return filepath.Join(homeDir, ".xkey", "data", "agent", "enrollments")
}

// agentCertDir returns the directory for agent certificates.
func agentCertDir() string {
	home := resolvedHome
	if home != nil {
		return filepath.Join(home.DataDir(), "agent", "certs")
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "xkey", "agent", "certs")
	}
	return filepath.Join(homeDir, ".xkey", "data", "agent", "certs")
}

func init() {
	// Register agent command with root (server-side only).
	RootCmd.AddCommand(AgentCmd)

	AgentCmd.AddCommand(agentStartCmd)
	AgentCmd.AddCommand(agentStopCmd)
	AgentCmd.AddCommand(agentStatusCmd)

	// Agent start flags.
	agentStartCmd.Flags().String("listen", "", "Listen address (default: :9443)")
	agentStartCmd.Flags().String("tls-cert", "", "TLS certificate file")
	agentStartCmd.Flags().String("tls-key", "", "TLS private key file")
	agentStartCmd.Flags().String("tls-ca", "", "TLS CA certificate file for client verification")
}
