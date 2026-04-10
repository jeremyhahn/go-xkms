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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go"
	sshagent "github.com/jeremyhahn/go-xkms/xkey/pkg/ssh/agent"
)

// SSH command errors.
var (
	ErrSSHAgentNotRunning     = errors.New("ssh: agent is not running")
	ErrSSHAgentAlreadyRunning = errors.New("ssh: agent is already running")
	ErrSSHConnectionFailed    = errors.New("ssh: failed to connect to xkmsd")
	ErrSSHLocalStoreFailed    = errors.New("ssh: failed to open local key store")
	ErrSSHKeyNotFound         = errors.New("ssh: key not found")
	ErrSSHKeyGenerateFailed   = errors.New("ssh: key generation failed")
	ErrSSHKeyImportFailed     = errors.New("ssh: key import failed")
	ErrSSHKeyDeleteFailed     = errors.New("ssh: key deletion failed")
	ErrSSHKeyExportFailed     = errors.New("ssh: key export failed")
	ErrSSHMissingKeyID        = errors.New("ssh: key ID is required")
	ErrSSHMissingKeyType      = errors.New("ssh: key type is required")
	ErrSSHInvalidKeyType      = errors.New("ssh: invalid key type (use ed25519, rsa, or ecdsa)")
	ErrSSHMissingImportFile   = errors.New("ssh: import file path is required")
)

// SSHCmd is the parent command for SSH operations.
var SSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH agent and key management",
	Long: `SSH agent and key management with standalone and server modes.

STANDALONE MODE (default):
  Keys are stored in a local directory. No external services required.

SERVER MODE:
  Keys are managed by xkmsd, which can be backed by TPM2, PKCS#11,
  or software key storage. Enable with --xkmsd-url flag or config.

Examples:
  # Standalone mode (default) - keys stored locally
  xkey ssh keys generate --type ed25519 --id my-ssh-key
  xkey ssh keys list
  xkey ssh agent start

  # Custom local store path
  xkey ssh keys list --store /path/to/keys

  # Server mode - keys managed by xkmsd
  xkey ssh keys list --xkmsd-url unix://xkms.sock
  xkey ssh agent start --xkmsd-url unix://xkms.sock

  # Start and set SSH_AUTH_SOCK (for eval)
  eval $(xkey ssh agent start --print-env)

  # Export public key in OpenSSH format
  xkey ssh keys export my-ssh-key`,
}

// sshAgentCmd is the parent command for SSH agent operations.
var sshAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "SSH agent operations",
	Long:  `Start, stop, and manage the SSH agent.`,
}

// sshAgentStartCmd starts the SSH agent.
var sshAgentStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the SSH agent",
	Long: `Start the SSH agent daemon.

The agent listens on a Unix socket and handles SSH authentication requests
using keys from xkmsd. Set SSH_AUTH_SOCK to the socket path to use
with standard SSH clients.

Examples:
  # Start in foreground
  xkey ssh agent start --foreground

  # Start and print environment variable for eval
  eval $(xkey ssh agent start --print-env)

  # Start with custom socket path
  xkey ssh agent start --socket /tmp/my-ssh-agent.sock`,
	RunE: runSSHAgentStart,
}

// sshAgentStopCmd stops the SSH agent.
var sshAgentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the SSH agent",
	Long: `Stop the running SSH agent.

Examples:
  xkey ssh agent stop`,
	RunE: runSSHAgentStop,
}

// sshAgentStatusCmd shows SSH agent status.
var sshAgentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show SSH agent status",
	Long: `Show the status of the SSH agent.

Examples:
  xkey ssh agent status`,
	RunE: runSSHAgentStatus,
}

// sshKeysCmd is the parent command for SSH key operations.
var sshKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "SSH key management",
	Long:  `Manage SSH keys in xkmsd.`,
}

// sshKeysListCmd lists SSH keys.
var sshKeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SSH keys",
	Long: `List all SSH-compatible keys from xkmsd.

Examples:
  xkey ssh keys list`,
	RunE: runSSHKeysList,
}

// sshKeysGenerateCmd generates a new SSH key.
var sshKeysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new SSH key",
	Long: `Generate a new SSH key in xkmsd.

Supported key types:
  - ed25519 (recommended, default)
  - rsa (2048, 3072, or 4096 bits)
  - ecdsa (P-256, P-384, or P-521)

Examples:
  # Generate Ed25519 key (default)
  xkey ssh keys generate --id my-key

  # Generate RSA 4096-bit key
  xkey ssh keys generate --id my-rsa-key --type rsa --bits 4096

  # Generate ECDSA P-384 key
  xkey ssh keys generate --id my-ecdsa-key --type ecdsa --curve P-384`,
	RunE: runSSHKeysGenerate,
}

// sshKeysImportCmd imports an SSH key.
var sshKeysImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import an SSH private key",
	Long: `Import an existing SSH private key into xkmsd.

Examples:
  # Import an existing key
  xkey ssh keys import ~/.ssh/id_ed25519 --id my-imported-key`,
	RunE: runSSHKeysImport,
}

// sshKeysDeleteCmd deletes an SSH key.
var sshKeysDeleteCmd = &cobra.Command{
	Use:     "delete [key-id]",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete an SSH key",
	Long: `Delete an SSH key from xkmsd.

Examples:
  xkey ssh keys delete my-key`,
	RunE: runSSHKeysDelete,
}

// sshKeysExportCmd exports an SSH public key.
var sshKeysExportCmd = &cobra.Command{
	Use:   "export [key-id]",
	Short: "Export SSH public key",
	Long: `Export an SSH public key in OpenSSH format.

The output can be added to ~/.ssh/authorized_keys or used with ssh-copy-id.

Examples:
  # Print public key
  xkey ssh keys export my-key

  # Save to file
  xkey ssh keys export my-key > ~/.ssh/id_xkey.pub

  # Append to authorized_keys
  xkey ssh keys export my-key >> ~/.ssh/authorized_keys`,
	RunE: runSSHKeysExport,
}

// runSSHAgentStart starts the SSH agent.
func runSSHAgentStart(cmd *cobra.Command, args []string) error {
	foreground, _ := cmd.Flags().GetBool("foreground")
	printEnv, _ := cmd.Flags().GetBool("print-env")
	shell, _ := cmd.Flags().GetString("shell")

	// Get store path for standalone mode (SSH-specific flag)
	storePath, _ := cmd.Flags().GetString("store")
	if storePath == "" {
		storePath = viper.GetString("ssh.store_path")
	}

	// Get xkmsd URL for server mode (global flag/config)
	xkmsdURL := viper.GetString("xkmsd_url")
	if xkmsdURL == "" {
		xkmsdURL = viper.GetString("ssh.xkmsd_url") // legacy ssh-specific config
	}

	// Get backend (global flag/config)
	backend := viper.GetString("backend")
	if backend == "" {
		backend = viper.GetString("ssh.backend") // legacy ssh-specific config
	}
	if backend == "" {
		backend = "software"
	}

	requireTouch := viper.GetBool("ssh.require_touch")
	socketPath := viper.GetString("ssh.agent_socket")
	if socketPath == "" {
		socketPath = sshagent.DefaultSocketPath()
	}

	// Create logger
	logger := slog.Default()

	// Build agent config - if store path is set or xkmsd URL is empty, use standalone mode
	agentCfg := &sshagent.AgentConfig{
		RequireTouch: requireTouch,
		Logger:       logger,
	}

	if storePath != "" {
		// Standalone mode with explicit store path
		agentCfg.LocalStorePath = storePath
	} else if xkmsdURL != "" {
		// Server mode with xkmsd
		agentCfg.XKMSURL = xkmsdURL
		agentCfg.Backend = backend
	}
	// If neither is set, NewAgent will use default local store path

	// Create the agent
	agent, err := sshagent.NewAgent(agentCfg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
	}

	// Create the server
	server, err := sshagent.NewServer(agent, &sshagent.ServerConfig{
		SocketPath: socketPath,
		Logger:     logger,
	})
	if err != nil {
		agent.Close()
		if errors.Is(err, sshagent.ErrAgentAlreadyRunning) {
			return ErrSSHAgentAlreadyRunning
		}
		return err
	}

	// If print-env, just print the export command and exit
	if printEnv {
		switch strings.ToLower(shell) {
		case "fish":
			fmt.Println(server.PrintEnvFish())
		case "csh", "tcsh":
			fmt.Println(server.PrintEnvCsh())
		default:
			fmt.Println(server.PrintEnvBash())
		}
		// Don't start in foreground mode when just printing env
		if !foreground {
			server.Close()
			return nil
		}
	}

	// Print socket path
	if !printEnv {
		fmt.Printf("SSH agent started\n")
		fmt.Printf("  Socket: %s\n", server.SocketPath())
		fmt.Println()
		fmt.Printf("To use: %s\n", server.PrintEnvBash())
	}

	if !foreground {
		// Write PID file for stop command
		if err := writeSSHAgentPID(socketPath); err != nil {
			logger.Warn("failed to write PID file", "error", err)
		}
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	// Run the server
	return server.Serve(ctx)
}

// runSSHAgentStop stops the SSH agent.
func runSSHAgentStop(cmd *cobra.Command, args []string) error {
	socketPath := viper.GetString("ssh.agent_socket")
	if socketPath == "" {
		socketPath = sshagent.DefaultSocketPath()
	}

	// Check if agent is running by trying to connect
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return ErrSSHAgentNotRunning
	}
	conn.Close()

	// Read PID file and kill the process
	pidFile := getSSHAgentPIDFile(socketPath)
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		// No PID file, try to remove socket directly
		os.Remove(socketPath)
		fmt.Println("SSH agent stopped (removed stale socket)")
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		os.Remove(socketPath)
		os.Remove(pidFile)
		fmt.Println("SSH agent stopped (removed stale files)")
		return nil
	}

	// Send SIGTERM to the agent process
	process, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(socketPath)
		os.Remove(pidFile)
		fmt.Println("SSH agent stopped (process not found)")
		return nil
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		os.Remove(socketPath)
		os.Remove(pidFile)
		fmt.Println("SSH agent stopped (process already terminated)")
		return nil
	}

	os.Remove(pidFile)
	fmt.Printf("SSH agent stopped (PID %d)\n", pid)
	return nil
}

// runSSHAgentStatus shows the SSH agent status.
func runSSHAgentStatus(cmd *cobra.Command, args []string) error {
	socketPath := viper.GetString("ssh.agent_socket")
	if socketPath == "" {
		socketPath = sshagent.DefaultSocketPath()
	}

	// Check if socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		fmt.Println("SSH agent: not running")
		fmt.Printf("  Socket: %s (not found)\n", socketPath)
		return nil
	}

	// Try to connect
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Println("SSH agent: not running")
		fmt.Printf("  Socket: %s (stale)\n", socketPath)
		return nil
	}
	conn.Close()

	fmt.Println("SSH agent: running")
	fmt.Printf("  Socket: %s\n", socketPath)

	// Show PID if available
	pidFile := getSSHAgentPIDFile(socketPath)
	if pidBytes, err := os.ReadFile(pidFile); err == nil {
		fmt.Printf("  PID:    %s\n", strings.TrimSpace(string(pidBytes)))
	}

	fmt.Println()
	fmt.Printf("To use: export SSH_AUTH_SOCK=%s\n", socketPath)

	return nil
}

// runSSHKeysList lists SSH keys.
func runSSHKeysList(cmd *cobra.Command, args []string) error {
	backendCloser, err := getSSHBackend(cmd)
	if err != nil {
		return err
	}
	defer backendCloser.Close()

	ctx := context.Background()
	keys, err := backendCloser.backend.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyNotFound, err)
	}

	if len(keys) == 0 {
		fmt.Println("No SSH keys found.")
		fmt.Println()
		fmt.Println("Generate a new key with: xkey ssh keys generate --id my-key")
		return nil
	}

	fmt.Printf("SSH Keys (%d):\n\n", len(keys))

	for _, ki := range keys {
		fmt.Printf("  ID:        %s\n", ki.KeyID)
		fmt.Printf("  Type:      %s\n", ki.KeyType)
		fmt.Printf("  Algorithm: %s\n", sshKeyAlgorithm(string(ki.KeyType)))

		// Show fingerprint
		if ki.Fingerprint != "" {
			fmt.Printf("  Fingerprint: %s\n", ki.Fingerprint)
		} else if ki.PublicKey != nil {
			fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(ki.PublicKey))
		}

		fmt.Println()
	}

	return nil
}

// runSSHKeysGenerate generates a new SSH key.
func runSSHKeysGenerate(cmd *cobra.Command, args []string) error {
	keyID, _ := cmd.Flags().GetString("id")
	keyType, _ := cmd.Flags().GetString("type")
	bits, _ := cmd.Flags().GetInt("bits")
	curve, _ := cmd.Flags().GetString("curve")

	if keyID == "" {
		return ErrSSHMissingKeyID
	}

	backendCloser, err := getSSHBackend(cmd)
	if err != nil {
		return err
	}
	defer backendCloser.Close()

	ctx := context.Background()

	// Determine key type
	var kt sshagent.KeyType
	opts := &sshagent.GenerateOptions{}

	switch strings.ToLower(keyType) {
	case "ed25519", "":
		kt = sshagent.KeyTypeEd25519
	case "rsa":
		kt = sshagent.KeyTypeRSA
		if bits == 0 {
			bits = 4096
		}
		opts.Bits = bits
	case "ecdsa":
		kt = sshagent.KeyTypeECDSA
		if curve == "" {
			curve = "P-256"
		}
		opts.Curve = curve
	default:
		return ErrSSHInvalidKeyType
	}

	keyInfo, err := backendCloser.backend.GenerateKey(ctx, keyID, kt, opts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyGenerateFailed, err)
	}

	fmt.Printf("Generated SSH key: %s\n", keyID)
	fmt.Printf("  Type:      %s\n", kt)

	// Show the public key
	if keyInfo.PublicKey != nil {
		fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(keyInfo.PublicKey))
		fmt.Println()
		fmt.Println("Public key:")
		fmt.Printf("  %s %s\n", keyInfo.PublicKey.Type(), base64.StdEncoding.EncodeToString(keyInfo.PublicKey.Marshal()))
	}

	return nil
}

// runSSHKeysImport imports an SSH key.
func runSSHKeysImport(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return ErrSSHMissingImportFile
	}

	filePath := args[0]
	keyID, _ := cmd.Flags().GetString("id")

	if keyID == "" {
		// Use filename as key ID
		keyID = filepath.Base(filePath)
		keyID = strings.TrimSuffix(keyID, filepath.Ext(keyID))
	}

	// Read the private key file
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyImportFailed, err)
	}

	// Parse the SSH private key to determine type
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return fmt.Errorf("%w: invalid SSH private key: %v", ErrSSHKeyImportFailed, err)
	}

	backendCloser, err := getSSHBackend(cmd)
	if err != nil {
		return err
	}
	defer backendCloser.Close()

	ctx := context.Background()

	// Determine key type from the parsed key
	keyType := "unknown"
	switch signer.PublicKey().Type() {
	case ssh.KeyAlgoED25519:
		keyType = "ed25519"
	case ssh.KeyAlgoRSA:
		keyType = "rsa"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		keyType = "ecdsa"
	}

	// Import the key
	keyInfo, err := backendCloser.backend.ImportKey(ctx, keyID, keyData)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyImportFailed, err)
	}

	fmt.Printf("Imported SSH key: %s\n", keyID)
	fmt.Printf("  From:    %s\n", filePath)
	fmt.Printf("  Type:    %s\n", keyType)

	if keyInfo.PublicKey != nil {
		fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(keyInfo.PublicKey))
	}

	return nil
}

// runSSHKeysDelete deletes an SSH key.
func runSSHKeysDelete(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return ErrSSHMissingKeyID
	}

	keyID := args[0]
	force, _ := cmd.Flags().GetBool("force")

	if !force {
		fmt.Printf("Delete SSH key '%s'? [y/N]: ", keyID)
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	backendCloser, err := getSSHBackend(cmd)
	if err != nil {
		return err
	}
	defer backendCloser.Close()

	ctx := context.Background()

	err = backendCloser.backend.DeleteKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyDeleteFailed, err)
	}

	fmt.Printf("Deleted SSH key: %s\n", keyID)
	return nil
}

// runSSHKeysExport exports an SSH public key.
func runSSHKeysExport(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return ErrSSHMissingKeyID
	}

	keyID := args[0]

	backendCloser, err := getSSHBackend(cmd)
	if err != nil {
		return err
	}
	defer backendCloser.Close()

	ctx := context.Background()

	pubKey, err := backendCloser.backend.GetPublicKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyExportFailed, err)
	}

	// Output in OpenSSH format: type base64 comment
	fmt.Printf("%s %s %s\n",
		pubKey.Type(),
		base64.StdEncoding.EncodeToString(pubKey.Marshal()),
		keyID)

	return nil
}

// sshBackendCloser wraps a KeyBackend with optional cleanup.
type sshBackendCloser struct {
	backend sshagent.KeyBackend
	client  xkms.Client // nil for local backend
}

func (s *sshBackendCloser) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// getSSHBackend returns a KeyBackend based on configuration.
// If store path is set, uses local storage (standalone mode).
// If xkmsd URL is set (global flag or config), uses xkmsd (server mode).
// If neither is set, defaults to local storage.
func getSSHBackend(cmd *cobra.Command) (*sshBackendCloser, error) {
	// Check for explicit store path (standalone mode) - SSH-specific flag
	storePath, _ := cmd.Flags().GetString("store")
	if storePath == "" {
		storePath = viper.GetString("ssh.store_path")
	}

	// Check for xkmsd URL (server mode) - global flag/config
	// Priority: global flag > ssh-specific config > global config
	xkmsdURL := viper.GetString("xkmsd_url")
	if xkmsdURL == "" {
		xkmsdURL = viper.GetString("ssh.xkmsd_url") // legacy ssh-specific config
	}

	// Check for backend - global flag/config
	backendName := viper.GetString("backend")
	if backendName == "" {
		backendName = viper.GetString("ssh.backend") // legacy ssh-specific config
	}
	if backendName == "" {
		backendName = "software"
	}

	// If store path is explicitly set, use standalone mode
	if storePath != "" {
		backend, err := createLocalSSHBackend(storePath)
		if err != nil {
			return nil, err
		}
		return &sshBackendCloser{backend: backend}, nil
	}

	// If xkmsd URL is set, use server mode
	if xkmsdURL != "" {
		client, err := xkms.NewFromURL(xkmsdURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
		}

		if err := client.Connect(context.Background()); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
		}

		backend, err := sshagent.NewXKMSdBackend(client, backendName)
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
		}

		return &sshBackendCloser{backend: backend, client: client}, nil
	}

	// Default to standalone mode with default path
	defaultPath := sshagent.DefaultLocalStorePath()
	backend, err := createLocalSSHBackend(defaultPath)
	if err != nil {
		return nil, err
	}
	return &sshBackendCloser{backend: backend}, nil
}

// createLocalSSHBackend creates a local KeyBackend for standalone mode.
func createLocalSSHBackend(storePath string) (sshagent.KeyBackend, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("%w: failed to create store directory: %v", ErrSSHLocalStoreFailed, err)
	}

	fileBackend, err := file.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHLocalStoreFailed, err)
	}

	return sshagent.NewLocalBackend(&sshagent.LocalBackendConfig{
		Backend: fileBackend,
	})
}

// getSSHXKMSClient creates a xkms client for SSH operations.
// Deprecated: Use getSSHBackend instead for both standalone and server modes.
func getSSHXKMSClient() (xkms.Client, error) {
	xkmsdURL := viper.GetString("ssh.xkmsd_url")
	if xkmsdURL == "" {
		return nil, fmt.Errorf("%w: xkmsd URL not configured (use --store for standalone mode)", ErrSSHConnectionFailed)
	}

	client, err := xkms.NewFromURL(xkmsdURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
	}

	return client, nil
}

// getSSHPublicKey retrieves and converts a key's public key to SSH format.
func getSSHPublicKey(client xkms.Client, backend, keyID string) (ssh.PublicKey, error) {
	ctx := context.Background()
	resp, err := client.GetKey(ctx, backend, keyID)
	if err != nil {
		return nil, err
	}

	return parseSSHPublicKeyPEM(resp.PublicKeyPEM)
}

// parseSSHPublicKeyPEM parses a PEM-encoded public key into SSH format.
func parseSSHPublicKeyPEM(pemData string) (ssh.PublicKey, error) {
	if pemData == "" {
		return nil, fmt.Errorf("empty public key")
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM encoding")
	}

	// Try to parse as PKIX public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return ssh.NewPublicKey(pub)
}

// isSSHCompatibleKeyType checks if a key type is compatible with SSH.
// Uses the centralized SSH algorithm support from the agent package.
func isSSHCompatibleKeyType(keyType string) bool {
	// Handle ECDSA curve variants
	normalized := strings.ToUpper(keyType)
	if strings.HasPrefix(normalized, "ECDSA") {
		return true
	}

	// Check against supported algorithms using the typed constants
	return sshagent.IsSSHSupportedAlgorithm(types.KeyAlgorithmString(keyType))
}

// sshKeyAlgorithm returns the SSH algorithm name for a key type.
func sshKeyAlgorithm(keyType string) string {
	switch strings.ToLower(keyType) {
	case "ed25519":
		return "ssh-ed25519"
	case "rsa":
		return "ssh-rsa"
	case "ecdsa", "ecdsa-p256":
		return "ecdsa-sha2-nistp256"
	case "ecdsa-p384":
		return "ecdsa-sha2-nistp384"
	case "ecdsa-p521":
		return "ecdsa-sha2-nistp521"
	default:
		return keyType
	}
}

// writeSSHAgentPID writes the current process PID to a file.
func writeSSHAgentPID(socketPath string) error {
	pidFile := getSSHAgentPIDFile(socketPath)
	if err := os.MkdirAll(filepath.Dir(pidFile), 0700); err != nil {
		return err
	}
	return os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)
}

// Git signing errors.
var (
	ErrSSHGitNotInRepo    = errors.New("ssh: not in a git repository (use --global for global config)")
	ErrSSHGitConfigFailed = errors.New("ssh: failed to configure git")
	ErrSSHGitExportFailed = errors.New("ssh: failed to export public key")
)

// sshGitConfigCmd configures git to use a xkey SSH key for signing.
var sshGitConfigCmd = &cobra.Command{
	Use:   "git-config [key-id]",
	Short: "Configure git to use a xkey SSH key for signing",
	Long: `Configure git to use SSH signing with a key from xkey.

This command:
1. Exports the public key to ~/.ssh/xkey-<key-id>.pub
2. Configures git to use SSH signing format
3. Sets the signing key to the exported public key
4. Enables commit signing by default

By default, configures the local repository. Use --global for global config.

Examples:
  # Configure local repo to sign with 'my-key'
  xkey ssh git-config my-key

  # Configure globally
  xkey ssh git-config my-key --global

  # Just show what commands would be run
  xkey ssh git-config my-key --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: runSSHGitSetup,
}

func runSSHGitSetup(cmd *cobra.Command, args []string) error {
	keyID := args[0]
	global, _ := cmd.Flags().GetBool("global")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	noSign, _ := cmd.Flags().GetBool("no-auto-sign")

	// Check if we're in a git repo (unless --global)
	if !global {
		if _, err := os.Stat(".git"); os.IsNotExist(err) {
			return ErrSSHGitNotInRepo
		}
	}

	// Get public key from xkmsd
	xkmsdURL := viper.GetString("ssh.xkmsd_url")
	backend := viper.GetString("ssh.backend")

	client, err := xkms.NewFromURL(xkmsdURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
	}
	defer client.Close()

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrSSHConnectionFailed, err)
	}

	// Get the key
	resp, err := client.GetKey(ctx, backend, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHKeyNotFound, err)
	}

	// Parse and format the public key
	pubKeyStr, err := formatSSHPublicKey(resp.PublicKeyPEM, resp.KeyType, keyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSHGitExportFailed, err)
	}

	// Determine public key file path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("%w: cannot determine home directory", ErrSSHGitConfigFailed)
	}
	pubKeyFile := filepath.Join(homeDir, ".ssh", fmt.Sprintf("xkey-%s.pub", keyID))

	// Git config scope
	scope := ""
	scopeDesc := "local"
	if global {
		scope = "--global"
		scopeDesc = "global"
	}

	if dryRun {
		fmt.Println("# Dry run - commands that would be executed:")
		fmt.Println()
		fmt.Printf("# Export public key to %s\n", pubKeyFile)
		fmt.Printf("mkdir -p %s\n", filepath.Dir(pubKeyFile))
		fmt.Printf("echo '%s' > %s\n", pubKeyStr, pubKeyFile)
		fmt.Println()
		fmt.Printf("# Configure git (%s)\n", scopeDesc)
		fmt.Printf("git config %s gpg.format ssh\n", scope)
		fmt.Printf("git config %s user.signingkey %s\n", scope, pubKeyFile)
		if !noSign {
			fmt.Printf("git config %s commit.gpgsign true\n", scope)
			fmt.Printf("git config %s tag.gpgsign true\n", scope)
		}
		return nil
	}

	// Create .ssh directory if needed
	sshDir := filepath.Dir(pubKeyFile)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("%w: cannot create .ssh directory: %v", ErrSSHGitConfigFailed, err)
	}

	// Write public key file
	if err := os.WriteFile(pubKeyFile, []byte(pubKeyStr+"\n"), 0644); err != nil {
		return fmt.Errorf("%w: cannot write public key file: %v", ErrSSHGitConfigFailed, err)
	}
	fmt.Printf("Exported public key to %s\n", pubKeyFile)

	// Run git config commands
	gitConfigs := [][]string{
		{"gpg.format", "ssh"},
		{"user.signingkey", pubKeyFile},
	}
	if !noSign {
		gitConfigs = append(gitConfigs, []string{"commit.gpgsign", "true"})
		gitConfigs = append(gitConfigs, []string{"tag.gpgsign", "true"})
	}

	for _, cfg := range gitConfigs {
		gitArgs := []string{"config"}
		if global {
			gitArgs = append(gitArgs, "--global")
		}
		gitArgs = append(gitArgs, cfg[0], cfg[1])

		gitCmd := execCommand("git", gitArgs...)
		if output, err := gitCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: git config %s failed: %s", ErrSSHGitConfigFailed, cfg[0], string(output))
		}
	}

	fmt.Printf("\nGit configured for SSH signing (%s):\n", scopeDesc)
	fmt.Printf("  gpg.format = ssh\n")
	fmt.Printf("  user.signingkey = %s\n", pubKeyFile)
	if !noSign {
		fmt.Printf("  commit.gpgsign = true\n")
		fmt.Printf("  tag.gpgsign = true\n")
	}
	fmt.Println()
	fmt.Println("Make sure the xkey SSH agent is running:")
	fmt.Println("  eval $(xkey ssh agent start --print-env)")

	return nil
}

// execCommand is a variable to allow mocking in tests.
var execCommand = func(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// formatSSHPublicKey formats a PEM-encoded public key as OpenSSH format.
func formatSSHPublicKey(pemData, keyType, comment string) (string, error) {
	pubKey, err := parseSSHPublicKeyPEM(pemData)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s %s",
		pubKey.Type(),
		base64.StdEncoding.EncodeToString(pubKey.Marshal()),
		comment), nil
}

// getSSHAgentPIDFile returns the PID file path for the agent socket.
func getSSHAgentPIDFile(socketPath string) string {
	return socketPath + ".pid"
}

func init() {
	// Register SSH command with root
	RootCmd.AddCommand(SSHCmd)

	// Add agent subcommand
	SSHCmd.AddCommand(sshAgentCmd)
	sshAgentCmd.AddCommand(sshAgentStartCmd)
	sshAgentCmd.AddCommand(sshAgentStopCmd)
	sshAgentCmd.AddCommand(sshAgentStatusCmd)

	// Add keys subcommand
	SSHCmd.AddCommand(sshKeysCmd)
	sshKeysCmd.AddCommand(sshKeysListCmd)
	sshKeysCmd.AddCommand(sshKeysGenerateCmd)
	sshKeysCmd.AddCommand(sshKeysImportCmd)
	sshKeysCmd.AddCommand(sshKeysDeleteCmd)
	sshKeysCmd.AddCommand(sshKeysExportCmd)

	// Add git-config subcommand
	SSHCmd.AddCommand(sshGitConfigCmd)
	sshGitConfigCmd.Flags().Bool("global", false, "Configure git globally instead of local repository")
	sshGitConfigCmd.Flags().Bool("dry-run", false, "Show what commands would be run without executing")
	sshGitConfigCmd.Flags().Bool("no-auto-sign", false, "Don't enable automatic commit/tag signing")

	// Agent start flags
	sshAgentStartCmd.Flags().Bool("foreground", false, "Run in foreground (don't daemonize)")
	sshAgentStartCmd.Flags().Bool("print-env", false, "Print SSH_AUTH_SOCK export command for eval")
	sshAgentStartCmd.Flags().String("shell", "bash", "Shell for print-env (bash, fish, csh)")
	sshAgentStartCmd.Flags().String("socket", "", "Unix socket path for SSH agent")
	sshAgentStartCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")
	sshAgentStartCmd.Flags().Bool("require-touch", false, "Require touch confirmation for signing")

	// Keys generate flags
	sshKeysGenerateCmd.Flags().String("id", "", "Key identifier (required)")
	sshKeysGenerateCmd.Flags().String("type", "ed25519", "Key type (ed25519, rsa, ecdsa)")
	sshKeysGenerateCmd.Flags().Int("bits", 0, "Key size in bits (for RSA: 2048, 3072, 4096)")
	sshKeysGenerateCmd.Flags().String("curve", "", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	sshKeysGenerateCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")

	// Keys import flags
	sshKeysImportCmd.Flags().String("id", "", "Key identifier (default: filename)")
	sshKeysImportCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")

	// Keys delete flags
	sshKeysDeleteCmd.Flags().Bool("force", false, "Skip confirmation prompt")
	sshKeysDeleteCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")

	// Keys list flags
	sshKeysListCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")

	// Keys export flags
	sshKeysExportCmd.Flags().String("store", "", "Local key store path (overrides to standalone mode)")

	// Bind viper config for SSH-specific settings
	_ = viper.BindPFlag("ssh.agent_socket", sshAgentStartCmd.Flags().Lookup("socket"))
	_ = viper.BindPFlag("ssh.store_path", sshAgentStartCmd.Flags().Lookup("store"))
	_ = viper.BindPFlag("ssh.require_touch", sshAgentStartCmd.Flags().Lookup("require-touch"))

	// Set defaults
	viper.SetDefault("ssh.require_touch", false)
	viper.SetDefault("ssh.enabled", false)
}
