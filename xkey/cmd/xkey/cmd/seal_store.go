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
	"os"

	"github.com/jeremyhahn/go-enclave"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// SealStore command errors.
var (
	ErrSealStoreMissingName   = errors.New("platform-store: secret name is required")
	ErrSealStoreMissingSource = errors.New(
		"platform-store: a value (--value-stdin or XKEY_PLATFORM_STORE_VALUE) or --file is required")
	ErrSealStoreMutualExclusive = errors.New(
		"platform-store: a value (--value-stdin or XKEY_PLATFORM_STORE_VALUE) and --file are mutually exclusive")

	// ErrSealStoreValueStdinEmpty indicates --value-stdin was given but
	// standard input carried no value.
	ErrSealStoreValueStdinEmpty = errors.New("platform-store: --value-stdin was given but standard input carried no value")

	// ErrSealStoreValueStdinRead indicates standard input could not be read
	// for --value-stdin.
	ErrSealStoreValueStdinRead    = errors.New("platform-store: failed to read the value from standard input")
	ErrSealStoreFileRead          = errors.New("platform-store: failed to read file")
	ErrSealStorePutFailed         = errors.New("platform-store: put operation failed")
	ErrSealStoreGetFailed         = errors.New("platform-store: get operation failed")
	ErrSealStoreDeleteFailed      = errors.New("platform-store: delete operation failed")
	ErrSealStoreListFailed        = errors.New("platform-store: list operation failed")
	ErrSealStoreResealFailed      = errors.New("platform-store: reseal operation failed")
	ErrSealStoreStatusFailed      = errors.New("platform-store: status operation failed")
	ErrSealStoreConnectFailed     = errors.New("platform-store: failed to connect to xkmsd")
	ErrSealStoreOutputWrite       = errors.New("platform-store: failed to write output file")
	ErrSealStoreNoSecretsToReseal = errors.New("platform-store: no secrets to reseal")
)

// sealStoreValueSource is the one way a secret's value enters the CLI for
// "platform-store put". It follows the PIN convention (pin_input.go):
// standard input or the environment, never a "--value" value flag -- a value
// on the command line is visible to every other process on the host via 'ps'
// (go-xkms#1209). The --file alternative is unaffected: a file path is not
// itself a secret.
var sealStoreValueSource = pinSource{
	label:      "secret value",
	stdinFlag:  "value-stdin",
	envVar:     "XKEY_PLATFORM_STORE_VALUE",
	stdinEmpty: ErrSealStoreValueStdinEmpty,
	stdinRead:  ErrSealStoreValueStdinRead,
}

// clientFactory is the function used to create transport clients.
// It is a package-level variable to allow tests to inject mock clients.
var clientFactory = defaultClientFactory

// SealStoreService defines the subset of the transport.Client interface
// needed by platform-store commands. This enables dependency injection for
// testing without importing the full client.
type SealStoreService interface {
	Connect(ctx context.Context) error
	Close() error
	SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error
	SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error)
	SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error
	SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error)
	SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error
	SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error)
}

// defaultClientFactory creates a real SDK transport client for the resolved
// xkmsd endpoint (see resolveXKMSdEndpoint for the URL/token/CA precedence).
// The returned client is not connected yet; connectSealStore completes the
// handshake. This is the production implementation; tests override
// clientFactory with a function that returns a mock.
func defaultClientFactory() (SealStoreService, error) {
	client, err := newXKMSdClient(platformStoreCmd)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// platformStoreCmd is the parent command for platform store operations.
var platformStoreCmd = &cobra.Command{
	Use:   "platform-store",
	Short: "Manage sealed secrets in the platform store",
	Long: `Manage sealed secrets stored on the local machine.

The platform store provides a simple key-value interface for storing
secrets that are sealed using the best available cryptographic mechanism
(TPM2, PKCS#11, or software-based sealing). Secrets are encrypted at
rest and can only be retrieved on the same machine.

This command wraps the xkmsd SDK transport, requiring a running xkmsd
server. The server is selected with --xkmsd-url, the XKMSD_URL environment
variable, or the xkmsd_url config key; the URL scheme picks the transport
(unix://, http://, https://, grpc://, grpcs://, quic://, mcp://, mcps://).
XKMSD_TOKEN supplies a bearer token and --tls-ca / XKMSD_TLS_CA the CA
bundle used to verify TLS transports.

Commands:
  put       Store a secret
  get       Retrieve a secret
  delete    Delete a secret
  list      List all secret names
  reseal    Re-encrypt a secret with current sealing key
  status    Show platform store status

Examples:
  # Store a secret by value
  echo -n "s3cret" | xkey platform-store put my-secret --value-stdin

  # Store a secret from a file
  xkey platform-store put my-cert --file /path/to/cert.pem

  # Retrieve a secret
  xkey platform-store get my-secret

  # Save a secret to a file
  xkey platform-store get my-cert --output /tmp/cert.pem

  # List all secrets
  xkey platform-store list

  # Delete a secret
  xkey platform-store delete my-secret

  # Reseal a specific secret
  xkey platform-store reseal my-secret

  # Reseal all secrets
  xkey platform-store reseal --all

  # Show platform store status
  xkey platform-store status`,
}

// platformStorePutCmd stores a secret in the platform store.
var platformStorePutCmd = &cobra.Command{
	Use:   "put <name>",
	Short: "Store a secret in the platform store",
	Long: `Store a secret in the platform store.

The secret is sealed using the best available sealing mechanism and stored
locally. Provide the secret value through --value-stdin or
XKEY_PLATFORM_STORE_VALUE, or read it from a file with --file. These are
mutually exclusive. There is no "--value" value flag: a value on the command
line is visible to every other process on the host via 'ps'.

Examples:
  # Store a secret by value
  echo -n "s3cret" | xkey platform-store put my-secret --value-stdin

  # Store a secret from a file
  xkey platform-store put my-cert --file /path/to/cert.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runSealStorePut,
}

// platformStoreGetCmd retrieves a secret from the platform store.
var platformStoreGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Retrieve a secret from the platform store",
	Long: `Retrieve a secret from the platform store.

Outputs the secret value to stdout by default, making it suitable for
piping to other commands. Use --output to write the secret to a file.

Examples:
  # Retrieve a secret to stdout
  xkey platform-store get my-secret

  # Save a secret to a file
  xkey platform-store get my-cert --output /tmp/cert.pem

  # Pipe to clipboard (Linux)
  xkey platform-store get my-secret | xclip -selection clipboard`,
	Args: cobra.ExactArgs(1),
	RunE: runSealStoreGet,
}

// platformStoreDeleteCmd deletes a secret from the platform store.
var platformStoreDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm"},
	Short:   "Delete a secret from the platform store",
	Long: `Delete a secret from the platform store.

Permanently removes the sealed secret. This action cannot be undone.

Examples:
  # Delete a secret
  xkey platform-store delete my-secret`,
	Args: cobra.ExactArgs(1),
	RunE: runSealStoreDelete,
}

// platformStoreListCmd lists all secrets in the platform store.
var platformStoreListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all secrets in the platform store",
	Long: `List the names of all secrets stored in the platform store.

Only secret names are displayed; values are not shown.

Examples:
  # List all secrets
  xkey platform-store list`,
	RunE: runSealStoreList,
}

// platformStoreResealCmd reseals one or all secrets.
var platformStoreResealCmd = &cobra.Command{
	Use:   "reseal [name]",
	Short: "Reseal a secret with the current sealing key",
	Long: `Reseal a secret (or all secrets) with the current sealing key.

This is useful after key rotation or TPM ownership changes to re-encrypt
secrets with the latest sealing key material. Use a specific name to
reseal one secret, or --all to reseal all secrets at once.

Examples:
  # Reseal a specific secret
  xkey platform-store reseal my-secret

  # Reseal all secrets
  xkey platform-store reseal --all`,
	RunE: runSealStoreReseal,
}

// platformStoreStatusCmd shows the platform store status.
var platformStoreStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show platform store status",
	Long: `Show the current status of the platform store.

Displays information about the available sealers, the number of stored
secrets, and the names of all secrets in the store.

Examples:
  # Show platform store status
  xkey platform-store status`,
	RunE: runSealStoreStatus,
}

func init() {
	// Register platform-store command with root.
	RootCmd.AddCommand(platformStoreCmd)

	// Add subcommands to platform-store.
	platformStoreCmd.AddCommand(platformStorePutCmd)
	platformStoreCmd.AddCommand(platformStoreGetCmd)
	platformStoreCmd.AddCommand(platformStoreDeleteCmd)
	platformStoreCmd.AddCommand(platformStoreListCmd)
	platformStoreCmd.AddCommand(platformStoreResealCmd)
	platformStoreCmd.AddCommand(platformStoreStatusCmd)

	// Shared connection flag: the CA bundle used to verify TLS-bearing
	// transports (https/grpcs/quic/mcps).
	platformStoreCmd.PersistentFlags().String("tls-ca", "",
		"TLS CA certificate file used to verify the xkmsd server")

	// platform-store put flags.
	sealStoreValueSource.addFlags(platformStorePutCmd)
	platformStorePutCmd.Flags().String("file", "", "Path to file containing the secret")

	// platform-store get flags.
	platformStoreGetCmd.Flags().String("output", "", "Write secret to file instead of stdout")

	// platform-store reseal flags.
	platformStoreResealCmd.Flags().Bool("all", false, "Reseal all secrets")
}

// connectSealStore creates and connects a SealStoreService client.
func connectSealStore() (SealStoreService, error) {
	client, err := clientFactory()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSealStoreConnectFailed, Cause: err}
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSealStoreConnectFailed, Cause: err}
	}

	return client, nil
}

// runSealStorePut executes the platform-store put command.
func runSealStorePut(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	value, err := sealStoreValueSource.resolveBytes(cmd)
	if err != nil {
		return err
	}
	defer enclave.Wipe(value)
	filePath, _ := cmd.Flags().GetString("file")

	hasValue := len(value) > 0
	hasFile := filePath != ""

	if !hasValue && !hasFile {
		return ErrSealStoreMissingSource
	}
	if hasValue && hasFile {
		return ErrSealStoreMutualExclusive
	}

	var secret []byte
	if hasFile {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrSealStoreFileRead, Cause: err}
		}
		secret = data
	} else {
		// Copy rather than alias value: the deferred Wipe above must not
		// zero the bytes the request below hands to the transport after
		// this function returns.
		secret = append([]byte(nil), value...)
	}

	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	req := &transport.SealStorePutRequest{
		Name:   name,
		Secret: secret,
	}

	if err := client.SealStorePut(ctx, req); err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStorePutFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Stored secret: %s\n", name)
	return nil
}

// runSealStoreGet executes the platform-store get command.
func runSealStoreGet(cmd *cobra.Command, args []string) (err error) {
	name := args[0]
	outputPath, _ := cmd.Flags().GetString("output")

	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	req := &transport.SealStoreGetRequest{
		Name: name,
	}

	resp, err := client.SealStoreGet(ctx, req)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStoreGetFailed, Cause: err}
	}

	if outputPath != "" {
		if err := fsutil.WriteFileAtomic(outputPath, resp.Secret, 0600); err != nil {
			return &SentinelCauseError{Sentinel: ErrSealStoreOutputWrite, Cause: err}
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Secret written to: %s\n", outputPath)
		return nil
	}

	// Write raw secret to stdout for piping.
	_, err = cmd.OutOrStdout().Write(resp.Secret)
	return err
}

// runSealStoreDelete executes the platform-store delete command.
func runSealStoreDelete(cmd *cobra.Command, args []string) (err error) {
	name := args[0]

	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	req := &transport.SealStoreDeleteRequest{
		Name: name,
	}

	if err := client.SealStoreDelete(ctx, req); err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStoreDeleteFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted secret: %s\n", name)
	return nil
}

// runSealStoreList executes the platform-store list command.
func runSealStoreList(cmd *cobra.Command, args []string) (err error) {
	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	resp, err := client.SealStoreList(ctx)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStoreListFailed, Cause: err}
	}

	out := cmd.OutOrStdout()

	if len(resp.Names) == 0 {
		_, _ = fmt.Fprintln(out, "No secrets stored.")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Stored Secrets (%d):\n\n", len(resp.Names))
	for _, name := range resp.Names {
		_, _ = fmt.Fprintf(out, "  %s\n", name)
	}

	return nil
}

// runSealStoreReseal executes the platform-store reseal command.
func runSealStoreReseal(cmd *cobra.Command, args []string) (err error) {
	resealAll, _ := cmd.Flags().GetBool("all")

	if !resealAll && len(args) == 0 {
		return ErrSealStoreMissingName
	}

	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	out := cmd.OutOrStdout()

	if resealAll {
		// List all secrets and reseal each one.
		listResp, err := client.SealStoreList(ctx)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrSealStoreListFailed, Cause: err}
		}

		if len(listResp.Names) == 0 {
			return ErrSealStoreNoSecretsToReseal
		}

		for _, name := range listResp.Names {
			req := &transport.SealStoreResealRequest{Name: name}
			if err := client.SealStoreReseal(ctx, req); err != nil {
				_, _ = fmt.Fprintf(out, "  %s: reseal failed: %v\n", name, err)
				continue
			}
			_, _ = fmt.Fprintf(out, "  Resealed: %s\n", name)
		}

		_, _ = fmt.Fprintf(out, "\nResealed %d secret(s).\n", len(listResp.Names))
		return nil
	}

	// Reseal a single secret.
	name := args[0]
	req := &transport.SealStoreResealRequest{Name: name}
	if err := client.SealStoreReseal(ctx, req); err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStoreResealFailed, Cause: err}
	}

	_, _ = fmt.Fprintf(out, "Resealed: %s\n", name)
	return nil
}

// runSealStoreStatus executes the platform-store status command.
func runSealStoreStatus(cmd *cobra.Command, args []string) (err error) {
	client, err := connectSealStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx := context.Background()
	resp, err := client.SealStoreStatus(ctx)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSealStoreStatusFailed, Cause: err}
	}

	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintln(out, "Platform Store Status:")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  Available:     %v\n", resp.Available)

	if resp.SealerID != "" {
		_, _ = fmt.Fprintf(out, "  Sealer:        %s\n", resp.SealerID)
	}

	_, _ = fmt.Fprintf(out, "  Secret Count:  %d\n", resp.SecretCount)

	if len(resp.SecretNames) > 0 {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "  Secrets:")
		for _, name := range resp.SecretNames {
			_, _ = fmt.Fprintf(out, "    %s\n", name)
		}
	}

	return nil
}

// SealStoreError represents a platform store operation error.
type SealStoreError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *SealStoreError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("platform-store: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("platform-store: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("platform-store: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("platform-store: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *SealStoreError) Unwrap() error {
	return e.Err
}
