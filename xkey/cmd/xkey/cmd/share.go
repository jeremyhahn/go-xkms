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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Default configuration for share management.
const (
	// defaultShareStoreSubdir is the subdirectory under ~/.xkey for local share storage.
	defaultShareStoreSubdir = "shares"

	// defaultShareStorePrefix is the DAO entity type namespace for the file-based store.
	// Must not include a trailing slash; the DAO layer appends one via prefixKey().
	defaultShareStorePrefix = "shamir"
)

// Share command errors.
var (
	// ErrShareStoreOpen indicates failure to open the local share store.
	ErrShareStoreOpen = errors.New("share: failed to open share store")

	// ErrShareStoreList indicates failure to list local shares.
	ErrShareStoreList = errors.New("share: failed to list shares")

	// ErrShareImportRead indicates failure to read the import file.
	ErrShareImportRead = errors.New("share: failed to read import file")

	// ErrShareImportParse indicates failure to parse the import file.
	ErrShareImportParse = errors.New("share: failed to parse import file")

	// ErrShareImportValidate indicates the imported share failed validation.
	ErrShareImportValidate = errors.New("share: imported share failed validation")

	// ErrShareImportSave indicates failure to save the imported share.
	ErrShareImportSave = errors.New("share: failed to save imported share")

	// ErrShareExportLoad indicates failure to load the share for export.
	ErrShareExportLoad = errors.New("share: failed to load share for export")

	// ErrShareExportWrite indicates failure to write the export file.
	ErrShareExportWrite = errors.New("share: failed to write export file")

	// ErrShareExportMissingFile indicates the --file flag is required for export.
	ErrShareExportMissingFile = errors.New("share: --file flag is required for export")

	// ErrShareReceiveConnect indicates failure to connect to the server.
	ErrShareReceiveConnect = errors.New("share: failed to connect to server")

	// ErrShareReceiveList indicates failure to list shares from server.
	ErrShareReceiveList = errors.New("share: failed to list shares from server")

	// ErrShareReceiveSave indicates failure to save a received share locally.
	ErrShareReceiveSave = errors.New("share: failed to save received share")

	// ErrShareUnsealLoad indicates failure to load the share for unseal submission.
	ErrShareUnsealLoad = errors.New("share: failed to load share for unseal")

	// ErrShareUnsealConnect indicates failure to connect to the server for unseal.
	ErrShareUnsealConnect = errors.New("share: failed to connect to server for unseal")

	// ErrShareUnsealSubmit indicates failure to submit the share for unseal.
	ErrShareUnsealSubmit = errors.New("share: failed to submit share for unseal")

	// ErrShareDeleteFailed indicates failure to delete a share.
	ErrShareDeleteFailed = errors.New("share: failed to delete share")

	// ErrShareMissingServer indicates the --server flag is required.
	ErrShareMissingServer = errors.New("share: --server flag is required")

	// ErrShareMissingGroupID indicates the --group-id flag is required.
	ErrShareMissingGroupID = errors.New("share: --group-id flag is required")

	// ErrShareMissingFile indicates the --file flag is required.
	ErrShareMissingFile = errors.New("share: --file flag is required")

	// ErrShareMissingShareIndex indicates the --share-index flag is required.
	ErrShareMissingShareIndex = errors.New("share: --share-index flag is required")
)

// ShareService defines the subset of the transport.Client interface needed
// by share commands that interact with a remote xkmsd server. This enables
// dependency injection for testing.
type ShareService interface {
	Connect(ctx context.Context) error
	Close() error
	ListShares(ctx context.Context) (*transport.ListSharesResponse, error)
	SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error)
	BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error)
}

// shareClientFactory is the function used to create share transport clients.
// It is a package-level variable to allow tests to inject mock clients.
var shareClientFactory = defaultShareClientFactory

// defaultShareClientFactory creates a real transport client for share operations.
func defaultShareClientFactory(serverURL string) (ShareService, error) {
	if serverURL == "" {
		return nil, ErrShareMissingServer
	}
	// TODO: Create transport client from serverURL once SDK client factory is available.
	// The transport layer supports unix://, grpc://, rest://, quic://, and mcp:// schemes.
	return nil, &ShareError{
		Operation: "connect",
		Message:   fmt.Sprintf("transport client creation for %s requires a running xkmsd server", serverURL),
	}
}

// shareCmd is the parent command for Shamir share management.
var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage Shamir secret shares",
	Long: `Manage locally stored Shamir secret shares for barrier unseal operations.

Shares are distributed to custodians by the xkmsd server during a Shamir
initialization ceremony. Each custodian stores their share locally and can
submit it back to the server when a quorum is needed to unseal the barrier.

Local shares are stored in ~/.xkey/shares/ by default, encrypted by the
local barrier when active.

Commands:
  list      List locally stored shares
  receive   Poll server for distributed shares
  import    Import a share from a JSON file
  export    Export a share to a JSON file
  unseal    Submit a share to unseal the server barrier
  delete    Delete a locally stored share

Examples:
  # List all locally stored shares
  xkey share list

  # Receive shares from a server
  xkey share receive --server grpc://xkmsd.example.com:9090

  # Import a share from a file
  xkey share import --file /tmp/share-1.json

  # Export a share to a file
  xkey share export --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1 --file /tmp/share-1.json

  # Submit a share to unseal the barrier
  xkey share unseal --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1

  # Delete a locally stored share
  xkey share delete --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1`,
}

// shareListCmd lists all locally stored shares.
var shareListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List locally stored shares",
	Long: `List all Shamir shares stored on this machine.

Displays a table showing the server URL, group ID, group name, share index,
purpose, and when each share was received.

Examples:
  # List all locally stored shares
  xkey share list`,
	RunE: runShareList,
}

// shareReceiveCmd polls a server for distributed shares.
var shareReceiveCmd = &cobra.Command{
	Use:   "receive",
	Short: "Receive shares from a server",
	Long: `Poll an xkmsd server for Shamir shares assigned to this user.

Connects to the specified server, retrieves any shares assigned to the
authenticated user, and stores them in the local share store.

Examples:
  # Receive shares from a server
  xkey share receive --server grpc://xkmsd.example.com:9090`,
	RunE: runShareReceive,
}

// shareImportCmd imports a share from a JSON file.
var shareImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a share from a JSON file",
	Long: `Import a Shamir share from a JSON file into the local store.

The JSON file must contain a valid ShareEntry with server_url, group_id,
share_index, and share_data fields.

Examples:
  # Import a share from a file
  xkey share import --file /tmp/share-1.json`,
	RunE: runShareImport,
}

// shareExportCmd exports a share to a JSON file.
var shareExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export a share to a JSON file",
	Long: `Export a locally stored Shamir share to a JSON file.

The share is identified by its server URL, group ID, and share index.
The output file contains the full ShareEntry in JSON format.

Examples:
  # Export a share to a file
  xkey share export --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1 --file /tmp/share-1.json`,
	RunE: runShareExport,
}

// shareUnsealCmd submits a share to unseal the server barrier.
var shareUnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Submit a share to unseal the server barrier",
	Long: `Submit a locally stored Shamir share to the xkmsd server to contribute
toward the unseal quorum.

The share is loaded from local storage by server URL, group ID, and share
index, then submitted to the server via the BarrierUnsealWithShare API.
The server reports how many shares have been collected and whether the
quorum threshold has been reached.

Examples:
  # Submit a share to unseal the barrier
  xkey share unseal --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1`,
	RunE: runShareUnseal,
}

// shareDeleteCmd deletes a locally stored share.
var shareDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"rm"},
	Short:   "Delete a locally stored share",
	Long: `Delete a Shamir share from local storage.

The share is identified by its server URL, group ID, and share index.
This operation is permanent and cannot be undone.

Examples:
  # Delete a locally stored share
  xkey share delete --server grpc://xkmsd.example.com:9090 --group-id barrier-ops --share-index 1`,
	RunE: runShareDelete,
}

func init() {
	// Register share command with root.
	RootCmd.AddCommand(shareCmd)

	// Add subcommands.
	shareCmd.AddCommand(shareListCmd)
	shareCmd.AddCommand(shareReceiveCmd)
	shareCmd.AddCommand(shareImportCmd)
	shareCmd.AddCommand(shareExportCmd)
	shareCmd.AddCommand(shareUnsealCmd)
	shareCmd.AddCommand(shareDeleteCmd)

	// shareReceiveCmd flags.
	shareReceiveCmd.Flags().String("server", "", "xkmsd server URL (e.g., grpc://host:9090)")
	_ = shareReceiveCmd.MarkFlagRequired("server")

	// shareImportCmd flags.
	shareImportCmd.Flags().String("file", "", "Path to JSON file containing the share")
	_ = shareImportCmd.MarkFlagRequired("file")

	// shareExportCmd flags.
	shareExportCmd.Flags().String("server", "", "xkmsd server URL that issued the share")
	shareExportCmd.Flags().String("group-id", "", "Custodian group ID")
	shareExportCmd.Flags().Int("share-index", 0, "1-based share index within the group")
	shareExportCmd.Flags().String("file", "", "Output path for the exported share JSON")
	_ = shareExportCmd.MarkFlagRequired("server")
	_ = shareExportCmd.MarkFlagRequired("group-id")
	_ = shareExportCmd.MarkFlagRequired("share-index")
	_ = shareExportCmd.MarkFlagRequired("file")

	// shareUnsealCmd flags.
	shareUnsealCmd.Flags().String("server", "", "xkmsd server URL to submit the share to")
	shareUnsealCmd.Flags().String("group-id", "", "Custodian group ID")
	shareUnsealCmd.Flags().Int("share-index", 0, "1-based share index within the group")
	_ = shareUnsealCmd.MarkFlagRequired("server")
	_ = shareUnsealCmd.MarkFlagRequired("group-id")
	_ = shareUnsealCmd.MarkFlagRequired("share-index")

	// shareDeleteCmd flags.
	shareDeleteCmd.Flags().String("server", "", "xkmsd server URL that issued the share")
	shareDeleteCmd.Flags().String("group-id", "", "Custodian group ID")
	shareDeleteCmd.Flags().Int("share-index", 0, "1-based share index within the group")
	_ = shareDeleteCmd.MarkFlagRequired("server")
	_ = shareDeleteCmd.MarkFlagRequired("group-id")
	_ = shareDeleteCmd.MarkFlagRequired("share-index")
}

// openLocalShareStore opens the file-backed share store from the resolved
// data directory. The store is created if it does not exist.
func openLocalShareStore() (sharestore.ShareStore, error) {
	dataDir, err := resolveShareDataDir()
	if err != nil {
		return nil, err
	}

	storePath := filepath.Join(dataDir, defaultShareStoreSubdir)
	backend, err := file.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShareStoreOpen, err)
	}

	store, err := sharestore.NewBackendShareStore(backend, defaultShareStorePrefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShareStoreOpen, err)
	}

	return store, nil
}

// resolveShareDataDir resolves the base data directory for share storage.
// Uses the same resolution logic as barrier commands.
func resolveShareDataDir() (string, error) {
	return resolveBarrierDataDir()
}

// runShareList lists all locally stored shares.
func runShareList(cmd *cobra.Command, _ []string) error {
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	entries, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareStoreList, err)
	}

	out := cmd.OutOrStdout()

	if len(entries) == 0 {
		fmt.Fprintln(out, "No shares stored locally.")
		return nil
	}

	fmt.Fprintf(out, "Locally Stored Shares (%d):\n\n", len(entries))

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SERVER\tGROUP ID\tGROUP NAME\tINDEX\tPURPOSE\tRECEIVED AT")
	fmt.Fprintln(w, "------\t--------\t----------\t-----\t-------\t-----------")

	for _, entry := range entries {
		receivedAt := entry.ReceivedAt.Format(time.RFC3339)
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			entry.ServerURL,
			entry.GroupID,
			entry.GroupName,
			entry.ShareIndex,
			entry.Purpose,
			receivedAt,
		)
	}

	return w.Flush()
}

// runShareReceive polls a server for shares and stores them locally.
func runShareReceive(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		return ErrShareMissingServer
	}

	logger := slog.Default()
	logger.Info("receiving shares from server", slog.String("server", serverURL))

	// Connect to the server.
	client, err := shareClientFactory(serverURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareReceiveConnect, err)
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrShareReceiveConnect, err)
	}
	defer func() { _ = client.Close() }()

	// List shares assigned to this user.
	resp, err := client.ListShares(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareReceiveList, err)
	}

	if len(resp.Shares) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No shares available on the server.")
		return nil
	}

	// Open local store to save received shares.
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	out := cmd.OutOrStdout()
	saved := 0

	for _, share := range resp.Shares {
		entry := &sharestore.ShareEntry{
			ServerURL:  serverURL,
			GroupID:    share.GroupID,
			GroupName:  share.GroupName,
			ShareIndex: share.ShareIndex,
			ShareData:  share.ShareData,
			Purpose:    share.Purpose,
			ReceivedAt: share.ReceivedAt,
			TenantID:   share.TenantID,
		}

		if err := store.Save(ctx, entry); err != nil {
			if errors.Is(err, sharestore.ErrShareExists) {
				logger.Info("share already stored locally",
					slog.String("group_id", share.GroupID),
					slog.Int("index", share.ShareIndex),
				)
				continue
			}
			fmt.Fprintf(out, "  Failed to save share %s/%d: %v\n", share.GroupID, share.ShareIndex, err)
			continue
		}

		saved++
		logger.Info("share saved locally",
			slog.String("group_id", share.GroupID),
			slog.Int("index", share.ShareIndex),
		)
	}

	fmt.Fprintf(out, "Received %d share(s), saved %d new share(s).\n", len(resp.Shares), saved)
	return nil
}

// runShareImport imports a share from a JSON file into the local store.
func runShareImport(cmd *cobra.Command, _ []string) error {
	filePath, _ := cmd.Flags().GetString("file")
	if filePath == "" {
		return ErrShareMissingFile
	}

	// Read the JSON file.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareImportRead, err)
	}

	// Parse the share entry.
	var entry sharestore.ShareEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return fmt.Errorf("%w: %v", ErrShareImportParse, err)
	}

	// Validate the parsed entry.
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrShareImportValidate, err)
	}

	// Open local store.
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Save the share.
	ctx := context.Background()
	if err := store.Save(ctx, &entry); err != nil {
		return fmt.Errorf("%w: %v", ErrShareImportSave, err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Imported share: server=%s group=%s index=%d\n",
		entry.ServerURL, entry.GroupID, entry.ShareIndex)
	return nil
}

// runShareExport exports a share from the local store to a JSON file.
func runShareExport(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	groupID, _ := cmd.Flags().GetString("group-id")
	shareIndex, _ := cmd.Flags().GetInt("share-index")
	filePath, _ := cmd.Flags().GetString("file")

	if serverURL == "" {
		return ErrShareMissingServer
	}
	if groupID == "" {
		return ErrShareMissingGroupID
	}
	if shareIndex == 0 {
		return ErrShareMissingShareIndex
	}
	if filePath == "" {
		return ErrShareExportMissingFile
	}

	// Open local store.
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Load the share.
	ctx := context.Background()
	entry, err := store.Load(ctx, serverURL, groupID, shareIndex)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareExportLoad, err)
	}

	// Marshal to JSON with indentation for readability.
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareExportWrite, err)
	}

	// Write to file with secure permissions.
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("%w: %v", ErrShareExportWrite, err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Exported share to: %s\n", filePath)
	return nil
}

// runShareUnseal loads a local share and submits it to unseal the server barrier.
func runShareUnseal(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	groupID, _ := cmd.Flags().GetString("group-id")
	shareIndex, _ := cmd.Flags().GetInt("share-index")

	if serverURL == "" {
		return ErrShareMissingServer
	}
	if groupID == "" {
		return ErrShareMissingGroupID
	}
	if shareIndex == 0 {
		return ErrShareMissingShareIndex
	}

	// Load the share from local store.
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	entry, err := store.Load(ctx, serverURL, groupID, shareIndex)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareUnsealLoad, err)
	}

	// Connect to the server.
	client, err := shareClientFactory(serverURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareUnsealConnect, err)
	}

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrShareUnsealConnect, err)
	}
	defer func() { _ = client.Close() }()

	// Submit the share for barrier unseal.
	shareB64 := base64.StdEncoding.EncodeToString(entry.ShareData)
	req := &transport.BarrierUnsealShareRequest{
		Share: shareB64,
	}

	resp, err := client.BarrierUnsealWithShare(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrShareUnsealSubmit, err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Share submitted for group %s (index %d)\n", groupID, shareIndex)
	fmt.Fprintf(out, "  Required:  %d\n", resp.Required)
	fmt.Fprintf(out, "  Submitted: %d\n", resp.Submitted)

	if resp.Complete {
		fmt.Fprintln(out, "  Status:    Quorum reached - barrier unsealed!")
	} else {
		remaining := resp.Required - resp.Submitted
		fmt.Fprintf(out, "  Status:    %d more share(s) needed\n", remaining)
	}

	return nil
}

// runShareDelete deletes a share from the local store.
func runShareDelete(cmd *cobra.Command, _ []string) error {
	serverURL, _ := cmd.Flags().GetString("server")
	groupID, _ := cmd.Flags().GetString("group-id")
	shareIndex, _ := cmd.Flags().GetInt("share-index")

	if serverURL == "" {
		return ErrShareMissingServer
	}
	if groupID == "" {
		return ErrShareMissingGroupID
	}
	if shareIndex == 0 {
		return ErrShareMissingShareIndex
	}

	// Open local store.
	store, err := openLocalShareStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Delete the share.
	ctx := context.Background()
	if err := store.Delete(ctx, serverURL, groupID, shareIndex); err != nil {
		return fmt.Errorf("%w: %v", ErrShareDeleteFailed, err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Deleted share: server=%s group=%s index=%d\n", serverURL, groupID, shareIndex)
	return nil
}

// ShareError represents a share command operation error.
type ShareError struct {
	Operation string
	Message   string
	Err       error
}

// Error returns the error message.
func (e *ShareError) Error() string {
	if e.Err != nil {
		if e.Message != "" {
			return fmt.Sprintf("share: %s: %s: %v", e.Operation, e.Message, e.Err)
		}
		return fmt.Sprintf("share: %s: %v", e.Operation, e.Err)
	}
	if e.Message != "" {
		return fmt.Sprintf("share: %s: %s", e.Operation, e.Message)
	}
	return fmt.Sprintf("share: %s", e.Operation)
}

// Unwrap returns the underlying error.
func (e *ShareError) Unwrap() error {
	return e.Err
}
