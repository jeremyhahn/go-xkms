// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"encoding/base64"
	"os"
	"path/filepath"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// shareCmd is the parent command for Shamir share collection operations.
var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage collected Shamir shares",
	Long: `Submit received Shamir shares back to the server, list collected
shares, and check per-group collection progress.`,
}

// shareSubmitCmd submits a received share.
var shareSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a received Shamir share",
	Long: `Submit a Shamir share back to the server toward a group's quorum.

The share bytes come from --data (base64) or --file.

Examples:
  xkmsctl share submit --group-id g1 --share-index 2 --file share.bin
  xkmsctl share submit --group-id g1 --share-index 2 --data "$(cat share.b64)"`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		groupID := fr.String("group-id")
		groupName := fr.String("group-name")
		serverURL := fr.String("server-url")
		shareIndex := fr.Int("share-index")
		purpose := fr.String("purpose")
		dataB64 := fr.String("data")
		file := fr.String("file")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if groupID == "" {
			handleError(ErrShareGroupIDRequired)
			return
		}

		if dataB64 != "" && file != "" {
			handleError(ErrShareDataSourceConflict)
			return
		}

		var shareData []byte
		switch {
		case file != "":
			data, err := os.ReadFile(filepath.Clean(file))
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrReadShareFileFailed, Err: err})
				return
			}
			shareData = data
		case dataB64 != "":
			decoded, err := base64.StdEncoding.DecodeString(dataB64)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrShareDataRequired, Err: err})
				return
			}
			shareData = decoded
		default:
			handleError(ErrShareDataRequired)
			return
		}

		shareSubmit(cfg, printer, &client.SubmitShareRequest{
			ServerURL:  serverURL,
			GroupID:    groupID,
			GroupName:  groupName,
			ShareIndex: shareIndex,
			ShareData:  shareData,
			Purpose:    purpose,
		})
	},
}

// shareListCmd lists collected shares.
var shareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List collected shares",
	Long: `List the Shamir shares collected for the authenticated user.

Example:
  xkmsctl share list`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		shareList(cfg, printer)
	},
}

// shareStatusCmd reports collection progress for a group.
var shareStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show share collection status for a group",
	Long: `Show how many shares have been collected toward a group's quorum.

Example:
  xkmsctl share status --group-id g1`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		groupID := fr.String("group-id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if groupID == "" {
			handleError(ErrShareGroupIDRequired)
			return
		}
		shareStatus(cfg, printer, groupID)
	},
}

// shareGetCmd shows a single collected share.
var shareGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show a single collected share",
	Long: `Show the metadata for one collected share.

A share is addressed by the triple (server URL, group ID, share index). The
share bytes themselves are never returned — they are write-only over the API
and readable only by the barrier's unseal quorum.

Example:
  xkmsctl share get --server-url https://xkms:8443 --group-id g1 --share-index 2`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		serverURL, groupID, shareIndex, ok := shareCoordinates(cmd)
		if !ok {
			return
		}
		shareGet(cfg, printer, serverURL, groupID, shareIndex)
	},
}

// shareDeleteCmd removes a single collected share.
var shareDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a single collected share",
	Long: `Delete one collected share, addressed by the triple (server URL,
group ID, share index).

Deleting a share lowers the group's collected count, so a quorum that was
ready may stop being ready.

Example:
  xkmsctl share delete --server-url https://xkms:8443 --group-id g1 --share-index 2`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		serverURL, groupID, shareIndex, ok := shareCoordinates(cmd)
		if !ok {
			return
		}
		shareDelete(cfg, printer, serverURL, groupID, shareIndex)
	},
}

// shareCoordinates reads and validates the triple addressing a single share.
// It reports the error itself and returns ok=false when a flag is missing, so
// callers stay a straight line.
func shareCoordinates(cmd *cobra.Command) (serverURL, groupID string, shareIndex int, ok bool) {
	fr := newFlagReader(cmd)
	serverURL = fr.String("server-url")
	groupID = fr.String("group-id")
	shareIndex = fr.Int("share-index")
	if err := fr.Err(); err != nil {
		handleError(err)
		return "", "", 0, false
	}
	if serverURL == "" {
		handleError(ErrShareServerURLRequired)
		return "", "", 0, false
	}
	if groupID == "" {
		handleError(ErrShareGroupIDRequired)
		return "", "", 0, false
	}
	return serverURL, groupID, shareIndex, true
}

// createShareClient creates and connects a client for share operations.
func createShareClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}
	if err := cl.Connect(context.Background()); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}
	return cl, func() { closeQuietly(cl) }, nil
}

func shareSubmit(cfg *Config, printer *Printer, req *client.SubmitShareRequest) {
	cl, cleanup, err := createShareClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.SubmitShare(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSubmitShareFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	default:
		if resp.Accepted {
			printer.printf("Share accepted for group %q (index %d).\n", req.GroupID, req.ShareIndex)
		} else {
			printer.printf("Share was not accepted.\n")
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func shareList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createShareClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.ListShares(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListSharesFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	default:
		if len(resp.Shares) == 0 {
			printer.printf("No shares collected.\n")
			return
		}
		printer.printf("Collected shares:\n")
		for _, s := range resp.Shares {
			printer.printf("  group=%s index=%d server=%s purpose=%s received=%s\n",
				s.GroupID, s.ShareIndex, s.ServerURL, s.Purpose, s.ReceivedAt.Format("2006-01-02T15:04:05Z07:00"))
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func shareGet(cfg *Config, printer *Printer, serverURL, groupID string, shareIndex int) {
	cl, cleanup, err := createShareClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	info, err := cl.GetShare(context.Background(), serverURL, groupID, shareIndex)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetShareFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(info); err != nil {
			handleError(err)
		}
	default:
		printer.printf("Share:\n")
		printer.printf("  Server:   %s\n", info.ServerURL)
		printer.printf("  Group:    %s\n", info.GroupID)
		printer.printf("  Name:     %s\n", info.GroupName)
		printer.printf("  Index:    %d\n", info.ShareIndex)
		printer.printf("  Purpose:  %s\n", info.Purpose)
		printer.printf("  Received: %s\n", info.ReceivedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func shareDelete(cfg *Config, printer *Printer, serverURL, groupID string, shareIndex int) {
	cl, cleanup, err := createShareClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	if err := cl.DeleteShare(context.Background(), serverURL, groupID, shareIndex); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteShareFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]any{
			"deleted":     true,
			"server_url":  serverURL,
			"group_id":    groupID,
			"share_index": shareIndex,
		}); err != nil {
			handleError(err)
		}
	default:
		printer.printf("Deleted share %d for group %q.\n", shareIndex, groupID)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func shareStatus(cfg *Config, printer *Printer, groupID string) {
	cl, cleanup, err := createShareClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.GetShareCollectionStatus(context.Background(), groupID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrShareCollectionStatusFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	default:
		printer.printf("Share Collection Status:\n")
		printer.printf("  Group:     %s\n", resp.GroupID)
		printer.printf("  Collected: %d\n", resp.Collected)
		printer.printf("  Threshold: %d\n", resp.Threshold)
		printer.printf("  Total:     %d\n", resp.Total)
		printer.printf("  Ready:     %t\n", resp.Ready)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	shareSubmitCmd.Flags().String("group-id", "", "custodian group ID (required)")
	shareSubmitCmd.Flags().String("group-name", "", "custodian group name (optional)")
	shareSubmitCmd.Flags().String("server-url", "", "originating server URL (optional)")
	shareSubmitCmd.Flags().Int("share-index", 0, "share index")
	shareSubmitCmd.Flags().String("purpose", "", "share purpose (optional)")
	shareSubmitCmd.Flags().String("data", "", "share bytes, base64-encoded")
	shareSubmitCmd.Flags().String("file", "", "file containing the raw share bytes")

	shareStatusCmd.Flags().String("group-id", "", "custodian group ID (required)")

	for _, c := range []*cobra.Command{shareGetCmd, shareDeleteCmd} {
		c.Flags().String("server-url", "", "originating server URL (required)")
		c.Flags().String("group-id", "", "custodian group ID (required)")
		c.Flags().Int("share-index", 0, "share index within the group")
	}

	shareCmd.AddCommand(shareSubmitCmd)
	shareCmd.AddCommand(shareListCmd)
	shareCmd.AddCommand(shareGetCmd)
	shareCmd.AddCommand(shareDeleteCmd)
	shareCmd.AddCommand(shareStatusCmd)

	rootCmd.AddCommand(shareCmd)
}
