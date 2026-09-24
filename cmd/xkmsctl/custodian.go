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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// custodianCmd is the top-level command for custodian group management.
var custodianCmd = &cobra.Command{
	Use:   "custodian",
	Short: "Manage custodian groups",
	Long: `Manage custodian groups for Shamir secret sharing ceremonies.

Custodian groups define the set of trusted individuals who hold Shamir
shares for a barrier or tenant barrier. Each group specifies the threshold
(minimum shares required) and the total number of shares to distribute.

Subcommands:
  create         Create a new custodian group
  list           List all custodian groups
  show           Show details for a custodian group
  delete         Delete a custodian group
  add-member     Add a member to a custodian group
  remove-member  Remove a member from a custodian group
  distribute     Distribute Shamir shares to group members`,
}

// custodianCreateCmd creates a new custodian group.
var custodianCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new custodian group",
	Long: `Create a new custodian group with the specified threshold and total shares.

Examples:
  xkmsctl custodian create --name "Ops Team" --purpose "production barrier" --threshold 3 --total 5
  xkmsctl custodian create --name "DR Group" --purpose "disaster recovery" --threshold 2 --total 3 --tenant-id acme`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		name := fr.String("name")
		purpose := fr.String("purpose")
		threshold := fr.Int("threshold")
		total := fr.Int("total")
		tenantID := fr.String("tenant-id")
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if name == "" {
			handleError(ErrCustodianNameRequired)
			return
		}
		if threshold <= 0 || total <= 0 {
			handleError(ErrCustodianInvalidThreshold)
			return
		}
		if threshold > total {
			handleError(ErrCustodianThresholdExceedsTotal)
			return
		}

		custodianCreate(cfg, printer, id, tenantID, name, purpose, threshold, total)
	},
}

// custodianListCmd lists all custodian groups.
var custodianListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all custodian groups",
	Long: `List all custodian groups, optionally filtered by tenant ID.

Examples:
  xkmsctl custodian list
  xkmsctl custodian list --tenant-id acme`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		custodianList(cfg, printer)
	},
}

// custodianShowCmd shows details for a custodian group.
var custodianShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show details for a custodian group",
	Long: `Display detailed information about a custodian group including members.

Example:
  xkmsctl custodian show --id my-group-id`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrCustodianIDRequired)
			return
		}

		custodianShow(cfg, printer, id)
	},
}

// custodianDeleteCmd deletes a custodian group.
var custodianDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a custodian group",
	Long: `Delete a custodian group by ID. This does not revoke previously
distributed shares.

Example:
  xkmsctl custodian delete --id my-group-id`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		id := fr.String("id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if id == "" {
			handleError(ErrCustodianIDRequired)
			return
		}

		custodianDelete(cfg, printer, id)
	},
}

// custodianAddMemberCmd adds a member to a custodian group.
var custodianAddMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a member to a custodian group",
	Long: `Add a user as a member to a custodian group. The user will be eligible
to receive a Shamir share when shares are distributed.

Examples:
  xkmsctl custodian add-member --group-id my-group --user-id user-123
  xkmsctl custodian add-member --group-id my-group --user-id user-123 --username alice --method encrypted`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		groupID := fr.String("group-id")
		userID := fr.String("user-id")
		username := fr.String("username")
		method := fr.String("method")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if groupID == "" {
			handleError(ErrCustodianGroupIDRequired)
			return
		}
		if userID == "" {
			handleError(ErrCustodianUserIDRequired)
			return
		}

		custodianAddMember(cfg, printer, groupID, userID, username, method)
	},
}

// custodianRemoveMemberCmd removes a member from a custodian group.
var custodianRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a member from a custodian group",
	Long: `Remove a user from a custodian group. If shares have already been
distributed, the removed member's share remains valid until the group
is re-keyed.

Example:
  xkmsctl custodian remove-member --group-id my-group --user-id user-123`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		groupID := fr.String("group-id")
		userID := fr.String("user-id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if groupID == "" {
			handleError(ErrCustodianGroupIDRequired)
			return
		}
		if userID == "" {
			handleError(ErrCustodianUserIDRequired)
			return
		}

		custodianRemoveMember(cfg, printer, groupID, userID)
	},
}

// custodianDistributeCmd distributes Shamir shares to group members.
var custodianDistributeCmd = &cobra.Command{
	Use:   "distribute",
	Short: "Distribute Shamir shares to group members",
	Long: `Distribute Shamir shares to all members of the custodian group.
Each member receives exactly one share via their configured delivery method.

The barrier must be unsealed to perform distribution.

Example:
  xkmsctl custodian distribute --group-id my-group`,
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
			handleError(ErrCustodianGroupIDRequired)
			return
		}

		custodianDistribute(cfg, printer, groupID)
	},
}

// createCustodianClient creates and connects a client, returning the client
// and a cleanup function. The caller must call cleanup when done.
func createCustodianClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cleanup := func() { closeQuietly(cl) }
	return cl, cleanup, nil
}

// custodianCreate creates a new custodian group.
func custodianCreate(cfg *Config, printer *Printer, id, tenantID, name, purpose string, threshold, total int) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Creating custodian group %q (threshold=%d, total=%d)", name, threshold, total)

	req := &transport.CreateCustodianGroupRequest{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		Purpose:   purpose,
		Threshold: threshold,
		Total:     total,
	}

	resp, err := cl.CreateCustodianGroup(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateCustodianGroupFailed, Err: err})
		return
	}

	printCustodianGroup(printer, &resp.Group)
}

// custodianList lists all custodian groups.
func custodianList(cfg *Config, printer *Printer) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Listing custodian groups")

	resp, err := cl.ListCustodianGroups(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListCustodianGroupsFailed, Err: err})
		return
	}

	printCustodianGroupList(printer, resp.Groups)
}

// custodianShow shows details for a custodian group.
func custodianShow(cfg *Config, printer *Printer, groupID string) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Retrieving custodian group %q", groupID)

	resp, err := cl.GetCustodianGroup(context.Background(), groupID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetCustodianGroupFailed, Err: err})
		return
	}

	printCustodianGroupDetail(printer, &resp.Group)
}

// custodianDelete deletes a custodian group.
func custodianDelete(cfg *Config, printer *Printer, groupID string) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Deleting custodian group %q", groupID)

	if err := cl.DeleteCustodianGroup(context.Background(), groupID); err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteCustodianGroupFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Custodian group %q deleted", groupID)); err != nil {
		handleError(err)
	}
}

// custodianAddMember adds a member to a custodian group.
func custodianAddMember(cfg *Config, printer *Printer, groupID, userID, username, method string) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Adding member %q to custodian group %q", userID, groupID)

	req := &transport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   userID,
		Username: username,
		Method:   method,
	}

	resp, err := cl.AddCustodianMember(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrAddCustodianMemberFailed, Err: err})
		return
	}

	printCustodianMember(printer, &resp.Member)
}

// custodianRemoveMember removes a member from a custodian group.
func custodianRemoveMember(cfg *Config, printer *Printer, groupID, userID string) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Removing member %q from custodian group %q", userID, groupID)

	req := &transport.RemoveCustodianMemberRequest{
		GroupID: groupID,
		UserID:  userID,
	}

	if err := cl.RemoveCustodianMember(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrRemoveCustodianMemberFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Member %q removed from group %q", userID, groupID)); err != nil {
		handleError(err)
	}
}

// custodianDistribute distributes Shamir shares to group members.
func custodianDistribute(cfg *Config, printer *Printer, groupID string) {
	cl, cleanup, err := createCustodianClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Distributing shares for custodian group %q", groupID)

	req := &transport.DistributeSharesRequest{
		GroupID: groupID,
	}

	resp, err := cl.DistributeShares(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDistributeSharesFailed, Err: err})
		return
	}

	printDistributeResult(printer, groupID, resp)
}

// Output helpers

// printCustodianGroup prints a custodian group summary.
func printCustodianGroup(printer *Printer, group *transport.CustodianGroupInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(group); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Custodian Group Created:\n")
		printer.printf("  ID:        %s\n", group.ID)
		printer.printf("  Name:      %s\n", group.Name)
		printer.printf("  Purpose:   %s\n", group.Purpose)
		printer.printf("  Threshold: %d of %d\n", group.Threshold, group.Total)
		if group.TenantID != "" {
			printer.printf("  Tenant:    %s\n", group.TenantID)
		}
		printer.printf("  Created:   %s\n", group.CreatedAt.Format(time.RFC3339))
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printCustodianGroupList prints a list of custodian groups.
func printCustodianGroupList(printer *Printer, groups []transport.CustodianGroupInfo) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"groups": groups,
			"total":  len(groups),
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(groups) == 0 {
			printer.println("No custodian groups found")
			return
		}
		printer.printf("%-20s %-25s %-10s %-8s %-20s\n",
			"ID", "NAME", "THRESHOLD", "MEMBERS", "CREATED")
		printer.println(strings.Repeat("-", 85))
		for _, g := range groups {
			printer.printf("%-20s %-25s %d/%-7d %-8d %-20s\n",
				truncateString(g.ID, 20),
				truncateString(g.Name, 25),
				g.Threshold, g.Total,
				len(g.Members),
				g.CreatedAt.Format("2006-01-02 15:04"))
		}
		printer.printf("\nTotal: %d group(s)\n", len(groups))
	case OutputFormatText:
		if len(groups) == 0 {
			printer.println("No custodian groups found")
			return
		}
		printer.println("Custodian Groups:")
		for _, g := range groups {
			printer.printf("  - %s (%s, threshold %d/%d, %d members)\n",
				g.Name, g.ID, g.Threshold, g.Total, len(g.Members))
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printCustodianGroupDetail prints detailed custodian group information.
func printCustodianGroupDetail(printer *Printer, group *transport.CustodianGroupInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(group); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Custodian Group Details:\n")
		printer.printf("  ID:        %s\n", group.ID)
		printer.printf("  Name:      %s\n", group.Name)
		printer.printf("  Purpose:   %s\n", group.Purpose)
		printer.printf("  Threshold: %d of %d\n", group.Threshold, group.Total)
		if group.TenantID != "" {
			printer.printf("  Tenant:    %s\n", group.TenantID)
		}
		printer.printf("  Created:   %s\n", group.CreatedAt.Format(time.RFC3339))
		printer.printf("  Updated:   %s\n", group.UpdatedAt.Format(time.RFC3339))

		if len(group.Members) == 0 {
			printer.printf("\n  Members: none\n")
		} else {
			printer.printf("\n  Members (%d):\n", len(group.Members))
			for i, m := range group.Members {
				label := m.UserID
				if m.Username != "" {
					label = fmt.Sprintf("%s (%s)", m.Username, m.UserID)
				}
				printer.printf("    %d. %s\n", i+1, label)
				printer.printf("       Share Index: %d\n", m.ShareIndex)
				printer.printf("       Method:      %s\n", m.Method)
				printer.printf("       Assigned:    %s\n", m.AssignedAt.Format(time.RFC3339))
				if m.ReceivedAt != nil {
					printer.printf("       Received:    %s\n", m.ReceivedAt.Format(time.RFC3339))
				}
			}
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printCustodianMember prints a custodian member summary.
func printCustodianMember(printer *Printer, member *transport.CustodianMemberInfo) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(member); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Member Added:\n")
		printer.printf("  User ID:     %s\n", member.UserID)
		if member.Username != "" {
			printer.printf("  Username:    %s\n", member.Username)
		}
		printer.printf("  Share Index: %d\n", member.ShareIndex)
		printer.printf("  Method:      %s\n", member.Method)
		printer.printf("  Assigned:    %s\n", member.AssignedAt.Format(time.RFC3339))
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// printDistributeResult prints the share distribution result.
func printDistributeResult(printer *Printer, groupID string, resp *transport.DistributeSharesResponse) {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"group_id":    groupID,
			"distributed": resp.Distributed,
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Shares distributed successfully\n")
		printer.printf("  Group:       %s\n", groupID)
		printer.printf("  Distributed: %d share(s)\n", resp.Distributed)
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	// custodian create flags
	custodianCreateCmd.Flags().String("name", "", "name of the custodian group (required)")
	custodianCreateCmd.Flags().String("purpose", "", "purpose description for the group")
	custodianCreateCmd.Flags().Int("threshold", 0, "minimum shares required to unseal (required)")
	custodianCreateCmd.Flags().Int("total", 0, "total number of shares to generate (required)")
	custodianCreateCmd.Flags().String("tenant-id", "", "tenant ID to associate the group with")
	custodianCreateCmd.Flags().String("id", "", "custom group ID (auto-generated if omitted)")

	// custodian list flags
	custodianListCmd.Flags().String("tenant-id", "", "filter groups by tenant ID")

	// custodian show flags
	custodianShowCmd.Flags().String("id", "", "custodian group ID (required)")

	// custodian delete flags
	custodianDeleteCmd.Flags().String("id", "", "custodian group ID (required)")

	// custodian add-member flags
	custodianAddMemberCmd.Flags().String("group-id", "", "custodian group ID (required)")
	custodianAddMemberCmd.Flags().String("user-id", "", "user ID of the member to add (required)")
	custodianAddMemberCmd.Flags().String("username", "", "display username for the member")
	custodianAddMemberCmd.Flags().String("method", "encrypted", "share delivery method (encrypted, manual)")

	// custodian remove-member flags
	custodianRemoveMemberCmd.Flags().String("group-id", "", "custodian group ID (required)")
	custodianRemoveMemberCmd.Flags().String("user-id", "", "user ID of the member to remove (required)")

	// custodian distribute flags
	custodianDistributeCmd.Flags().String("group-id", "", "custodian group ID (required)")

	// Build subcommand tree
	custodianCmd.AddCommand(custodianCreateCmd)
	custodianCmd.AddCommand(custodianListCmd)
	custodianCmd.AddCommand(custodianShowCmd)
	custodianCmd.AddCommand(custodianDeleteCmd)
	custodianCmd.AddCommand(custodianAddMemberCmd)
	custodianCmd.AddCommand(custodianRemoveMemberCmd)
	custodianCmd.AddCommand(custodianDistributeCmd)

	// Register with root
	rootCmd.AddCommand(custodianCmd)
}
