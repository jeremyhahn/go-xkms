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
	"fmt"
	"os"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// auditMaxFollowPages bounds how many pages `audit query --all` will fetch
// while following the cursor chain. Without a bound, a server bug that
// always returns a non-empty AuditPage.Next (or an operator pointed at a
// genuinely enormous log) would make --all spin forever.
const auditMaxFollowPages = 10000

// auditCmd is the top-level command for querying the tamper-evident audit
// log owned by the embedded qrdb node.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Query the tamper-evident audit log",
	Long: `Query the tamper-evident audit log owned by the embedded qrdb node.

There is no command to write an audit event: the server appends a record
as a side effect of the operation being audited, never on a caller's
request, so a client cannot forge the log.

Subcommands:
  query   Query audit events`,
}

// auditQueryCmd queries the audit log.
var auditQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query audit events",
	Long: `Query audit events from the tamper-evident audit log.

Results are cursor-paginated. Pass the cursor printed as "next" back via
--cursor to fetch the following page, or use --all to follow the cursor
chain automatically until it is exhausted.

Each event carries a prev_hash, the chain link that makes the log
verifiable; it is included in JSON output but omitted from the table view
to keep it readable.

Examples:
  xkmsctl audit query --actor alice --limit 50
  xkmsctl audit query --resource key/prod-signing --action delete
  xkmsctl audit query --from 2026-08-01T00:00:00Z --to 2026-08-12T00:00:00Z --all
  xkmsctl audit query --cursor <next-from-previous-page>`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		filter, err := auditFilterFromFlags(cmd)
		if err != nil {
			handleError(err)
			return
		}

		fr := newFlagReader(cmd)
		all := fr.Bool("all")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if all {
			auditQueryAll(cfg, printer, filter)
			return
		}
		auditQuery(cfg, printer, filter)
	},
}

// auditFilterFromFlags builds an AuditFilter from the query command's flags,
// parsing --from/--to as RFC3339 timestamps.
func auditFilterFromFlags(cmd *cobra.Command) (*client.AuditFilter, error) {
	fr := newFlagReader(cmd)
	actor := fr.String("actor")
	resource := fr.String("resource")
	action := fr.String("action")
	outcome := fr.String("outcome")
	tenantID := fr.String("tenant")
	limit := fr.Int("limit")
	cursor := fr.String("cursor")
	fromStr := fr.String("from")
	toStr := fr.String("to")
	if err := fr.Err(); err != nil {
		return nil, err
	}

	filter := &client.AuditFilter{
		Actor:    actor,
		Resource: resource,
		Action:   action,
		Outcome:  outcome,
		TenantID: tenantID,
		Limit:    limit,
		Cursor:   cursor,
	}

	if fromStr != "" {
		from, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrAuditFromInvalid, Detail: fromStr, Err: err}
		}
		filter.From = from
	}
	if toStr != "" {
		to, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrAuditToInvalid, Detail: toStr, Err: err}
		}
		filter.To = to
	}

	return filter, nil
}

// createAuditClient creates and connects a client, returning the client and
// a cleanup function. The caller must call cleanup when done.
func createAuditClient(cfg *Config) (client.Client, func(), error) {
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

// auditQuery fetches a single page of audit events and prints it.
func auditQuery(cfg *Config, printer *Printer, filter *client.AuditFilter) {
	cl, cleanup, err := createAuditClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	printVerbose("Querying audit log actor=%q resource=%q action=%q cursor=%q", filter.Actor, filter.Resource, filter.Action, filter.Cursor)

	page, err := cl.QueryAudit(context.Background(), filter)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrQueryAuditFailed, Err: err})
		return
	}

	printAuditPage(printer, page)
}

// auditQueryAll follows AuditPage.Next until the chain is exhausted or the
// auditMaxFollowPages safety bound is reached, then prints every event
// collected as a single page.
func auditQueryAll(cfg *Config, printer *Printer, filter *client.AuditFilter) {
	cl, cleanup, err := createAuditClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	var events []client.AuditEvent
	total := 0
	cursor := filter.Cursor

	for pages := 0; ; pages++ {
		if pages >= auditMaxFollowPages {
			if err := printer.PrintWarning(fmt.Sprintf(
				"--all stopped after the safety limit of %d pages; pass --cursor %q to continue",
				auditMaxFollowPages, cursor)); err != nil {
				handleError(err)
				return
			}
			break
		}

		pageFilter := *filter
		pageFilter.Cursor = cursor

		printVerbose("Querying audit log (page %d) cursor=%q", pages+1, cursor)

		page, err := cl.QueryAudit(context.Background(), &pageFilter)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrQueryAuditFailed, Err: err})
			return
		}

		events = append(events, page.Events...)
		total = page.Total

		if page.Next == "" {
			break
		}
		cursor = page.Next
	}

	printAuditPage(printer, &client.AuditPage{Events: events, Total: total})
}

// printAuditPage renders an audit page through the Printer abstraction.
// JSON output includes every field, including PrevHash, the tamper-evidence
// chain link. Table output stays narrow: timestamp, actor, resource,
// action, outcome.
func printAuditPage(printer *Printer, page *client.AuditPage) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(page); err != nil {
			handleError(err)
		}
	case OutputFormatTable:
		if len(page.Events) == 0 {
			printer.println("No audit events found")
			return
		}
		printer.printf("%-25s %-15s %-25s %-15s %-10s\n",
			"TIMESTAMP", "ACTOR", "RESOURCE", "ACTION", "OUTCOME")
		printer.println(repeatString("-", 94))
		for _, e := range page.Events {
			printer.printf("%-25s %-15s %-25s %-15s %-10s\n",
				e.Timestamp.Format(time.RFC3339),
				truncateString(e.Actor, 15),
				truncateString(e.Resource, 25),
				truncateString(e.Action, 15),
				truncateString(e.Outcome, 10))
		}
		printer.printf("\nTotal: %d event(s)\n", len(page.Events))
		if page.Next != "" {
			printer.printf("Next cursor: %s\n", page.Next)
		}
	case OutputFormatText:
		if len(page.Events) == 0 {
			printer.println("No audit events found")
			return
		}
		printer.println("Audit Events:")
		for _, e := range page.Events {
			printer.printf("  - %s actor=%s resource=%s action=%s outcome=%s\n",
				e.Timestamp.Format(time.RFC3339), e.Actor, e.Resource, e.Action, e.Outcome)
		}
		if page.Next != "" {
			printer.printf("Next cursor: %s\n", page.Next)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	auditQueryCmd.Flags().String("actor", "", "filter by actor")
	auditQueryCmd.Flags().String("resource", "", "filter by resource")
	auditQueryCmd.Flags().String("action", "", "filter by action")
	auditQueryCmd.Flags().String("outcome", "", "filter by outcome")
	auditQueryCmd.Flags().String("tenant", "", "filter by tenant ID")
	auditQueryCmd.Flags().String("from", "", "only events at or after this RFC3339 timestamp")
	auditQueryCmd.Flags().String("to", "", "only events at or before this RFC3339 timestamp")
	auditQueryCmd.Flags().Int("limit", 0, "maximum events per page (server default when 0)")
	auditQueryCmd.Flags().String("cursor", "", "continue from a previous page's next cursor")
	auditQueryCmd.Flags().Bool("all", false, fmt.Sprintf(
		"follow the cursor chain and fetch every page (bounded at %d pages)", auditMaxFollowPages))

	auditCmd.AddCommand(auditQueryCmd)

	rootCmd.AddCommand(auditCmd)
}
