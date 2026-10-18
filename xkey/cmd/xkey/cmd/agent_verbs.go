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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// Agent enrollment verb errors.
var (
	// ErrAgentCodeFailed indicates the one-time enrollment code could not
	// be generated.
	ErrAgentCodeFailed = errors.New("agent: failed to generate enrollment code")

	// ErrAgentPendingFailed indicates pending enrollment requests could
	// not be listed.
	ErrAgentPendingFailed = errors.New("agent: failed to list pending enrollments")

	// ErrAgentApproveFailed indicates a pending enrollment request could
	// not be approved.
	ErrAgentApproveFailed = errors.New("agent: failed to approve enrollment")

	// ErrAgentRejectFailed indicates a pending enrollment request could
	// not be rejected.
	ErrAgentRejectFailed = errors.New("agent: failed to reject enrollment")

	// ErrAgentRemoveFailed indicates an enrolled agent could not be
	// removed.
	ErrAgentRemoveFailed = errors.New("agent: failed to remove agent")

	// ErrAgentMissingRequestID indicates "agent approve" was called
	// without the pending request's ID.
	ErrAgentMissingRequestID = errors.New("agent: enrollment request ID is required")

	// ErrAgentMissingAgentID indicates "agent remove" was called without
	// the enrolled agent's ID.
	ErrAgentMissingAgentID = errors.New("agent: agent ID is required")
)

var (
	agentCodeJSON     bool
	agentCodeValidity time.Duration
	agentPendingJSON  bool
	agentApproveJSON  bool
	agentRejectJSON   bool
	agentRejectReason string
	agentRemoveJSON   bool
)

// agentCodeCmd generates a one-time enrollment code.
var agentCodeCmd = &cobra.Command{
	Use:   "code",
	Short: "Generate a one-time agent enrollment code",
	Long: `Generate a one-time code a remote agent presents, alongside its CSR,
to enroll against this master.

This shares the same enrollment service the GUI's "Generate Code" action
uses. The code's hash - never the code itself - is persisted through the
enrollment store, the same on-disk store "agent status" and "agent remove"
already share with a running "agent start" process, so the code is honored
regardless of which process ("agent start", the GUI, or another "xkey
agent" invocation) an agent presents it to.

Examples:
  xkey agent code
  xkey agent code --validity 30m
  xkey agent code --json`,
	RunE: runAgentCode,
}

// agentPendingCmd lists pending enrollment requests awaiting approval.
var agentPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending agent enrollment requests",
	Long: `List enrollment requests submitted for admin approval that have not
yet been approved or rejected.

Pending requests, including their CSRs, are persisted through the
enrollment store, so a request submitted while "agent start" is running is
visible here regardless of which process lists it.

Examples:
  xkey agent pending
  xkey agent pending --json`,
	RunE: runAgentPending,
}

// agentApproveCmd approves a pending enrollment request.
var agentApproveCmd = &cobra.Command{
	Use:   "approve <request-id>",
	Short: "Approve a pending agent enrollment request",
	Long: `Approve a pending enrollment request, signing its CSR with the
xkmsd certificate authority and recording the new agent in the enrollment
store. The pending request is deleted once approval completes.

The issued certificate and the CA certificate are printed so the
administrator can deliver them to the enrolling agent out of band; xkey
never transmits them anywhere on the approver's behalf.

Examples:
  xkey agent approve 3f9c2a1b8e7d4f60
  xkey agent approve 3f9c2a1b8e7d4f60 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentApprove,
}

// agentRejectCmd rejects a pending enrollment request.
var agentRejectCmd = &cobra.Command{
	Use:   "reject <request-id>",
	Short: "Reject a pending agent enrollment request",
	Long: `Reject a pending enrollment request, deleting it from the enrollment
store without signing its CSR. This is the same operation the GUI's
"Reject" action performs, over the same shared service.

Examples:
  xkey agent reject 3f9c2a1b8e7d4f60
  xkey agent reject 3f9c2a1b8e7d4f60 --reason "not authorized"
  xkey agent reject 3f9c2a1b8e7d4f60 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentReject,
}

// agentRemoveCmd removes an enrolled agent, revoking its certificate first.
var agentRemoveCmd = &cobra.Command{
	Use:   "remove <agent-id>",
	Short: "Remove an enrolled agent",
	Long: `Remove an enrolled agent from this master.

The agent's certificate is revoked through the xkmsd certificate authority
before its enrollment record is deleted. If revocation fails, the record
is left in place and the command fails: an agent is never left "removed"
while its certificate is still valid, since that would let it keep
connecting.

Examples:
  xkey agent remove 3f9c2a1b8e7d4f60
  xkey agent remove 3f9c2a1b8e7d4f60 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAgentRemove,
}

func init() {
	AgentCmd.AddCommand(agentCodeCmd)
	AgentCmd.AddCommand(agentPendingCmd)
	AgentCmd.AddCommand(agentApproveCmd)
	AgentCmd.AddCommand(agentRejectCmd)
	AgentCmd.AddCommand(agentRemoveCmd)

	for _, cmd := range []*cobra.Command{agentCodeCmd, agentPendingCmd, agentApproveCmd, agentRejectCmd, agentRemoveCmd} {
		cmd.Flags().String("cert-profile", agent.CertProfileDefault,
			"xkmsd CA profile used to sign or revoke agent certificates")
		cmd.Flags().Int("cert-validity-days", 0,
			"validity period for issued agent certificates (0 uses the CA default)")
	}

	agentCodeCmd.Flags().BoolVar(&agentCodeJSON, "json", false, "output the code as JSON")
	agentCodeCmd.Flags().DurationVar(&agentCodeValidity, "validity", 0,
		"code validity duration (0 uses the configured default)")

	agentPendingCmd.Flags().BoolVar(&agentPendingJSON, "json", false, "output pending requests as JSON")
	agentApproveCmd.Flags().BoolVar(&agentApproveJSON, "json", false, "output the approval result as JSON")
	agentRejectCmd.Flags().BoolVar(&agentRejectJSON, "json", false, "output the rejection result as JSON")
	agentRejectCmd.Flags().StringVar(&agentRejectReason, "reason", "", "reason recorded in the log and event for this rejection")
	agentRemoveCmd.Flags().BoolVar(&agentRemoveJSON, "json", false, "output the removal result as JSON")
}

// newCLIAgentService builds an agent.EnrollmentService backed by the same
// on-disk enrollment store "agent start" uses and a CA client connected to
// the configured xkmsd authority, then wraps both in a services.AgentService
// so every entry point - GUI and CLI alike - drives agent enrollment through
// the identical shared service layer. The returned closer releases the CA's
// transport client and must be called once the command is done.
func newCLIAgentService(cmd *cobra.Command) (*services.AgentService, func(), error) {
	logger := slog.Default()

	storeDir, err := agentStoreDir()
	if err != nil {
		return nil, nil, err
	}
	store, err := agent.NewFileStore(storeDir, logger)
	if err != nil {
		return nil, nil, err
	}

	certValidityDays, _ := cmd.Flags().GetInt("cert-validity-days")
	ca, err := newAgentCA(agentCertProfile(cmd), certValidityDays)
	if err != nil {
		return nil, nil, err
	}
	closer := func() {
		if closeErr := ca.Close(); closeErr != nil {
			logger.Warn("failed to close certificate authority client", "error", closeErr)
		}
	}

	cfg := agent.DefaultConfig()
	cfg.EnrollmentMethods = []agent.EnrollmentMethod{
		agent.EnrollOneTimeCode,
		agent.EnrollAdminApproval,
	}

	enrollment, err := agent.NewEnrollmentService(cfg, ca, store, logger)
	if err != nil {
		closer()
		return nil, nil, err
	}

	svc := services.NewAgentService()
	svc.SetEnrollmentService(enrollment)
	svc.SetEnrollmentStore(store)

	return svc, closer, nil
}

// newCLIAgentServiceFunc is newCLIAgentService behind a variable so tests
// can substitute a service backed by a stub CA and an isolated store,
// without a network round trip to a fake xkmsd endpoint for every case.
// One-time codes and pending requests are fully persisted through
// EnrollmentStore, so this seam is a test-speed convenience, not a
// requirement for correctness: production code always uses
// newCLIAgentService, and any command here also works correctly against
// state a completely separate process wrote to the same store.
var newCLIAgentServiceFunc = newCLIAgentService

func runAgentCode(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	svc, closer, err := newCLIAgentServiceFunc(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCodeFailed, Cause: err}
	}
	defer closer()

	code, err := generateAgentCode(svc, agentCodeValidity)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCodeFailed, Cause: err}
	}

	if agentCodeJSON {
		return writeJSON(out, code)
	}

	_, _ = fmt.Fprintln(out, "Enrollment code generated")
	_, _ = fmt.Fprintf(out, "  Code:       %s\n", code.Code)
	_, _ = fmt.Fprintf(out, "  Expires at: %s\n", code.ExpiresAt)
	return nil
}

// generateAgentCode is split out from runAgentCode so tests can drive it
// against a service wired to a fake CA without going through cobra flags.
func generateAgentCode(svc *services.AgentService, validity time.Duration) (*services.EnrollmentCodeInfo, error) {
	if validity > 0 {
		return svc.GenerateEnrollmentCodeWithValidity(validity)
	}
	return svc.GenerateEnrollmentCode()
}

func runAgentPending(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	svc, closer, err := newCLIAgentServiceFunc(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentPendingFailed, Cause: err}
	}
	defer closer()

	pending, err := svc.ListPendingEnrollments()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentPendingFailed, Cause: err}
	}

	if agentPendingJSON {
		return writeJSON(out, pending)
	}

	if len(pending) == 0 {
		_, _ = fmt.Fprintln(out, "No pending enrollment requests")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Pending Enrollment Requests (%d):\n\n", len(pending))
	for _, p := range pending {
		_, _ = fmt.Fprintf(out, "  ID:           %s\n", p.ID)
		_, _ = fmt.Fprintf(out, "  Fingerprint:  %s\n", p.Fingerprint)
		_, _ = fmt.Fprintf(out, "  Requested at: %s\n", p.RequestedAt)
		_, _ = fmt.Fprintf(out, "  Status:       %s\n", p.Status)
		_, _ = fmt.Fprintln(out)
	}
	return nil
}

func runAgentApprove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	requestID := args[0]
	if requestID == "" {
		return ErrAgentMissingRequestID
	}

	svc, closer, err := newCLIAgentServiceFunc(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentApproveFailed, Cause: err}
	}
	defer closer()

	result, err := svc.ApproveEnrollmentWithCertificate(requestID)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentApproveFailed, Cause: err}
	}

	if agentApproveJSON {
		return writeJSON(out, result)
	}

	_, _ = fmt.Fprintln(out, "Enrollment approved")
	_, _ = fmt.Fprintf(out, "  Request ID: %s\n", requestID)
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Certificate:")
	_, _ = fmt.Fprintln(out, string(result.CertificatePEM))
	_, _ = fmt.Fprintln(out, "CA certificate:")
	_, _ = fmt.Fprintln(out, string(result.CACertificatePEM))
	return nil
}

func runAgentReject(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	requestID := args[0]
	if requestID == "" {
		return ErrAgentMissingRequestID
	}

	svc, closer, err := newCLIAgentServiceFunc(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentRejectFailed, Cause: err}
	}
	defer closer()

	if err := svc.RejectEnrollment(requestID, agentRejectReason); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentRejectFailed, Cause: err}
	}

	if agentRejectJSON {
		return writeJSON(out, map[string]string{"request_id": requestID, "status": "rejected"})
	}

	_, _ = fmt.Fprintf(out, "Enrollment rejected: %s\n", requestID)
	return nil
}

func runAgentRemove(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	agentID := args[0]
	if agentID == "" {
		return ErrAgentMissingAgentID
	}

	svc, closer, err := newCLIAgentServiceFunc(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentRemoveFailed, Cause: err}
	}
	defer closer()

	if err := svc.RemoveAgent(agentID); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentRemoveFailed, Cause: err}
	}

	if agentRemoveJSON {
		return writeJSON(out, map[string]string{"agent_id": agentID, "status": "removed"})
	}

	_, _ = fmt.Fprintf(out, "Agent removed: %s\n", agentID)
	return nil
}
