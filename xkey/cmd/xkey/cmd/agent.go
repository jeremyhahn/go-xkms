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
	ErrAgentStatusFailed       = errors.New("agent: failed to read agent status")
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

Enrolling agents receive certificates signed by the xkmsd certificate
authority, so a reachable xkmsd server is required: set --xkmsd-url or
XKMSD_URL. The command fails closed when no authority is reachable; xkey
never signs certificates locally.

The process records its PID and bound listen address under the xKey home
directory so 'xkey agent status' and 'xkey agent stop' can find it, and
removes that record on shutdown. A second 'agent start' against the same
home fails with an already-running error.

Examples:
  xkey agent start --xkmsd-url unix:///var/run/xkmsd.sock
  xkey agent start --xkmsd-url grpcs://xkms.example.com:8443 --listen :9443
  xkey agent start --tls-cert server.pem --tls-key server-key.pem`,
	RunE: runAgentStart,
}

// agentStopCmd stops the agent server.
var agentStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the agent server",
	Long: `Stop the running agent server gracefully.

The server started by 'xkey agent start' records its process ID and bound
listen address in a run-state file under the xKey home directory. This
command reads that record, verifies the process is still a live agent
server, sends SIGTERM, and waits up to 10 seconds for a graceful exit
before escalating to SIGKILL. The run-state file is removed once the
process is gone.

When no agent server is running the command reports that and exits with a
non-zero status; it never claims to have stopped a server it did not stop.

Examples:
  xkey agent stop`,
	RunE: runAgentStop,
}

// agentStatusCmd shows agent server status.
var agentStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent server status and connections",
	Long: `Show whether the agent server is running - including its process ID
and bound listen address - followed by the list of enrolled agents.

A run-state file left behind by a crashed server is detected (the recorded
process is gone or has been recycled by an unrelated program), reported as
not running, and removed.

Examples:
  xkey agent status`,
	RunE: runAgentStatus,
}

// runAgentStart starts the agent server.
func runAgentStart(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	tlsCA, _ := cmd.Flags().GetString("tls-ca")

	cfg := agent.DefaultConfig()
	// The listen address is configuration: --listen over agent.listen_address
	// over the built-in default.
	cfg.ListenAddress = agentListenAddress(cmd)
	cfg.TLSCertFile = tlsCert
	cfg.TLSKeyFile = tlsKey
	cfg.TLSCAFile = tlsCA

	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := slog.Default()

	// Claim the run-state file before binding anything so a second
	// "agent start" fails fast with a clear error instead of racing the
	// listener bind.
	state, err := newAgentServerState(cfg.ListenAddress, tlsCert != "")
	if err != nil {
		return err
	}
	if err := claimAgentServerState(state); err != nil {
		return err
	}
	stateReleased := false
	releaseState := func() {
		if stateReleased {
			return
		}
		stateReleased = true
		if releaseErr := releaseAgentServerState(state.PID); releaseErr != nil {
			logger.Warn("failed to remove agent server state file", "error", releaseErr)
		}
	}
	defer releaseState()

	// Create enrollment store.
	storeDir, err := agentStoreDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStartFailed, Cause: err}
	}
	store, err := agent.NewFileStore(storeDir, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStartFailed, Cause: err}
	}

	// Connect the enrollment service to the xkmsd certificate authority.
	// Agent enrollment issues real client certificates, so the server
	// fails closed when no authority is reachable.
	certValidityDays, _ := cmd.Flags().GetInt("cert-validity-days")
	ca, err := newAgentCA(agentCertProfile(cmd), certValidityDays)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := ca.Close(); closeErr != nil {
			logger.Warn("failed to close certificate authority client", "error", closeErr)
		}
	}()

	enrollment, err := agent.NewEnrollmentService(cfg, ca, store, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStartFailed, Cause: err}
	}

	server, err := agent.NewServer(cfg, enrollment, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStartFailed, Cause: err}
	}

	if err := server.Start(); err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStartFailed, Cause: err}
	}

	// Record the resolved bound address (the configured address may use
	// an ephemeral port) so "agent status" and "agent stop" can report it.
	state.ListenAddr = server.Addr()
	if err := updateAgentServerState(state); err != nil {
		if stopErr := server.Stop(); stopErr != nil {
			logger.Error("failed to stop agent server after state update failure", "error", stopErr)
		}
		return err
	}

	_, _ = fmt.Fprintf(out, "Agent server started\n")
	_, _ = fmt.Fprintf(out, "  PID:    %d\n", state.PID)
	_, _ = fmt.Fprintf(out, "  Listen: %s\n", server.Addr())
	if tlsCert != "" {
		_, _ = fmt.Fprintf(out, "  TLS:    enabled (mTLS)\n")
	} else {
		_, _ = fmt.Fprintf(out, "  TLS:    disabled (development mode)\n")
	}

	// Wait for signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		_, _ = fmt.Fprintln(out, "\nShutting down agent server...")
	case <-ctx.Done():
	}

	return server.Stop()
}

// runAgentStop stops the running agent server, returning
// ErrAgentServerNotRunning (a non-zero exit) when there is nothing to stop.
func runAgentStop(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	state, forced, err := stopAgentServer(agentStopGracePeriod, agentKillGracePeriod)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(out, "Agent server stopped")
	_, _ = fmt.Fprintf(out, "  PID:    %d\n", state.PID)
	_, _ = fmt.Fprintf(out, "  Listen: %s\n", state.ListenAddr)
	if forced {
		_, _ = fmt.Fprintf(out, "  Signal: SIGKILL (graceful shutdown exceeded %s)\n", agentStopGracePeriod)
	} else {
		_, _ = fmt.Fprintf(out, "  Signal: SIGTERM\n")
	}
	return nil
}

// runAgentStatus reports whether the agent server process is running and
// lists the agents enrolled against this master.
func runAgentStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()
	state, running, err := agentServerStatus()
	if err != nil {
		return err
	}

	if running {
		_, _ = fmt.Fprintln(out, "Agent server: running")
		_, _ = fmt.Fprintf(out, "  PID:     %d\n", state.PID)
		_, _ = fmt.Fprintf(out, "  Listen:  %s\n", state.ListenAddr)
		if state.TLS {
			_, _ = fmt.Fprintf(out, "  TLS:     enabled (mTLS)\n")
		} else {
			_, _ = fmt.Fprintf(out, "  TLS:     disabled (development mode)\n")
		}
		_, _ = fmt.Fprintf(out, "  Started: %s\n", state.StartedAt.Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintln(out, "Agent server: not running")
	}
	_, _ = fmt.Fprintln(out)

	storeDir, err := agentStoreDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStatusFailed, Cause: err}
	}
	logger := slog.Default()

	store, err := agent.NewFileStore(storeDir, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStatusFailed, Cause: err}
	}

	agents, err := store.ListAgents()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentStatusFailed, Cause: err}
	}

	if len(agents) == 0 {
		_, _ = fmt.Fprintln(out, "No enrolled agents")
		return nil
	}

	_, _ = fmt.Fprintf(out, "Enrolled Agents (%d):\n\n", len(agents))
	for _, a := range agents {
		_, _ = fmt.Fprintf(out, "  ID:          %s\n", a.ID)
		_, _ = fmt.Fprintf(out, "  Name:        %s\n", a.Name)
		_, _ = fmt.Fprintf(out, "  Status:      %s\n", a.Status)
		_, _ = fmt.Fprintf(out, "  Enrolled:    %s\n", a.EnrolledAt.Format(time.RFC3339))
		_, _ = fmt.Fprintf(out, "  Last Seen:   %s\n", a.LastSeen.Format(time.RFC3339))
		if a.Address != "" {
			_, _ = fmt.Fprintf(out, "  Address:     %s\n", a.Address)
		}
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

// agentDataDir returns the base directory holding all agent state,
// <dataDir>/agent, with the data directory resolved through the CLI's
// single chain (featureDataDir) — the same resolution the root command
// performs, with no private $HOME fallback and no silent temporary
// directory when the home cannot be resolved.
func agentDataDir() (string, error) {
	return featureDataDir(agent.DataSubdir)
}

// agentStoreDir returns the directory for agent enrollment data.
func agentStoreDir() (string, error) {
	dataDir, err := resolveDataDir("")
	if err != nil {
		return "", err
	}
	return agent.EnrollmentStoreDir(dataDir), nil
}

// agentCertDir returns the directory for agent certificates.
func agentCertDir() (string, error) {
	dataDir, err := agentDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "certs"), nil
}

func init() {
	// Register agent command with root (server-side only).
	RootCmd.AddCommand(AgentCmd)

	AgentCmd.AddCommand(agentStartCmd)
	AgentCmd.AddCommand(agentStopCmd)
	AgentCmd.AddCommand(agentStatusCmd)

	// Agent start flags.
	agentStartCmd.Flags().String("listen", "", "Listen address as host:port (default: agent.listen_address, :9443)")
	agentStartCmd.Flags().String("tls-cert", "", "TLS certificate file")
	agentStartCmd.Flags().String("tls-key", "", "TLS private key file")
	agentStartCmd.Flags().String("tls-ca", "",
		"TLS CA certificate file used to verify connecting agents (the xkmsd trust bundle comes from XKMSD_TLS_CA)")
	agentStartCmd.Flags().String("cert-profile", agent.CertProfileDefault,
		"xkmsd CA profile used to sign enrolling agent CSRs")
	agentStartCmd.Flags().Int("cert-validity-days", 0,
		"validity period for issued agent certificates (0 uses the CA default)")
}
