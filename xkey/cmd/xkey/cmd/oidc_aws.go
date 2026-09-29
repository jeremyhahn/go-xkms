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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
	"github.com/spf13/cobra"
)

// AWS OIDC command errors.
//
// The interactive login dance's own failure modes -- authorization timeout,
// a state mismatch, a response with no credentials, a callback with no
// authorization code -- are NOT re-declared here. aws.Login already returns
// its own typed sentinels for them (aws.ErrLoginTimeout, aws.ErrStateMismatch,
// aws.ErrMissingCredentials, aws.ErrNoAuthorizationCode) and runAWSLogin
// propagates that error as-is, so errors.Is against the aws package's
// sentinel already works end to end; a second, cmd-level sentinel for the
// same concept would just be a duplicate identity to keep in sync. The same
// is true of the "--exec is required" check: handlers.NewForMode already
// returns handlers.ErrExecModeRequiresCommand, and handleAWSOutput
// propagates it unchanged.
var (
	ErrAWSMissingRegion          = errors.New("aws: --region is required")
	ErrAWSLoginFailed            = errors.New("aws: login failed")
	ErrAWSCallbackFailed         = errors.New("aws: callback failed")
	ErrAWSTokenExchangeFailed    = errors.New("aws: token exchange failed")
	ErrAWSCredentialsWriteFailed = errors.New("aws: failed to write credentials")
	ErrAWSSessionLoadFailed      = errors.New("aws: failed to load session")
	ErrAWSNoRefreshToken         = errors.New("aws: no refresh token in session")
)

// AWSStoredSession represents a stored AWS session with DPoP key.
type AWSStoredSession struct {
	Region       string    `json:"region"`
	Profile      string    `json:"profile"`
	AccessKeyID  string    `json:"access_key_id"`
	Expiration   time.Time `json:"expiration"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	DPoPKeyPEM   string    `json:"dpop_key_pem,omitempty"`
}

// oidcAWSCmd is the AWS-specific OIDC login command.
var oidcAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS Console OIDC login",
	Long: `Login to AWS using native OIDC authentication.

This command uses AWS's native OIDC signin endpoints with DPoP (Demonstrating
Proof-of-Possession) to obtain temporary AWS credentials directly, without
needing an IAM role or identity provider.

The flow is similar to 'aws login' from the AWS CLI:
1. Opens browser to AWS signin endpoint
2. User authenticates with AWS
3. Receives authorization code via callback
4. Exchanges code for DPoP-bound tokens
5. Writes credentials to ~/.aws/credentials

Features:
  - DPoP token binding (RFC 9449) for enhanced security
  - Cross-device authentication support
  - Automatic credential refresh
  - Multiple output modes: aws-credentials, json, exec

Examples:
  # Basic login (writes to ~/.aws/credentials default profile)
  xkey oidc aws --region us-east-1

  # Login to specific profile
  xkey oidc aws --region us-east-1 --profile my-profile

  # Cross-device login (shows QR code)
  xkey oidc aws --region us-east-1 --cross-device

  # Output credentials as JSON
  xkey oidc aws --region us-east-1 --output json

  # Auto-refresh credentials (runs in foreground)
  xkey oidc aws --region us-east-1 --auto-refresh 840

  # Run custom exec script after login
  xkey oidc aws --region us-east-1 --exec ./my-script.sh`,
	RunE: runOIDCAWS,
}

// runOIDCAWS executes the AWS OIDC login flow.
func runOIDCAWS(cmd *cobra.Command, args []string) error {
	// Check if running as background worker (internal use)
	backgroundWorker, _ := cmd.Flags().GetBool("background-worker")
	if backgroundWorker {
		return runAWSBackgroundWorker(cmd, args)
	}

	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")
	crossDevice, _ := cmd.Flags().GetBool("cross-device")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")
	output, _ := cmd.Flags().GetString("output")
	credentialsFile, _ := cmd.Flags().GetString("credentials-file")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	sessionStore, _ := cmd.Flags().GetString("session-store")
	background, _ := cmd.Flags().GetBool("background")
	logFile, _ := cmd.Flags().GetString("log-file")

	callback, err := resolveOIDCCallback(cmd)
	if err != nil {
		return err
	}

	return runAWSLogin(cmd.OutOrStdout(), region, profile, crossDevice, noBrowser, output, credentialsFile, execCmd, autoRefresh, sessionStore, background, logFile, "", callback)
}

// writeAWSLoginSummary prints the outcome of a successful AWS login. The
// access key ID comes back from the AWS sign-in token endpoint, so it is
// sanitised before it reaches the terminal.
func writeAWSLoginSummary(out io.Writer, region, profile, accessKeyID string, expiration time.Time) {
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "AWS login successful!")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "  Region:         %s\n", region)
	_, _ = fmt.Fprintf(out, "  Profile:        %s\n", profile)
	_, _ = fmt.Fprintf(out, "  Access Key ID:  %s\n", oidc.SanitizeProviderText(accessKeyID))
	_, _ = fmt.Fprintf(out, "  Expires:        %s\n", expiration.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "  Time remaining: %s\n", formatDuration(time.Until(expiration)))
}

// runAWSLogin is the core AWS login implementation that can be called from both
// the aws subcommand and from provider-based login. The interactive OIDC
// dance itself (DPoP key, PKCE, callback listener, code exchange) lives in
// the shared aws.Login; this function is a thin caller that adds the CLI's
// presentation, output-mode dispatch, session persistence and background
// refresh.
func runAWSLogin(out io.Writer, region, profile string, crossDevice, noBrowser bool, output, credentialsFile, execCmd string, autoRefresh int, sessionStore string, background bool, logFile, providerName string, callback oidc.Callback) error {
	if region == "" {
		return ErrAWSMissingRegion
	}
	if profile == "" {
		profile = handlers.DefaultAWSProfile
	}
	if credentialsFile == "" {
		credentialsFile = handlers.DefaultAWSCredentialsPath
	}

	onAuthURL := func(authURL string) {
		if noBrowser || crossDevice {
			_, _ = fmt.Fprintln(out, "Open the following URL in your browser:")
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, authURL)
			_, _ = fmt.Fprintln(out)
			if crossDevice {
				_, _ = fmt.Fprintln(out, "(Cross-device mode: you can open this on a different device)")
			}
			_, _ = fmt.Fprintln(out, "Waiting for authorization...")
			return
		}
		_, _ = fmt.Fprintln(out, "Opening browser for AWS authentication...")
		if err := openLaunchURL(authURL); err != nil {
			_, _ = fmt.Fprintf(out, "Failed to open browser: %v\n", err)
			_, _ = fmt.Fprintln(out, "Please open the following URL manually:")
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(out, authURL)
		}
		_, _ = fmt.Fprintln(out, "Waiting for authorization...")
	}

	result, err := aws.Login(context.Background(), aws.LoginOptions{
		Region:      region,
		CrossDevice: crossDevice,
		Callback:    callback,
	}, onAuthURL)
	if err != nil {
		switch {
		case errors.Is(err, aws.ErrCallbackFailed):
			return &SentinelCauseError{Sentinel: ErrAWSCallbackFailed, Cause: err}
		case errors.Is(err, aws.ErrTokenExchangeFailed):
			return &SentinelCauseError{Sentinel: ErrAWSTokenExchangeFailed, Cause: err}
		default:
			// aws.Login already returns a fully typed, wrapped error
			// (including ErrLoginTimeout and ErrStateMismatch); it is
			// propagated as-is rather than re-wrapped.
			return err
		}
	}
	tokenResp := result.TokenResponse
	dpopKey := result.DPoPKey

	// Convert to token data
	tokenData, err := tokenResp.ToTokenData(region)
	if err != nil {
		return &WrappedError{Msg: "failed to convert token data", Err: err}
	}

	// Process output
	if err := handleAWSOutput(output, tokenData, profile, credentialsFile, execCmd); err != nil {
		return err
	}

	// Print success message
	creds := tokenResp.GetCredentials()
	expiration, _ := tokenResp.GetExpirationTime()
	writeAWSLoginSummary(out, region, profile, creds.AccessKeyID, expiration)

	// Store session for refresh (if refresh token available)
	if tokenResp.RefreshToken != "" && sessionStore != "" {
		dpopKeyPEM, _ := dpopKey.SerializePrivateKey()
		session := AWSStoredSession{
			Region:       region,
			Profile:      profile,
			AccessKeyID:  creds.AccessKeyID,
			Expiration:   expiration,
			RefreshToken: tokenResp.RefreshToken,
			DPoPKeyPEM:   dpopKeyPEM,
		}
		if err := storeAWSSession(sessionStore, session); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to store session: %v\n", err)
		}
	}

	// Auto-refresh loop
	if autoRefresh > 0 {
		if tokenResp.RefreshToken == "" {
			_, _ = fmt.Fprintln(out, "\nWarning: No refresh token received. Auto-refresh will not work.")
			return nil
		}

		// Determine log file path
		if logFile == "" {
			logFile = getAWSDefaultLogFile(sessionStore, region)
		} else {
			logFile = expandPath(logFile)
		}

		if background {
			// Start background process
			return startAWSBackgroundRefresh(out, region, profile, credentialsFile, output, execCmd, sessionStore, logFile, autoRefresh, providerName)
		}

		_, _ = fmt.Fprintf(out, "\nAuto-refresh enabled: refreshing every %d seconds\n", autoRefresh)
		_, _ = fmt.Fprintln(out, "Press Ctrl+C to stop...")
		_, _ = fmt.Fprintln(out)

		client, err := aws.NewClient(&aws.ClientConfig{
			Region:      region,
			CrossDevice: crossDevice,
			RedirectURL: callback.AWSRedirectURL(),
		}, dpopKey)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrAWSLoginFailed, Cause: err}
		}

		return runAWSAutoRefresh(client, tokenResp.RefreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName, time.Duration(autoRefresh)*time.Second)
	}

	return nil
}

// handleAWSOutput processes the token data according to the output mode.
// It is a thin wrapper over handlers.NewForMode, the output-mode dispatch
// shared with the xKey GUI's OIDC service.
func handleAWSOutput(outputMode string, data *handlers.TokenData, profile, credentialsFile, execCmd string) error {
	handler, err := handlers.NewForMode(outputMode, profile, credentialsFile, execCmd)
	if err != nil {
		return err
	}
	return handler.Handle(context.Background(), data)
}

// runAWSAutoRefresh runs the auto-refresh loop for AWS credentials.
func runAWSAutoRefresh(client *aws.Client, refreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName string, interval time.Duration) error {
	return runAWSAutoRefreshWithWriter(client, refreshToken, region, profile,
		credentialsFile, output, execCmd, sessionStore, providerName, interval, os.Stdout)
}

// runAWSAutoRefreshWithWriter runs the auto-refresh loop for AWS credentials with a custom writer.
func runAWSAutoRefreshWithWriter(client *aws.Client, refreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName string, interval time.Duration, logWriter io.Writer) error {
	if logWriter == nil {
		logWriter = os.Stdout
	}
	log := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(logWriter, format, args...)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	refreshCount := 0
	intervalSecs := int(interval.Seconds())

	// Helper to save status
	updateStatus := func(lastStatus, lastError string) {
		status := &OIDCRefreshStatus{
			LastRefresh:  time.Now(),
			NextRefresh:  time.Now().Add(interval),
			RefreshCount: refreshCount,
			LastStatus:   lastStatus,
			LastError:    lastError,
			IntervalSecs: intervalSecs,
		}
		// Use session store directory for status file
		statusName := providerName
		if statusName == "" {
			statusName = fmt.Sprintf("aws-%s", region)
		}
		if err := saveRefreshStatus(sessionStore, statusName, status); err != nil {
			log("  Warning: failed to save status: %v\n", err)
		}
	}

	for {
		select {
		case <-sigChan:
			log("\n[%s] Auto-refresh stopped.\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil

		case <-ticker.C:
			refreshCount++
			log("[%s] Refreshing AWS credentials (#%d)...\n", time.Now().Format("2006-01-02 15:04:05"), refreshCount)

			// Refresh credentials through the shared refresh step.
			tokenResp, nextRefreshToken, err := aws.RefreshCredentials(context.Background(), client, refreshToken)
			if err != nil {
				log("  Error refreshing: %v\n", err)
				updateStatus("error", fmt.Sprintf("refresh failed: %v", err))
				continue
			}
			refreshToken = nextRefreshToken

			// Convert and output
			tokenData, err := tokenResp.ToTokenData(region)
			if err != nil {
				log("  Error converting: %v\n", err)
				updateStatus("error", fmt.Sprintf("conversion failed: %v", err))
				continue
			}

			if err := handleAWSOutput(output, tokenData, profile, credentialsFile, execCmd); err != nil {
				log("  Error outputting: %v\n", err)
				updateStatus("error", fmt.Sprintf("output failed: %v", err))
				continue
			}

			expiration, _ := tokenResp.GetExpirationTime()
			log("  Credentials refreshed. Expires: %s\n", expiration.Format(time.RFC3339))
			updateStatus("success", "")
		}
	}
}

// storeAWSSession stores an AWS session for later refresh.
func storeAWSSession(storePath string, session AWSStoredSession) error {
	path := expandPath(storePath)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// loadAWSSession loads an AWS session from storage.
func loadAWSSession(storePath string) (*AWSStoredSession, error) {
	path := expandPath(storePath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var session AWSStoredSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// getAWSDefaultLogFile returns the default log file path for AWS refresh.
func getAWSDefaultLogFile(sessionStore, region string) string {
	dir := filepath.Dir(expandPath(sessionStore))
	logsDir := filepath.Join(dir, "logs")
	return filepath.Join(logsDir, fmt.Sprintf("aws-%s.log", region))
}

// getAWSPIDFile returns the PID file path for AWS background refresh.
// If providerName is provided, use it; otherwise fall back to aws-{region}.
func getAWSPIDFile(sessionStore, region, providerName string) string {
	dir := filepath.Dir(expandPath(sessionStore))
	pidsDir := filepath.Join(dir, "pids")
	name := providerName
	if name == "" {
		name = fmt.Sprintf("aws-%s", region)
	}
	return filepath.Join(pidsDir, name+".pid")
}

// startAWSBackgroundRefresh starts a background refresh process for AWS.
func startAWSBackgroundRefresh(out io.Writer, region, profile, credentialsFile, output, execCmd, sessionStore, logFile string, autoRefresh int, providerName string) error {
	// Ensure log directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create log directory", Err: err}
	}

	// Ensure PID directory exists
	pidFile := getAWSPIDFile(sessionStore, region, providerName)
	pidDir := filepath.Dir(pidFile)
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create PID directory", Err: err}
	}

	// Check if already running
	displayName := providerName
	if displayName == "" {
		displayName = fmt.Sprintf("AWS region '%s'", region)
	} else {
		displayName = fmt.Sprintf("'%s'", displayName)
	}
	if pid, running := isAWSProcessRunning(pidFile); running {
		return &MessageError{Msg: fmt.Sprintf("background refresh for %s is already running (PID %d)", displayName, pid)}
	}

	// Load session to get refresh token and DPoP key
	session, err := loadAWSSession(sessionStore)
	if err != nil {
		return &DetailError{Err: &WrappedError{Msg: "failed to load session", Err: err}, Detail: " (run login without --background first)"}
	}

	if session.RefreshToken == "" {
		return &MessageError{Msg: "no refresh token in session store"}
	}

	// Open log file
	logFileHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return &WrappedError{Msg: "failed to open log file", Err: err}
	}

	// Build command to run ourselves with --background-worker flag (skips login)
	executable, err := os.Executable()
	if err != nil {
		return &WrappedError{Msg: "failed to get executable path", Err: errors.Join(err, logFileHandle.Close())}
	}

	args := []string{
		"oidc", "aws",
		"--background-worker",
		"--region", region,
		"--profile", profile,
		"--credentials-file", credentialsFile,
		"--output", output,
		"--auto-refresh", fmt.Sprintf("%d", autoRefresh),
		"--session-store", sessionStore,
		"--log-file", logFile,
	}
	if providerName != "" {
		args = append(args, "--provider-name", providerName)
	}
	if execCmd != "" {
		args = append(args, "--exec", execCmd)
	}

	cmd := exec.Command(executable, args...)
	cmd.Stdout = logFileHandle
	cmd.Stderr = logFileHandle

	// Start the process
	if err := cmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start background process", Err: errors.Join(err, logFileHandle.Close())}
	}

	// Write PID file
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0600); err != nil {
		killErr := cmd.Process.Kill()
		return &WrappedError{Msg: "failed to write PID file", Err: errors.Join(err, killErr, logFileHandle.Close())}
	}

	// Don't wait for the process - let it run in background. There is no
	// caller left to report a cleanup failure to at this point, so each is
	// logged instead of dropped.
	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			slog.Debug("oidc aws: background worker exited with an error", "error", waitErr)
		}
		if closeErr := logFileHandle.Close(); closeErr != nil {
			slog.Warn("oidc aws: failed to close background worker log file", "error", closeErr)
		}
		if rmErr := os.Remove(pidFile); rmErr != nil {
			slog.Warn("oidc aws: failed to remove PID file", "error", rmErr)
		}
	}()

	stopName := providerName
	if stopName == "" {
		stopName = fmt.Sprintf("aws-%s", region)
		_, _ = fmt.Fprintf(out, "Background refresh started for AWS region '%s'\n", region)
	} else {
		_, _ = fmt.Fprintf(out, "Background refresh started for '%s'\n", providerName)
	}
	_, _ = fmt.Fprintf(out, "  PID:      %d\n", cmd.Process.Pid)
	_, _ = fmt.Fprintf(out, "  Log file: %s\n", logFile)
	_, _ = fmt.Fprintf(out, "\nUse 'xkey oidc status' to see running refreshes\n")
	_, _ = fmt.Fprintf(out, "Use 'xkey oidc stop %s' to stop\n", stopName)

	return nil
}

// runAWSBackgroundWorker runs the actual AWS auto-refresh loop (called by background process).
// This function loads the stored session and goes directly to the refresh loop,
// skipping the interactive login flow.
func runAWSBackgroundWorker(cmd *cobra.Command, args []string) (err error) {
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")
	credentialsFile, _ := cmd.Flags().GetString("credentials-file")
	output, _ := cmd.Flags().GetString("output")
	execCmd, _ := cmd.Flags().GetString("exec")
	autoRefresh, _ := cmd.Flags().GetInt("auto-refresh")
	sessionStore, _ := cmd.Flags().GetString("session-store")
	logFile, _ := cmd.Flags().GetString("log-file")
	providerName, _ := cmd.Flags().GetString("provider-name")

	// Load stored session
	session, err := loadAWSSession(sessionStore)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAWSSessionLoadFailed, Cause: err}
	}

	if session.RefreshToken == "" {
		return ErrAWSNoRefreshToken
	}

	// Restore DPoP key from stored session
	dpopKey, err := oidc.DeserializeDPoPKey(session.DPoPKeyPEM)
	if err != nil {
		return &WrappedError{Msg: "failed to restore DPoP key", Err: err}
	}

	// Create AWS client with restored DPoP key
	callback, err := resolveOIDCCallback(cmd)
	if err != nil {
		return err
	}
	clientConfig := &aws.ClientConfig{
		Region:      region,
		RedirectURL: callback.AWSRedirectURL(),
	}

	client, err := aws.NewClient(clientConfig, dpopKey)
	if err != nil {
		return &WrappedError{Msg: "failed to create AWS client", Err: err}
	}

	// Open log file for writing
	var logWriter io.Writer = os.Stdout
	if logFile != "" {
		f, openErr := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if openErr != nil {
			return &WrappedError{Msg: "failed to open log file", Err: openErr}
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()
		logWriter = f
	}

	// Determine display name for logging
	displayName := providerName
	if displayName == "" {
		displayName = fmt.Sprintf("aws-%s", region)
	}

	_, _ = fmt.Fprintf(logWriter, "[%s] Background refresh started for '%s'\n", time.Now().Format("2006-01-02 15:04:05"), displayName)
	_, _ = fmt.Fprintf(logWriter, "  Region: %s\n", region)
	_, _ = fmt.Fprintf(logWriter, "  Profile: %s\n", profile)
	_, _ = fmt.Fprintf(logWriter, "  Refresh interval: %d seconds\n", autoRefresh)
	if execCmd != "" {
		_, _ = fmt.Fprintf(logWriter, "  Exec command: %s\n", execCmd)
	}
	_, _ = fmt.Fprintf(logWriter, "\n")

	return runAWSAutoRefreshWithWriter(client, session.RefreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName, time.Duration(autoRefresh)*time.Second, logWriter)
}

// isAWSProcessRunning checks if an AWS background process is running.
func isAWSProcessRunning(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}

	err = process.Signal(syscall.Signal(0))
	return pid, err == nil
}

func init() {
	// Add aws subcommand to oidc
	OIDCCmd.AddCommand(oidcAWSCmd)

	// AWS OIDC flags
	oidcAWSCmd.Flags().StringP("region", "r", "", "AWS region (required)")
	oidcAWSCmd.Flags().String("profile", "default", "AWS profile name to write credentials to")
	oidcAWSCmd.Flags().Bool("cross-device", false, "Enable cross-device authentication flow")
	oidcAWSCmd.Flags().Bool("no-browser", false, "Don't open browser, print URL instead")
	oidcAWSCmd.Flags().StringP("output", "o", "aws-credentials", "Output mode: aws-credentials, json, exec, none")
	oidcAWSCmd.Flags().String("credentials-file", "~/.aws/credentials", "Path to AWS credentials file")
	oidcAWSCmd.Flags().String("exec", "", "Execute script after login (for --output exec)")
	oidcAWSCmd.Flags().Int("auto-refresh", 0, "Auto-refresh interval in seconds (0 to disable)")
	oidcAWSCmd.Flags().String("session-store", "~/.xkey/aws-session.json", "Path to session store")
	oidcAWSCmd.Flags().Bool("background", false, "Run auto-refresh in background (requires --auto-refresh)")
	oidcAWSCmd.Flags().String("log-file", "", "Log file for background refresh (default: ~/.xkey/logs/aws-{region}.log)")

	// Hidden flags for background worker mode (used internally)
	oidcAWSCmd.Flags().Bool("background-worker", false, "Internal: run as background worker")
	oidcAWSCmd.Flags().String("provider-name", "", "Internal: provider name for PID file")
	_ = oidcAWSCmd.Flags().MarkHidden("background-worker")
	_ = oidcAWSCmd.Flags().MarkHidden("provider-name")

	registerOIDCCallbackFlags(oidcAWSCmd.Flags())

	// Mark region as required
	_ = oidcAWSCmd.MarkFlagRequired("region")
}
