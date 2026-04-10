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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/handlers"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

// AWS OIDC command errors.
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

	return runAWSLogin(region, profile, crossDevice, noBrowser, output, credentialsFile, execCmd, autoRefresh, sessionStore, background, logFile, "")
}

// runAWSLogin is the core AWS login implementation that can be called from both
// the aws subcommand and from provider-based login.
func runAWSLogin(region, profile string, crossDevice, noBrowser bool, output, credentialsFile, execCmd string, autoRefresh int, sessionStore string, background bool, logFile, providerName string) error {
	if region == "" {
		return ErrAWSMissingRegion
	}
	if profile == "" {
		profile = "default"
	}
	if credentialsFile == "" {
		credentialsFile = "~/.aws/credentials"
	}

	// Generate DPoP key
	dpopKey, err := oidc.GenerateDPoPKey()
	if err != nil {
		return fmt.Errorf("failed to generate DPoP key: %w", err)
	}

	// Create AWS client
	// AWS signin requires 127.0.0.1 (not localhost) and /oauth/callback path
	clientConfig := &aws.ClientConfig{
		Region:      region,
		CrossDevice: crossDevice,
		RedirectURL: "http://127.0.0.1:8085/oauth/callback",
	}

	client, err := aws.NewClient(clientConfig, dpopKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAWSLoginFailed, err)
	}

	// Generate PKCE and state
	codeVerifier, err := oidc.GenerateCodeVerifier()
	if err != nil {
		return fmt.Errorf("failed to generate code verifier: %w", err)
	}

	state, err := oidc.GenerateState()
	if err != nil {
		return fmt.Errorf("failed to generate state: %w", err)
	}

	// Build authorization URL
	authURL, err := client.AuthCodeURL(&aws.AuthCodeOptions{
		State:        state,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return fmt.Errorf("failed to build auth URL: %w", err)
	}

	// Parse redirect URL to get port
	parsedRedirect, _ := url.Parse(clientConfig.RedirectURL)
	port := parsedRedirect.Port()
	if port == "" {
		port = "8085"
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Channel for callback
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	receivedState := new(atomic.Value)

	// Start callback server
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		handleAWSCallback(w, r, codeChan, errChan, receivedState)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return fmt.Errorf("failed to start callback server: %w", err)
	}

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			errChan <- serveErr
		}
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	// Open browser or print URL
	if noBrowser || crossDevice {
		fmt.Println("Open the following URL in your browser:")
		fmt.Println()
		fmt.Println(authURL)
		fmt.Println()
		if crossDevice {
			fmt.Println("(Cross-device mode: you can open this on a different device)")
		}
		fmt.Println("Waiting for authorization...")
	} else {
		fmt.Println("Opening browser for AWS authentication...")
		if err := browser.OpenURL(authURL); err != nil {
			fmt.Printf("Failed to open browser: %v\n", err)
			fmt.Println("Please open the following URL manually:")
			fmt.Println()
			fmt.Println(authURL)
		}
		fmt.Println("Waiting for authorization...")
	}

	// Wait for callback
	var code string
	select {
	case code = <-codeChan:
		// Success
	case err := <-errChan:
		return fmt.Errorf("%w: %v", ErrAWSCallbackFailed, err)
	case <-ctx.Done():
		return errors.New("authorization timed out")
	}

	// Verify state
	if receivedState.Load() != state {
		return errors.New("state mismatch")
	}

	// Exchange code for tokens
	tokenResp, err := client.Exchange(ctx, code, &aws.AuthCodeOptions{
		State:        state,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAWSTokenExchangeFailed, err)
	}

	// Check for credentials
	if !tokenResp.HasCredentials() {
		return errors.New("no AWS credentials in response")
	}

	// Convert to token data
	tokenData, err := tokenResp.ToTokenData(region)
	if err != nil {
		return fmt.Errorf("failed to convert token data: %w", err)
	}

	// Process output
	if err := handleAWSOutput(output, tokenData, profile, credentialsFile, execCmd); err != nil {
		return err
	}

	// Print success message
	creds := tokenResp.GetCredentials()
	expiration, _ := tokenResp.GetExpirationTime()

	fmt.Println()
	fmt.Println("AWS login successful!")
	fmt.Println()
	fmt.Printf("  Region:         %s\n", region)
	fmt.Printf("  Profile:        %s\n", profile)
	fmt.Printf("  Access Key ID:  %s\n", creds.AccessKeyID)
	fmt.Printf("  Expires:        %s\n", expiration.Format(time.RFC3339))
	fmt.Printf("  Time remaining: %s\n", formatDuration(time.Until(expiration)))

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
			fmt.Println("\nWarning: No refresh token received. Auto-refresh will not work.")
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
			return startAWSBackgroundRefresh(region, profile, credentialsFile, output, execCmd, sessionStore, logFile, autoRefresh, providerName)
		}

		fmt.Printf("\nAuto-refresh enabled: refreshing every %d seconds\n", autoRefresh)
		fmt.Println("Press Ctrl+C to stop...")
		fmt.Println()

		return runAWSAutoRefresh(client, tokenResp.RefreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName, time.Duration(autoRefresh)*time.Second)
	}

	return nil
}

// handleAWSCallback handles the OAuth2 callback for AWS.
func handleAWSCallback(w http.ResponseWriter, r *http.Request, codeChan chan<- string, errChan chan<- error, state *atomic.Value) {
	query := r.URL.Query()

	if errParam := query.Get("error"); errParam != "" {
		errDesc := query.Get("error_description")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<html><body><h1>AWS Authentication Failed</h1><p>%s: %s</p></body></html>", errParam, errDesc)))
		errChan <- fmt.Errorf("%s: %s", errParam, errDesc)
		return
	}

	code := query.Get("code")
	if code == "" {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>AWS Authentication Failed</h1><p>No authorization code received</p></body></html>"))
		errChan <- errors.New("no authorization code received")
		return
	}

	state.Store(query.Get("state"))

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html><body><h1>AWS Authentication Successful</h1><p>You may close this window.</p></body></html>"))

	codeChan <- code
}

// handleAWSOutput processes the token data according to the output mode.
func handleAWSOutput(outputMode string, data *handlers.TokenData, profile, credentialsFile, execCmd string) error {
	var handler handlers.OutputHandler

	switch outputMode {
	case "aws-credentials", "":
		handler = handlers.NewAWSCredentialsHandler(profile).
			WithPath(credentialsFile)
	case "json":
		handler = handlers.NewJSONHandler().
			WithAWSOnly()
	case "exec":
		if execCmd == "" {
			return errors.New("--exec is required when using --output exec")
		}
		handler = handlers.NewExecHandler(execCmd)
	case "none":
		handler = handlers.NewNoopHandler()
	default:
		return fmt.Errorf("unknown output mode: %s", outputMode)
	}

	return handler.Handle(context.Background(), data)
}

// runAWSAutoRefresh runs the auto-refresh loop for AWS credentials.
func runAWSAutoRefresh(client *aws.Client, refreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName string, interval time.Duration) error {
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
			fmt.Printf("  Warning: failed to save status: %v\n", err)
		}
	}

	for {
		select {
		case <-sigChan:
			fmt.Printf("\n[%s] Auto-refresh stopped.\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil

		case <-ticker.C:
			refreshCount++
			fmt.Printf("[%s] Refreshing AWS credentials (#%d)...\n", time.Now().Format("2006-01-02 15:04:05"), refreshCount)

			// Refresh tokens
			tokenResp, err := client.Refresh(context.Background(), refreshToken)
			if err != nil {
				fmt.Printf("  Error refreshing: %v\n", err)
				updateStatus("error", fmt.Sprintf("refresh failed: %v", err))
				continue
			}

			// Update refresh token if new one provided
			if tokenResp.RefreshToken != "" {
				refreshToken = tokenResp.RefreshToken
			}

			if !tokenResp.HasCredentials() {
				fmt.Printf("  Error: No credentials in refresh response\n")
				updateStatus("error", "no credentials in response")
				continue
			}

			// Convert and output
			tokenData, err := tokenResp.ToTokenData(region)
			if err != nil {
				fmt.Printf("  Error converting: %v\n", err)
				updateStatus("error", fmt.Sprintf("conversion failed: %v", err))
				continue
			}

			if err := handleAWSOutput(output, tokenData, profile, credentialsFile, execCmd); err != nil {
				fmt.Printf("  Error outputting: %v\n", err)
				updateStatus("error", fmt.Sprintf("output failed: %v", err))
				continue
			}

			expiration, _ := tokenResp.GetExpirationTime()
			fmt.Printf("  Credentials refreshed. Expires: %s\n", expiration.Format(time.RFC3339))
			updateStatus("success", "")
		}
	}
}

// runAWSAutoRefreshWithWriter runs the auto-refresh loop for AWS credentials with a custom writer.
func runAWSAutoRefreshWithWriter(client *aws.Client, refreshToken, region, profile, credentialsFile, output, execCmd, sessionStore, providerName string, interval time.Duration, logWriter io.Writer) error {
	if logWriter == nil {
		logWriter = os.Stdout
	}
	log := func(format string, args ...interface{}) {
		fmt.Fprintf(logWriter, format, args...)
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

			// Refresh tokens
			tokenResp, err := client.Refresh(context.Background(), refreshToken)
			if err != nil {
				log("  Error refreshing: %v\n", err)
				updateStatus("error", fmt.Sprintf("refresh failed: %v", err))
				continue
			}

			// Update refresh token if new one provided
			if tokenResp.RefreshToken != "" {
				refreshToken = tokenResp.RefreshToken
			}

			if !tokenResp.HasCredentials() {
				log("  Error: No credentials in refresh response\n")
				updateStatus("error", "no credentials in response")
				continue
			}

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
func startAWSBackgroundRefresh(region, profile, credentialsFile, output, execCmd, sessionStore, logFile string, autoRefresh int, providerName string) error {
	// Ensure log directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Ensure PID directory exists
	pidFile := getAWSPIDFile(sessionStore, region, providerName)
	pidDir := filepath.Dir(pidFile)
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	// Check if already running
	displayName := providerName
	if displayName == "" {
		displayName = fmt.Sprintf("AWS region '%s'", region)
	} else {
		displayName = fmt.Sprintf("'%s'", displayName)
	}
	if pid, running := isAWSProcessRunning(pidFile); running {
		return fmt.Errorf("background refresh for %s is already running (PID %d)", displayName, pid)
	}

	// Load session to get refresh token and DPoP key
	session, err := loadAWSSession(sessionStore)
	if err != nil {
		return fmt.Errorf("failed to load session: %w (run login without --background first)", err)
	}

	if session.RefreshToken == "" {
		return fmt.Errorf("no refresh token in session store")
	}

	// Open log file
	logFileHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Build command to run ourselves with --background-worker flag (skips login)
	executable, err := os.Executable()
	if err != nil {
		logFileHandle.Close()
		return fmt.Errorf("failed to get executable path: %w", err)
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
		logFileHandle.Close()
		return fmt.Errorf("failed to start background process: %w", err)
	}

	// Write PID file
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0600); err != nil {
		cmd.Process.Kill()
		logFileHandle.Close()
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Don't wait for the process - let it run in background
	go func() {
		cmd.Wait()
		logFileHandle.Close()
		os.Remove(pidFile)
	}()

	stopName := providerName
	if stopName == "" {
		stopName = fmt.Sprintf("aws-%s", region)
		fmt.Printf("Background refresh started for AWS region '%s'\n", region)
	} else {
		fmt.Printf("Background refresh started for '%s'\n", providerName)
	}
	fmt.Printf("  PID:      %d\n", cmd.Process.Pid)
	fmt.Printf("  Log file: %s\n", logFile)
	fmt.Printf("\nUse 'xkey oidc status' to see running refreshes\n")
	fmt.Printf("Use 'xkey oidc stop %s' to stop\n", stopName)

	return nil
}

// runAWSBackgroundWorker runs the actual AWS auto-refresh loop (called by background process).
// This function loads the stored session and goes directly to the refresh loop,
// skipping the interactive login flow.
func runAWSBackgroundWorker(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("%w: %v", ErrAWSSessionLoadFailed, err)
	}

	if session.RefreshToken == "" {
		return ErrAWSNoRefreshToken
	}

	// Restore DPoP key from stored session
	dpopKey, err := oidc.DeserializeDPoPKey(session.DPoPKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to restore DPoP key: %w", err)
	}

	// Create AWS client with restored DPoP key
	clientConfig := &aws.ClientConfig{
		Region:      region,
		RedirectURL: "http://127.0.0.1:8085/oauth/callback",
	}

	client, err := aws.NewClient(clientConfig, dpopKey)
	if err != nil {
		return fmt.Errorf("failed to create AWS client: %w", err)
	}

	// Open log file for writing
	var logWriter io.Writer = os.Stdout
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defer f.Close()
		logWriter = f
	}

	// Determine display name for logging
	displayName := providerName
	if displayName == "" {
		displayName = fmt.Sprintf("aws-%s", region)
	}

	fmt.Fprintf(logWriter, "[%s] Background refresh started for '%s'\n", time.Now().Format("2006-01-02 15:04:05"), displayName)
	fmt.Fprintf(logWriter, "  Region: %s\n", region)
	fmt.Fprintf(logWriter, "  Profile: %s\n", profile)
	fmt.Fprintf(logWriter, "  Refresh interval: %d seconds\n", autoRefresh)
	if execCmd != "" {
		fmt.Fprintf(logWriter, "  Exec command: %s\n", execCmd)
	}
	fmt.Fprintf(logWriter, "\n")

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

	// Mark region as required
	_ = oidcAWSCmd.MarkFlagRequired("region")
}
