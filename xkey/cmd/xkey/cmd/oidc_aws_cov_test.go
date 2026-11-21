package cmd

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc/aws"
)

// awsLoginArgs holds the runAWSLogin parameters a test varies.
type awsLoginArgs struct {
	output       string
	autoRefresh  int
	sessionStore string
	background   bool
	logFile      string
}

// startAWSLogin runs runAWSLogin in a goroutine; the returned channel
// yields its result.
func startAWSLogin(t *testing.T, h *awsLoginHarness, out *bytes.Buffer, credentialsFile string, a awsLoginArgs) <-chan error {
	t.Helper()

	cmd, _ := awsTestCmd(t)
	done := make(chan error, 1)
	go func() {
		done <- runAWSLogin(cmd, out, "us-east-1", "dev", false, true, a.output, credentialsFile, "",
			a.autoRefresh, a.sessionStore, a.sessionStore != "", a.background, a.logFile, "", h.callback)
	}()
	return done
}

func TestRunAWSLogin_WritesCredentialsAndStoresSession(t *testing.T) {
	h := newAWSLoginHarness(t, awsTokenHandler("AKIALOGINSUCCESS0001", "refresh-1"))
	dir := t.TempDir()
	credentialsFile := filepath.Join(dir, "credentials")
	sessionStore := filepath.Join(dir, "session")

	var out bytes.Buffer
	done := startAWSLogin(t, h, &out, credentialsFile, awsLoginArgs{output: "aws-credentials", sessionStore: sessionStore})
	h.redirect(t, url.Values{"code": {"auth-code"}})
	require.NoError(t, <-done)

	assert.Contains(t, out.String(), "Open the following URL in your browser:")
	assert.Contains(t, out.String(), "AWS login successful!")
	assert.Contains(t, out.String(), "AKIALOGINSUCCESS0001")

	creds, err := os.ReadFile(credentialsFile)
	require.NoError(t, err)
	assert.Contains(t, string(creds), "[dev]")
	assert.Contains(t, string(creds), "AKIALOGINSUCCESS0001")

	session, err := loadAWSSession(&cobra.Command{}, sessionStore)
	require.NoError(t, err)
	assert.Equal(t, "refresh-1", session.RefreshToken)
	assert.Equal(t, "us-east-1", session.Region)
	assert.Equal(t, "dev", session.Profile)
	_, err = oidc.DeserializeDPoPKey(session.DPoPKeyPEM)
	assert.NoError(t, err, "the stored DPoP key must restore for the refresh worker")
}

func TestRunAWSLogin_TokenExchangeFailure(t *testing.T) {
	h := newAWSLoginHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	})

	var out bytes.Buffer
	done := startAWSLogin(t, h, &out, filepath.Join(t.TempDir(), "credentials"), awsLoginArgs{output: "none"})
	h.redirect(t, url.Values{"code": {"auth-code"}})

	err := <-done
	assert.ErrorIs(t, err, ErrAWSTokenExchangeFailed)
	assert.ErrorIs(t, err, aws.ErrTokenExchangeFailed)
}

func TestRunAWSLogin_AuthorizationDenied(t *testing.T) {
	h := newAWSLoginHarness(t, awsTokenHandler("AKIAUNUSED", ""))

	var out bytes.Buffer
	done := startAWSLogin(t, h, &out, filepath.Join(t.TempDir(), "credentials"), awsLoginArgs{output: "none"})
	h.redirect(t, url.Values{"error": {"access_denied"}})

	err := <-done
	assert.ErrorIs(t, err, ErrAWSCallbackFailed)
	assert.ErrorIs(t, err, aws.ErrAuthorizationFailed)
}

func TestRunAWSLogin_AutoRefreshWithoutRefreshTokenWarns(t *testing.T) {
	h := newAWSLoginHarness(t, awsTokenHandler("AKIANOREFRESH", ""))

	var out bytes.Buffer
	done := startAWSLogin(t, h, &out, filepath.Join(t.TempDir(), "credentials"), awsLoginArgs{output: "none", autoRefresh: 60})
	h.redirect(t, url.Values{"code": {"auth-code"}})

	require.NoError(t, <-done)
	assert.Contains(t, out.String(), "No refresh token received. Auto-refresh will not work.")
}

func TestRunAWSLogin_BackgroundRefusesWhenAlreadyRunning(t *testing.T) {
	h := newAWSLoginHarness(t, awsTokenHandler("AKIABACKGROUND", "refresh-bg"))
	dir := t.TempDir()
	sessionStore := filepath.Join(dir, "session")
	pidFile := getAWSPIDFile(sessionStore, "us-east-1", "")
	require.NoError(t, os.MkdirAll(filepath.Dir(pidFile), 0o700))
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600))

	var out bytes.Buffer
	done := startAWSLogin(t, h, &out, filepath.Join(dir, "credentials"), awsLoginArgs{
		output: "none", autoRefresh: 60, sessionStore: sessionStore, background: true,
		logFile: filepath.Join(dir, "logs", "aws.log"),
	})
	h.redirect(t, url.Values{"code": {"auth-code"}})

	err := <-done
	require.Error(t, err)
	assert.Contains(t, err.Error(), "background refresh for AWS region 'us-east-1' is already running")
}

func TestStartAWSBackgroundRefresh_Errors(t *testing.T) {
	validSession := func(t *testing.T, store string) {
		require.NoError(t, storeAWSSession(&cobra.Command{}, store, AWSStoredSession{Region: "us-east-1", RefreshToken: "r"}))
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir, store string) (logFile string)
		wantErr string
	}{
		{
			name: "session store empty",
			setup: func(t *testing.T, dir, store string) string {
				return filepath.Join(dir, "aws.log")
			},
			wantErr: "failed to load session",
		},
		{
			name: "no refresh token",
			setup: func(t *testing.T, dir, store string) string {
				require.NoError(t, storeAWSSession(&cobra.Command{}, store, AWSStoredSession{Region: "us-east-1"}))
				return filepath.Join(dir, "aws.log")
			},
			wantErr: "no refresh token in session store",
		},
		{
			name: "log directory under a file",
			setup: func(t *testing.T, dir, store string) string {
				blocker := filepath.Join(dir, "blocker")
				require.NoError(t, os.WriteFile(blocker, nil, 0o600))
				return filepath.Join(blocker, "aws.log")
			},
			wantErr: "failed to create log directory",
		},
		{
			name: "log file is a directory",
			setup: func(t *testing.T, dir, store string) string {
				validSession(t, store)
				logFile := filepath.Join(dir, "logdir")
				require.NoError(t, os.Mkdir(logFile, 0o700))
				return logFile
			},
			wantErr: "failed to open log file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := filepath.Join(dir, "session")
			logFile := tt.setup(t, dir, store)
			cmd, _ := awsTestCmd(t)
			cmd.Flags().String("barrier-password-file", "", "")

			var out bytes.Buffer
			err := startAWSBackgroundRefresh(cmd, &out, "us-east-1", "dev", filepath.Join(dir, "credentials"),
				"none", "", store, store, logFile, 60, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Empty(t, out.String(), "nothing is reported started on failure")
		})
	}
}

func TestRunOIDCAWS_BackgroundWorkerErrors(t *testing.T) {
	dpopKey, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)
	keyPEM, err := dpopKey.SerializePrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name    string
		session *AWSStoredSession
		logDir  bool
		wantIs  error
		wantMsg string
	}{
		{name: "no stored session", wantIs: ErrAWSSessionLoadFailed},
		{name: "no refresh token", session: &AWSStoredSession{Region: "us-east-1"}, wantIs: ErrAWSNoRefreshToken},
		{
			name:    "corrupt DPoP key",
			session: &AWSStoredSession{Region: "us-east-1", RefreshToken: "r", DPoPKeyPEM: "not a pem"},
			wantMsg: "failed to restore DPoP key",
		},
		{
			name:    "log file is a directory",
			session: &AWSStoredSession{Region: "us-east-1", RefreshToken: "r", DPoPKeyPEM: keyPEM},
			logDir:  true,
			wantMsg: "failed to open log file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := filepath.Join(dir, "session")
			if tt.session != nil {
				require.NoError(t, storeAWSSession(&cobra.Command{}, store, *tt.session))
			}
			cmd, _ := awsTestCmd(t)
			require.NoError(t, cmd.Flags().Set("background-worker", "true"))
			require.NoError(t, cmd.Flags().Set("region", "us-east-1"))
			require.NoError(t, cmd.Flags().Set("session-store", store))
			if tt.logDir {
				require.NoError(t, cmd.Flags().Set("log-file", dir))
			}

			err := runOIDCAWS(cmd, nil)
			require.Error(t, err)
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
			if tt.wantMsg != "" {
				assert.Contains(t, err.Error(), tt.wantMsg)
			}
		})
	}
}
