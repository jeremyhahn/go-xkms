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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
)

// oidcTestCmd builds a detached cobra command carrying every flag the OIDC
// handlers read, wired to a token store inside a temp directory. --token-store
// is explicitly Set (not just defaulted), so openOIDCTokenStore always takes
// the plain-file-at-this-exact-path branch here -- exactly like `xkey oath`'s
// --store override -- keeping these tests independent of barrier state. See
// oidc_barrier_test.go for the barrier-auto-detection behavior itself.
func oidcTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer, string) {
	t.Helper()

	store := filepath.Join(t.TempDir(), "tokens.json")

	cmd := &cobra.Command{Use: "oidc-test"}
	fs := cmd.Flags()
	fs.String("token-store", "", "")
	require.NoError(t, fs.Set("token-store", store))
	fs.String("barrier-password", "", "")
	fs.String("barrier-password-file", "", "")
	for _, name := range []string{
		"name", "type", "issuer", "client-id", "client-secret", "redirect-url",
		"scopes", "exec", "log-file", "region", "profile", "credentials-file",
		"output", "session-store", "provider",
		"authorization-endpoint", "token-endpoint", "jwks-uri", "userinfo-endpoint",
		"token-encoding",
	} {
		fs.String(name, "", "")
	}
	fs.Int("auto-refresh", 0, "")
	fs.Bool("background", false, "")
	fs.Bool("cross-device", false, "")
	fs.Bool("show-full", false, "")
	fs.Bool("all", false, "")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf, store
}

func setOIDCFlags(t *testing.T, cmd *cobra.Command, values map[string]string) {
	t.Helper()
	for k, v := range values {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), k, v), "set --%s", k)
	}
}

// mustOIDCStoredToken builds an OIDCStoredToken for tests, moving access,
// refresh, and id into protected memory the way production code does
// (newOIDCStoredToken) rather than via a struct literal, which the
// unexported protected fields make impossible outside this package's own
// production code. The caller owns the result and should defer Destroy.
func mustOIDCStoredToken(t *testing.T, provider, issuer, clientID, access, refresh, idTok string, expiresAt time.Time, scopes []string) *OIDCStoredToken {
	t.Helper()
	tok := &OIDCStoredToken{Provider: provider, Issuer: issuer, ClientID: clientID, ExpiresAt: expiresAt, Scopes: scopes}
	require.NoError(t, tok.SetAccessToken(access))
	require.NoError(t, tok.SetRefreshToken(refresh))
	require.NoError(t, tok.SetIDToken(idTok))
	return tok
}

// --- path helpers ---

func TestOIDCPathHelpers_DeriveFromTokenStore(t *testing.T) {
	store := "/var/lib/xkey/tokens.json"

	assert.Equal(t, "/var/lib/xkey/pids", getPIDDir(store))
	assert.Equal(t, "/var/lib/xkey/pids/okta.pid", getPIDFile(store, "okta"))
	assert.Equal(t, "/var/lib/xkey/pids/okta.status.json", getStatusFile(store, "okta"))
	assert.Equal(t, "/var/lib/xkey/logs/okta.log", getDefaultLogFile(store, "okta"))

	// An unnamed provider falls back to "default" so the files never collide
	// with the PID directory itself.
	assert.Equal(t, "/var/lib/xkey/pids/default.pid", getPIDFile(store, ""))
	assert.Equal(t, "/var/lib/xkey/pids/default.status.json", getStatusFile(store, ""))
	assert.Equal(t, "/var/lib/xkey/logs/default.log", getDefaultLogFile(store, ""))
}

func TestOIDCPathHelpers_ExpandTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	assert.Equal(t, filepath.Join(home, "xkey", "pids"), getPIDDir("~/xkey/tokens.json"))
	assert.Equal(t, filepath.Join(home, "xkey", "logs", "okta.log"),
		getDefaultLogFile("~/xkey/tokens.json", "okta"))
}

// --- refresh status persistence ---

func TestSaveAndLoadRefreshStatus(t *testing.T) {
	store := filepath.Join(t.TempDir(), "tokens.json")

	want := &OIDCRefreshStatus{
		LastRefresh:  time.Now().UTC().Truncate(time.Second),
		NextRefresh:  time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		RefreshCount: 3,
		LastStatus:   "success",
		IntervalSecs: 3600,
	}
	require.NoError(t, saveRefreshStatus(store, "okta", want))

	got, err := loadRefreshStatus(store, "okta")
	require.NoError(t, err)
	assert.Equal(t, want.RefreshCount, got.RefreshCount)
	assert.Equal(t, want.LastStatus, got.LastStatus)
	assert.Equal(t, want.IntervalSecs, got.IntervalSecs)
	assert.True(t, want.LastRefresh.Equal(got.LastRefresh))

	info, err := os.Stat(getStatusFile(store, "okta"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestLoadRefreshStatus_MissingAndCorrupt(t *testing.T) {
	store := filepath.Join(t.TempDir(), "tokens.json")

	_, err := loadRefreshStatus(store, "absent")
	assert.ErrorIs(t, err, os.ErrNotExist)

	statusFile := getStatusFile(store, "broken")
	require.NoError(t, os.MkdirAll(filepath.Dir(statusFile), 0700))
	require.NoError(t, os.WriteFile(statusFile, []byte("{not json"), 0600))

	_, err = loadRefreshStatus(store, "broken")
	assert.Error(t, err)
}

// --- isProcessRunning ---

func TestIsProcessRunning_SelfIsRunning(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "self.pid")
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600))

	pid, running := isProcessRunning(pidFile)
	assert.Equal(t, os.Getpid(), pid)
	assert.True(t, running)
}

func TestIsProcessRunning_MissingOrGarbage(t *testing.T) {
	dir := t.TempDir()

	_, running := isProcessRunning(filepath.Join(dir, "absent.pid"))
	assert.False(t, running)

	garbage := filepath.Join(dir, "garbage.pid")
	require.NoError(t, os.WriteFile(garbage, []byte("not-a-pid"), 0600))
	_, running = isProcessRunning(garbage)
	assert.False(t, running, "an unparseable PID file must not be treated as a live process")
}

// --- oidc status ---

func TestRunOIDCStatus_NoPIDDirectory(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)

	require.NoError(t, runOIDCStatus(cmd, nil))
	assert.Contains(t, buf.String(), "No background refresh processes running.")
}

func TestRunOIDCStatus_RemovesStalePIDFiles(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)

	// PID 0 never matches a real process for an unprivileged signal check.
	stale := getPIDFile(store, "ghost")
	require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0700))
	require.NoError(t, os.WriteFile(stale, []byte("999999999"), 0600))
	// A non-.pid file in the same directory must be ignored entirely.
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(stale), "notes.txt"), []byte("x"), 0600))

	require.NoError(t, runOIDCStatus(cmd, nil))
	assert.Contains(t, buf.String(), "No background refresh processes running.")
	assert.NoFileExists(t, stale, "a stale PID file must be cleaned up")
}

func TestRunOIDCStatus_ReportsLiveProcessWithStatus(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)

	pidFile := getPIDFile(store, "okta")
	require.NoError(t, os.MkdirAll(filepath.Dir(pidFile), 0700))
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600))

	require.NoError(t, saveRefreshStatus(store, "okta", &OIDCRefreshStatus{
		LastRefresh:  time.Now().Add(-5 * time.Minute),
		NextRefresh:  time.Now().Add(10 * time.Minute),
		RefreshCount: 4,
		LastStatus:   "success",
		IntervalSecs: 900,
	}))

	require.NoError(t, runOIDCStatus(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Background Refresh Processes (1):")
	assert.Contains(t, out, "Provider:     okta")
	assert.Contains(t, out, "PID:          "+strconv.Itoa(os.Getpid()))
	assert.Contains(t, out, "Refreshes:    4 successful")
	assert.Contains(t, out, "Next Refresh: in")
	assert.Contains(t, out, "Log file:     "+getDefaultLogFile(store, "okta"))
}

func TestRunOIDCStatus_ShowsLastErrorFromStatusFile(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)

	pidFile := getPIDFile(store, "okta")
	require.NoError(t, os.MkdirAll(filepath.Dir(pidFile), 0700))
	require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600))

	require.NoError(t, saveRefreshStatus(store, "okta", &OIDCRefreshStatus{
		LastRefresh:  time.Now().Add(-time.Minute),
		RefreshCount: 2,
		LastStatus:   "error",
		LastError:    "refresh failed: 401",
	}))

	require.NoError(t, runOIDCStatus(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "(last error: refresh failed: 401)")
	assert.Contains(t, out, "✗", "a failed refresh must be visibly marked")
}

// --- oidc stop ---

func TestRunOIDCStop_RequiresProviderOrAll(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)

	err := runOIDCStop(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "specify provider name or use --all")
	assert.True(t, errors.Is(err, ErrOIDCMissingProviderArg), "want errors.Is match against ErrOIDCMissingProviderArg")
}

func TestRunOIDCStop_AllWithNoPIDDirectory(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))

	require.NoError(t, runOIDCStop(cmd, nil))
	assert.Contains(t, buf.String(), "No background refresh processes running.")
}

func TestRunOIDCStop_UnknownProviderReportsNoProcess(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)

	err := runOIDCStop(cmd, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no running process for 'ghost'")
}

func TestStopProcess_CleansStalePIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "ghost.pid")
	require.NoError(t, os.WriteFile(pidFile, []byte("999999999"), 0600))

	var buf bytes.Buffer
	err := stopProcess(&buf, pidFile, "ghost")
	require.Error(t, err)
	assert.NoFileExists(t, pidFile, "stopping a dead process must remove its stale PID file")
}

func TestStopProcess_MissingPIDFileIsNotAnError(t *testing.T) {
	// A PID file that was never created (as opposed to a stale one left
	// behind by a dead process) must not surface os.ErrNotExist from the
	// cleanup Remove -- there is nothing to clean up.
	pidFile := filepath.Join(t.TempDir(), "missing.pid")

	var buf bytes.Buffer
	err := stopProcess(&buf, pidFile, "missing")
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist), "want no os.ErrNotExist wrapped for a PID file that never existed")
	assert.Equal(t, "no running process for 'missing'", err.Error())
}

func TestRunOIDCStop_AllReportsNoneWhenAllStale(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))

	stale := getPIDFile(store, "ghost")
	require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0700))
	require.NoError(t, os.WriteFile(stale, []byte("999999999"), 0600))

	require.NoError(t, runOIDCStop(cmd, nil))
	assert.Contains(t, buf.String(), "No background refresh processes were running.")
}

// --- oidc providers add/list/remove ---

func addStandardProvider(t *testing.T, store string, values map[string]string) string {
	t.Helper()

	cmd, buf, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "token-store", store))
	setOIDCFlags(t, cmd, values)
	require.NoError(t, runOIDCProvidersAdd(cmd, nil))
	return buf.String()
}

func TestRunOIDCProvidersAdd_StandardProvider(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":          "okta",
		"issuer":        "https://example.okta.com",
		"client-id":     "abc123",
		"client-secret": "s3cr3t",
		"redirect-url":  "http://localhost:8085/callback",
		"scopes":        "openid, profile ,email",
	})

	require.NoError(t, runOIDCProvidersAdd(cmd, nil))
	assert.Contains(t, buf.String(), "Added OIDC provider: okta")

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)

	p := config.Providers[0]
	assert.Equal(t, OIDCProviderTypeStandard, p.Type)
	assert.Equal(t, "https://example.okta.com", p.Issuer)
	assert.Equal(t, []string{"openid", "profile", "email"}, p.Scopes,
		"comma-separated scopes must be split and trimmed")
}

func TestRunOIDCProvidersAdd_AWSProvider(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":   "aws-dev",
		"type":   "aws",
		"region": "us-east-1",
	})

	require.NoError(t, runOIDCProvidersAdd(cmd, nil))
	assert.Contains(t, buf.String(), "Added AWS OIDC provider: aws-dev (region: us-east-1)")

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)
	assert.Equal(t, OIDCProviderTypeAWS, config.Providers[0].Type)
	assert.Equal(t, "us-east-1", config.Providers[0].AWSRegion)
}

func TestRunOIDCProvidersAdd_Validation(t *testing.T) {
	tests := []struct {
		name  string
		flags map[string]string
		want  error
	}{
		{"missing name", map[string]string{}, ErrOIDCMissingProviderName},
		{"aws without region", map[string]string{"name": "a", "type": "aws"}, ErrAWSMissingRegion},
		{"standard without issuer", map[string]string{"name": "a"}, ErrOIDCMissingIssuer},
		{"standard without client id", map[string]string{"name": "a", "issuer": "https://i"}, ErrOIDCMissingClientID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, _, _ := oidcTestCmd(t)
			setOIDCFlags(t, cmd, tt.flags)
			assert.ErrorIs(t, runOIDCProvidersAdd(cmd, nil), tt.want)
		})
	}
}

func TestRunOIDCProvidersAdd_ManualEndpointsSkipDiscovery(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":                   "no-discovery",
		"issuer":                 "https://auth.example.com",
		"client-id":              "abc123",
		"authorization-endpoint": "https://auth.example.com/authorize",
		"token-endpoint":         "https://auth.example.com/token",
		"jwks-uri":               "https://auth.example.com/jwks",
		"userinfo-endpoint":      "https://auth.example.com/userinfo",
	})

	require.NoError(t, runOIDCProvidersAdd(cmd, nil))
	assert.Contains(t, buf.String(), "Added OIDC provider: no-discovery")

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)

	p := config.Providers[0]
	assert.Equal(t, "https://auth.example.com/authorize", p.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/token", p.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/jwks", p.JwksURI)
	assert.Equal(t, "https://auth.example.com/userinfo", p.UserinfoEndpoint)
}

func TestRunOIDCProvidersAdd_PartialManualEndpointsRefused(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":                   "partial",
		"issuer":                 "https://auth.example.com",
		"client-id":              "abc123",
		"authorization-endpoint": "https://auth.example.com/authorize",
	})

	err := runOIDCProvidersAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCIncompleteEndpoints)
	assert.Contains(t, err.Error(), "--token-endpoint")
	assert.Contains(t, err.Error(), "--jwks-uri")
	assert.NotContains(t, err.Error(), "--authorization-endpoint")
}

func TestRunOIDCProvidersAdd_TokenEncoding(t *testing.T) {
	cmd, _, store := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":           "json-provider",
		"issuer":         "https://auth.example.com",
		"client-id":      "abc123",
		"token-encoding": "json",
	})

	require.NoError(t, runOIDCProvidersAdd(cmd, nil))

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)
	assert.Equal(t, oidc.TokenEncodingJSON, config.Providers[0].TokenEncoding)
}

func TestRunOIDCProvidersAdd_UnknownTokenEncodingRefused(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name":           "bad-encoding",
		"issuer":         "https://auth.example.com",
		"client-id":      "abc123",
		"token-encoding": "xml",
	})

	err := runOIDCProvidersAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrInvalidTokenEncoding)
}

func TestRunOIDCProvidersAdd_RegionWithoutAWSTypeHintsAtFix(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{"name": "a", "region": "us-east-1"})

	err := runOIDCProvidersAdd(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCMissingIssuer)
	assert.Contains(t, err.Error(), "hint: use --type aws for AWS providers")
}

func TestRunOIDCProvidersAdd_RejectsDuplicateName(t *testing.T) {
	_, _, store := oidcTestCmd(t)
	addStandardProvider(t, store, map[string]string{
		"name": "okta", "issuer": "https://i", "client-id": "c",
	})

	cmd, _, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "token-store", store))
	setOIDCFlags(t, cmd, map[string]string{"name": "okta", "issuer": "https://i", "client-id": "c"})

	assert.ErrorIs(t, runOIDCProvidersAdd(cmd, nil), ErrOIDCProviderExists)
}

func TestRunOIDCProvidersAdd_ExpandsRelativePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cmd, _, store := oidcTestCmd(t)
	setOIDCFlags(t, cmd, map[string]string{
		"name": "aws-dev", "type": "aws", "region": "us-east-1",
		"log-file": "~/logs/aws.log", "session-store": "~/aws-session.json",
	})
	require.NoError(t, runOIDCProvidersAdd(cmd, nil))

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)
	assert.Equal(t, filepath.Join(home, "logs", "aws.log"), config.Providers[0].LogFile,
		"paths must be absolute at storage time so the background worker can find them")
	assert.Equal(t, filepath.Join(home, "aws-session.json"), config.Providers[0].AWSSessionStore)
}

func TestRunOIDCProvidersList_Empty(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)

	require.NoError(t, runOIDCProvidersList(cmd, nil))
	assert.Contains(t, buf.String(), "No OIDC providers configured.")
}

func TestRunOIDCProvidersList_EmptyProviderArray(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{}}))

	require.NoError(t, runOIDCProvidersList(cmd, nil))
	assert.Contains(t, buf.String(), "No OIDC providers configured.")
}

func TestRunOIDCProvidersList_RendersStandardAndAWS(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{
		{
			Name: "okta", Type: OIDCProviderTypeStandard,
			Issuer: "https://example.okta.com", ClientID: "abc",
			ClientSecret: "s3cr3t", RedirectURL: "http://localhost:8085/callback",
			Scopes: []string{"openid", "email"},
			Exec:   "/usr/local/bin/hook", AutoRefresh: 900,
			Background: true, LogFile: "/var/log/okta.log",
		},
		{
			Name: "aws-dev", Type: OIDCProviderTypeAWS,
			AWSRegion: "us-east-1", AWSProfile: "dev",
			AWSCredentialsFile: "~/.aws/credentials", AWSOutput: "aws-credentials",
			AWSCrossDevice: true, AWSSessionStore: "/tmp/aws.json",
		},
	}}))

	require.NoError(t, runOIDCProvidersList(cmd, nil))
	out := buf.String()

	assert.Contains(t, out, "OIDC Providers (2):")
	assert.Contains(t, out, "Name:         okta")
	assert.Contains(t, out, "Issuer:       https://example.okta.com")
	assert.Contains(t, out, "Client Secret: ***")
	assert.NotContains(t, out, "s3cr3t", "a client secret must never be printed in the clear")
	assert.Contains(t, out, "Scopes:       openid, email")
	assert.Contains(t, out, "Exec:         /usr/local/bin/hook")
	assert.Contains(t, out, "Auto-Refresh: 900 seconds")
	assert.Contains(t, out, "Background:   yes")
	assert.Contains(t, out, "Log File:     /var/log/okta.log")

	assert.Contains(t, out, "Name:         aws-dev")
	assert.Contains(t, out, "Region:       us-east-1")
	assert.Contains(t, out, "Profile:      dev")
	assert.Contains(t, out, "Cross-Device: yes")
	assert.Contains(t, out, "Session Store: /tmp/aws.json")
}

func TestRunOIDCProvidersList_UntypedProviderDefaultsToStandard(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, saveOIDCConfig(getConfigPath(store), OIDCConfig{Providers: []OIDCProvider{
		{Name: "legacy", Issuer: "https://legacy", ClientID: "id"},
	}}))

	require.NoError(t, runOIDCProvidersList(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, "Type:         "+string(OIDCProviderTypeStandard))
	assert.Contains(t, out, "Issuer:       https://legacy")
}

func TestRunOIDCProvidersRemove_RemovesOnlyTheNamedProvider(t *testing.T) {
	_, _, store := oidcTestCmd(t)
	addStandardProvider(t, store, map[string]string{"name": "a", "issuer": "https://a", "client-id": "id"})
	addStandardProvider(t, store, map[string]string{"name": "b", "issuer": "https://b", "client-id": "id"})

	cmd, buf, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "token-store", store))
	require.NoError(t, runOIDCProvidersRemove(cmd, []string{"a"}))
	assert.Contains(t, buf.String(), "Removed OIDC provider: a")

	config, err := loadOIDCConfig(getConfigPath(store))
	require.NoError(t, err)
	require.Len(t, config.Providers, 1)
	assert.Equal(t, "b", config.Providers[0].Name)
}

func TestRunOIDCProvidersRemove_UnknownProvider(t *testing.T) {
	_, _, store := oidcTestCmd(t)
	addStandardProvider(t, store, map[string]string{"name": "a", "issuer": "https://a", "client-id": "id"})

	cmd, _, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "token-store", store))
	assert.ErrorIs(t, runOIDCProvidersRemove(cmd, []string{"missing"}), ErrOIDCProviderNotFound)
}

func TestRunOIDCProvidersRemove_NoConfigFile(t *testing.T) {
	cmd, _, _ := oidcTestCmd(t)
	assert.ErrorIs(t, runOIDCProvidersRemove(cmd, []string{"a"}), ErrOIDCProviderNotFound)
}

// --- loadProvider ---

func TestLoadProvider(t *testing.T) {
	_, _, store := oidcTestCmd(t)
	addStandardProvider(t, store, map[string]string{"name": "okta", "issuer": "https://o", "client-id": "id"})

	p, err := loadProvider(store, "okta")
	require.NoError(t, err)
	assert.Equal(t, "https://o", p.Issuer)

	_, err = loadProvider(store, "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider not found: missing")

	// Lookup is case-insensitive so `xkey oidc status` can match the PID
	// file name back to the configured provider.
	p, err = loadProvider(store, "OKTA")
	require.NoError(t, err)
	assert.Equal(t, "okta", p.Name)

	_, err = loadProvider(filepath.Join(t.TempDir(), "absent.json"), "okta")
	assert.Error(t, err, "a missing config file must be reported, not treated as an empty config")
}

// --- oidc token ---

// signedTestIDToken builds an unsigned-but-well-formed JWT carrying claims.
func signedTestIDToken(t *testing.T, claims OIDCIDTokenClaims) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestRunOIDCToken_NoTokens(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)

	require.NoError(t, runOIDCToken(cmd, nil))
	assert.Contains(t, buf.String(), "No OIDC tokens found. Run 'xkey oidc login' to authenticate.")
}

func TestRunOIDCToken_TruncatesSecretsByDefault(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)

	access := strings.Repeat("A", 120)
	idToken := signedTestIDToken(t, OIDCIDTokenClaims{
		Claims: jwt.Claims{Subject: "user-1"},
		Email:  "alice@example.com",
		Name:   "Alice",
	})
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://example.okta.com", "",
		access, strings.Repeat("R", 80), idToken, time.Now().Add(time.Hour), []string{"openid", "email"})))

	require.NoError(t, runOIDCToken(cmd, nil))
	out := buf.String()

	assert.Contains(t, out, "Provider:      https://example.okta.com")
	assert.Contains(t, out, "Subject:       user-1")
	assert.Contains(t, out, "Email:         alice@example.com")
	assert.Contains(t, out, "Name:          Alice")
	assert.Contains(t, out, "Scopes:        openid email")
	assert.Contains(t, out, "(in ")
	assert.Contains(t, out, "(120 chars)")
	assert.Contains(t, out, "AAAAAAAA…", "expected an 8-character prefix of the access token")
	assert.NotContains(t, out, access, "the full access token must not leak without --show-full")
	assert.NotContains(t, out, strings.Repeat("A", 9), "no more than an 8-character prefix of the access token may print")
	assert.NotContains(t, out, "Refresh Token:",
		"the refresh token is the most sensitive value and stays hidden by default")
}

func TestRunOIDCToken_ShowFullRevealsTokens(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "show-full", "true"))

	access := strings.Repeat("A", 120)
	refresh := strings.Repeat("R", 80)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://example.okta.com", "",
		access, refresh, signedTestIDToken(t, OIDCIDTokenClaims{Claims: jwt.Claims{Subject: "u"}}),
		time.Now().Add(time.Hour), nil)))

	require.NoError(t, runOIDCToken(cmd, nil))
	out := buf.String()
	assert.Contains(t, out, access)
	assert.Contains(t, out, refresh)
}

func TestRunOIDCToken_ExpiredTokenIsFlagged(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://example.okta.com", "",
		"token", "", "", time.Now().Add(-time.Hour), nil)))

	require.NoError(t, runOIDCToken(cmd, nil))
	assert.Contains(t, buf.String(), "(EXPIRED)")
}

func TestRunOIDCToken_UnparseableIDTokenStillPrintsWhatItHas(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://example.okta.com", "",
		"token", "", "garbage", time.Now().Add(time.Hour), nil)))

	require.NoError(t, runOIDCToken(cmd, nil),
		"a malformed ID token must not abort the command")
	out := buf.String()
	assert.Contains(t, out, "Provider:      https://example.okta.com")
	assert.NotContains(t, out, "Subject:")
}

// --- oidc logout ---

func TestRunOIDCLogout_ClearsCurrentTokens(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://i", "",
		"t", "", "", time.Now().Add(time.Hour), nil)))

	require.NoError(t, runOIDCLogout(cmd, nil))
	assert.Contains(t, buf.String(), "Tokens cleared.")

	_, err := loadToken(cmd, store)
	assert.ErrorIs(t, err, ErrOIDCNoTokensFound)
	// The CLI's token store reduces logout to deleting the one stored key
	// (oidcCLITokenStore.Clear), so the backing file is gone -- there is no
	// "empty envelope" form to leave behind and no permissions left to pin.
	assert.NoFileExists(t, expandPath(store))
}

func TestRunOIDCLogout_AllRemovesStoreFile(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://i", "",
		"t", "", "", time.Now().Add(time.Hour), nil)))

	require.NoError(t, runOIDCLogout(cmd, nil))
	assert.Contains(t, buf.String(), "All tokens cleared.")
	assert.NoFileExists(t, expandPath(store))
}

func TestRunOIDCLogout_AllOnMissingStore(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "all", "true"))

	require.NoError(t, runOIDCLogout(cmd, nil))
	assert.Contains(t, buf.String(), "No tokens to clear.")
}

// --- oidc refresh ---

func TestRunOIDCRefresh_NoTokens(t *testing.T) {
	cmd, buf, _ := oidcTestCmd(t)

	require.NoError(t, runOIDCRefresh(cmd, nil))
	assert.Contains(t, buf.String(), "No OIDC tokens found.")
}

func TestRunOIDCRefresh_RequiresRefreshToken(t *testing.T) {
	cmd, _, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://i", "",
		"t", "", "", time.Now().Add(time.Hour), nil)))

	assert.ErrorIs(t, runOIDCRefresh(cmd, nil), ErrOIDCInvalidRefreshToken)
}

func TestRunOIDCRefresh_RotatesStoredTokens(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
				Issuer:                issuer,
				AuthorizationEndpoint: issuer + "/authorize",
				TokenEndpoint:         issuer + "/token",
			})
		case "/token":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
			assert.Equal(t, "old-refresh", r.Form.Get("refresh_token"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OIDCTokenResponse{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				IDToken:      "new-id",
				ExpiresIn:    3600,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	issuer = server.URL

	cmd, buf, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", issuer, "client",
		"old-access", "old-refresh", "", time.Now().Add(-time.Minute), nil)))

	require.NoError(t, runOIDCRefresh(cmd, nil))
	assert.Contains(t, buf.String(), "Token refreshed successfully!")

	token, err := loadToken(cmd, store)
	require.NoError(t, err)
	defer token.Destroy()
	assert.Equal(t, "new-access", token.AccessToken())
	assert.Equal(t, "new-refresh", token.RefreshToken(), "a rotated refresh token must be persisted")
	assert.Equal(t, "new-id", token.IDToken())
	assert.True(t, token.ExpiresAt.After(time.Now()))
}

func TestRunOIDCRefresh_ReportsDiscoveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cmd, _, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", server.URL, "c",
		"", "r", "", time.Now().Add(-time.Minute), nil)))

	err := runOIDCRefresh(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCDiscoveryFailed)
}

func TestRunOIDCRefresh_ReportsTokenEndpointFailure(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
				Issuer: issuer, TokenEndpoint: issuer + "/token",
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer server.Close()
	issuer = server.URL

	cmd, _, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", issuer, "c",
		"", "expired", "", time.Now().Add(-time.Minute), nil)))

	err := runOIDCRefresh(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCTokenRefreshFailed)
}

func TestRunOIDCRefresh_WithProviderSkipsDiscoveryAndHonoursEncoding(t *testing.T) {
	// A discovery document is never served: any GET fails the test, proving
	// the manual endpoints saved on the provider bypassed discovery.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected non-POST request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var decoded map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&decoded))
		assert.Equal(t, "refresh_token", decoded["grant_type"])
		assert.Equal(t, "old-refresh", decoded["refresh_token"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCTokenResponse{
			AccessToken:  "new-access",
			RefreshToken: "new-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	cmd, buf, store := oidcTestCmd(t)
	addStandardProvider(t, store, map[string]string{
		"name":                   "manual",
		"issuer":                 "https://issuer.invalid",
		"client-id":              "client",
		"authorization-endpoint": "https://issuer.invalid/authorize",
		"token-endpoint":         server.URL,
		"jwks-uri":               "https://issuer.invalid/jwks",
		"token-encoding":         "json",
	})

	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://issuer.invalid", "client",
		"old-access", "old-refresh", "", time.Now().Add(-time.Minute), nil)))

	require.NoError(t, setFlagForTest(t, cmd.Flags(), "provider", "manual"))
	require.NoError(t, runOIDCRefresh(cmd, nil))
	assert.Contains(t, buf.String(), "Token refreshed successfully!")

	token, err := loadToken(cmd, store)
	require.NoError(t, err)
	defer token.Destroy()
	assert.Equal(t, "new-access", token.AccessToken())
}

func TestRunOIDCRefresh_UnknownProviderReturnsTypedError(t *testing.T) {
	cmd, _, store := oidcTestCmd(t)
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://issuer.invalid", "c",
		"", "r", "", time.Now().Add(-time.Minute), nil)))

	require.NoError(t, setFlagForTest(t, cmd.Flags(), "provider", "does-not-exist"))
	err := runOIDCRefresh(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

// --- executeOIDCScript ---

func TestExecuteOIDCScript_PassesTokenThroughEnvironment(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "captured.txt")

	var buf bytes.Buffer
	script := fmt.Sprintf(`printf '%%s|%%s|%%s' "$OIDC_ACCESS_TOKEN" "$OIDC_SUBJECT" "$OIDC_EXPIRES_IN" > %q`, marker)
	require.NoError(t, executeOIDCScript(&buf, script, OIDCExecPayload{
		AccessToken: "at-123",
		Subject:     "user-1",
		ExpiresIn:   3600,
	}))

	assert.Contains(t, buf.String(), "Executing: ")

	data, err := os.ReadFile(marker)
	require.NoError(t, err)
	assert.Equal(t, "at-123|user-1|3600", string(data))
}

func TestExecuteOIDCScript_PropagatesFailure(t *testing.T) {
	var buf bytes.Buffer
	err := executeOIDCScript(&buf, "exit 3", OIDCExecPayload{AccessToken: "x"})
	assert.Error(t, err, "a failing hook must surface as an error, not be swallowed")
}

// TestRunAutoRefresh_MalformedIDToken_SkipsExecHook verifies that when the
// refreshed ID token cannot be parsed, the exec hook for that refresh
// cycle is skipped and logged, instead of running with empty
// Subject/Email/Name claims.
func TestRunAutoRefresh_MalformedIDToken_SkipsExecHook(t *testing.T) {
	cmd, _, storePath := oidcTestCmd(t)
	store, err := openOIDCTokenStore(cmd, storePath)
	require.NoError(t, err)

	seed := mustOIDCStoredToken(t, "", "https://example.okta.com", "client",
		"seed-access", "seed-refresh", "", time.Now().Add(-time.Minute), nil)
	defer seed.Destroy()
	require.NoError(t, store.Save(seed))

	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCTokenResponse{
			AccessToken:  "rotated-access",
			RefreshToken: "rotated-refresh",
			IDToken:      "not-a-valid-jwt",
			ExpiresIn:    3600,
		})
	}))
	defer server.Close()

	marker := filepath.Join(t.TempDir(), "exec-ran.txt")
	execCmd := fmt.Sprintf("echo ran > %q", marker)

	var buf bytes.Buffer
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runAutoRefresh(server.URL, "client", store, storePath, execCmd, "", 10*time.Millisecond, &buf, oidc.TokenEncodingForm, stop)
	}()

	require.Eventually(t, func() bool {
		return refreshes.Load() >= 2
	}, 5*time.Second, 10*time.Millisecond, "fewer than 2 refresh ticks before the deadline")
	close(stop)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("runAutoRefresh did not stop after its stop channel closed")
	}

	assert.Contains(t, buf.String(), "skipping exec hook", "a malformed ID token must be logged and the exec hook skipped; log:\n%s", buf.String())

	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "the exec hook must never run when the ID token cannot be parsed")
}

// hostileProviderText carries an OSC 52 clipboard write, a clear-screen
// CSI, an 8-bit CSI and a NUL between two words; sanitised it reads
// "deniedend".
const hostileProviderText = "denied\x1b]52;c;ZXZpbA==\x07\x1b[2J\u009b31m\x00end"

// TestHandleOIDCCallback_ProviderErrorIsTerminalInert proves the callback's
// error and error_description reach the error the CLI prints sanitised, so
// a hostile redirect cannot drive the user's terminal (#1015).
func TestHandleOIDCCallback_ProviderErrorIsTerminalInert(t *testing.T) {
	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	query := url.Values{"error": {hostileProviderText}, "error_description": {hostileProviderText}}

	req := httptest.NewRequest(http.MethodGet, "/callback?"+query.Encode(), nil)
	handleOIDCCallback(httptest.NewRecorder(), req, codeChan, errChan, new(atomic.Value))

	select {
	case err := <-errChan:
		assert.Equal(t, "deniedend: deniedend", err.Error())
		wrapped := &SentinelCauseError{Sentinel: ErrOIDCCallbackFailed, Cause: err}
		assert.NotContains(t, wrapped.Error(), "\x1b", "the error runOIDCLogin returns must carry no escape")
	default:
		t.Fatal("no error delivered")
	}
	assert.Empty(t, codeChan)
}

// TestRunOIDCToken_ClaimsAreTerminalInert proves ID-token claims the
// provider chose are printed sanitised: a hostile subject, email or name
// cannot drive the terminal or forge an extra output line (#1015).
func TestRunOIDCToken_ClaimsAreTerminalInert(t *testing.T) {
	cmd, buf, store := oidcTestCmd(t)
	idToken := signedTestIDToken(t, OIDCIDTokenClaims{
		Claims: jwt.Claims{Subject: hostileProviderText},
		Email:  hostileProviderText,
		Name:   "Alice\nExpires:       never",
	})
	require.NoError(t, storeToken(cmd, store, mustOIDCStoredToken(t, "", "https://example.okta.com", "",
		"token", "", idToken, time.Now().Add(time.Hour), nil)))

	require.NoError(t, runOIDCToken(cmd, nil))
	out := buf.String()

	assert.Contains(t, out, "Subject:       deniedend\n")
	assert.Contains(t, out, "Email:         deniedend\n")
	assert.Contains(t, out, "Name:          Alice Expires:       never\n")
	assert.NotContains(t, out, "\nExpires:       never", "a claim must not forge its own output line")
	assert.NotContains(t, out, "\x1b")
	assert.NotContains(t, out, "ZXZpbA==")
}

// TestWriteOIDCIdentity proves each set claim is printed on its own line in
// the caller's layout, sanitised, and an unset claim is left out.
func TestWriteOIDCIdentity(t *testing.T) {
	var buf bytes.Buffer
	writeOIDCIdentity(&buf, &OIDCIDTokenClaims{Claims: jwt.Claims{Subject: hostileProviderText}, Name: "Alice"}, "  %-10s%s\n")
	assert.Equal(t, "  Subject:  deniedend\n  Name:     Alice\n", buf.String())

	buf.Reset()
	writeOIDCIdentity(&buf, &OIDCIDTokenClaims{}, "%-15s%s\n")
	assert.Empty(t, buf.String(), "no claims, no lines")
}

// TestWriteAWSLoginSummary_AccessKeyIDIsTerminalInert proves the access key
// ID the AWS token endpoint returned is printed sanitised (#1015).
func TestWriteAWSLoginSummary_AccessKeyIDIsTerminalInert(t *testing.T) {
	var buf bytes.Buffer
	expiration := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	writeAWSLoginSummary(&buf, "us-east-1", "default", hostileProviderText, expiration)
	out := buf.String()

	assert.Contains(t, out, "AWS login successful!")
	assert.Contains(t, out, "  Region:         us-east-1\n")
	assert.Contains(t, out, "  Profile:        default\n")
	assert.Contains(t, out, "  Access Key ID:  deniedend\n")
	assert.Contains(t, out, "  Expires:        2030-01-02T03:04:05Z\n")
	assert.NotContains(t, out, "\x1b")
}
