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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// xkey's OIDC has two backends. Its local backend -- providers, browser
// logins, refresh loops and tokens kept in the xKey data directory -- is
// what every `xkey oidc` command uses when no xkmsd is configured, exactly
// as it always has. With an xkmsd configured (--xkmsd-url, XKMSD_URL or the
// config), the same commands act on the server's OIDC credentials, which the
// server holds and refreshes: `providers add` creates one there, `login`
// runs the provider's device login on the server, `token` asks it for a
// current access token. `providers list` then shows both. --local keeps a
// command on the local backend while an xkmsd is configured.

var (
	// ErrOIDCServerConnect is returned when the configured xkmsd cannot be
	// reached.
	ErrOIDCServerConnect = errors.New("oidc: failed to connect to xkmsd")

	// ErrOIDCServerNameRequired is returned when a server-mode command is
	// given no credential name (--provider, or --name for providers add).
	ErrOIDCServerNameRequired = errors.New("oidc: a server credential needs a name (--provider)")

	// ErrOIDCServerLocalOnly is returned when a server-mode command is given
	// a flag of the local backend only.
	ErrOIDCServerLocalOnly = errors.New("oidc: flag applies to the local backend only; add --local")

	// ErrOIDCServerLogout is returned by logout in server mode: a server
	// credential is not logged out, it is removed.
	ErrOIDCServerLogout = errors.New("oidc: server credentials are removed with 'xkey oidc providers remove'; add --local to clear local tokens")

	// ErrOIDCImportNeedsServer is returned by import without a configured
	// xkmsd: imported logins are server credentials.
	ErrOIDCImportNeedsServer = errors.New("oidc: import stores the login on an xkmsd server; configure --xkmsd-url")

	// ErrOIDCImportSource is returned by import without --codex-auth or
	// --access-token, or with both.
	ErrOIDCImportSource = errors.New("oidc: import needs exactly one of --codex-auth or --access-token")

	// ErrOIDCDeviceLoginExpired is returned when a device login is not
	// approved before it expires.
	ErrOIDCDeviceLoginExpired = errors.New("oidc: the device login was not approved in time")

	// ErrOIDCNoDeviceLogin is returned when the server starts no device
	// login.
	ErrOIDCNoDeviceLogin = errors.New("oidc: the server returned no device login")
)

// oidcServerClientFactory connects the configured xkmsd. Tests replace it.
var oidcServerClientFactory = connectXKMSdClient

// oidcUseServer reports whether a command acts on the server's OIDC
// credentials: an xkmsd is configured and --local was not given.
func oidcUseServer(cmd *cobra.Command) (bool, error) {
	if resolveXKMSdURL() == "" {
		return false, nil
	}
	local, err := commandFlagBool(cmd, "local")
	if err != nil {
		return false, err
	}
	return !local, nil
}

// runOnOIDCServer runs server when cmd acts on the server's OIDC
// credentials, and reports whether it did.
func runOnOIDCServer(cmd *cobra.Command, server func() error) (handled bool, err error) {
	useServer, err := oidcUseServer(cmd)
	if err != nil {
		return true, err
	}
	if !useServer {
		return false, nil
	}
	return true, server()
}

// withOIDCServer connects the configured xkmsd, runs fn, and disconnects.
func withOIDCServer(cmd *cobra.Command, fn func(context.Context, transport.Client) error) (err error) {
	client, err := oidcServerClientFactory(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrOIDCServerConnect, Cause: err}
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return fn(ctx, client)
}

// oidcServerRef reads a server credential reference: its name from
// nameFlag, and --scope, --owner and --tenant.
func oidcServerRef(cmd *cobra.Command, name string) (*transport.OIDCCredentialRef, error) {
	if name == "" {
		return nil, ErrOIDCServerNameRequired
	}
	scope := commandFlagString(cmd, "scope")
	if scope == "" {
		scope = transport.OIDCCredentialScopeUser
	}
	return &transport.OIDCCredentialRef{
		Name:     name,
		Scope:    scope,
		Owner:    commandFlagString(cmd, "owner"),
		TenantID: commandFlagString(cmd, "tenant"),
	}, nil
}

// refuseLocalOnlyFlags fails when any of flags -- settings of the local
// backend's browser login and refresh loops -- was given.
func refuseLocalOnlyFlags(cmd *cobra.Command, flags ...string) error {
	for _, name := range flags {
		if commandFlagChanged(cmd, name) {
			return &DetailError{Err: ErrOIDCServerLocalOnly, Detail: ": --" + name}
		}
	}
	return nil
}

// runOIDCServerProvidersAdd creates a server credential.
func runOIDCServerProvidersAdd(cmd *cobra.Command) error {
	if err := refuseLocalOnlyFlags(cmd, "type", "redirect-url", "jwks-uri", "userinfo-endpoint", "exec",
		"auto-refresh", "background", "log-file", "region", "profile", "credentials-file", "output",
		"cross-device", "session-store"); err != nil {
		return err
	}
	ref, err := oidcServerRef(cmd, commandFlagString(cmd, "name"))
	if err != nil {
		return err
	}
	cfg := transport.OIDCCredentialConfig{
		Template:                    commandFlagString(cmd, "template"),
		Issuer:                      commandFlagString(cmd, "issuer"),
		ClientID:                    commandFlagString(cmd, "client-id"),
		ClientSecret:                commandFlagString(cmd, "client-secret"),
		Scopes:                      splitScopes(commandFlagString(cmd, "scopes")),
		AuthorizationEndpoint:       commandFlagString(cmd, "authorization-endpoint"),
		TokenEndpoint:               commandFlagString(cmd, "token-endpoint"),
		DeviceAuthorizationEndpoint: commandFlagString(cmd, "device-endpoint"),
		TokenEncoding:               commandFlagString(cmd, "token-encoding"),
		DeviceStyle:                 commandFlagString(cmd, "device-style"),
	}
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		cred, err := client.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: *ref, Config: cfg})
		if err != nil {
			return err
		}
		printServerOIDCCredential(cmd.OutOrStdout(), "Server OIDC credential created", cred)
		return nil
	})
}

// splitScopes splits a comma-separated scope list.
func splitScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runOIDCServerProvidersRemove deletes a server credential.
func runOIDCServerProvidersRemove(cmd *cobra.Command, name string) error {
	ref, err := oidcServerRef(cmd, name)
	if err != nil {
		return err
	}
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		if err := client.OIDCCredentialDelete(ctx, ref); err != nil {
			return err
		}
		writeLine(cmd.OutOrStdout(), "Server OIDC credential "+name+" removed.")
		return nil
	})
}

// printServerOIDCCredentials prints the server credentials the caller can
// see, ahead of the local providers in `providers list`.
func printServerOIDCCredentials(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		list, err := client.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{TenantID: commandFlagString(cmd, "tenant")})
		if err != nil {
			return err
		}
		writeLine(out, fmt.Sprintf("Server OIDC credentials (%d):", len(list.Credentials)))
		writeLine(out, "")
		for i := range list.Credentials {
			printServerOIDCCredential(out, "", &list.Credentials[i])
		}
		return nil
	})
}

// runOIDCServerLogin runs a server credential's device login.
func runOIDCServerLogin(cmd *cobra.Command) error {
	if err := refuseLocalOnlyFlags(cmd, "issuer", "client-id", "client-secret", "redirect-url", "no-browser",
		"exec", "auto-refresh", "background", "log-file", "authorization-endpoint", "token-endpoint",
		"jwks-uri", "userinfo-endpoint", "token-encoding", "scopes"); err != nil {
		return err
	}
	ref, err := oidcServerRef(cmd, commandFlagString(cmd, "provider"))
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		cred, err := oidcServerDeviceLogin(ctx, client, ref, out)
		if err != nil {
			return err
		}
		printServerOIDCCredential(out, "Server OIDC credential logged in", cred)
		return nil
	})
}

// oidcServerDeviceLogin starts the device login, prints the code, and polls
// the server at the provider's interval until the login is active or
// expires. The server talks to the provider; no token reaches xkey.
func oidcServerDeviceLogin(ctx context.Context, client transport.Client, ref *transport.OIDCCredentialRef, out io.Writer) (*transport.OIDCCredential, error) {
	cred, err := client.OIDCCredentialDeviceStart(ctx, ref)
	if err != nil {
		return nil, err
	}
	login := cred.DeviceLogin
	if login == nil {
		return nil, ErrOIDCNoDeviceLogin
	}
	uri := login.VerificationURI
	if login.VerificationURIComplete != "" {
		uri = login.VerificationURIComplete
	}
	writeLine(out, "Open "+uri)
	writeLine(out, "and enter the code: "+login.UserCode)

	ctx, cancel := context.WithDeadline(ctx, login.ExpiresAt)
	defer cancel()
	interval := time.Duration(login.IntervalSeconds) * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, &SentinelCauseError{Sentinel: ErrOIDCDeviceLoginExpired, Cause: ctx.Err()}
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return nil, &SentinelCauseError{Sentinel: ErrOIDCDeviceLoginExpired, Cause: ctx.Err()}
		}
		cred, err = client.OIDCCredentialDevicePoll(ctx, ref)
		if err != nil {
			return nil, err
		}
		if cred.Status == transport.OIDCCredentialStatusActive && cred.DeviceLogin == nil {
			return cred, nil
		}
		if cred.DeviceLogin != nil && cred.DeviceLogin.IntervalSeconds > 0 {
			interval = time.Duration(cred.DeviceLogin.IntervalSeconds) * time.Second
		}
		timer.Reset(interval)
	}
}

// runOIDCServerToken shows a current access token of a server credential,
// or writes the codex auth.json for it.
func runOIDCServerToken(cmd *cobra.Command) error {
	ref, err := oidcServerRef(cmd, commandFlagString(cmd, "provider"))
	if err != nil {
		return err
	}
	showFull, err := commandFlagBool(cmd, "show-full")
	if err != nil {
		return err
	}
	codexOut := commandFlagString(cmd, "codex-auth-out")
	out := cmd.OutOrStdout()
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		tok, err := client.OIDCCredentialGetAccessToken(ctx, ref)
		if err != nil {
			return err
		}
		if codexOut != "" {
			data, err := xkms.CodexAuthFile(tok, time.Now())
			if err != nil {
				return err
			}
			if err := os.WriteFile(codexOut, data, 0o600); err != nil {
				return &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
			}
			writeLine(out, "codex auth.json written to "+codexOut)
			return nil
		}
		writeLine(out, "Server OIDC credential: "+ref.Name)
		writeLine(out, "  Token type:   "+tok.TokenType)
		if tok.ExpiresAt != nil {
			writeLine(out, "  Expires:      "+tok.ExpiresAt.Format(time.RFC3339))
		}
		access := tok.AccessToken
		if !showFull {
			access = truncateServerToken(access)
		}
		writeLine(out, "  Access token: "+access)
		return nil
	})
}

// truncateServerToken shortens a token for display.
func truncateServerToken(token string) string {
	const keep = 12
	if len(token) <= 2*keep {
		return token
	}
	return token[:keep] + "..." + token[len(token)-keep:]
}

// runOIDCServerRefresh refreshes a server credential now.
func runOIDCServerRefresh(cmd *cobra.Command) error {
	ref, err := oidcServerRef(cmd, commandFlagString(cmd, "provider"))
	if err != nil {
		return err
	}
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		cred, err := client.OIDCCredentialRefresh(ctx, ref)
		if err != nil {
			return err
		}
		printServerOIDCCredential(cmd.OutOrStdout(), "Server OIDC credential refreshed", cred)
		return nil
	})
}

// oidcImportCmd is `xkey oidc import`: a login obtained elsewhere becomes a
// server credential.
var oidcImportCmd = &cobra.Command{
	Use:   "import <name>",
	Short: "Import an existing login as a server OIDC credential",
	Long: `Import a login obtained elsewhere into the configured xkmsd server, which
then holds and refreshes it: a codex auth.json (--codex-auth, imported into
an openai credential), or tokens (--access-token and, for a refreshable
login, --refresh-token; '-' reads a value from stdin).

--create creates the credential first, from --template (openai with
--codex-auth); otherwise the credential must exist.`,
	Example: `  xkey oidc import codex --scope tenant --codex-auth ~/.codex/auth.json --create
  xkey oidc import claude --create --template anthropic --access-token -`,
	Args: cobra.ExactArgs(1),
	RunE: runOIDCImport,
}

// runOIDCImport imports a login into a server credential.
func runOIDCImport(cmd *cobra.Command, args []string) error {
	if resolveXKMSdURL() == "" {
		return ErrOIDCImportNeedsServer
	}
	ref, err := oidcServerRef(cmd, args[0])
	if err != nil {
		return err
	}
	tokens, err := oidcImportedTokens(cmd)
	if err != nil {
		return err
	}
	create, err := commandFlagBool(cmd, "create")
	if err != nil {
		return err
	}
	template := commandFlagString(cmd, "template")
	if template == "" && commandFlagString(cmd, "codex-auth") != "" {
		template = "openai"
	}
	return withOIDCServer(cmd, func(ctx context.Context, client transport.Client) error {
		var cred *transport.OIDCCredential
		var err error
		if create {
			cred, err = client.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
				OIDCCredentialRef: *ref,
				Config:            transport.OIDCCredentialConfig{Template: template},
				Tokens:            tokens,
			})
		} else {
			cred, err = client.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{OIDCCredentialRef: *ref, Tokens: *tokens})
		}
		if err != nil {
			return err
		}
		printServerOIDCCredential(cmd.OutOrStdout(), "Server OIDC credential imported", cred)
		return nil
	})
}

// oidcImportedTokens reads the imported tokens from --codex-auth or the
// token flags.
func oidcImportedTokens(cmd *cobra.Command) (*transport.OIDCCredentialTokens, error) {
	codexPath := commandFlagString(cmd, "codex-auth")
	access := commandFlagString(cmd, "access-token")
	if (codexPath == "") == (access == "") {
		return nil, ErrOIDCImportSource
	}
	if codexPath != "" {
		data, err := os.ReadFile(codexPath)
		if err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
		}
		auth, err := xkms.ParseCodexAuth(data)
		if err != nil {
			return nil, err
		}
		return xkms.CodexAuthTokens(auth), nil
	}
	accessToken, err := readSecretFlag(cmd, access)
	if err != nil {
		return nil, err
	}
	tokens := &transport.OIDCCredentialTokens{AccessToken: accessToken}
	if refresh := commandFlagString(cmd, "refresh-token"); refresh != "" {
		if tokens.RefreshToken, err = readSecretFlag(cmd, refresh); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

// readSecretFlag returns value, or the command's standard input when value
// is "-".
func readSecretFlag(cmd *cobra.Command, value string) (string, error) {
	if value != "-" {
		return value, nil
	}
	data, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrOIDCTokenStoreFailed, Cause: err}
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// printServerOIDCCredential prints one server credential, under title when
// one is given.
func printServerOIDCCredential(out io.Writer, title string, c *transport.OIDCCredential) {
	if title != "" {
		writeLine(out, title+":")
	}
	scope := "shared"
	if c.Scope == transport.OIDCCredentialScopeUser {
		scope = "personal (" + c.Owner + ")"
	}
	writeLine(out, "  Name:         "+c.Name)
	writeLine(out, "  Source:       server")
	writeLine(out, "  Scope:        "+scope)
	if c.Config.Template != "" {
		writeLine(out, "  Template:     "+c.Config.Template)
	}
	writeLine(out, "  Issuer:       "+c.Config.Issuer)
	status := c.Status
	if c.StatusReason != "" {
		status += " (" + c.StatusReason + ")"
	}
	writeLine(out, "  Status:       "+status)
	if c.ExpiresAt != nil {
		writeLine(out, "  Expires:      "+c.ExpiresAt.Format(time.RFC3339))
	}
	if c.LastError != "" {
		writeLine(out, "  Last error:   "+c.LastError)
	}
	writeLine(out, "")
}

// writeLine writes a line to out. A failed write to the command's output
// has nowhere better to be reported, as everywhere in this CLI.
func writeLine(out io.Writer, line string) {
	if _, err := fmt.Fprintln(out, line); err != nil {
		return
	}
}

func init() {
	OIDCCmd.PersistentFlags().Bool("local", false, "use the local OIDC backend even when an xkmsd server is configured")

	serverRefFlags := func(cmd *cobra.Command) {
		cmd.Flags().String("scope", "", "server credential scope: user (personal, default) or tenant (shared)")
		cmd.Flags().String("owner", "", "owner of a personal server credential (default: you)")
		cmd.Flags().String("tenant", "", "tenant holding the server credential (default: your own)")
	}
	for _, cmd := range []*cobra.Command{oidcLoginCmd, oidcTokenCmd, oidcRefreshCmd, oidcProvidersAddCmd, oidcProvidersRemoveCmd, oidcImportCmd} {
		serverRefFlags(cmd)
	}
	oidcProvidersListCmd.Flags().String("tenant", "", "tenant whose server credentials to list (default: your own)")
	oidcProvidersAddCmd.Flags().String("template", "", "server credential provider template (openai, anthropic, google, ...)")
	oidcProvidersAddCmd.Flags().String("device-endpoint", "", "server credential device authorization endpoint")
	oidcProvidersAddCmd.Flags().String("device-style", "", "server credential device login protocol: rfc8628 (default) or openai")
	oidcTokenCmd.Flags().String("provider", "", "server credential name (with an xkmsd configured)")
	oidcTokenCmd.Flags().String("codex-auth-out", "", "write a codex auth.json (chatgptAuthTokens mode) for the server credential to this path")

	oidcImportCmd.Flags().String("codex-auth", "", "import the ChatGPT login of a codex auth.json")
	oidcImportCmd.Flags().Bool("create", false, "create the credential before importing")
	oidcImportCmd.Flags().String("template", "", "provider template of a created credential")
	oidcImportCmd.Flags().String("access-token", "", "access token; '-' reads it from stdin")
	oidcImportCmd.Flags().String("refresh-token", "", "refresh token; '-' reads it from stdin")
	OIDCCmd.AddCommand(oidcImportCmd)
}
