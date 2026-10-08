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
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
	"github.com/jeremyhahn/go-xkms/sdk/go/oidc"
)

// oidcCmd groups the server-side OIDC credential commands.
var oidcCmd = &cobra.Command{
	Use:   "oidc",
	Short: "Manage server-side OIDC credentials",
	Long: `Manage OIDC credentials held and refreshed by xkmsd: named OAuth/OIDC
logins on the tenant barrier. A credential is tenant-shared (--scope tenant,
visible to every user of the tenant) or personal (--scope user, the default,
visible only to you). Consumers ask for a current access token by name; the
server refreshes it before it expires and never hands out the refresh token.

Subcommands:
  templates   List the provider templates
  create      Create a credential
  login       Log in with the provider's device flow
  import      Import tokens, or an existing codex auth.json
  list        List the credentials you can see
  get         Show a credential
  token       Print a current access token (or write a codex auth.json)
  refresh     Refresh a credential now
  delete      Delete a credential`,
}

// oidcTemplatesCmd lists the provider templates. It needs no server.
var oidcTemplatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "List the OIDC provider templates",
	Long: `List the provider templates a credential can be created from, with the
ways a login for each is obtained (device, import, authorization_code).
Templates that need a region (aws) are xkey-local logins, not server
credentials.

Example:
  xkmsctl oidc templates`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		printer := NewPrinter(getConfig().OutputFormat, os.Stdout)
		names := oidc.ListTemplates()
		sort.Strings(names)
		rows := make([]oidcTemplateRow, 0, len(names))
		for _, name := range names {
			tmpl, err := oidc.GetTemplate(name)
			if err != nil {
				handleError(err)
				return
			}
			rows = append(rows, oidcTemplateRowOf(tmpl))
		}
		printOIDCTemplates(printer, rows)
		if err := printer.Err(); err != nil {
			handleError(err)
		}
	},
}

// oidcTemplateRow is one template in `oidc templates`.
type oidcTemplateRow struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Issuer       string   `json:"issuer,omitempty"`
	Flows        []string `json:"flows"`
	Refreshable  bool     `json:"refreshable"`
	ServerUsable bool     `json:"server_usable"`
}

// oidcTemplateRowOf describes tmpl.
func oidcTemplateRowOf(tmpl *oidc.ProviderTemplate) oidcTemplateRow {
	flows := make([]string, 0, 3)
	for _, f := range []oidc.Flow{oidc.FlowDevice, oidc.FlowImport, oidc.FlowAuthorizationCode} {
		if tmpl.SupportsFlow(f) {
			flows = append(flows, string(f))
		}
	}
	return oidcTemplateRow{
		Name:         tmpl.Name,
		Description:  tmpl.Description,
		Issuer:       tmpl.Issuer,
		Flows:        flows,
		Refreshable:  !tmpl.NoRefresh,
		ServerUsable: !tmpl.RequiresRegion,
	}
}

// printOIDCTemplates prints the template rows.
func printOIDCTemplates(p *Printer, rows []oidcTemplateRow) {
	if printJSONResult(p, rows) {
		return
	}
	for _, r := range rows {
		usable := ""
		if !r.ServerUsable {
			usable = "  (xkey-local only)"
		}
		p.printf("%-10s %s%s\n", r.Name, r.Description, usable)
		p.printf("           flows: %s  refreshable: %t\n", strings.Join(r.Flows, ", "), r.Refreshable)
	}
}

// oidcRefFlags reads the reference flags (--scope, --owner, --tenant) of a
// credential named name.
func oidcRefFlags(cmd *cobra.Command, name string) (client.OIDCCredentialRef, bool) {
	fr := newFlagReader(cmd)
	ref := client.OIDCCredentialRef{
		Scope:    fr.String("scope"),
		Owner:    fr.String("owner"),
		TenantID: fr.String("tenant"),
		Name:     name,
	}
	if err := fr.Err(); err != nil {
		handleError(err)
		return client.OIDCCredentialRef{}, false
	}
	return ref, true
}

// oidcCreateCmd creates a credential.
var oidcCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an OIDC credential",
	Long: `Create an OIDC credential. A --template fills every provider setting you
leave out; without one, --issuer and --client-id are required and the
endpoints are discovered from the issuer unless --token-endpoint is given.

The credential starts pending: log in with 'xkmsctl oidc login' or import
tokens with 'xkmsctl oidc import'.

Examples:
  xkmsctl oidc create codex --template openai --scope tenant
  xkmsctl oidc create corp --issuer https://idp.example.com --client-id cli-app
  xkmsctl oidc create api --issuer https://idp.example.com --client-id svc \
      --client-secret - --token-endpoint https://idp.example.com/oauth/token`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ref, ok := oidcRefFlags(cmd, args[0])
		if !ok {
			return
		}
		cfg, ok := oidcConfigFlags(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Creating OIDC credential "+args[0], ErrOIDCCredentialCreateFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.OIDCCredentialCreate(ctx, &client.OIDCCredentialCreateRequest{OIDCCredentialRef: ref, Config: cfg})
		}, printOIDCCredentialResult("OIDC Credential Created"))
	},
}

// oidcConfigFlags reads the provider configuration flags.
func oidcConfigFlags(cmd *cobra.Command) (client.OIDCCredentialConfig, bool) {
	fr := newFlagReader(cmd)
	cfg := client.OIDCCredentialConfig{
		Template:                    fr.String("template"),
		Issuer:                      fr.String("issuer"),
		ClientID:                    fr.String("client-id"),
		Scopes:                      fr.StringSlice("scopes"),
		AuthorizationEndpoint:       fr.String("authorization-endpoint"),
		TokenEndpoint:               fr.String("token-endpoint"),
		DeviceAuthorizationEndpoint: fr.String("device-endpoint"),
		TokenEncoding:               fr.String("token-encoding"),
		DeviceStyle:                 fr.String("device-style"),
		RefreshMarginSeconds:        int64(fr.Duration("refresh-margin") / time.Second),
	}
	secret := fr.String("client-secret")
	if err := fr.Err(); err != nil {
		handleError(err)
		return client.OIDCCredentialConfig{}, false
	}
	if secret != "" {
		value, err := resolveSecret(secret, "Client secret")
		if err != nil {
			handleError(err)
			return client.OIDCCredentialConfig{}, false
		}
		cfg.ClientSecret = value
	}
	return cfg, true
}

// oidcImportCmd imports tokens into a credential.
var oidcImportCmd = &cobra.Command{
	Use:   "import <name>",
	Short: "Import tokens into an OIDC credential",
	Long: `Import a login obtained elsewhere, so the server holds and refreshes it
without a new login. Either name a codex auth.json with --codex-auth (its
ChatGPT tokens are imported into an openai credential), or give the tokens:
--access-token and, for a refreshable login, --refresh-token. A value of '-'
reads it from standard input.

--create creates the credential first (from --template, default openai with
--codex-auth); otherwise it must exist.

Examples:
  xkmsctl oidc import codex --scope tenant --codex-auth ~/.codex/auth.json --create
  xkmsctl oidc import claude --create --template anthropic --access-token -
  xkmsctl oidc import corp --access-token - --refresh-token "$RT"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ref, ok := oidcRefFlags(cmd, args[0])
		if !ok {
			return
		}
		cfg, ok := oidcConfigFlags(cmd)
		if !ok {
			return
		}
		fr := newFlagReader(cmd)
		codexPath := fr.String("codex-auth")
		create := fr.Bool("create")
		accessToken := fr.String("access-token")
		refreshToken := fr.String("refresh-token")
		idToken := fr.String("id-token")
		expiresAt := fr.String("expires-at")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		tokens, err := oidcImportTokens(codexPath, accessToken, refreshToken, idToken, expiresAt)
		if err != nil {
			handleError(err)
			return
		}
		if codexPath != "" && cfg.Template == "" {
			cfg.Template = "openai"
		}
		runClientCall(getConfig(), "Importing OIDC credential "+args[0], ErrOIDCCredentialImportFailed, func(ctx context.Context, cl client.Client) (any, error) {
			if create {
				return cl.OIDCCredentialCreate(ctx, &client.OIDCCredentialCreateRequest{OIDCCredentialRef: ref, Config: cfg, Tokens: tokens})
			}
			return cl.OIDCCredentialImport(ctx, &client.OIDCCredentialImportRequest{OIDCCredentialRef: ref, Tokens: *tokens})
		}, printOIDCCredentialResult("OIDC Credential Imported"))
	},
}

// oidcImportTokens assembles the imported tokens from a codex auth.json or
// from the token flags.
func oidcImportTokens(codexPath, accessToken, refreshToken, idToken, expiresAt string) (*client.OIDCCredentialTokens, error) {
	if codexPath != "" {
		if accessToken != "" || refreshToken != "" || idToken != "" {
			return nil, ErrOIDCImportSourceConflict
		}
		data, err := os.ReadFile(codexPath)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrOIDCCodexAuthRead, Detail: codexPath, Err: err}
		}
		auth, err := client.ParseCodexAuth(data)
		if err != nil {
			return nil, err
		}
		return client.CodexAuthTokens(auth), nil
	}
	if accessToken == "" {
		return nil, ErrOIDCAccessTokenRequired
	}
	access, err := resolveSecret(accessToken, "Access token")
	if err != nil {
		return nil, err
	}
	tokens := &client.OIDCCredentialTokens{AccessToken: access, IDToken: idToken}
	if refreshToken != "" {
		if tokens.RefreshToken, err = resolveSecret(refreshToken, "Refresh token"); err != nil {
			return nil, err
		}
	}
	if expiresAt != "" {
		exp, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrOIDCInvalidExpiry, Detail: expiresAt, Err: err}
		}
		tokens.ExpiresAt = &exp
	}
	return tokens, nil
}

// oidcLoginCmd logs a credential in with the provider's device flow.
var oidcLoginCmd = &cobra.Command{
	Use:   "login <name>",
	Short: "Log an OIDC credential in with the device flow",
	Long: `Start the provider's device login for a credential, print the code to
enter and the URL to enter it at, and wait until you approve it on any
device. The server polls the provider and stores the login; no token passes
through this command.

Examples:
  xkmsctl oidc create codex --template openai --scope tenant
  xkmsctl oidc login codex --scope tenant`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ref, ok := oidcRefFlags(cmd, args[0])
		if !ok {
			return
		}
		cfg := getConfig()
		cl, err := cfg.CreateClient()
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
			return
		}
		defer closeQuietly(cl)
		ctx := context.Background()
		if err := cl.Connect(ctx); err != nil {
			handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
			return
		}
		cred, err := oidcDeviceLogin(ctx, cl, &ref, os.Stderr)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrOIDCLoginFailed, Err: err})
			return
		}
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		printOIDCCredentialResult("OIDC Credential Logged In")(printer, cred)
		if err := printer.Err(); err != nil {
			handleError(err)
		}
	},
}

// oidcDeviceLogin starts a device login, prints the user code to out, and
// polls at the provider's interval until the login is active or expires.
func oidcDeviceLogin(ctx context.Context, cl client.Client, ref *client.OIDCCredentialRef, out io.Writer) (*client.OIDCCredential, error) {
	cred, err := cl.OIDCCredentialDeviceStart(ctx, ref)
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
	if _, err := io.WriteString(out, "Open "+uri+"\nand enter the code: "+login.UserCode+"\n"); err != nil {
		return nil, &WrappedError{Sentinel: ErrOIDCLoginFailed, Err: err}
	}
	ctx, cancel := context.WithDeadline(ctx, login.ExpiresAt)
	defer cancel()
	interval := time.Duration(login.IntervalSeconds) * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, &WrappedError{Sentinel: ErrOIDCLoginExpired, Err: ctx.Err()}
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return nil, &WrappedError{Sentinel: ErrOIDCLoginExpired, Err: ctx.Err()}
		}
		cred, err = cl.OIDCCredentialDevicePoll(ctx, ref)
		if err != nil {
			return nil, err
		}
		if cred.Status == client.OIDCCredentialStatusActive && cred.DeviceLogin == nil {
			return cred, nil
		}
		if cred.DeviceLogin != nil && cred.DeviceLogin.IntervalSeconds > 0 {
			interval = time.Duration(cred.DeviceLogin.IntervalSeconds) * time.Second
		}
		timer.Reset(interval)
	}
}

// oidcListCmd lists the visible credentials.
var oidcListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the OIDC credentials you can see",
	Long: `List the tenant's shared credentials and your personal ones.

Example:
  xkmsctl oidc list`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		tenant, ok := tenantFlag(cmd)
		if !ok {
			return
		}
		runClientCall(getConfig(), "Listing OIDC credentials", ErrOIDCCredentialListFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.OIDCCredentialList(ctx, &client.OIDCCredentialListRequest{TenantID: tenant})
		}, printOIDCCredentialList)
	},
}

// newOIDCRefCmd builds a command that runs call on one named credential.
func newOIDCRefCmd(use, short, long, verbose string, failure error, call func(context.Context, client.Client, *client.OIDCCredentialRef) (any, error), show func(*Printer, any)) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ref, ok := oidcRefFlags(cmd, args[0])
			if !ok {
				return
			}
			runClientCall(getConfig(), verbose+" "+args[0], failure, func(ctx context.Context, cl client.Client) (any, error) {
				return call(ctx, cl, &ref)
			}, show)
		},
	}
}

var oidcGetCmd = newOIDCRefCmd("get <name>", "Show an OIDC credential",
	`Show a credential: its provider, status, expiry and last refresh. Tokens
are never shown; use 'xkmsctl oidc token'.

Example:
  xkmsctl oidc get codex --scope tenant`,
	"Getting OIDC credential", ErrOIDCCredentialGetFailed,
	func(ctx context.Context, cl client.Client, ref *client.OIDCCredentialRef) (any, error) {
		return cl.OIDCCredentialGet(ctx, ref)
	}, printOIDCCredentialResult("OIDC Credential"))

var oidcRefreshCmd = newOIDCRefCmd("refresh <name>", "Refresh an OIDC credential now",
	`Refresh a credential now, whether or not it is due. The server refreshes
every credential before it expires on its own; this is for testing a login
or recovering after a provider outage.

Example:
  xkmsctl oidc refresh codex --scope tenant`,
	"Refreshing OIDC credential", ErrOIDCCredentialRefreshFailed,
	func(ctx context.Context, cl client.Client, ref *client.OIDCCredentialRef) (any, error) {
		return cl.OIDCCredentialRefresh(ctx, ref)
	}, printOIDCCredentialResult("OIDC Credential Refreshed"))

var oidcDeleteCmd = newOIDCRefCmd("delete <name>", "Delete an OIDC credential",
	`Delete a credential. Its tokens are not revoked at the provider.

Example:
  xkmsctl oidc delete codex --scope tenant`,
	"Deleting OIDC credential", ErrOIDCCredentialDeleteFailed,
	func(ctx context.Context, cl client.Client, ref *client.OIDCCredentialRef) (any, error) {
		if err := cl.OIDCCredentialDelete(ctx, ref); err != nil {
			return nil, err
		}
		return "OIDC credential " + ref.Name + " deleted", nil
	}, func(p *Printer, result any) {
		message, ok := result.(string)
		if !ok || printJSONResult(p, map[string]string{"message": message}) {
			return
		}
		printCallSuccess(p, message)
	})

// oidcTokenCmd prints a current access token.
var oidcTokenCmd = &cobra.Command{
	Use:   "token <name>",
	Short: "Print a current access token of an OIDC credential",
	Long: `Print a current access token, refreshed first when it is about to
expire. --codex-auth-out writes a codex auth.json instead, in the
"chatgptAuthTokens" mode: codex uses the token and never refreshes it, and
the file holds no refresh token.

Examples:
  xkmsctl oidc token corp
  curl -H "Authorization: Bearer $(xkmsctl oidc token corp)" https://api.example.com/
  xkmsctl oidc token codex --scope tenant --codex-auth-out "$CODEX_HOME/auth.json"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ref, ok := oidcRefFlags(cmd, args[0])
		if !ok {
			return
		}
		fr := newFlagReader(cmd)
		codexOut := fr.String("codex-auth-out")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		runClientCall(getConfig(), "Getting an access token of OIDC credential "+args[0], ErrOIDCTokenFailed, func(ctx context.Context, cl client.Client) (any, error) {
			tok, err := cl.OIDCCredentialGetAccessToken(ctx, &ref)
			if err != nil || codexOut == "" {
				return tok, err
			}
			if err := writeCodexAuth(codexOut, tok, time.Now()); err != nil {
				return nil, err
			}
			return "codex auth.json written to " + codexOut, nil
		}, printOIDCAccessToken)
	},
}

// writeCodexAuth writes the chatgptAuthTokens auth.json for tok to path,
// readable by its owner only.
func writeCodexAuth(path string, tok *client.OIDCAccessToken, now time.Time) error {
	data, err := client.CodexAuthFile(tok, now)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return &WrappedDetailError{Sentinel: ErrOIDCCodexAuthWrite, Detail: path, Err: err}
	}
	return nil
}

// printOIDCAccessToken prints an access token alone on a line (so it can be
// captured by a shell), or the message of a written codex auth.json.
func printOIDCAccessToken(p *Printer, result any) {
	switch v := result.(type) {
	case *client.OIDCAccessToken:
		if printJSONResult(p, v) {
			return
		}
		p.println(v.AccessToken)
	case string:
		if printJSONResult(p, map[string]string{"message": v}) {
			return
		}
		printCallSuccess(p, v)
	}
}

// printOIDCCredentialResult returns a printer of one credential under title.
func printOIDCCredentialResult(title string) func(*Printer, any) {
	return func(p *Printer, result any) {
		c, ok := result.(*client.OIDCCredential)
		if !ok || printJSONResult(p, result) {
			return
		}
		p.printf("%s:\n", title)
		p.printf("  Name:        %s\n", c.Name)
		p.printf("  Scope:       %s\n", oidcScopeLabel(c))
		if c.TenantID != "" {
			p.printf("  Tenant:      %s\n", c.TenantID)
		}
		if c.Config.Template != "" {
			p.printf("  Template:    %s\n", c.Config.Template)
		}
		p.printf("  Issuer:      %s\n", c.Config.Issuer)
		if c.Config.ClientID != "" {
			p.printf("  Client ID:   %s\n", c.Config.ClientID)
		}
		p.printf("  Status:      %s", c.Status)
		if c.StatusReason != "" {
			p.printf(" (%s)", c.StatusReason)
		}
		p.printf("\n")
		p.printf("  Refreshable: %t\n", c.Refreshable)
		if c.ExpiresAt != nil {
			p.printf("  Expires:     %s\n", c.ExpiresAt.Format(time.RFC3339))
		}
		if c.LastRefresh != nil {
			p.printf("  Refreshed:   %s\n", c.LastRefresh.Format(time.RFC3339))
		}
		if c.LastError != "" {
			p.printf("  Last error:  %s\n", c.LastError)
		}
		if d := c.DeviceLogin; d != nil {
			p.printf("  Device code: %s at %s (until %s)\n", d.UserCode, d.VerificationURI, d.ExpiresAt.Format(time.RFC3339))
		}
	}
}

// oidcScopeLabel names a credential's scope for display.
func oidcScopeLabel(c *client.OIDCCredential) string {
	if c.Scope == client.OIDCCredentialScopeUser {
		return "personal (" + c.Owner + ")"
	}
	return "shared"
}

// printOIDCCredentialList prints the visible credentials.
func printOIDCCredentialList(p *Printer, result any) {
	list, ok := result.(*client.OIDCCredentialListResponse)
	if !ok || printJSONResult(p, result) {
		return
	}
	if len(list.Credentials) == 0 {
		p.printf("No OIDC credentials\n")
		return
	}
	p.printf("%-24s %-22s %-10s %-17s %s\n", "NAME", "SCOPE", "TEMPLATE", "STATUS", "EXPIRES")
	for i := range list.Credentials {
		c := &list.Credentials[i]
		expires := "-"
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.Format(time.RFC3339)
		}
		p.printf("%-24s %-22s %-10s %-17s %s\n", c.Name, oidcScopeLabel(c), c.Config.Template, c.Status, expires)
	}
}

func init() {
	for _, cmd := range []*cobra.Command{oidcCreateCmd, oidcImportCmd, oidcLoginCmd, oidcGetCmd, oidcRefreshCmd, oidcDeleteCmd, oidcTokenCmd} {
		cmd.Flags().String("scope", "user", "credential scope: user (personal) or tenant (shared)")
		cmd.Flags().String("owner", "", "owner of a personal credential (default: you)")
		cmd.Flags().String("tenant", "", "tenant holding the credential (default: your own)")
	}
	oidcListCmd.Flags().String("tenant", "", "tenant whose credentials to list (default: your own)")

	for _, cmd := range []*cobra.Command{oidcCreateCmd, oidcImportCmd} {
		cmd.Flags().String("template", "", "provider template (see 'xkmsctl oidc templates')")
		cmd.Flags().String("issuer", "", "provider issuer URL")
		cmd.Flags().String("client-id", "", "OAuth client ID")
		cmd.Flags().String("client-secret", "", "client secret of a confidential client; '-' reads it from stdin")
		cmd.Flags().StringSlice("scopes", nil, "scopes to request (comma-separated)")
		cmd.Flags().String("authorization-endpoint", "", "authorization endpoint (no discovery)")
		cmd.Flags().String("token-endpoint", "", "token endpoint; set to skip discovery")
		cmd.Flags().String("device-endpoint", "", "device authorization endpoint (no discovery)")
		cmd.Flags().String("token-encoding", "", "token request encoding: form (default) or json")
		cmd.Flags().String("device-style", "", "device login protocol: rfc8628 (default) or openai")
		cmd.Flags().Duration("refresh-margin", 0, "refresh this long before expiry (default 5m)")
	}
	oidcImportCmd.Flags().String("codex-auth", "", "import the ChatGPT login of a codex auth.json")
	oidcImportCmd.Flags().Bool("create", false, "create the credential before importing")
	oidcImportCmd.Flags().String("access-token", "", "access token; '-' reads it from stdin")
	oidcImportCmd.Flags().String("refresh-token", "", "refresh token; '-' reads it from stdin")
	oidcImportCmd.Flags().String("id-token", "", "ID token")
	oidcImportCmd.Flags().String("expires-at", "", "access token expiry (RFC 3339); default: read from the token")
	oidcTokenCmd.Flags().String("codex-auth-out", "", "write a codex auth.json (chatgptAuthTokens mode) to this path instead")

	oidcCmd.AddCommand(oidcTemplatesCmd, oidcCreateCmd, oidcLoginCmd, oidcImportCmd, oidcListCmd,
		oidcGetCmd, oidcTokenCmd, oidcRefreshCmd, oidcDeleteCmd)
	rootCmd.AddCommand(oidcCmd)
}
