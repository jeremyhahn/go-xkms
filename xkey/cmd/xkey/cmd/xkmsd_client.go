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
	"crypto/tls"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// This file is the single place where the xkey CLI turns configuration into
// an SDK transport client. Command groups that talk to xkmsd (platform-store,
// ca, ...) resolve their endpoint here so URL/token/CA precedence and the URL
// scheme dispatch are defined exactly once, mirroring the SSH commands'
// sshClient() behavior.

// xkmsdConnectTimeout bounds the initial handshake. Every SDK transport
// performs a health check inside Connect, so an unreachable server surfaces
// here rather than on the first operation.
const xkmsdConnectTimeout = 30 * time.Second

// Environment variables consulted when resolving the xkmsd endpoint.
const (
	envXKMSdURL     = "XKMSD_URL"
	envXKeyXKMSdURL = "XKEY_XKMSD_URL"
	envXKMSdToken   = "XKMSD_TOKEN"
	envXKMSdTLSCA   = "XKMSD_TLS_CA"

	// envXKMSdTLSCert and envXKMSdTLSKey name an mTLS client credential
	// presented to TLS-bearing transports. The unified server's gRPC and
	// MCP transports authenticate module calls by client certificate, so a
	// bearer token alone reaches only REST and QUIC.
	envXKMSdTLSCert = "XKMSD_TLS_CERT"
	envXKMSdTLSKey  = "XKMSD_TLS_KEY"

	// envXKMSdServerName names a server whose TLS identity is not probed
	// (plaintext transports and the Unix socket), selecting the stored login
	// whose server name matches.
	envXKMSdServerName = "XKMSD_SERVER_NAME"
)

// cfgKeyXKMSdURL is the viper key bound to the global --xkmsd-url flag.
const cfgKeyXKMSdURL = "xkmsd_url"

// tlsCAFlagName is the per-command flag that overrides the CA bundle used to
// verify TLS-bearing transports. Commands that do not declare it simply fall
// through to the environment and config sources.
const tlsCAFlagName = "tls-ca"

// xkmsd client errors.
var (
	// ErrXKMSdURLRequired indicates no xkmsd server URL was configured by any
	// source (flag, environment, or config file).
	ErrXKMSdURLRequired = errors.New("xkmsd: server URL is required; use --xkmsd-url, set " +
		envXKMSdURL + ", or set xkmsd.address in the xkey config")

	// ErrXKMSdURLInvalid indicates the configured URL could not be parsed.
	ErrXKMSdURLInvalid = errors.New("xkmsd: invalid server URL")

	// ErrXKMSdUnsupportedScheme indicates the URL scheme names no known
	// transport.
	ErrXKMSdUnsupportedScheme = errors.New("xkmsd: unsupported server URL scheme")

	// ErrXKMSdTLSConfigFailed indicates the CA bundle for a TLS-bearing
	// transport could not be loaded.
	ErrXKMSdTLSConfigFailed = errors.New("xkmsd: failed to build TLS configuration")

	// ErrXKMSdClientCreateFailed indicates the SDK rejected the resolved
	// client configuration.
	ErrXKMSdClientCreateFailed = errors.New("xkmsd: failed to create transport client")

	// ErrXKMSdConnectFailed indicates the connection handshake to the server
	// failed.
	ErrXKMSdConnectFailed = errors.New("xkmsd: failed to connect to server")

	// ErrCommandFlagInvalid indicates a declared flag could not be read as
	// the requested type.
	ErrCommandFlagInvalid = errors.New("cmd: invalid flag value")
)

// XKMSdEndpoint is a resolved xkmsd connection target: the scheme-qualified
// server URL plus the credentials and trust material used to reach it.
type XKMSdEndpoint struct {
	// URL is the scheme-qualified server URL. The scheme selects the
	// transport (see xkmsdTransports).
	URL string

	// Token is the bearer/JWT token presented to the server. Empty when no
	// token is configured.
	Token string

	// TLSCertFile and TLSKeyFile are the PEM mTLS client credential
	// presented on TLS-bearing transports. Both or neither.
	TLSCertFile string
	TLSKeyFile  string

	// TLSCAFile is the PEM CA bundle used to verify the server on
	// TLS-bearing transports. Empty means the system trust store.
	TLSCAFile string
}

// xkmsdTransport describes how a URL scheme maps onto an SDK transport: the
// protocol to construct, whether that protocol negotiates TLS, and the address
// form the protocol expects.
type xkmsdTransport struct {
	protocol xkms.Protocol
	tls      bool
	address  func(rawURL string, u *url.URL) string
}

// xkmsdTransports is the scheme dispatch table. It is the CLI-side mirror of
// the SDK's own scheme handling; the SDK's xkms.NewFromURL cannot be used
// directly because it carries neither an auth token nor a CA bundle.
var xkmsdTransports = map[string]xkmsdTransport{
	"unix":  {protocol: xkms.ProtocolUnix, tls: true, address: xkmsdSocketPath},
	"http":  {protocol: xkms.ProtocolREST, address: xkmsdFullURL},
	"https": {protocol: xkms.ProtocolREST, tls: true, address: xkmsdFullURL},
	"grpc":  {protocol: xkms.ProtocolGRPC, address: xkmsdHostPort},
	"grpcs": {protocol: xkms.ProtocolGRPC, tls: true, address: xkmsdHostPort},
	"quic":  {protocol: xkms.ProtocolQUIC, tls: true, address: xkmsdHostPort},
	"mcp":   {protocol: xkms.ProtocolMCP, address: xkmsdHostPort},
	"mcps":  {protocol: xkms.ProtocolMCP, tls: true, address: xkmsdHostPort},
}

// xkmsdFullURL keeps the complete URL, which is what the REST transport uses
// as its base URL.
func xkmsdFullURL(rawURL string, _ *url.URL) string { return rawURL }

// xkmsdHostPort reduces the URL to host:port for the socket-dialing
// transports (gRPC, QUIC, MCP).
func xkmsdHostPort(_ string, u *url.URL) string { return u.Host }

// xkmsdSocketPath strips the unix:// scheme. The Unix transport prepends the
// scheme itself when dialing, so leaving it in place yields
// "unix://unix:///path", which gRPC rejects with
// `invalid (non-empty) authority: unix:`.
func xkmsdSocketPath(rawURL string, _ *url.URL) string {
	return strings.TrimPrefix(rawURL, "unix://")
}

// xkmsdSupportedSchemes returns the sorted scheme list used in error messages.
func xkmsdSupportedSchemes() string {
	schemes := make([]string, 0, len(xkmsdTransports))
	for scheme := range xkmsdTransports {
		schemes = append(schemes, scheme+"://")
	}
	sort.Strings(schemes)
	return strings.Join(schemes, ", ")
}

// resolveXKMSdEndpoint resolves the xkmsd endpoint with the same precedence
// the ssh commands use:
//
//  1. the explicit --xkmsd-url flag,
//  2. the XKMSD_URL / XKEY_XKMSD_URL environment variables,
//  3. the xkmsd_url config key,
//  4. the xkmsd.address key of the unified xkey config.
//
// The auth token comes from resolveXKMSdToken. The CA bundle comes from a --tls-ca
// flag when the command declares one, then XKMSD_TLS_CA, then the config's
// xkmsd.tls_ca_file. cmd may be nil for callers outside a cobra invocation.
func resolveXKMSdEndpoint(cmd *cobra.Command) (XKMSdEndpoint, error) {
	serverURL := resolveXKMSdURL()
	if serverURL == "" {
		return XKMSdEndpoint{}, ErrXKMSdURLRequired
	}

	return withXKMSdToken(XKMSdEndpoint{
		URL:         serverURL,
		TLSCAFile:   resolveXKMSdTLSCAFile(cmd),
		TLSCertFile: strings.TrimSpace(os.Getenv(envXKMSdTLSCert)),
		TLSKeyFile:  strings.TrimSpace(os.Getenv(envXKMSdTLSKey)),
	})
}

// withXKMSdToken sets the endpoint's bearer token (see resolveXKMSdToken).
func withXKMSdToken(endpoint XKMSdEndpoint) (XKMSdEndpoint, error) {
	token, err := resolveXKMSdToken(endpoint)
	if err != nil {
		return XKMSdEndpoint{}, err
	}
	endpoint.Token = token
	return endpoint, nil
}

// resolveXKMSdToken returns the bearer token presented to the endpoint's
// server: the explicit XKMSD_TOKEN when set, otherwise the `xkey auth
// login` stored for that server. A login is bound to the server's TLS
// identity, read from a handshake verified by the endpoint's own trust, so
// one login serves every transport of that server and never a different
// server on the same host. On a transport without TLS the configured server
// name (XKMSD_SERVER_NAME, xkmsd.server_name) selects the login. No stored
// login is no token (the call relies on its mTLS client certificate); an
// expired one is an error naming the refresh command.
func resolveXKMSdToken(endpoint XKMSdEndpoint) (string, error) {
	if token := strings.TrimSpace(os.Getenv(envXKMSdToken)); token != "" {
		return token, nil
	}

	// Read-only: inspecting the login store never creates the xKey home or
	// the store. Without either, nothing was ever logged in.
	dir, err := featureDataDirExisting(defaultAuthStoragePath)
	if errors.Is(err, xhome.ErrHomeNotResolved) {
		return "", nil
	}
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrAuthTokenLoadFailed, Cause: err}
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}

	store, err := tokenstore.Open(dir)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrAuthTokenLoadFailed, Cause: err}
	}
	token, err := storedLoginToken(store, endpoint)
	if closeErr := store.Close(); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	return token, err
}

// storedLoginToken picks the endpoint's login from store. An empty store
// holds no login, so the server is not even identified.
func storedLoginToken(store tokenstore.TokenStore, endpoint XKMSdEndpoint) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), xkmsdConnectTimeout)
	defer cancel()
	logins, err := store.List(ctx)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrAuthTokenLoadFailed, Cause: err}
	}
	if len(logins) == 0 {
		return "", nil
	}
	ref, err := xkmsdServerRef(ctx, endpoint)
	if err != nil {
		return "", err
	}
	token, err := tokenstore.LoginToken(ctx, store, ref)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrAuthTokenLoadFailed, Cause: err}
	}
	return token, nil
}

// probeServerID reads a server's TLS identity. Tests that stand in a fake
// server replace it.
var probeServerID = serverid.Probe

// xkmsdServerRef identifies the endpoint's server for picking its login:
// by the TLS identity it presents, or, on a transport without TLS, by the
// configured server name.
func xkmsdServerRef(ctx context.Context, endpoint XKMSdEndpoint) (tokenstore.ServerRef, error) {
	tlsConfig, err := endpoint.TLSConfig()
	if err != nil {
		return tokenstore.ServerRef{}, err
	}
	id, err := probeServerID(ctx, endpoint.URL, tlsConfig)
	if errors.Is(err, serverid.ErrNoTLS) {
		return tokenstore.ServerRef{Name: resolveXKMSdServerName()}, nil
	}
	if err != nil {
		return tokenstore.ServerRef{}, &SentinelCauseError{Sentinel: ErrXKMSdConnectFailed, Cause: err}
	}
	return tokenstore.ServerRef{ID: id}, nil
}

// resolveXKMSdServerName returns the configured name of the server reached
// without TLS: XKMSD_SERVER_NAME, then the config's xkmsd.server_name.
func resolveXKMSdServerName() string {
	sources := []string{os.Getenv(envXKMSdServerName)}
	if cfg := GetConfig(); cfg != nil {
		sources = append(sources, cfg.XKMSD.ServerName)
	}
	return strings.TrimSpace(firstNonEmpty(sources...))
}

// resolveXKMSdURL applies the URL precedence chain. It returns an empty
// string when no source supplies a URL.
func resolveXKMSdURL() string {
	sources := []string{
		xkmsdURL,
		os.Getenv(envXKMSdURL),
		os.Getenv(envXKeyXKMSdURL),
		viper.GetString(cfgKeyXKMSdURL),
	}
	if cfg := GetConfig(); cfg != nil {
		sources = append(sources, cfg.XKMSD.Address)
	}
	return strings.TrimSpace(firstNonEmpty(sources...))
}

// resolveXKMSdTLSCAFile applies the CA-bundle precedence chain.
func resolveXKMSdTLSCAFile(cmd *cobra.Command) string {
	sources := []string{
		commandFlagString(cmd, tlsCAFlagName),
		os.Getenv(envXKMSdTLSCA),
	}
	if cfg := GetConfig(); cfg != nil {
		sources = append(sources, cfg.XKMSD.TLSCAFile)
	}
	return strings.TrimSpace(firstNonEmpty(sources...))
}

// commandFlagString reads a flag value when the command declares one,
// returning an empty string otherwise. Both the command's own flag set and
// its persistent flag set are consulted, so the value is found whether cmd is
// the executed sub-command (inherited flags land in Flags()) or the parent
// that declared the persistent flag. cmd may be nil.
func commandFlagString(cmd *cobra.Command, name string) string {
	if cmd == nil {
		return ""
	}
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
		if flag := flags.Lookup(name); flag != nil {
			if value := flag.Value.String(); value != "" {
				return value
			}
		}
	}
	return ""
}

// commandFlagBool reads a boolean flag when the command declares one,
// returning false otherwise. It is the bool companion to commandFlagString
// and exists so callers never discard a flag-parse error with the blank
// identifier. cmd may be nil.
func commandFlagBool(cmd *cobra.Command, name string) (bool, error) {
	if cmd == nil {
		return false, nil
	}
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
		if flags.Lookup(name) == nil {
			continue
		}
		value, err := flags.GetBool(name)
		if err != nil {
			return false, &DetailError{Err: ErrCommandFlagInvalid, Detail: ": " + name + ": " + err.Error()}
		}
		return value, nil
	}
	return false, nil
}

// commandFlagDuration reads a duration flag when the command declares one,
// returning zero otherwise. It is the duration companion to commandFlagString
// and commandFlagBool. cmd may be nil.
func commandFlagDuration(cmd *cobra.Command, name string) (time.Duration, error) {
	if cmd == nil {
		return 0, nil
	}
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
		if flags.Lookup(name) == nil {
			continue
		}
		value, err := flags.GetDuration(name)
		if err != nil {
			return 0, &DetailError{Err: ErrCommandFlagInvalid, Detail: ": " + name + ": " + err.Error()}
		}
		return value, nil
	}
	return 0, nil
}

// commandFlagChanged reports whether the named flag exists on cmd -- its own
// flag set or its persistent flag set -- and was explicitly set on the
// command line. Checking both flag sets mirrors commandFlagString and
// commandFlagBool, so Changed is read off whichever FlagSet actually
// declared the flag: the executed sub-command's own set when the flag is
// local, or its persistent set when an ancestor declared it and cobra has
// not yet merged it into the child (a state unit tests construct directly
// without a full cobra.Execute). cmd may be nil.
func commandFlagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	for _, flags := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
		if flag := flags.Lookup(name); flag != nil {
			return flag.Changed
		}
	}
	return false
}

// TLSConfig builds the TLS configuration for the endpoint's TLS transports:
// the CA bundle (empty selects the system roots) and the mTLS client
// credential, through the SDK's shared TLS builder.
func (e XKMSdEndpoint) TLSConfig() (*tls.Config, error) {
	cfg, err := transport.BuildTLSConfig(transport.TLSOptions{
		CAFile:   e.TLSCAFile,
		CertFile: e.TLSCertFile,
		KeyFile:  e.TLSKeyFile,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrXKMSdTLSConfigFailed, Cause: err}
	}
	return cfg, nil
}

// Client constructs an SDK transport client for the endpoint. The URL scheme
// selects the transport (http(s) → REST, grpc(s) → gRPC, unix → gRPC over
// TLS on a Unix socket, quic → HTTP/3, mcp(s) → JSON-RPC). The client is not connected;
// callers own Close.
func (e XKMSdEndpoint) Client() (transport.Client, error) {
	rawURL := strings.TrimSpace(e.URL)
	if rawURL == "" {
		return nil, ErrXKMSdURLRequired
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrXKMSdURLInvalid, Cause: err}
	}

	selected, ok := xkmsdTransports[strings.ToLower(parsed.Scheme)]
	if !ok {
		return nil, &DetailError{
			Err:    ErrXKMSdUnsupportedScheme,
			Detail: ": " + rawURL + " (want one of " + xkmsdSupportedSchemes() + ")",
		}
	}

	address := selected.address(rawURL, parsed)
	if address == "" {
		return nil, &DetailError{Err: ErrXKMSdURLInvalid, Detail: ": " + rawURL + " has no address"}
	}

	opts := []xkms.Option{
		xkms.WithProtocol(selected.protocol),
		xkms.WithAddress(address),
	}
	if selected.tls {
		tlsConfig, err := e.TLSConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, xkms.WithTLS(tlsConfig))
	}
	if e.Token != "" {
		opts = append(opts, xkms.WithJWTToken(e.Token))
	}

	client, err := xkms.NewWithOptions(opts...)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrXKMSdClientCreateFailed, Cause: err}
	}
	return client, nil
}

// newXKMSdClient resolves the endpoint for cmd and constructs an unconnected
// transport client. cmd may be nil.
func newXKMSdClient(cmd *cobra.Command) (transport.Client, error) {
	endpoint, err := resolveXKMSdEndpoint(cmd)
	if err != nil {
		return nil, err
	}
	return endpoint.Client()
}

// connectXKMSdClient constructs a transport client and completes the
// connection handshake, so callers can issue operations immediately. The
// client is closed before returning an error, so a successful call always
// hands back a client the caller must Close.
func connectXKMSdClient(cmd *cobra.Command) (transport.Client, error) {
	client, err := newXKMSdClient(cmd)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), xkmsdConnectTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrXKMSdConnectFailed, Cause: errors.Join(err, client.Close())}
	}
	return client, nil
}
