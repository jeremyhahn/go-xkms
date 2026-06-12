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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Phase 1c xkey SSH surface. Every command goes through the SDK's
// sshsdk.Client — no direct imports of pkg/ssh/* are permitted here.
// Transport selection (REST vs. embedded) is driven by the XKMSD_URL
// env var or the xkmsd_url config key; both are handled through the
// common sshClient() helper so sub-command handlers stay transport-
// agnostic.

// SSH-command typed errors. All returned errors wrap one of these so
// callers (tests, scripts) can inspect via errors.Is / errors.As.
var (
	// ErrSSHMissingKeyName is returned when a required --name flag is
	// absent.
	ErrSSHMissingKeyName = errors.New("ssh: --name is required")

	// ErrSSHMissingImportFile is returned when xkey ssh keys import is
	// invoked without a path argument.
	ErrSSHMissingImportFile = errors.New("ssh: import file path is required")

	// ErrSSHInvalidKeyType is returned when --type is outside the
	// {ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521} set.
	ErrSSHInvalidKeyType = errors.New("ssh: invalid key type")

	// ErrSSHMissingHost is returned when a host argument is absent.
	ErrSSHMissingHost = errors.New("ssh: host is required")

	// ErrSSHMissingFingerprint is returned when a fingerprint argument
	// is absent.
	ErrSSHMissingFingerprint = errors.New("ssh: fingerprint is required")

	// ErrSSHClientConstruct wraps any sshsdk.NewREST / NewEmbeddedFile
	// failure.
	ErrSSHClientConstruct = errors.New("ssh: failed to construct client")
)

// SSHConfigError wraps a configuration-resolution failure. The Op
// field names the operation (resolve_home / open_store / etc.) that
// triggered the error.
type SSHConfigError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *SSHConfigError) Error() string {
	return "ssh: config: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *SSHConfigError) Unwrap() error { return e.Err }

// SSHCmd is the parent command for SSH key management.
var SSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH key, host-key, and authorized-key management",
	Long: `SSH key, host-key, and authorized-key management.

Transport selection:
  * When XKMSD_URL is set (or the config file has xkmsd_url set) the
    CLI uses the REST transport to talk to xkmsd.
  * Otherwise the CLI uses the embedded transport with a file-backed
    store rooted at ~/.xkey-store/ssh (or whatever the resolved xhome
    directory provides).

Both transports expose the same operations, so scripts written
against one work unchanged against the other.

Examples:
  # Generate an ed25519 key (embedded transport)
  xkey ssh keys generate --scope user --owner alice --name laptop

  # Import an existing key (encrypted PEM — passphrase prompted)
  xkey ssh keys import ~/.ssh/id_ed25519 --scope user --owner alice --name imported

  # Pin a host key fingerprint
  xkey ssh host-keys add --scope user --owner alice \
    --host bastion.example.com --fingerprint SHA256:abc...`,
}

// sshKeysCmd groups key-level subcommands.
var sshKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "SSH key management",
}

var sshKeysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new SSH key",
	RunE:  runSSHKeysGenerate,
}

var sshKeysImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import an existing PEM-encoded SSH private key",
	Args:  cobra.ExactArgs(1),
	RunE:  runSSHKeysImport,
}

var sshKeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SSH keys",
	RunE:    runSSHKeysList,
}

var sshKeysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show metadata for a single SSH key",
	RunE:  runSSHKeysGet,
}

var sshKeysDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete an SSH key",
	RunE:    runSSHKeysDelete,
}

var sshKeysExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print the authorized_keys-format public half",
	RunE:  runSSHKeysExport,
}

// sshHostKeysCmd groups host-key pin subcommands.
var sshHostKeysCmd = &cobra.Command{
	Use:     "host-keys",
	Aliases: []string{"known-hosts"},
	Short:   "SSH host-key pin management",
}

var sshHostKeysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add (pin) a host-key fingerprint",
	RunE:  runSSHHostKeysAdd,
}

var sshHostKeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List pinned host-key fingerprints",
	RunE:    runSSHHostKeysList,
}

var sshHostKeysRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a pinned host-key fingerprint",
	RunE:    runSSHHostKeysRemove,
}

// sshAuthorizedCmd groups authorized_keys subcommands.
var sshAuthorizedCmd = &cobra.Command{
	Use:     "authorized-keys",
	Aliases: []string{"authorized"},
	Short:   "Authorized-key management",
}

var sshAuthorizedAddCmd = &cobra.Command{
	Use:   "add [line]",
	Short: "Add an authorized_keys line",
	Args:  cobra.ExactArgs(1),
	RunE:  runSSHAuthorizedAdd,
}

var sshAuthorizedListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List authorized_keys entries",
	RunE:    runSSHAuthorizedList,
}

var sshAuthorizedRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove an authorized_keys entry",
	RunE:    runSSHAuthorizedRemove,
}

// sshClient resolves the transport and returns an sshsdk.Client along
// with its Close function. The Close returned is always safe to defer;
// it is a no-op on the REST transport.
func sshClient(_ *cobra.Command) (sshsdk.Client, func(), error) {
	url := strings.TrimSpace(os.Getenv("XKMSD_URL"))
	if url == "" {
		url = strings.TrimSpace(viper.GetString("xkmsd_url"))
	}
	if url != "" {
		client, err := sshsdk.NewREST(sshsdk.RESTOptions{
			BaseURL:   url,
			AuthToken: strings.TrimSpace(os.Getenv("XKMSD_TOKEN")),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrSSHClientConstruct, err)
		}
		return client, func() { _ = client.Close() }, nil
	}
	root, err := resolveXKeySSHRoot()
	if err != nil {
		return nil, nil, err
	}
	client, err := sshsdk.NewEmbeddedFile(sshsdk.EmbeddedFileOptions{RootDir: root})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSSHClientConstruct, err)
	}
	return client, func() { _ = client.Close() }, nil
}

// resolveXKeySSHRoot computes the file-backed store location. Uses the
// global resolvedHome when set (consistent with the rest of the xkey
// CLI) and falls back to $HOME/.xkey-store/ssh otherwise. Last-chance
// fallback is the current working directory so CI invocations without
// a stable $HOME still function.
func resolveXKeySSHRoot() (string, error) {
	if resolvedHome != nil {
		return filepath.Join(resolvedHome.DataDir(), "ssh"), nil
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".xkey-store", "ssh"), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", &SSHConfigError{Op: "resolve_store_root", Err: err}
	}
	return filepath.Join(cwd, ".xkey-store", "ssh"), nil
}

// sshPassphraseProvider returns a provider appropriate to the CLI's
// attachment: on a TTY we use TerminalProvider (no echo), elsewhere
// we use StdinProvider (for piped passphrase input in CI).
func sshPassphraseProvider() secure.PassphraseProvider {
	if isStdinTTY() {
		return secure.NewTerminalProvider()
	}
	return secure.NewStdinProvider()
}

// isStdinTTY checks whether stdin is attached to a terminal. Kept as a
// small helper so the transport-selection logic stays readable.
func isStdinTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ---------------------------------------------------------------
// Keys handlers.
// ---------------------------------------------------------------

func runSSHKeysGenerate(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	algo, _ := cmd.Flags().GetString("type")
	bits, _ := cmd.Flags().GetInt("bits")
	comment, _ := cmd.Flags().GetString("comment")

	if name == "" {
		return ErrSSHMissingKeyName
	}
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	if algo == "" {
		algo = "ed25519"
	}
	if !isValidSSHAlgorithm(algo) {
		return fmt.Errorf("%w: %q", ErrSSHInvalidKeyType, algo)
	}

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()

	out, err := client.Keys().Generate(context.Background(), sshsdk.GenerateRequest{
		Scope:     scope,
		Owner:     owner,
		Name:      name,
		Algorithm: algo,
		RSABits:   bits,
		Comment:   comment,
	})
	if err != nil {
		return err
	}
	printGeneratedKey(cmd, out)
	return nil
}

func runSSHKeysImport(cmd *cobra.Command, args []string) error {
	path := args[0]
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	comment, _ := cmd.Flags().GetString("comment")

	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return &SSHConfigError{Op: "read_pem", Err: err}
	}

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()

	provider := sshPassphraseProvider()
	out, err := client.Keys().Import(context.Background(), sshsdk.ImportRequest{
		Scope:   scope,
		Owner:   owner,
		Name:    name,
		Comment: comment,
		PEM:     pemBytes,
	}, provider)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Imported SSH key: %s/%s/%s\n", out.Scope, out.Owner, out.Name)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint: %s\n", out.Fingerprint)
	return nil
}

func runSSHKeysList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()

	list, err := client.Keys().List(context.Background(), sshsdk.ListKeysRequest{
		Scope: scope,
		Owner: owner,
	})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No SSH keys found.")
		return nil
	}
	for _, k := range list {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s/%s/%s  %s  %s\n",
			k.Scope, k.Owner, k.Name, k.Algorithm, k.Fingerprint)
	}
	return nil
}

func runSSHKeysGet(cmd *cobra.Command, _ []string) error {
	scope, owner, name, err := readKeySelector(cmd)
	if err != nil {
		return err
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	out, err := client.Keys().Get(context.Background(), sshsdk.GetKeyRequest{
		Scope: scope, Owner: owner, Name: name,
	})
	if err != nil {
		return err
	}
	printGeneratedKey(cmd, out)
	return nil
}

func runSSHKeysDelete(cmd *cobra.Command, _ []string) error {
	scope, owner, name, err := readKeySelector(cmd)
	if err != nil {
		return err
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	if err := client.Keys().Delete(context.Background(), sshsdk.DeleteKeyRequest{
		Scope: scope, Owner: owner, Name: name,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s/%s/%s\n", scope, owner, name)
	return nil
}

func runSSHKeysExport(cmd *cobra.Command, _ []string) error {
	scope, owner, name, err := readKeySelector(cmd)
	if err != nil {
		return err
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	out, err := client.Keys().ExportPublic(context.Background(), sshsdk.ExportRequest{
		Scope: scope, Owner: owner, Name: name,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), out.Line)
	return nil
}

// ---------------------------------------------------------------
// Host-key handlers.
// ---------------------------------------------------------------

func runSSHHostKeysAdd(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	host, _ := cmd.Flags().GetString("host")
	fp, _ := cmd.Flags().GetString("fingerprint")
	algo, _ := cmd.Flags().GetString("algorithm")
	src, _ := cmd.Flags().GetString("source")

	if host == "" {
		return ErrSSHMissingHost
	}
	if fp == "" {
		return ErrSSHMissingFingerprint
	}
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	if err := client.KnownHosts().Add(context.Background(), sshsdk.AddKnownHostRequest{
		Scope: scope, Owner: owner, Host: host,
		Fingerprint: fp, Algorithm: algo, Source: src,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Pinned %s -> %s\n", host, fp)
	return nil
}

func runSSHHostKeysList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")

	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	list, err := client.KnownHosts().List(context.Background(), sshsdk.ListKnownHostsRequest{
		Scope: scope, Owner: owner,
	})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No host-key pins found.")
		return nil
	}
	for _, p := range list {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s/%s  %s  %s  %s\n", p.Scope, p.Owner, p.Host, p.Fingerprint, p.Algorithm)
	}
	return nil
}

func runSSHHostKeysRemove(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	host, _ := cmd.Flags().GetString("host")
	if host == "" {
		return ErrSSHMissingHost
	}
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	if err := client.KnownHosts().Remove(context.Background(), sshsdk.RemoveKnownHostRequest{
		Scope: scope, Owner: owner, Host: host,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed pin for %s\n", host)
	return nil
}

// ---------------------------------------------------------------
// Authorized-keys handlers.
// ---------------------------------------------------------------

func runSSHAuthorizedAdd(cmd *cobra.Command, args []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	if name == "" {
		return ErrSSHMissingKeyName
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	if err := client.AuthorizedKeys().Add(context.Background(), sshsdk.AddAuthorizedKeyRequest{
		Scope: scope, Owner: owner, Name: name, Line: args[0],
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added authorized entry %s/%s/%s\n", scope, owner, name)
	return nil
}

func runSSHAuthorizedList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	list, err := client.AuthorizedKeys().List(context.Background(), sshsdk.ListAuthorizedKeysRequest{
		Scope: scope, Owner: owner,
	})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No authorized entries.")
		return nil
	}
	for _, e := range list {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), e.Line)
	}
	return nil
}

func runSSHAuthorizedRemove(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHMissingKeyName
	}
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	client, closer, err := sshClient(cmd)
	if err != nil {
		return err
	}
	defer closer()
	if err := client.AuthorizedKeys().Remove(context.Background(), scope, owner, name); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed authorized entry %s/%s/%s\n", scope, owner, name)
	return nil
}

// ---------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------

// readKeySelector pulls scope/owner/name from persistent flags and
// applies defaults. Scope defaults to "user" and owner defaults to the
// current Unix user login.
func readKeySelector(cmd *cobra.Command) (string, string, string, error) {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return "", "", "", ErrSSHMissingKeyName
	}
	if scope == "" {
		scope = "user"
	}
	if owner == "" {
		owner = defaultOwner()
	}
	return scope, owner, name, nil
}

// defaultOwner returns a sensible default owner identifier. We prefer
// the $USER env var, then the Unix login, falling back to "default".
func defaultOwner() string {
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LOGNAME")); v != "" {
		return v
	}
	return "default"
}

// printGeneratedKey emits metadata for a returned *sshsdk.Key.
func printGeneratedKey(cmd *cobra.Command, k *sshsdk.Key) {
	if k == nil {
		return
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Key: %s/%s/%s\n", k.Scope, k.Owner, k.Name)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Algorithm:   %s\n", k.Algorithm)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Fingerprint: %s\n", k.Fingerprint)
	if k.Comment != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Comment:     %s\n", k.Comment)
	}
	if k.PublicKey != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Public:      %s\n", k.PublicKey)
	}
}

// isValidSSHAlgorithm reports whether a is one of the supported SSH
// algorithm identifiers.
func isValidSSHAlgorithm(a string) bool {
	switch a {
	case "ed25519", "rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		return true
	}
	return false
}

// init wires the SSH commands onto the root command tree.
func init() {
	RootCmd.AddCommand(SSHCmd)

	SSHCmd.AddCommand(sshKeysCmd)
	sshKeysCmd.AddCommand(sshKeysGenerateCmd)
	sshKeysCmd.AddCommand(sshKeysImportCmd)
	sshKeysCmd.AddCommand(sshKeysListCmd)
	sshKeysCmd.AddCommand(sshKeysGetCmd)
	sshKeysCmd.AddCommand(sshKeysDeleteCmd)
	sshKeysCmd.AddCommand(sshKeysExportCmd)

	SSHCmd.AddCommand(sshHostKeysCmd)
	sshHostKeysCmd.AddCommand(sshHostKeysAddCmd)
	sshHostKeysCmd.AddCommand(sshHostKeysListCmd)
	sshHostKeysCmd.AddCommand(sshHostKeysRemoveCmd)

	SSHCmd.AddCommand(sshAuthorizedCmd)
	sshAuthorizedCmd.AddCommand(sshAuthorizedAddCmd)
	sshAuthorizedCmd.AddCommand(sshAuthorizedListCmd)
	sshAuthorizedCmd.AddCommand(sshAuthorizedRemoveCmd)

	// Shared selector flags across keys subcommands.
	for _, c := range []*cobra.Command{
		sshKeysGenerateCmd, sshKeysImportCmd, sshKeysListCmd,
		sshKeysGetCmd, sshKeysDeleteCmd, sshKeysExportCmd,
	} {
		c.Flags().String("scope", "", "Scope (tenant|user|service) — defaults to user")
		c.Flags().String("owner", "", "Owner identifier — defaults to $USER")
	}
	sshKeysGenerateCmd.Flags().String("name", "", "Key name (required)")
	sshKeysGenerateCmd.Flags().String("type", "ed25519", "Key algorithm (ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521)")
	sshKeysGenerateCmd.Flags().Int("bits", 0, "RSA key size (default 4096 for rsa)")
	sshKeysGenerateCmd.Flags().String("comment", "", "Free-form key comment")

	sshKeysImportCmd.Flags().String("name", "", "Key name (defaults to the imported file's basename)")
	sshKeysImportCmd.Flags().String("comment", "", "Free-form key comment")

	sshKeysGetCmd.Flags().String("name", "", "Key name (required)")
	sshKeysDeleteCmd.Flags().String("name", "", "Key name (required)")
	sshKeysExportCmd.Flags().String("name", "", "Key name (required)")

	// Host-key flags.
	for _, c := range []*cobra.Command{sshHostKeysAddCmd, sshHostKeysListCmd, sshHostKeysRemoveCmd} {
		c.Flags().String("scope", "", "Scope — defaults to user")
		c.Flags().String("owner", "", "Owner identifier — defaults to $USER")
	}
	sshHostKeysAddCmd.Flags().String("host", "", "Target host (required)")
	sshHostKeysAddCmd.Flags().String("fingerprint", "", "SSH SHA256 fingerprint (required)")
	sshHostKeysAddCmd.Flags().String("algorithm", "", "Host-key algorithm (e.g. ssh-ed25519)")
	sshHostKeysAddCmd.Flags().String("source", "", "Provenance tag (manual, cert, ...)")
	sshHostKeysRemoveCmd.Flags().String("host", "", "Target host (required)")

	// Authorized flags.
	for _, c := range []*cobra.Command{sshAuthorizedAddCmd, sshAuthorizedListCmd, sshAuthorizedRemoveCmd} {
		c.Flags().String("scope", "", "Scope — defaults to user")
		c.Flags().String("owner", "", "Owner identifier — defaults to $USER")
	}
	sshAuthorizedAddCmd.Flags().String("name", "", "Entry name (required)")
	sshAuthorizedRemoveCmd.Flags().String("name", "", "Entry name (required)")
}
