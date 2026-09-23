// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	gossh "golang.org/x/crypto/ssh"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Sentinel errors for absent or unusable SSH command inputs.
var (
	// ErrSSHName is returned when a required --name flag is absent.
	ErrSSHName = errors.New("ssh: --name is required")

	// ErrSSHFile is returned when a required --file flag is absent.
	ErrSSHFile = errors.New("ssh: --file is required")

	// ErrSSHHost is returned when a required --host flag is absent.
	ErrSSHHost = errors.New("ssh: --host is required")

	// ErrSSHFingerprint is returned when a required --fingerprint flag
	// is absent.
	ErrSSHFingerprint = errors.New("ssh: --fingerprint is required")

	// ErrSSHLine is returned when a required --line flag is absent.
	ErrSSHLine = errors.New("ssh: --line is required")

	// ErrSSHReadFile is the classifying sentinel for a failed key-file
	// read.
	ErrSSHReadFile = errors.New("ssh: cannot read key file")

	// ErrSSHParsePublicKey is the classifying sentinel for an
	// unparseable authorized_keys line.
	ErrSSHParsePublicKey = errors.New("ssh: cannot parse public key line")
)

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH key management",
	Long: `SSH key management over any protocol.

The transport is selected by the global --transport / --server flags, so the
same commands work over embedded, rest, grpc, quic, mcp, and unix transports.`,
}

var sshKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "SSH key operations",
}

var sshKeysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an SSH key",
	RunE:  runXkmsctlSSHGenerate,
}

var sshKeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SSH keys",
	RunE:    runXkmsctlSSHList,
}

var sshKeysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show a single SSH key",
	RunE:  runXkmsctlSSHGet,
}

var sshKeysExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print the authorized_keys public line",
	RunE:  runXkmsctlSSHExport,
}

var sshKeysSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a digest with an SSH key",
	RunE:  runXkmsctlSSHSign,
}

var sshKeysDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete an SSH key",
	RunE:    runXkmsctlSSHDelete,
}

var sshKeysImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a PEM-encoded private key",
	Long: `Import a PEM-encoded private key into the SSH key store.

Encrypted PEMs are supported: the passphrase is read without echo from the
terminal, or from stdin when the CLI is not attached to one. The plaintext
never lands in a Go string — it is read directly into an enclaved buffer.`,
	RunE: runXkmsctlSSHImport,
}

var sshKnownHostsCmd = &cobra.Command{
	Use:     "known-hosts",
	Aliases: []string{"knownhosts"},
	Short:   "Host-key pin management",
}

var sshKnownHostsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Pin a host key fingerprint",
	RunE:  runXkmsctlSSHKnownHostsAdd,
}

var sshKnownHostsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List pinned host keys",
	RunE:    runXkmsctlSSHKnownHostsList,
}

var sshKnownHostsRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a host-key pin",
	RunE:    runXkmsctlSSHKnownHostsRemove,
}

var sshKnownHostsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a host key against the pin store",
	Long: `Verify a received host key against the pin store.

The key is supplied as an authorized_keys-format line via --key, or read
from a file via --file.`,
	RunE: runXkmsctlSSHKnownHostsVerify,
}

var sshAuthorizedKeysCmd = &cobra.Command{
	Use:     "authorized-keys",
	Aliases: []string{"authorizedkeys"},
	Short:   "authorized_keys entry management",
}

var sshAuthorizedKeysAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an authorized_keys entry",
	RunE:  runXkmsctlSSHAuthorizedAdd,
}

var sshAuthorizedKeysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show a single authorized_keys entry",
	RunE:  runXkmsctlSSHAuthorizedGet,
}

var sshAuthorizedKeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List authorized_keys entries",
	RunE:    runXkmsctlSSHAuthorizedList,
}

var sshAuthorizedKeysRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove an authorized_keys entry",
	RunE:    runXkmsctlSSHAuthorizedRemove,
}

var sshAuthorizedKeysEmitCmd = &cobra.Command{
	Use:   "emit",
	Short: "Format a public key as an authorized_keys line",
	RunE:  runXkmsctlSSHAuthorizedEmit,
}

var sshAuthorizedKeysVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Match a public key against the stored authorized entries",
	RunE:  runXkmsctlSSHAuthorizedVerify,
}

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.AddCommand(sshKeysCmd, sshKnownHostsCmd, sshAuthorizedKeysCmd)
	sshKeysCmd.AddCommand(sshKeysGenerateCmd, sshKeysListCmd, sshKeysGetCmd, sshKeysExportCmd, sshKeysSignCmd, sshKeysDeleteCmd, sshKeysImportCmd)
	sshKnownHostsCmd.AddCommand(sshKnownHostsAddCmd, sshKnownHostsListCmd, sshKnownHostsRemoveCmd, sshKnownHostsVerifyCmd)
	sshAuthorizedKeysCmd.AddCommand(sshAuthorizedKeysAddCmd, sshAuthorizedKeysGetCmd, sshAuthorizedKeysListCmd,
		sshAuthorizedKeysRemoveCmd, sshAuthorizedKeysEmitCmd, sshAuthorizedKeysVerifyCmd)

	// Every SSH command is addressed by (scope, owner); emit is the sole
	// exception because it is a pure formatting helper.
	scoped := []*cobra.Command{
		sshKeysGenerateCmd, sshKeysListCmd, sshKeysGetCmd, sshKeysExportCmd, sshKeysSignCmd, sshKeysDeleteCmd, sshKeysImportCmd,
		sshKnownHostsAddCmd, sshKnownHostsListCmd, sshKnownHostsRemoveCmd, sshKnownHostsVerifyCmd,
		sshAuthorizedKeysAddCmd, sshAuthorizedKeysGetCmd, sshAuthorizedKeysListCmd, sshAuthorizedKeysRemoveCmd, sshAuthorizedKeysVerifyCmd,
	}
	for _, c := range scoped {
		c.Flags().String("scope", "user", "Scope (tenant|user|service)")
		c.Flags().String("owner", "default", "Owner identifier")
	}

	sshKeysGenerateCmd.Flags().String("name", "", "Key name (required)")
	sshKeysGenerateCmd.Flags().String("type", "ed25519", "Algorithm (ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521)")
	sshKeysGenerateCmd.Flags().Int("bits", 0, "RSA key size (RSA only)")
	sshKeysGenerateCmd.Flags().String("comment", "", "Key comment")
	sshKeysGenerateCmd.Flags().String("key-backend", "", "Crypto backend to generate the key on (software, tpm2, pkcs11, cloud)")
	sshKeysGetCmd.Flags().String("name", "", "Key name (required)")
	sshKeysExportCmd.Flags().String("name", "", "Key name (required)")
	sshKeysDeleteCmd.Flags().String("name", "", "Key name (required)")
	sshKeysSignCmd.Flags().String("name", "", "Key name (required)")
	sshKeysSignCmd.Flags().String("data", "xkmsctl-ssh-sign", "Data to sign")
	sshKeysImportCmd.Flags().String("file", "", "Path to the PEM-encoded private key (required)")
	sshKeysImportCmd.Flags().String("name", "", "Key name (defaults to the file base name)")
	sshKeysImportCmd.Flags().String("comment", "", "Key comment")

	sshKnownHostsAddCmd.Flags().String("host", "", "Host address (required)")
	sshKnownHostsAddCmd.Flags().String("fingerprint", "", "OpenSSH SHA256 host-key fingerprint (required)")
	sshKnownHostsAddCmd.Flags().String("algorithm", "", "Host-key algorithm")
	sshKnownHostsAddCmd.Flags().String("source", "xkmsctl", "Provenance of the pin")
	sshKnownHostsRemoveCmd.Flags().String("host", "", "Host address (required)")
	sshKnownHostsVerifyCmd.Flags().String("host", "", "Host address (required)")
	sshKnownHostsVerifyCmd.Flags().String("key", "", "Host key as an authorized_keys-format line")
	sshKnownHostsVerifyCmd.Flags().String("file", "", "Read the host key from a file instead of --key")

	sshAuthorizedKeysAddCmd.Flags().String("name", "", "Entry name (required)")
	sshAuthorizedKeysAddCmd.Flags().String("line", "", "authorized_keys line (required)")
	sshAuthorizedKeysAddCmd.Flags().StringSlice("option", nil, "authorized_keys option (repeatable)")
	sshAuthorizedKeysAddCmd.Flags().String("comment", "", "Entry comment")
	sshAuthorizedKeysGetCmd.Flags().String("name", "", "Entry name (required)")
	sshAuthorizedKeysRemoveCmd.Flags().String("name", "", "Entry name (required)")
	sshAuthorizedKeysEmitCmd.Flags().String("line", "", "Public key as an authorized_keys-format line (required)")
	sshAuthorizedKeysEmitCmd.Flags().StringSlice("option", nil, "authorized_keys option (repeatable)")
	sshAuthorizedKeysEmitCmd.Flags().String("comment", "", "Entry comment")
	sshAuthorizedKeysVerifyCmd.Flags().String("key", "", "Public key as an authorized_keys-format line")
	sshAuthorizedKeysVerifyCmd.Flags().String("file", "", "Read the public key from a file instead of --key")
}

// xkmsctlSSHClient builds the SSH SDK client from the global transport config.
// embedded uses a file-backed store under the key directory; every other
// protocol dispatches by the --server URL scheme.
func xkmsctlSSHClient() (sshsdk.Client, func(), error) {
	cfg := getConfig()
	if cfg.Protocol == "embedded" || (cfg.Server == "" && cfg.Protocol == "") {
		root := filepath.Join(cfg.KeyDir, "ssh")
		c, err := sshsdk.NewEmbeddedFile(sshsdk.EmbeddedFileOptions{RootDir: root})
		if err != nil {
			return nil, nil, err
		}
		return c, func() { _ = c.Close() }, nil
	}
	if strings.TrimSpace(cfg.Server) == "" {
		return nil, nil, errors.New("ssh: --server is required for non-embedded transports")
	}
	c, err := sshsdk.NewClientForServer(cfg.Server, cfg.TLSCACert, cfg.JWTToken)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { _ = c.Close() }, nil
}

func runXkmsctlSSHGenerate(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	algo, _ := cmd.Flags().GetString("type")
	bits, _ := cmd.Flags().GetInt("bits")
	comment, _ := cmd.Flags().GetString("comment")
	backend, _ := cmd.Flags().GetString("key-backend")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	key, err := client.Keys().Generate(context.Background(), sshsdk.GenerateRequest{
		Scope: scope, Owner: owner, Name: name, Algorithm: algo, RSABits: bits, Comment: comment, Backend: backend,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Generated SSH key %q (%s) backend=%s\n%s\n", key.Name, key.Algorithm, key.Backend, key.PublicKey)
	fmt.Printf("Fingerprint: %s\n", key.Fingerprint)
	return nil
}

func runXkmsctlSSHList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	keys, err := client.Keys().List(context.Background(), sshsdk.ListKeysRequest{Scope: scope, Owner: owner})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("No SSH keys found")
		return nil
	}
	for _, k := range keys {
		fmt.Printf("%s\t%s\t%s\tbackend=%s\n", k.Name, k.Algorithm, k.Fingerprint, k.Backend)
	}
	return nil
}

func runXkmsctlSSHGet(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	key, err := client.Keys().Get(context.Background(), sshsdk.GetKeyRequest{Scope: scope, Owner: owner, Name: name})
	if err != nil {
		return err
	}
	fmt.Printf("Name: %s\nAlgorithm: %s\nBackend: %s\nFingerprint: %s\nPublicKey: %s\n", key.Name, key.Algorithm, key.Backend, key.Fingerprint, key.PublicKey)
	return nil
}

func runXkmsctlSSHExport(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	pub, err := client.Keys().ExportPublic(context.Background(), sshsdk.ExportRequest{Scope: scope, Owner: owner, Name: name})
	if err != nil {
		return err
	}
	fmt.Println(pub.Line)
	return nil
}

func runXkmsctlSSHSign(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	data, _ := cmd.Flags().GetString("data")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	signer, err := client.Keys().Signer(context.Background(), sshsdk.GetKeyRequest{Scope: scope, Owner: owner, Name: name})
	if err != nil {
		return err
	}
	sig, err := signer.Sign(rand.Reader, []byte(data))
	if err != nil {
		return err
	}
	fmt.Printf("Format: %s\nSignature: %s\n", sig.Format, base64.StdEncoding.EncodeToString(sig.Blob))
	return nil
}

func runXkmsctlSSHDelete(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.Keys().Delete(context.Background(), sshsdk.DeleteKeyRequest{Scope: scope, Owner: owner, Name: name}); err != nil {
		return err
	}
	fmt.Printf("Deleted SSH key %q\n", name)
	return nil
}

// sshPassphraseProvider returns a provider matched to the CLI's
// attachment: a no-echo terminal read when stdin is a TTY, and a plain
// stdin read otherwise so scripted pipelines can pipe a passphrase in.
// The terminal seams come from prompt.go so tests can drive both paths.
func sshPassphraseProvider() secure.PassphraseProvider {
	if isTerminalFn(secretStdinFd()) {
		return secure.NewTerminalProvider()
	}
	return secure.NewStdinProvider()
}

// sshPublicKeyFromFlags resolves an SSH public key from either the
// --key flag (an authorized_keys-format line) or the --file flag (the
// same line read from disk). Exactly one is required.
func sshPublicKeyFromFlags(cmd *cobra.Command) (gossh.PublicKey, error) {
	line, _ := cmd.Flags().GetString("key")
	path, _ := cmd.Flags().GetString("file")
	if strings.TrimSpace(line) == "" {
		if strings.TrimSpace(path) == "" {
			return nil, ErrSSHLine
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrSSHReadFile, Err: err}
		}
		line = string(data)
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrSSHParsePublicKey, Err: err}
	}
	return pub, nil
}

func runXkmsctlSSHImport(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	comment, _ := cmd.Flags().GetString("comment")
	path, _ := cmd.Flags().GetString("file")
	if strings.TrimSpace(path) == "" {
		return ErrSSHFile
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return &WrappedError{Sentinel: ErrSSHReadFile, Err: err}
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	key, err := client.Keys().Import(context.Background(), sshsdk.ImportRequest{
		Scope: scope, Owner: owner, Name: name, PEM: pem, Comment: comment,
	}, sshPassphraseProvider())
	if err != nil {
		return err
	}
	fmt.Printf("Imported SSH key %q (%s)\nFingerprint: %s\n", key.Name, key.Algorithm, key.Fingerprint)
	return nil
}

func runXkmsctlSSHKnownHostsAdd(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	host, _ := cmd.Flags().GetString("host")
	fingerprint, _ := cmd.Flags().GetString("fingerprint")
	algorithm, _ := cmd.Flags().GetString("algorithm")
	source, _ := cmd.Flags().GetString("source")
	if host == "" {
		return ErrSSHHost
	}
	if fingerprint == "" {
		return ErrSSHFingerprint
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.KnownHosts().Add(context.Background(), sshsdk.AddKnownHostRequest{
		Scope: scope, Owner: owner, Host: host, Fingerprint: fingerprint, Algorithm: algorithm, Source: source,
	}); err != nil {
		return err
	}
	fmt.Printf("Pinned host key for %q\n", host)
	return nil
}

func runXkmsctlSSHKnownHostsList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	pins, err := client.KnownHosts().List(context.Background(), sshsdk.ListKnownHostsRequest{Scope: scope, Owner: owner})
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		fmt.Println("No pinned host keys found")
		return nil
	}
	for _, p := range pins {
		fmt.Printf("%s\t%s\t%s\tsource=%s\n", p.Host, p.Algorithm, p.Fingerprint, p.Source)
	}
	return nil
}

func runXkmsctlSSHKnownHostsRemove(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	host, _ := cmd.Flags().GetString("host")
	if host == "" {
		return ErrSSHHost
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.KnownHosts().Remove(context.Background(), sshsdk.RemoveKnownHostRequest{
		Scope: scope, Owner: owner, Host: host,
	}); err != nil {
		return err
	}
	fmt.Printf("Removed host-key pin for %q\n", host)
	return nil
}

func runXkmsctlSSHKnownHostsVerify(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	host, _ := cmd.Flags().GetString("host")
	if host == "" {
		return ErrSSHHost
	}
	pub, err := sshPublicKeyFromFlags(cmd)
	if err != nil {
		return err
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.KnownHosts().Verify(context.Background(), scope, owner, host, pub); err != nil {
		return err
	}
	fmt.Printf("Host key for %q matches the pin store\n", host)
	return nil
}

func runXkmsctlSSHAuthorizedAdd(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	line, _ := cmd.Flags().GetString("line")
	options, _ := cmd.Flags().GetStringSlice("option")
	comment, _ := cmd.Flags().GetString("comment")
	if name == "" {
		return ErrSSHName
	}
	if strings.TrimSpace(line) == "" {
		return ErrSSHLine
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.AuthorizedKeys().Add(context.Background(), sshsdk.AddAuthorizedKeyRequest{
		Scope: scope, Owner: owner, Name: name, Line: line, Options: options, Comment: comment,
	}); err != nil {
		return err
	}
	fmt.Printf("Added authorized entry %q\n", name)
	return nil
}

func runXkmsctlSSHAuthorizedGet(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	entry, err := client.AuthorizedKeys().Get(context.Background(), scope, owner, name)
	if err != nil {
		return err
	}
	fmt.Printf("Name: %s\nOptions: %s\nComment: %s\nLine: %s\n",
		entry.Name, strings.Join(entry.Options, ","), entry.Comment, entry.Line)
	return nil
}

func runXkmsctlSSHAuthorizedList(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	entries, err := client.AuthorizedKeys().List(context.Background(), sshsdk.ListAuthorizedKeysRequest{Scope: scope, Owner: owner})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No authorized entries found")
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%s\t%s\n", e.Name, e.Line)
	}
	return nil
}

func runXkmsctlSSHAuthorizedRemove(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		return ErrSSHName
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	if err := client.AuthorizedKeys().Remove(context.Background(), scope, owner, name); err != nil {
		return err
	}
	fmt.Printf("Removed authorized entry %q\n", name)
	return nil
}

func runXkmsctlSSHAuthorizedEmit(cmd *cobra.Command, _ []string) error {
	line, _ := cmd.Flags().GetString("line")
	options, _ := cmd.Flags().GetStringSlice("option")
	comment, _ := cmd.Flags().GetString("comment")
	if strings.TrimSpace(line) == "" {
		return ErrSSHLine
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	emitted, err := client.AuthorizedKeys().Emit(context.Background(), sshsdk.EmitRequest{
		PublicKey: line, Options: options, Comment: comment,
	})
	if err != nil {
		return err
	}
	fmt.Println(emitted)
	return nil
}

func runXkmsctlSSHAuthorizedVerify(cmd *cobra.Command, _ []string) error {
	scope, _ := cmd.Flags().GetString("scope")
	owner, _ := cmd.Flags().GetString("owner")
	pub, err := sshPublicKeyFromFlags(cmd)
	if err != nil {
		return err
	}
	client, closer, err := xkmsctlSSHClient()
	if err != nil {
		return err
	}
	defer closer()
	entry, err := client.AuthorizedKeys().Verify(context.Background(), scope, owner, pub)
	if err != nil {
		return err
	}
	fmt.Printf("Authorized as %q\n%s\n", entry.Name, entry.Line)
	return nil
}
