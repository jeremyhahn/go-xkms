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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	sshsdk "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrSSHName is returned when a required --name flag is absent.
var ErrSSHName = errors.New("ssh: --name is required")

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH key management",
	Long: `SSH key management over any protocol.

The transport is selected by the global --protocol / --server flags, so the
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

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.AddCommand(sshKeysCmd)
	sshKeysCmd.AddCommand(sshKeysGenerateCmd, sshKeysListCmd, sshKeysGetCmd, sshKeysExportCmd, sshKeysSignCmd, sshKeysDeleteCmd)

	for _, c := range []*cobra.Command{sshKeysGenerateCmd, sshKeysListCmd, sshKeysGetCmd, sshKeysExportCmd, sshKeysSignCmd, sshKeysDeleteCmd} {
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
