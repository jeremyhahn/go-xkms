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
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var keySigningKeyCmd = &cobra.Command{
	Use:   "signing-key",
	Short: "Manage repository signing keys and sign with them",
	Long: `Name the key that signs a repository (set, get, list, delete), see which
key signs it (resolve), and sign release artifacts with that key (sign). A
repository with no binding is signed by the tenant's release signing key.`,
}

var keySigningKeySignCmd = &cobra.Command{
	Use:   "sign <repository> <corim-file>",
	Short: "Sign a release CoRIM with a repository's key",
	Long: `Sign an unsigned CoRIM with the repository's signing key (the tenant's
release key unless the repository names another) and print the base64 signed
CoRIM and the key that signed it. With --out the signed CoRIM is written to
the file instead.

Example:
  xkmsctl key signing-key sign acme/app corim.cbor --out corim.signed.cbor`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		signer := fr.String("signer")
		outPath := fr.String("out")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		corim, err := os.ReadFile(filepath.Clean(args[1]))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadDataFileFailed, Err: err})
			return
		}
		cfg := getConfig()
		req := &client.SignReleaseCoRIMRequest{Repository: args[0], CoRIM: corim, SignerName: signer}
		runClientCall(cfg, "Signing a release CoRIM for "+args[0], ErrSignReleaseCoRIMFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.SignReleaseCoRIM(ctx, req)
		}, func(p *Printer, result any) { printReleaseCoRIM(p, result, outPath) })
	},
}

// printReleaseCoRIM prints the signed CoRIM in base64 with its key, or
// writes the CoRIM to outPath and prints the key.
func printReleaseCoRIM(p *Printer, result any, outPath string) {
	resp, ok := result.(*client.SignReleaseCoRIMResponse)
	if !ok {
		return
	}
	if outPath != "" {
		if err := os.WriteFile(filepath.Clean(outPath), resp.SignedCoRIM, 0o600); err != nil {
			handleError(&WrappedError{Sentinel: ErrSignReleaseCoRIMFailed, Err: err})
			return
		}
		if err := p.PrintMessage("Signed CoRIM written to " + outPath + " with key " + resp.KeyID); err != nil {
			handleError(err)
		}
		return
	}
	if p.format == OutputFormatJSON {
		if err := p.printJSON(map[string]any{
			"signed_corim": base64.StdEncoding.EncodeToString(resp.SignedCoRIM),
			"key_id":       resp.KeyID,
			"backend":      resp.Backend,
		}); err != nil {
			handleError(err)
		}
		return
	}
	if err := p.PrintMessage("Signed with key " + resp.KeyID); err != nil {
		handleError(err)
		return
	}
	if err := p.PrintSignature(base64.StdEncoding.EncodeToString(resp.SignedCoRIM), 0); err != nil {
		handleError(err)
	}
}

var keySigningKeySetCmd = &cobra.Command{
	Use:   "set <repository> <key-id>",
	Short: "Name the key that signs a repository",
	Long: `Bind a repository to a tenant key, so that key signs the repository's
images and CoRIM instead of the release key.

Example:
  xkmsctl key signing-key set acme/app app-key --key-backend pkcs11`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fr := newFlagReader(cmd)
		backend := fr.String("key-backend")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		req := &client.SetAttestationSigningKeyBindingRequest{Repository: args[0], KeyID: args[1], Backend: backend}
		runClientCall(getConfig(), "Binding "+args[0]+" to key "+args[1], ErrSetSigningKeyBindingFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.SetSigningKeyBinding(ctx, req)
		}, printSigningKeyBinding)
	},
}

var keySigningKeyGetCmd = &cobra.Command{
	Use:   "get <repository>",
	Short: "Show a repository's signing-key binding",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		req := &client.GetAttestationSigningKeyBindingRequest{Repository: args[0]}
		runClientCall(getConfig(), "Getting the signing-key binding of "+args[0], ErrGetSigningKeyBindingFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.GetSigningKeyBinding(ctx, req)
		}, printSigningKeyBinding)
	},
}

var keySigningKeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the tenant's signing-key bindings",
	Args:  cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		runClientCall(getConfig(), "Listing signing-key bindings", ErrListSigningKeyBindingsFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.ListSigningKeyBindings(ctx)
		}, printSigningKeyBindings)
	},
}

var keySigningKeyDeleteCmd = &cobra.Command{
	Use:   "delete <repository>",
	Short: "Remove a repository's binding, so the release key signs it again",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		repository := args[0]
		req := &client.DeleteAttestationSigningKeyBindingRequest{Repository: repository}
		runClientCall(getConfig(), "Deleting the signing-key binding of "+repository, ErrDeleteSigningKeyBindingFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return nil, cl.DeleteSigningKeyBinding(ctx, req)
		}, func(p *Printer, _ any) {
			if err := p.PrintMessage("Signing-key binding of " + repository + " deleted; the release key signs it"); err != nil {
				handleError(err)
			}
		})
	},
}

var keySigningKeyResolveCmd = &cobra.Command{
	Use:   "resolve <repository>",
	Short: "Show the key that signs a repository",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		req := &client.ResolveAttestationSigningKeyRequest{Repository: args[0]}
		runClientCall(getConfig(), "Resolving the signing key of "+args[0], ErrResolveSigningKeyFailed, func(ctx context.Context, cl client.Client) (any, error) {
			return cl.ResolveSigningKey(ctx, req)
		}, printSigningKeyResolution)
	},
}

// signingKeyLine renders a repository's key and, when set, its backend.
func signingKeyLine(repository, keyID, backend string) string {
	line := repository + ": key " + keyID
	if backend != "" {
		line += " (backend " + backend + ")"
	}
	return line
}

// printSigningKeyBinding prints one binding.
func printSigningKeyBinding(p *Printer, result any) {
	b, ok := result.(*client.AttestationSigningKeyBinding)
	if !ok {
		return
	}
	var err error
	if p.format == OutputFormatJSON {
		err = p.printJSON(b)
	} else {
		err = p.PrintMessage(signingKeyLine(b.Repository, b.KeyID, b.Backend))
	}
	if err != nil {
		handleError(err)
	}
}

// printSigningKeyBindings prints the tenant's bindings, one per line.
func printSigningKeyBindings(p *Printer, result any) {
	resp, ok := result.(*client.ListAttestationSigningKeyBindingsResponse)
	if !ok {
		return
	}
	if p.format == OutputFormatJSON {
		if err := p.printJSON(resp); err != nil {
			handleError(err)
		}
		return
	}
	if len(resp.Bindings) == 0 {
		if err := p.PrintMessage("No signing-key bindings; the release key signs every repository"); err != nil {
			handleError(err)
		}
		return
	}
	for _, b := range resp.Bindings {
		if err := p.PrintMessage(signingKeyLine(b.Repository, b.KeyID, b.Backend)); err != nil {
			handleError(err)
			return
		}
	}
}

// printSigningKeyResolution prints the key that signs a repository and
// whether it is the release key.
func printSigningKeyResolution(p *Printer, result any) {
	r, ok := result.(*client.AttestationSigningKeyResolution)
	if !ok {
		return
	}
	var err error
	if p.format == OutputFormatJSON {
		err = p.printJSON(r)
	} else {
		line := signingKeyLine(r.Repository, r.KeyID, r.Backend)
		if r.Default {
			line += ", the tenant's release key"
		}
		err = p.PrintMessage(line)
	}
	if err != nil {
		handleError(err)
	}
}

func init() {
	keyCmd.AddCommand(keySigningKeyCmd)
	keySigningKeyCmd.AddCommand(keySigningKeySignCmd, keySigningKeySetCmd, keySigningKeyGetCmd,
		keySigningKeyListCmd, keySigningKeyDeleteCmd, keySigningKeyResolveCmd)
	keySigningKeySetCmd.Flags().String("key-backend", "", "Backend of the key (default: the tenant's default backend)")
	keySigningKeySignCmd.Flags().String("signer", "", "corim-meta signer name (default: the repository)")
	keySigningKeySignCmd.Flags().String("out", "", "Write the signed CoRIM to this file instead of printing it")
}
