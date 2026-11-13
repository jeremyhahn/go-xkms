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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
)

// acmeClient, acmeClientOptions and the factory are shared with the GUI
// ACMEService (xkey/pkg/gui/services/acme_client.go).
type (
	acmeClient        = services.ACMEClient
	acmeClientOptions = services.ACMEClientOptions
)

// newACMEClientFunc builds the client; a package variable so tests can
// replace it.
var newACMEClientFunc = services.NewACMEClient

// loadACMEAccountKey reads a PEM account key; errors name the file only.
var loadACMEAccountKey = services.LoadACMEAccountKey

// acmeFlags holds the persistent flags of xkey acme.
type acmeFlags struct {
	directory    string
	accountKey   string
	trustedRoots []string
	systemRoots  bool
}

func newACMECmd() *cobra.Command {
	flags := &acmeFlags{}
	c := &cobra.Command{
		Use:   "acme",
		Short: "ACME client: account and certificate revocation",
		Long: `Talk to an ACME server (RFC 8555) as a client.

The account is identified by the account key (--account-key); the server
is the source of truth, so no local account state is kept.`,
		SilenceUsage: true,
	}
	pf := c.PersistentFlags()
	pf.StringVar(&flags.directory, "directory", "", "ACME directory URL (required)")
	pf.StringVar(&flags.accountKey, "account-key", "", "PEM private key of the ACME account (required)")
	pf.StringArrayVar(&flags.trustedRoots, "trusted-root", nil, "PEM CA certificate file to trust (repeatable)")
	pf.BoolVar(&flags.systemRoots, "system-roots", false, "also trust the OS root certificates")

	c.AddCommand(newACMEAccountCmd(flags))
	c.AddCommand(newACMERevokeCmd(flags))
	c.AddCommand(newACMERenewCmd(flags))
	c.AddCommand(newACMEEnrollCmd(flags))
	c.AddCommand(newACMEEndorseCmd(flags))
	return c
}

func init() {
	RootCmd.AddCommand(newACMECmd())
}

// clientOptions validates the shared flags and loads the account key and
// trusted roots.
func (f *acmeFlags) clientOptions(c *cobra.Command, contact string) (acmeClientOptions, error) {
	if f.directory == "" {
		return acmeClientOptions{}, errors.New("acme: --directory is required")
	}
	if f.accountKey == "" {
		return acmeClientOptions{}, errors.New("acme: --account-key is required")
	}
	signer, err := loadACMEAccountKey(f.accountKey)
	if err != nil {
		return acmeClientOptions{}, err
	}
	roots := make([]string, 0, len(f.trustedRoots))
	for _, path := range f.trustedRoots {
		data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
		if err != nil {
			return acmeClientOptions{}, fmt.Errorf("acme: trusted root %s: %w", path, err)
		}
		roots = append(roots, string(data))
	}
	return acmeClientOptions{
		DirectoryURL: f.directory,
		Contact:      contact,
		Signer:       signer,
		TrustedRoots: roots,
		SystemRoots:  f.systemRoots,
		Logger:       slog.New(slog.NewTextHandler(c.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn})),
	}, nil
}

// withACMEClient builds the client, runs fn and closes the client.
func (f *acmeFlags) withACMEClient(c *cobra.Command, contact string, fn func(acmeClient) error) (err error) {
	opts, err := f.clientOptions(c, contact)
	if err != nil {
		return err
	}
	client, err := newACMEClientFunc(opts)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := client.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("acme: close client: %w", cerr)
		}
	}()
	return fn(client)
}

// stripMailto removes a leading mailto: so the client adds exactly one.
func stripMailto(contact string) string {
	return strings.TrimPrefix(contact, "mailto:")
}

// printACMEAccount writes the account URL, status and contacts.
func printACMEAccount(c *cobra.Command, account *acme.Account) {
	out := c.OutOrStdout()
	_, _ = fmt.Fprintf(out, "account: %s\n", account.URI)
	_, _ = fmt.Fprintf(out, "status: %s\n", account.Status)
	if len(account.Contact) > 0 {
		_, _ = fmt.Fprintf(out, "contact: %s\n", strings.Join(account.Contact, ", "))
	}
}
