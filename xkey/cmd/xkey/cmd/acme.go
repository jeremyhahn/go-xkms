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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
)

// acmeClient is the part of the sdk/go ACME client the xkey acme verbs
// call. *sdkacme.ACMEClient satisfies it; tests swap in a fake.
type acmeClient interface {
	RegisterAccount() (*acme.Account, error)
	UpdateAccount(ctx context.Context, contacts []string) (*acme.Account, error)
	DeactivateAccount(ctx context.Context) error
	RevokeCertificate(ctx context.Context, cert *x509.Certificate, reason acme.CRLReasonCode) error
	Close() error
}

// acmeClientOptions carries the shared xkey acme flags to the client
// constructor.
type acmeClientOptions struct {
	DirectoryURL string
	Contact      string
	Signer       crypto.Signer
	TrustedRoots []string
	SystemRoots  bool
	Logger       *slog.Logger
}

// acmeClientTimeout bounds each HTTP request to the ACME server.
const acmeClientTimeout = 30 * time.Second

// newACMEClientFunc builds the client; a package variable so tests can
// replace it.
var newACMEClientFunc = newSDKACMEClient

// newSDKACMEClient builds an sdk/go ACME client. The account DAO is in
// memory: the server finds the account again from the account key
// (RFC 8555 7.3.1), so the verbs keep no local state.
func newSDKACMEClient(opts acmeClientOptions) (acmeClient, error) {
	factory, err := sdkacme.NewACMEStorageFactoryFromKVStore(qrdbsdk.NewMemoryKVStore())
	if err != nil {
		return nil, fmt.Errorf("acme: account storage: %w", err)
	}
	accounts, err := factory.AccountDAO()
	if err != nil {
		return nil, fmt.Errorf("acme: account storage: %w", err)
	}
	client, err := sdkacme.NewACMEClient(&sdkacme.ACMEClientParams{
		AccountEmail:  opts.Contact,
		AccountSigner: opts.Signer,
		Logger:        opts.Logger,
		Storage:       accounts,
		Config: &sdkacme.ACMEClientConfig{
			DirectoryURL:   opts.DirectoryURL,
			TrustedRoots:   opts.TrustedRoots,
			SystemCertPool: opts.SystemRoots,
			Timeout:        acmeClientTimeout,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("acme: client: %w", err)
	}
	return client, nil
}

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

// loadACMEAccountKey reads a PEM private key (PKCS#8, SEC 1 EC or PKCS#1).
// Errors name the file, never its content.
func loadACMEAccountKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("acme: account key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("acme: account key %s: no PEM block", path)
	}
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("acme: account key %s: unsupported or malformed %q block", path, block.Type)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("acme: account key %s: key cannot sign", path)
	}
	return signer, nil
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
