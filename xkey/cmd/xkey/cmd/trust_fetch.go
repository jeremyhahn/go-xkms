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
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Trust fetch / import-platform errors.
var (
	// ErrTrustFetchFailed indicates a CA bundle fetch from a platform node failed.
	ErrTrustFetchFailed = errors.New("trust: platform CA bundle fetch failed")

	// ErrTrustFetchInvalidArgs indicates the user supplied incompatible flags.
	ErrTrustFetchInvalidArgs = errors.New("trust: invalid fetch arguments")

	// ErrTrustImportPlatformFailed indicates the import-platform convenience
	// flow failed. Wraps the underlying fetch / store / install error.
	ErrTrustImportPlatformFailed = errors.New("trust: import-platform failed")

	// ErrTrustHostRequired indicates host:port was not supplied to import-platform.
	ErrTrustHostRequired = errors.New("trust: host:port argument is required")
)

// trustFetchCmd downloads a CA bundle from a go-trusted-platform node using
// SPKI-pinned TLS. The pin is mandatory and must be obtained out-of-band.
var trustFetchCmd = &cobra.Command{
	Use:   "fetch <url>",
	Short: "Fetch a CA bundle from a platform node (SPKI-pinned)",
	Long: `Fetch a CA bundle from a go-trusted-platform REST endpoint and add the
returned certificates to the xKey trust store.

The endpoint is expected to honor the canonical platform contract:
  GET https://<host>:<port>/api/v1/ca/bundle
with Accept: application/x-pem-file (raw PEM) or application/json (the
platform CABundleResponse JSON shape with a base64-encoded "bundle" field).

Trust verification:
  --spki-pin <hex>   Required. Verify the leaf certificate's SPKI SHA-256
                     hash. The pin must be obtained out-of-band via a
                     secure channel (e.g., HSM-attested deployment manifest,
                     signed deploy log, or manual transcription from the
                     server console).

There is NO trust-on-first-use path. Direct fetches always require a pin;
the supported alternatives for first-time bootstrap are:

  1. xkey trust bootstrap     — go-truststrap-mediated trust establishment
                                (DANE/Noise/SPKI/Direct), recommended when
                                a truststrap configuration is provisioned.
  2. xkey trust fetch <url>   — this command, with --spki-pin obtained
                                out-of-band.
  3. xkey trust add <pem>     — manual import after copying the PEM bundle
                                via a secure out-of-band channel
                                (USB stick, signed email, etc.).

Example:
  xkey trust fetch https://cp.example.internal:9443/api/v1/ca/bundle \
      --spki-pin 3a7b...e1 \
      --install-system`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustFetch,
}

// trustImportPlatformCmd is a convenience wrapper that builds the canonical
// /api/v1/ca/bundle URL from a host:port argument and runs the same logic
// as trust fetch.
var trustImportPlatformCmd = &cobra.Command{
	Use:   "import-platform <host:port>",
	Short: "Import a platform node's CA bundle (canonical URL, SPKI-pinned)",
	Long: `Import the CA bundle from a go-trusted-platform node by host:port.

This is a thin convenience wrapper around 'xkey trust fetch'. It builds the
canonical URL https://<host:port>/api/v1/ca/bundle and applies the same
SPKI verification flag (--spki-pin is required).

Use this when scripting bootstrap of newly deployed nodes; use 'fetch' when
the endpoint URL is non-standard.

Example:
  xkey trust import-platform cp.example.internal:9443 --spki-pin 3a7b...e1`,
	Args: cobra.ExactArgs(1),
	RunE: runTrustImportPlatform,
}

func init() {
	registerTrustFetchFlags(trustFetchCmd)
	registerTrustFetchFlags(trustImportPlatformCmd)
	trustCmd.AddCommand(trustFetchCmd, trustImportPlatformCmd)
}

// registerTrustFetchFlags installs the shared flag set on the supplied
// command. Both fetch and import-platform expose the same flags so users
// can copy/paste between them.
func registerTrustFetchFlags(cmd *cobra.Command) {
	cmd.Flags().String("spki-pin", "",
		"SPKI SHA-256 hash (64-char hex) of the server's leaf certificate (required)")
	cmd.Flags().String("purpose", string(truststore.PurposeBootstrapCA),
		"certificate purpose (default: bootstrap-ca)")
	cmd.Flags().String("source", "",
		"override the recorded source (default: \"platform:<host>\")")
	cmd.Flags().Bool("install-system", false,
		"after adding to xKey trust store, install root certificates to OS trust store")
	cmd.Flags().Duration("timeout", xkms.TrustFetcherDefaultTimeout,
		"HTTP transaction timeout")
}

// runTrustFetch executes the fetch subcommand.
func runTrustFetch(cmd *cobra.Command, args []string) error {
	target := args[0]
	return executeTrustFetch(cmd, target)
}

// runTrustImportPlatform builds the canonical URL and delegates to fetch.
func runTrustImportPlatform(cmd *cobra.Command, args []string) error {
	hostPort := strings.TrimSpace(args[0])
	if hostPort == "" {
		return ErrTrustHostRequired
	}
	// Strip an accidental scheme so users can paste either form.
	hostPort = strings.TrimPrefix(hostPort, "https://")
	hostPort = strings.TrimPrefix(hostPort, "http://")
	hostPort = strings.TrimSuffix(hostPort, "/")

	target := "https://" + hostPort + xkms.TrustFetcherDefaultBundlePath
	if _, err := url.Parse(target); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustImportPlatformFailed, Cause: err}
	}
	if err := executeTrustFetch(cmd, target); err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustImportPlatformFailed, Cause: err}
	}
	return nil
}

// executeTrustFetch is the shared implementation. It validates flags,
// performs the HTTP fetch, persists results to the trust store, and
// optionally promotes root certificates to the OS trust store.
func executeTrustFetch(cmd *cobra.Command, target string) error {
	pinFlag, _ := cmd.Flags().GetString("spki-pin")
	purposeStr, _ := cmd.Flags().GetString("purpose")
	sourceStr, _ := cmd.Flags().GetString("source")
	installSystem, _ := cmd.Flags().GetBool("install-system")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	if strings.TrimSpace(pinFlag) == "" {
		return &DetailError{Err: ErrTrustFetchInvalidArgs, Detail: ": --spki-pin is required (no trust-on-first-use path)"}
	}
	if timeout <= 0 {
		timeout = xkms.TrustFetcherDefaultTimeout
	}

	purpose := truststore.PurposeBootstrapCA
	if purposeStr != "" {
		parsed, parseErr := truststore.ParsePurpose(purposeStr)
		if parseErr != nil {
			return &SentinelCauseError{Sentinel: ErrTrustFetchInvalidArgs, Cause: parseErr}
		}
		purpose = parsed
	}

	opts := xkms.TrustFetcherOptions{
		Timeout: timeout,
		SPKIPin: pinFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Fetching CA bundle from %s\n", target)

	bundle, err := xkms.TrustFetcherFetch(ctx, target, opts)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrTrustFetchFailed, Cause: err}
	}

	store, err := openTrustStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	source := sourceStr
	if source == "" {
		source = bundle.Source
	}
	addOpts := &truststore.AddCertificateOptions{
		Purpose: purpose,
		Source:  source,
	}

	added := 0
	skipped := 0
	rootFingerprints := make([]string, 0, len(bundle.Certificates))
	for _, cert := range bundle.Certificates {
		err := store.AddCertificateWithOptions(cert, addOpts)
		switch {
		case err == nil:
			added++
		case errors.Is(err, truststore.ErrCertificateExists):
			skipped++
		default:
			return &SentinelCauseError{Sentinel: ErrTrustFetchFailed, Cause: err}
		}
		// Track the root cert(s) for the optional OS install step.
		if cert.IsCA && certIsSelfSigned(cert.Subject.String(), cert.Issuer.String()) {
			rootFingerprints = append(rootFingerprints, truststore.Fingerprint(cert))
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"Bundle fetched from %s\n  certificates: %d (added: %d, skipped: %d)\n  leaf SPKI:    %s\n",
		target, len(bundle.Certificates), added, skipped, bundle.LeafSPKI)

	if !installSystem {
		return nil
	}

	osStore, err := truststore.NewOSCertStore()
	if err != nil {
		return &DetailError{Err: ErrTrustFetchFailed, Detail: fmt.Sprintf(": OS trust store unavailable: %v", err)}
	}

	for _, fp := range rootFingerprints {
		certs, certsErr := store.Certificates()
		if certsErr != nil {
			return &SentinelCauseError{Sentinel: ErrTrustFetchFailed, Cause: certsErr}
		}
		var found bool
		for _, c := range certs {
			if truststore.Fingerprint(c) != fp {
				continue
			}
			label := "xkey-" + fp[:16]
			if installErr := osStore.Install(c, label); installErr != nil {
				return &DetailError{Err: ErrTrustFetchFailed, Detail: fmt.Sprintf(": OS install failed: %v", installErr)}
			}
			if metaErr := store.SetSystemInstalled(fp, true); metaErr != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: failed to mark %s system-installed: %v\n", fp, metaErr)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(),
				"  installed to OS trust store: %s (%s)\n",
				label, c.Subject.CommonName)
			found = true
			break
		}
		if !found {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"warning: root %s not found in trust store after fetch\n", fp)
		}
	}

	return nil
}

// certIsSelfSigned reports whether a certificate's Subject and Issuer DNs
// are equal, which is the cheap structural check for "this is a root CA".
// We deliberately avoid a full signature verification here because the
// truststore stores roots regardless of cryptographic self-signature; the
// fetcher already gated the leaf via SPKI pinning.
func certIsSelfSigned(subject, issuer string) bool {
	return subject != "" && subject == issuer
}
