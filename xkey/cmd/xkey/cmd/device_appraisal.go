package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

var (
	// ErrDeviceEvidenceRefused indicates the xkmsd server refused device
	// evidence (an Android key attestation chain or a TPM EK certificate)
	// under the tenant's endorsements, or returned a verdict that did not
	// verify.
	ErrDeviceEvidenceRefused = errors.New("device: server refused the device evidence")

	// ErrDeviceAppraisalFailed indicates the xkmsd server could not be asked
	// to appraise device evidence.
	ErrDeviceAppraisalFailed = errors.New("device: server appraisal failed")
)

// deviceAppraisalTimeout bounds one server appraisal call.
const deviceAppraisalTimeout = 30 * time.Second

// deviceAppraisalClientFactory connects the xkmsd client device evidence is
// appraised through. Tests replace it with a fake client.
var deviceAppraisalClientFactory = getSDKClient

// appraiseAndroidChainRemote asks the configured xkmsd server to appraise the
// Android key attestation chain (DER, leaf first) the command verified
// locally, and prints the server's verdict to out. Without a configured
// server it does nothing: the command keeps its in-process result.
func appraiseAndroidChainRemote(cmd *cobra.Command, out io.Writer, chainDER [][]byte) error {
	return appraiseDeviceEvidenceRemote(cmd, out, func(ctx context.Context, client transport.Client) (*transport.AttestationResult, error) {
		return client.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{ChainDER: chainDER})
	})
}

// appraiseEKCertificateRemote asks the configured xkmsd server to appraise
// the TPM EK certificate (DER) the command verified locally, and prints the
// server's verdict to out. Without a configured server it does nothing.
func appraiseEKCertificateRemote(cmd *cobra.Command, out io.Writer, certDER []byte) error {
	return appraiseDeviceEvidenceRemote(cmd, out, func(ctx context.Context, client transport.Client) (*transport.AttestationResult, error) {
		return client.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{CertificateDER: certDER})
	})
}

// appraiseDeviceEvidenceRemote runs appraise against the configured xkmsd
// server. A server refusal, or a verdict that did not verify, is
// ErrDeviceEvidenceRefused carrying the server's error; any other failure is
// ErrDeviceAppraisalFailed.
func appraiseDeviceEvidenceRemote(
	cmd *cobra.Command,
	out io.Writer,
	appraise func(context.Context, transport.Client) (*transport.AttestationResult, error),
) (err error) {
	if resolveXKMSdURL() == "" {
		return nil
	}

	client, err := deviceAppraisalClientFactory(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), deviceAppraisalTimeout)
	defer cancel()

	result, err := appraise(ctx, client)
	if err != nil {
		if errors.Is(err, transport.ErrEvidenceRefused) {
			printDeviceAppraisal(out, nil)
			return &SentinelCauseError{Sentinel: ErrDeviceEvidenceRefused, Cause: err}
		}
		return &SentinelCauseError{Sentinel: ErrDeviceAppraisalFailed, Cause: err}
	}
	if result == nil {
		return &SentinelCauseError{Sentinel: ErrDeviceAppraisalFailed, Cause: errors.New("server returned no result")}
	}

	printDeviceAppraisal(out, result)
	if !result.Verified {
		return ErrDeviceEvidenceRefused
	}
	return nil
}

// printDeviceAppraisal prints the server's verdict; a nil result is a
// refusal.
func printDeviceAppraisal(out io.Writer, result *transport.AttestationResult) {
	_, _ = fmt.Fprintln(out, "Server Appraisal")
	_, _ = fmt.Fprintln(out, strings.Repeat("=", 70))
	if result == nil || !result.Verified {
		_, _ = fmt.Fprintln(out, "  Verdict:             REFUSED")
	} else {
		_, _ = fmt.Fprintln(out, "  Verdict:             VERIFIED")
	}
	if result != nil {
		if result.TrustAnchor != "" {
			_, _ = fmt.Fprintf(out, "  Trust Anchor:        %s\n", result.TrustAnchor)
		}
		if result.BootState != "" {
			_, _ = fmt.Fprintf(out, "  Boot State:          %s\n", result.BootState)
		}
		if result.KeyOrigin != "" {
			_, _ = fmt.Fprintf(out, "  Key Origin:          %s\n", result.KeyOrigin)
		}
		if result.CryptographicFailure {
			_, _ = fmt.Fprintln(out, "  Cryptographic Failure: yes")
		}
	}
	_, _ = fmt.Fprintln(out)
}
