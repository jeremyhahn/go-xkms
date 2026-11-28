package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// withDeviceAppraisalServer configures an xkmsd URL and routes the device
// appraisal client factory to client, restoring both when t ends.
func withDeviceAppraisalServer(t *testing.T, client transport.Client, err error) {
	t.Helper()
	isolateXKMSdEndpoint(t)
	xkmsdURL = "https://xkmsd.test:8443"
	previous := deviceAppraisalClientFactory
	deviceAppraisalClientFactory = func(*cobra.Command) (transport.Client, error) { return client, err }
	t.Cleanup(func() { deviceAppraisalClientFactory = previous })
}

// newAppraisalClient is a mock SDK client whose attestation appraisal
// service is appraiser.
func newAppraisalClient(appraiser *fakeAttestationAppraisal) *mockSDKClient {
	return &mockSDKClient{baseSDKClient: baseSDKClient{AttestationAppraisalService: appraiser}}
}

func affirmedResult() *transport.AttestationResult {
	return &transport.AttestationResult{
		Verified:    true,
		TrustAnchor: "google-hardware-root",
		BootState:   "verified",
		KeyOrigin:   "generated",
	}
}

func TestAppraiseAndroidChainRemoteSendsTheVerifiedChain(t *testing.T) {
	appraiser := &fakeAttestationAppraisal{result: affirmedResult()}
	client := newAppraisalClient(appraiser)
	withDeviceAppraisalServer(t, client, nil)

	chain := [][]byte{{0x30, 0x01}, {0x30, 0x02}, {0x30, 0x03}}
	var out bytes.Buffer
	if err := appraiseAndroidChainRemote(&cobra.Command{}, &out, chain); err != nil {
		t.Fatalf("appraiseAndroidChainRemote() error = %v", err)
	}

	if len(appraiser.androidRequests) != 1 {
		t.Fatalf("AppraiseAndroidKeyAttestation calls = %d, want 1", len(appraiser.androidRequests))
	}
	sent := appraiser.androidRequests[0].ChainDER
	if len(sent) != len(chain) {
		t.Fatalf("sent chain length = %d, want %d", len(sent), len(chain))
	}
	for i := range chain {
		if !bytes.Equal(sent[i], chain[i]) {
			t.Fatalf("sent chain[%d] = %x, want %x", i, sent[i], chain[i])
		}
	}
	if len(appraiser.ekRequests) != 0 {
		t.Fatalf("AppraiseEKCertificate called %d times, want 0", len(appraiser.ekRequests))
	}
	if !client.closed {
		t.Fatal("the xkmsd client was not closed")
	}
	for _, want := range []string{"Server Appraisal", "VERIFIED", "google-hardware-root", "verified", "generated"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q does not contain %q", out.String(), want)
		}
	}
}

func TestAppraiseAndroidChainRemoteRefusal(t *testing.T) {
	refusal := &appraisal.EvidenceRefusedError{Check: "android_key", Cause: errors.New("chain does not anchor")}
	appraiser := &fakeAttestationAppraisal{err: refusal}
	client := newAppraisalClient(appraiser)
	withDeviceAppraisalServer(t, client, nil)

	var out bytes.Buffer
	err := appraiseAndroidChainRemote(&cobra.Command{}, &out, [][]byte{{0x30, 0x01}})
	if !errors.Is(err, ErrDeviceEvidenceRefused) {
		t.Fatalf("error = %v, want ErrDeviceEvidenceRefused", err)
	}
	if !errors.Is(err, appraisal.ErrEvidenceRefused) {
		t.Fatalf("error = %v, want the server's ErrEvidenceRefused kept as the cause", err)
	}
	if !client.closed {
		t.Fatal("the xkmsd client was not closed")
	}
}

func TestAppraiseAndroidChainRemoteUnverifiedVerdict(t *testing.T) {
	appraiser := &fakeAttestationAppraisal{result: &transport.AttestationResult{Verified: false, CryptographicFailure: true}}
	withDeviceAppraisalServer(t, newAppraisalClient(appraiser), nil)

	var out bytes.Buffer
	err := appraiseAndroidChainRemote(&cobra.Command{}, &out, [][]byte{{0x30, 0x01}})
	if !errors.Is(err, ErrDeviceEvidenceRefused) {
		t.Fatalf("error = %v, want ErrDeviceEvidenceRefused", err)
	}
	if !strings.Contains(out.String(), "REFUSED") {
		t.Fatalf("output %q does not print the refused verdict", out.String())
	}
}

func TestAppraiseAndroidChainRemoteTransportFailure(t *testing.T) {
	appraiser := &fakeAttestationAppraisal{err: errors.New("connection reset")}
	withDeviceAppraisalServer(t, newAppraisalClient(appraiser), nil)

	err := appraiseAndroidChainRemote(&cobra.Command{}, &bytes.Buffer{}, [][]byte{{0x30, 0x01}})
	if !errors.Is(err, ErrDeviceAppraisalFailed) {
		t.Fatalf("error = %v, want ErrDeviceAppraisalFailed", err)
	}
	if errors.Is(err, ErrDeviceEvidenceRefused) {
		t.Fatalf("error = %v: a transport failure is not a refusal", err)
	}
}

func TestAppraiseRemoteConnectFailure(t *testing.T) {
	withDeviceAppraisalServer(t, nil, ErrXKMSdConnectFailed)

	if err := appraiseAndroidChainRemote(&cobra.Command{}, &bytes.Buffer{}, [][]byte{{0x30, 0x01}}); !errors.Is(err, ErrXKMSdConnectFailed) {
		t.Fatalf("android error = %v, want ErrXKMSdConnectFailed", err)
	}
	if err := appraiseEKCertificateRemote(&cobra.Command{}, &bytes.Buffer{}, []byte{0x30, 0x01}); !errors.Is(err, ErrXKMSdConnectFailed) {
		t.Fatalf("ek error = %v, want ErrXKMSdConnectFailed", err)
	}
}

func TestAppraiseEKCertificateRemoteSendsTheCertificate(t *testing.T) {
	result := affirmedResult()
	result.TrustAnchor = "tpm-vendor-root"
	appraiser := &fakeAttestationAppraisal{result: result}
	client := newAppraisalClient(appraiser)
	withDeviceAppraisalServer(t, client, nil)

	der := []byte{0x30, 0x82, 0x01, 0x0a}
	var out bytes.Buffer
	if err := appraiseEKCertificateRemote(&cobra.Command{}, &out, der); err != nil {
		t.Fatalf("appraiseEKCertificateRemote() error = %v", err)
	}

	if len(appraiser.ekRequests) != 1 {
		t.Fatalf("AppraiseEKCertificate calls = %d, want 1", len(appraiser.ekRequests))
	}
	if !bytes.Equal(appraiser.ekRequests[0].CertificateDER, der) {
		t.Fatalf("sent certificate = %x, want %x", appraiser.ekRequests[0].CertificateDER, der)
	}
	if len(appraiser.androidRequests) != 0 {
		t.Fatalf("AppraiseAndroidKeyAttestation called %d times, want 0", len(appraiser.androidRequests))
	}
	if !client.closed {
		t.Fatal("the xkmsd client was not closed")
	}
	for _, want := range []string{"Server Appraisal", "VERIFIED", "tpm-vendor-root"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q does not contain %q", out.String(), want)
		}
	}
}

func TestAppraiseEKCertificateRemoteRefusal(t *testing.T) {
	refusal := &appraisal.EvidenceRefusedError{Check: "ek_certificate", Cause: errors.New("no endorsement")}
	withDeviceAppraisalServer(t, newAppraisalClient(&fakeAttestationAppraisal{err: refusal}), nil)

	err := appraiseEKCertificateRemote(&cobra.Command{}, &bytes.Buffer{}, []byte{0x30, 0x01})
	if !errors.Is(err, ErrDeviceEvidenceRefused) || !errors.Is(err, appraisal.ErrEvidenceRefused) {
		t.Fatalf("error = %v, want ErrDeviceEvidenceRefused with the server's refusal", err)
	}
}

// TestDeviceAppraisalStandaloneMakesNoClientCall pins standalone use: with
// no xkmsd configured, neither appraisal connects or prints anything, so the
// commands keep today's in-process result.
func TestDeviceAppraisalStandaloneMakesNoClientCall(t *testing.T) {
	isolateXKMSdEndpoint(t)
	previous := deviceAppraisalClientFactory
	deviceAppraisalClientFactory = func(*cobra.Command) (transport.Client, error) {
		t.Fatal("a standalone appraisal must not connect to xkmsd")
		return nil, nil
	}
	t.Cleanup(func() { deviceAppraisalClientFactory = previous })

	var out bytes.Buffer
	if err := appraiseAndroidChainRemote(&cobra.Command{}, &out, [][]byte{{0x30, 0x01}}); err != nil {
		t.Fatalf("android error = %v, want nil", err)
	}
	if err := appraiseEKCertificateRemote(&cobra.Command{}, &out, []byte{0x30, 0x01}); err != nil {
		t.Fatalf("ek error = %v, want nil", err)
	}
	if out.Len() != 0 {
		t.Fatalf("standalone output = %q, want none", out.String())
	}
}
