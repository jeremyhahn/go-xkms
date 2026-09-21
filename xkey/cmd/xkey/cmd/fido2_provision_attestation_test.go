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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// The Security Officer PIN used throughout. It is never asserted on in output;
// these tests check that it authorizes provisioning, not that it appears
// anywhere.
const testProvisionSOPIN = "so-pin-provision-1"

// ---------------------------------------------------------------------------
// A conforming attestation CA
// ---------------------------------------------------------------------------

// testAttestationCA is an in-process attestation CA that issues certificates
// meeting the WebAuthn Level 2 §8.2.1 requirements: X.509 v3, Subject-C,
// Subject-O and the literal Subject-OU, Basic Constraints CA:false, and a
// non-critical id-fido-gen-ce-aaguid extension.
//
// The real xkms CA is exercised through the same transport.SignCSR request this
// stands in for; substituting it here is what makes the misissuance cases —
// wrong key, wrong AAGUID — reachable at all, since a correct CA never produces
// them.
type testAttestationCA struct {
	rootKey   *ecdsa.PrivateKey
	rootCert  *x509.Certificate
	interKey  *ecdsa.PrivateKey
	interCert *x509.Certificate
}

// newTestAttestationCA builds a CA, optionally with one intermediate.
func newTestAttestationCA(t *testing.T, withIntermediate bool) *testAttestationCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	ca := &testAttestationCA{rootKey: rootKey, rootCert: rootCert}
	if !withIntermediate {
		return ca
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Attestation Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, interKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("create intermediate certificate: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse intermediate certificate: %v", err)
	}

	ca.interKey = interKey
	ca.interCert = interCert
	return ca
}

// testIssueOptions perturbs issuance so misissuance can be tested.
type testIssueOptions struct {
	// aaguid overrides the AAGUID vouched for. Nil copies the request's.
	aaguid []byte

	// publicKey overrides the certified key. Nil certifies the request's.
	publicKey crypto.PublicKey

	// omitCountry drops the Subject-C attribute §8.2.1 requires.
	omitCountry bool
}

// issue signs a device request and returns the leaf and the issuer chain, both
// PEM, in the shape transport.SignCSRResponse carries them.
func (ca *testAttestationCA) issue(t *testing.T, csrDER []byte, opts testIssueOptions) ([]byte, []byte) {
	t.Helper()

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse device request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("device request signature: %v", err)
	}

	aaguid := opts.aaguid
	if aaguid == nil {
		aaguid = aaguidFromCSR(t, csr)
	}
	extensionValue, err := keybackend.MarshalAAGUIDExtensionValue(aaguid)
	if err != nil {
		t.Fatalf("marshal AAGUID extension: %v", err)
	}

	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Test Attestation Authority"},
		OrganizationalUnit: []string{keybackend.AttestationCertificateOU},
		CommonName:         csr.Subject.CommonName,
	}
	if opts.omitCountry {
		subject.Country = nil
	}

	publicKey := opts.publicKey
	if publicKey == nil {
		publicKey = csr.PublicKey
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       keybackend.OIDFIDOGenCEAAGUID,
			Critical: false,
			Value:    extensionValue,
		}},
	}

	issuerCert, issuerKey := ca.rootCert, ca.rootKey
	if ca.interCert != nil {
		issuerCert, issuerKey = ca.interCert, ca.interKey
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, issuerKey)
	if err != nil {
		t.Fatalf("issue attestation certificate: %v", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	// xkms returns its issuers leaf-to-root, ending with its own trust anchor.
	var chainPEM []byte
	if ca.interCert != nil {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.interCert.Raw})...)
	}
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.rootCert.Raw})...)

	return leafPEM, chainPEM
}

// aaguidFromCSR reads the id-fido-gen-ce-aaguid extension out of a device
// request, so the test CA vouches for exactly what the device asked for.
func aaguidFromCSR(t *testing.T, csr *x509.CertificateRequest) []byte {
	t.Helper()

	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(keybackend.OIDFIDOGenCEAAGUID) {
			continue
		}
		var aaguid []byte
		if _, err := asn1.Unmarshal(ext.Value, &aaguid); err != nil {
			t.Fatalf("decode AAGUID extension: %v", err)
		}
		return aaguid
	}
	t.Fatal("device request carries no id-fido-gen-ce-aaguid extension")
	return nil
}

// ---------------------------------------------------------------------------
// A substitutable CA connection
// ---------------------------------------------------------------------------

// stubAttestationCA stands in for the SDK transport client.
type stubAttestationCA struct {
	sign   func(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error)
	calls  int
	closed bool
}

func (s *stubAttestationCA) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	s.calls++
	return s.sign(ctx, req)
}

func (s *stubAttestationCA) Close() error {
	s.closed = true
	return nil
}

var _ attestationCA = (*stubAttestationCA)(nil)

// The SDK transport client is what the production connector returns, so it must
// satisfy the same narrowed contract the stub does. Stating it here means a
// change to the SDK's SignCSR signature fails the build with a clear cause
// rather than only inside connectAttestationCA.
var _ attestationCA = (transport.Client)(nil)

// useAttestationCA points the command at an in-process CA for one test.
func useAttestationCA(t *testing.T, connect func(cmd *cobra.Command) (attestationCA, error)) {
	t.Helper()
	previous := connectAttestationCA
	connectAttestationCA = connect
	t.Cleanup(func() { connectAttestationCA = previous })
}

// ---------------------------------------------------------------------------
// Device fixtures
// ---------------------------------------------------------------------------

// newProvisioningDevice points the FIDO2 storage at an isolated directory and
// returns its path.
func newProvisioningDevice(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	previousType := viper.GetString("fido2.storage")
	previousPath := viper.GetString("fido2.storage_path")
	previousFormat := viper.GetString("fido2.attestation")

	viper.Set("fido2.storage", string(FIDO2StorageTypeFile))
	viper.Set("fido2.storage_path", dir)
	viper.Set("fido2.attestation", keybackend.AttestationFormatPacked)

	t.Cleanup(func() {
		viper.Set("fido2.storage", previousType)
		viper.Set("fido2.storage_path", previousPath)
		viper.Set("fido2.attestation", previousFormat)
	})
	return dir
}

// openTestDevice opens the device state the command operates on.
func openTestDevice(t *testing.T) (*authenticator.Authenticator, authenticator.StatefulCredentialStorage) {
	t.Helper()

	storage, err := createFIDO2Storage(buildFIDO2Config(), discardLogger())
	if err != nil {
		t.Fatalf("open device storage: %v", err)
	}

	// The presence handler is required; auto-grant stands in for the human
	// the interactive handler would ask, so the SO ceremony under test —
	// PIN-gated vendor commands — is exercised without a terminal.
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             storage,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	if err != nil {
		_ = storage.Close()
		t.Fatalf("open device: %v", err)
	}
	return auth, storage
}

// setDeviceSOPIN initializes the device's Security Officer PIN through the same
// vendor command a Security Officer's tooling uses.
func setDeviceSOPIN(t *testing.T) {
	t.Helper()

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	if _, err := sendVendorCommand(auth, authenticator.VendorCmdSetSOPIN, map[string]interface{}{
		"pin": testProvisionSOPIN,
	}); err != nil {
		t.Fatalf("initialize SO PIN: %v", err)
	}
}

// deviceState reads the device's persisted state.
func deviceState(t *testing.T) *authenticator.AuthenticatorState {
	t.Helper()

	storage, err := createFIDO2Storage(buildFIDO2Config(), discardLogger())
	if err != nil {
		t.Fatalf("open device storage: %v", err)
	}
	defer func() { _ = storage.Close() }()

	state, err := storage.LoadState()
	if err != nil {
		t.Fatalf("load device state: %v", err)
	}
	return state
}

// attestationKeyFingerprint identifies the attestation key the device currently
// holds, or nil when it holds none.
//
// Initializing the Security Officer PIN already generates an attestation key
// (KeyManager.InitializeSOPIN), so the presence of a key proves nothing about
// provisioning. What a failed attempt must not do is *replace* the key the
// device had, because replacing it discards any certificate issued for it.
func attestationKeyFingerprint(t *testing.T) []byte {
	t.Helper()

	pub := deviceAttestationPublicKey(t)
	if pub == nil {
		return nil
	}
	encoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal attestation public key: %v", err)
	}
	return encoded
}

// deviceAttestationPublicKey resolves the public half of the attestation key
// the device currently holds, or nil when it holds none. The persisted state
// deliberately carries only wrapped copies of the key, so the only path to it
// is the SO-unlocked key manager — the same path reportAttestationState uses.
func deviceAttestationPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	if !auth.IsTokenInitialized() {
		return nil
	}
	if _, err := sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
		"pin": testProvisionSOPIN,
	}); err != nil {
		t.Fatalf("unlock SO: %v", err)
	}

	signer, err := auth.GetKeyManager().AttestationSigner()
	if err != nil {
		if errors.Is(err, authenticator.ErrKeyManagerNoAttestKey) {
			return nil
		}
		t.Fatalf("resolve attestation signer: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("attestation public key is %T, want *ecdsa.PublicKey", signer.Public())
	}
	return pub
}

// ---------------------------------------------------------------------------
// Command invocation
// ---------------------------------------------------------------------------

// resetProvisionAttestationFlags restores the command's flags between runs.
// Cobra retains flag state across Execute calls in one process.
func resetProvisionAttestationFlags() {
	for _, fs := range []*pflag.FlagSet{
		fido2Cmd.Flags(),
		fido2Cmd.PersistentFlags(),
		fido2ProvisionAttestationCmd.Flags(),
	} {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

// absentSocketPath names a socket no daemon listens on, so the liveness check
// resolves to "not running" without depending on what is running on the host.
func absentSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent.sock")
}

// runProvisionAttestation drives the real CLI against a socket no daemon is
// listening on: root command, real argument parsing, real SO PIN prompt fed
// from piped stdin.
func runProvisionAttestation(t *testing.T, extraArgs ...string) (string, error) {
	t.Helper()
	return runProvisionAttestationAs(t, testProvisionSOPIN, absentSocketPath(t), extraArgs...)
}

// runProvisionAttestationAs drives the CLI with a chosen Security Officer PIN
// against a chosen daemon socket, so the authentication and daemon-liveness
// paths are exercised through the same invocation everything else uses.
func runProvisionAttestationAs(t *testing.T, soPIN, socketPath string, extraArgs ...string) (string, error) {
	t.Helper()

	resetProvisionAttestationFlags()

	restoreStdin := setPINStdin(strings.NewReader(soPIN + "\n"))
	previousTerminal := pinInputIsTerminal
	pinInputIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		restoreStdin()
		pinInputIsTerminal = previousTerminal
	})

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	t.Cleanup(func() {
		RootCmd.SetOut(os.Stdout)
		RootCmd.SetErr(os.Stderr)
		RootCmd.SetArgs(nil)
	})

	args := append([]string{"fido2", "provision-attestation", "--socket", socketPath}, extraArgs...)
	RootCmd.SetArgs(args)

	err := RootCmd.Execute()
	return buf.String(), err
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// TestProvisionAttestation_ProvisionsAnUnprovisionedDevice is the acceptance
// case: an unprovisioned device is given an attestation identity, and the very
// next MakeCredential presents a packed statement with a chain reaching the
// operator's root. Before this command existed the same registration produced
// fmt "none", because nothing ever installed a key.
func TestProvisionAttestation_ProvisionsAnUnprovisionedDevice(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	stub := &stubAttestationCA{
		sign: func(_ context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
			block, _ := pem.Decode(req.CSRPEM)
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Fatalf("CA received %q, want a PEM certificate request", req.CSRPEM)
			}
			certPEM, chainPEM := ca.issue(t, block.Bytes, testIssueOptions{})
			return &transport.SignCSRResponse{CertificatePEM: certPEM, ChainPEM: chainPEM}, nil
		},
	}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	output, err := runProvisionAttestation(t)
	if err != nil {
		t.Fatalf("provision-attestation: %v (output: %s)", err, output)
	}

	if stub.calls != 1 {
		t.Errorf("CA called %d times, want 1", stub.calls)
	}
	if !stub.closed {
		t.Error("the CA connection was not closed")
	}

	state := deviceState(t)
	if len(state.AttestationCert) == 0 {
		t.Fatal("no attestation certificate was stored")
	}
	deviceKey := deviceAttestationPublicKey(t)
	if deviceKey == nil {
		t.Fatal("no attestation key was stored")
	}

	leaf, parseErr := x509.ParseCertificate(state.AttestationCert)
	if parseErr != nil {
		t.Fatalf("parse stored certificate: %v", parseErr)
	}
	if !deviceKey.Equal(leaf.PublicKey) {
		t.Error("the stored certificate does not certify the device's attestation key")
	}
	if err := keybackend.ValidateAttestationCertificate(leaf, state.AAGUID[:]); err != nil {
		t.Errorf("stored certificate is not §8.2.1 conforming: %v", err)
	}

	// The single-tier CA's own certificate is the root, so it is not carried in
	// x5c; the relying party is configured to trust it out of band.
	if len(state.AttestationCertChain) != 0 {
		t.Errorf("stored %d intermediates, want 0 for a single-tier CA", len(state.AttestationCertChain))
	}

	for _, want := range []string{
		"Attestation: provisioned",
		formatAAGUID(state.AAGUID),
		"Test Attestation Root",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q, got:\n%s", want, output)
		}
	}

	// The identity is live: a registration now carries provenance.
	format, x5c := makeCredentialAttestation(t)
	if format != keybackend.AttestationFormatPacked {
		t.Fatalf("attestation format = %q, want %q", format, keybackend.AttestationFormatPacked)
	}
	if len(x5c) == 0 {
		t.Fatal("packed attestation carried no x5c chain")
	}
	assertChainsToRoot(t, x5c, ca.rootCert)
}

// TestProvisionAttestation_InstallsAnIntermediateChain verifies the issuer
// chain is carried onto the device leaf-first and the trust anchor is dropped,
// which is what WebAuthn Level 2 §8.2 x5c is.
func TestProvisionAttestation_InstallsAnIntermediateChain(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, true)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}, nil
	})

	output, err := runProvisionAttestation(t)
	if err != nil {
		t.Fatalf("provision-attestation: %v (output: %s)", err, output)
	}

	state := deviceState(t)
	if len(state.AttestationCertChain) != 1 {
		t.Fatalf("stored %d intermediates, want 1", len(state.AttestationCertChain))
	}
	stored, parseErr := x509.ParseCertificate(state.AttestationCertChain[0])
	if parseErr != nil {
		t.Fatalf("parse stored intermediate: %v", parseErr)
	}
	if !stored.Equal(ca.interCert) {
		t.Error("the stored intermediate is not the CA's intermediate")
	}
	if !strings.Contains(output, "Intermediates: 1") {
		t.Errorf("output does not report the intermediate, got:\n%s", output)
	}

	format, x5c := makeCredentialAttestation(t)
	if format != keybackend.AttestationFormatPacked {
		t.Fatalf("attestation format = %q, want %q", format, keybackend.AttestationFormatPacked)
	}
	if len(x5c) != 2 {
		t.Fatalf("x5c carried %d certificates, want leaf + intermediate", len(x5c))
	}
	assertChainsToRoot(t, x5c, ca.rootCert)
}

// ---------------------------------------------------------------------------
// The CA-unreachable failure mode
// ---------------------------------------------------------------------------

// TestProvisionAttestation_UnreachableCALeavesDeviceUnprovisioned is the
// failure mode that matters: a device that can neither attest nor fall back is
// unusable, so an unreachable CA must leave it exactly as it was — no key, no
// certificate, still registering with "none".
func TestProvisionAttestation_UnreachableCALeavesDeviceUnprovisioned(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	keyBefore := attestationKeyFingerprint(t)

	dialFailure := errors.New("dial tcp 127.0.0.1:8443: connect: connection refused")
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return nil, dialFailure
	})

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("provision-attestation succeeded with no CA (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionCAUnreachable) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCAUnreachable)
	}
	if !errors.Is(err, dialFailure) {
		t.Errorf("error = %v, want the dial failure preserved", err)
	}

	if len(deviceState(t).AttestationCert) != 0 {
		t.Error("an attestation certificate was stored even though the CA was unreachable")
	}
	if !bytes.Equal(attestationKeyFingerprint(t), keyBefore) {
		t.Error("the device's attestation key was replaced even though the CA was unreachable")
	}

	format, _ := makeCredentialAttestation(t)
	if format != "none" {
		t.Errorf("attestation format = %q, want %q so the device still registers", format, "none")
	}
}

// TestProvisionAttestation_CARefusalLeavesDeviceUnattested covers the CA that
// answers and then declines. The device has generated a key by then — that is
// unavoidable, because the CA signs a key the device already holds — so the
// requirement is the weaker but sufficient one: no certificate is installed, so
// the device still registers, unattested, rather than presenting a statement no
// relying party can verify.
func TestProvisionAttestation_CARefusalLeavesDeviceUnattested(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	refusal := errors.New("policy: device is not enrolled")
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{
			sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
				return nil, refusal
			},
		}, nil
	})

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("provision-attestation succeeded against a refusing CA (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionCARefused) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCARefused)
	}

	state := deviceState(t)
	if len(state.AttestationCert) != 0 {
		t.Error("a certificate was installed even though the CA refused")
	}

	format, _ := makeCredentialAttestation(t)
	if format != "none" {
		t.Errorf("attestation format = %q, want %q so the device still registers", format, "none")
	}
}

// TestProvisionAttestation_RetryAfterCAFailureSucceeds proves the device is not
// wedged by a failed attempt: the key-without-certificate state an interrupted
// run leaves behind is resumable without --rotate, because nothing was ever
// certified under that key.
func TestProvisionAttestation_RetryAfterCAFailureSucceeds(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{
			sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
				return nil, errors.New("CA is down")
			},
		}, nil
	})
	if _, err := runProvisionAttestation(t); err == nil {
		t.Fatal("expected the first attempt to fail")
	}

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}, nil
	})

	output, err := runProvisionAttestation(t)
	if err != nil {
		t.Fatalf("retry after a CA failure: %v (output: %s)", err, output)
	}
	if len(deviceState(t).AttestationCert) == 0 {
		t.Error("the retry installed no certificate")
	}
}

// ---------------------------------------------------------------------------
// Misissuance is refused at install
// ---------------------------------------------------------------------------

// TestProvisionAttestation_RefusesCertificateForAnotherKey verifies a
// certificate that certifies some other key is refused while the operator is
// watching, rather than silently disabling attestation at first registration.
func TestProvisionAttestation_RefusesCertificateForAnotherKey(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{
			sign: signWithTestCA(t, ca, testIssueOptions{publicKey: otherKey.Public()}),
		}, nil
	})

	output, runErr := runProvisionAttestation(t)
	if runErr == nil {
		t.Fatalf("a certificate for an unrelated key was accepted (output: %s)", output)
	}
	if !errors.Is(runErr, ErrAttestProvisionInstallFailed) {
		t.Errorf("error = %v, want wrapped %v", runErr, ErrAttestProvisionInstallFailed)
	}
	if !errors.Is(runErr, authenticator.ErrAttestationCertNotIssuedForKey) {
		t.Errorf("error = %v, want the device's key-agreement refusal preserved", runErr)
	}
	if len(deviceState(t).AttestationCert) != 0 {
		t.Error("the mismatched certificate was stored")
	}
}

// TestProvisionAttestation_RefusesCertificateWithWrongAAGUID verifies the
// id-fido-gen-ce-aaguid binding is checked at install. A leaf vouching for a
// different model is what a relying party's allowlist keys on, so accepting it
// would produce registrations no policy could evaluate.
func TestProvisionAttestation_RefusesCertificateWithWrongAAGUID(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	wrongAAGUID := make([]byte, 16)
	for i := range wrongAAGUID {
		wrongAAGUID[i] = byte(i + 1)
	}

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{aaguid: wrongAAGUID})}, nil
	})

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("a certificate vouching for another AAGUID was accepted (output: %s)", output)
	}
	if !errors.Is(err, keybackend.ErrAttestationAAGUIDMismatch) {
		t.Errorf("error = %v, want wrapped %v", err, keybackend.ErrAttestationAAGUIDMismatch)
	}
	if len(deviceState(t).AttestationCert) != 0 {
		t.Error("the mismatched certificate was stored")
	}
}

// TestProvisionAttestation_RefusesNonConformingCertificate verifies the §8.2.1
// subject requirements are enforced at install. The check matters because the
// certificate reaches a relying party unchanged.
func TestProvisionAttestation_RefusesNonConformingCertificate(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{omitCountry: true})}, nil
	})

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("a certificate with no Subject-C was accepted (output: %s)", output)
	}
	if !errors.Is(err, keybackend.ErrAttestationCertInvalid) {
		t.Errorf("error = %v, want wrapped %v", err, keybackend.ErrAttestationCertInvalid)
	}
	if len(deviceState(t).AttestationCert) != 0 {
		t.Error("the non-conforming certificate was stored")
	}
}

// TestProvisionAttestation_RefusesEmptyCAResponse verifies a CA that answers
// with no certificate is an error rather than a silent no-op.
func TestProvisionAttestation_RefusesEmptyCAResponse(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{
			sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
				return &transport.SignCSRResponse{}, nil
			},
		}, nil
	})

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("an empty CA response was accepted (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionCARefused) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCARefused)
	}
	if len(deviceState(t).AttestationCert) != 0 {
		t.Error("a certificate was stored from an empty response")
	}
}

// ---------------------------------------------------------------------------
// Re-provisioning
// ---------------------------------------------------------------------------

// TestProvisionAttestation_RefusesToReplaceAnInstalledIdentity is the
// re-provisioning decision: a device that already attests is not silently
// rotated, because every statement it has issued was signed by the key rotation
// would discard.
func TestProvisionAttestation_RefusesToReplaceAnInstalledIdentity(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	stub := &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	if _, err := runProvisionAttestation(t); err != nil {
		t.Fatalf("first provisioning: %v", err)
	}
	installed := deviceState(t).AttestationCert
	callsAfterFirst := stub.calls

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("a provisioned device was re-provisioned without --rotate (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionAlreadyProvisioned) {
		t.Errorf("error = %v, want %v", err, ErrAttestProvisionAlreadyProvisioned)
	}
	if stub.calls != callsAfterFirst {
		t.Error("the CA was contacted for a refused re-provisioning")
	}
	if !bytes.Equal(deviceState(t).AttestationCert, installed) {
		t.Error("the installed certificate changed on a refused re-provisioning")
	}
}

// TestProvisionAttestation_RotateReplacesTheIdentity verifies --rotate is the
// deliberate opt-in that replaces the key and the certificate together.
func TestProvisionAttestation_RotateReplacesTheIdentity(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}, nil
	})

	if _, err := runProvisionAttestation(t); err != nil {
		t.Fatalf("first provisioning: %v", err)
	}
	first := deviceState(t)
	firstCert := append([]byte(nil), first.AttestationCert...)
	firstKey := deviceAttestationPublicKey(t)

	output, err := runProvisionAttestation(t, "--rotate")
	if err != nil {
		t.Fatalf("rotate: %v (output: %s)", err, output)
	}
	if !strings.Contains(output, "Replacing this device's attestation identity") {
		t.Errorf("rotation did not warn about the invalidated statements, got:\n%s", output)
	}

	second := deviceState(t)
	secondKey := deviceAttestationPublicKey(t)
	if bytes.Equal(second.AttestationCert, firstCert) {
		t.Error("--rotate did not replace the certificate")
	}
	if secondKey.Equal(firstKey) {
		t.Error("--rotate did not replace the attestation key")
	}

	leaf, parseErr := x509.ParseCertificate(second.AttestationCert)
	if parseErr != nil {
		t.Fatalf("parse rotated certificate: %v", parseErr)
	}
	if !secondKey.Equal(leaf.PublicKey) {
		t.Error("the rotated certificate does not certify the rotated key")
	}
}

// ---------------------------------------------------------------------------
// Security Officer gating
// ---------------------------------------------------------------------------

// TestProvisionAttestation_RequiresASecurityOfficerPIN verifies a device with
// no SO PIN cannot be provisioned, and says why.
func TestProvisionAttestation_RequiresASecurityOfficerPIN(t *testing.T) {
	newProvisioningDevice(t)

	stub := &stubAttestationCA{
		sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
			t.Fatal("the CA was contacted for an unauthorized device")
			return nil, nil
		},
	}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("provisioning succeeded with no SO PIN set (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionSOPINNotSet) {
		t.Errorf("error = %v, want %v", err, ErrAttestProvisionSOPINNotSet)
	}
	if stub.calls != 0 {
		t.Error("the CA was contacted before Security Officer authentication")
	}
}

// TestProvisionAttestation_RefusesAWrongSecurityOfficerPIN verifies the wrong
// PIN neither provisions nor reaches the CA, and that the PIN is not echoed
// into the error or the output.
func TestProvisionAttestation_RefusesAWrongSecurityOfficerPIN(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	keyBefore := attestationKeyFingerprint(t)

	stub := &stubAttestationCA{
		sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
			t.Fatal("the CA was contacted after a failed SO authentication")
			return nil, nil
		},
	}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	const wrongPIN = "definitely-not-the-so-pin"
	output, err := runProvisionAttestationAs(t, wrongPIN, absentSocketPath(t))
	if err == nil {
		t.Fatal("provisioning succeeded with the wrong SO PIN")
	}
	if !errors.Is(err, ErrAttestProvisionSOAuthFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionSOAuthFailed)
	}
	if strings.Contains(err.Error(), wrongPIN) || strings.Contains(output, wrongPIN) {
		t.Error("the supplied PIN leaked into the error or the output")
	}
	if stub.calls != 0 {
		t.Error("the CA was contacted after a failed SO authentication")
	}
	if !bytes.Equal(attestationKeyFingerprint(t), keyBefore) {
		t.Error("the device's attestation key was replaced without SO authentication")
	}
}

// ---------------------------------------------------------------------------
// Preconditions that would produce a half-provisioned device
// ---------------------------------------------------------------------------

// TestProvisionAttestation_RefusesVolatileStorage verifies memory storage is
// refused. An identity written there is discarded with the process, so the
// operator would be told the device was provisioned and it would still register
// unattested.
func TestProvisionAttestation_RefusesVolatileStorage(t *testing.T) {
	newProvisioningDevice(t)
	viper.Set("fido2.storage", string(FIDO2StorageTypeMemory))

	stub := &stubAttestationCA{
		sign: func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
			t.Fatal("the CA was contacted for a volatile device")
			return nil, nil
		},
	}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	output, err := runProvisionAttestation(t)
	if err == nil {
		t.Fatalf("provisioning succeeded against memory storage (output: %s)", output)
	}
	if !errors.Is(err, ErrAttestProvisionVolatileStorage) {
		t.Errorf("error = %v, want %v", err, ErrAttestProvisionVolatileStorage)
	}
	if stub.calls != 0 {
		t.Error("the CA was contacted for a volatile device")
	}
}

// TestProvisionAttestation_RefusesWhileTheDaemonRuns verifies a running daemon
// blocks provisioning. The daemon owns the state in memory and writes it back
// on its next change, so an identity installed underneath it would be silently
// discarded.
func TestProvisionAttestation_RefusesWhileTheDaemonRuns(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	socketPath := startFakeFIDO2Daemon(t)
	keyBefore := attestationKeyFingerprint(t)

	// The CA would issue happily. Only the daemon check stands between this
	// invocation and a device provisioned underneath a running daemon, so a
	// missing check shows up as a success rather than as some other refusal.
	ca := newTestAttestationCA(t, false)
	stub := &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) { return stub, nil })

	output, err := runProvisionAttestationAs(t, testProvisionSOPIN, socketPath)
	if err == nil {
		t.Fatalf("provisioning succeeded while the daemon was running (output: %s)", output)
	}
	if !errors.Is(err, ErrFIDO2DaemonRunning) {
		t.Errorf("error = %v, want %v", err, ErrFIDO2DaemonRunning)
	}
	if stub.calls != 0 {
		t.Error("the CA was contacted while the daemon was running")
	}
	if !bytes.Equal(attestationKeyFingerprint(t), keyBefore) {
		t.Error("the device's attestation key was replaced while the daemon was running")
	}
}

// TestFIDO2DaemonRunning_AbsentSocketIsNotRunning verifies the liveness check
// reads a missing socket as "not running" rather than as an error, which is
// what lets provisioning proceed on a host where the daemon is stopped.
func TestFIDO2DaemonRunning_AbsentSocketIsNotRunning(t *testing.T) {
	running, err := fido2DaemonRunning(absentSocketPath(t))
	if err != nil {
		t.Fatalf("fido2DaemonRunning: %v", err)
	}
	if running {
		t.Error("an absent socket was reported as a running daemon")
	}
}

// TestFIDO2DaemonRunning_ListeningSocketIsRunning verifies a daemon answering
// on the socket is detected.
func TestFIDO2DaemonRunning_ListeningSocketIsRunning(t *testing.T) {
	running, err := fido2DaemonRunning(startFakeFIDO2Daemon(t))
	if err != nil {
		t.Fatalf("fido2DaemonRunning: %v", err)
	}
	if !running {
		t.Error("a listening daemon was reported as absent")
	}
}

// TestFIDO2DaemonRunning_AnUnanswerableProbeIsAnError verifies a probe that
// fails for any reason other than "no daemon" is an error rather than a silent
// "not running". Provisioning past an unanswered question is how a device ends
// up with an identity a live daemon then overwrites.
func TestFIDO2DaemonRunning_AnUnanswerableProbeIsAnError(t *testing.T) {
	socketPath := startUnresponsiveFIDO2Daemon(t)

	running, err := fido2DaemonRunning(socketPath)
	if err == nil {
		t.Fatal("an unanswerable probe was reported as a clean result")
	}
	if !errors.Is(err, ErrFIDO2DaemonCheckFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrFIDO2DaemonCheckFailed)
	}
	if running {
		t.Error("an unanswerable probe reported a running daemon")
	}
}

// startUnresponsiveFIDO2Daemon accepts connections and hangs up without
// answering, which is neither "no daemon" nor a usable reply.
func startUnresponsiveFIDO2Daemon(t *testing.T) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "xkey.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", socketPath, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return socketPath
}

// startFakeFIDO2Daemon listens on a Unix socket and answers the IPC status
// message the way the daemon does, so the liveness check is exercised over a
// real connection rather than a substituted predicate.
func startFakeFIDO2Daemon(t *testing.T) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "xkey.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", socketPath, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var msg ipc.Message
			if decodeErr := json.NewDecoder(conn).Decode(&msg); decodeErr == nil {
				_ = json.NewEncoder(conn).Encode(ipc.OKResponse(ipc.ActionDaemonReady))
			}
			_ = conn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return socketPath
}

// ---------------------------------------------------------------------------
// Command shape
// ---------------------------------------------------------------------------

// TestProvisionAttestationCmd_Shape pins the command's registration and flags.
// The other tests drive the command through the root command by name, so a
// rename or a dropped flag would turn them into tests of a command that no
// longer exists.
func TestProvisionAttestationCmd_Shape(t *testing.T) {
	var found *cobra.Command
	for _, sub := range fido2Cmd.Commands() {
		if sub.Name() == "provision-attestation" {
			found = sub
		}
	}
	if found == nil {
		t.Fatal("provision-attestation is not registered under fido2")
	}
	if found != fido2ProvisionAttestationCmd {
		t.Fatal("a different command is registered as provision-attestation")
	}

	wantFlags := map[string]string{
		"rotate":        "false",
		"profile":       "",
		"validity-days": "0",
		"socket":        "",
		tlsCAFlagName:   "",
	}
	for name, want := range wantFlags {
		flag := found.Flags().Lookup(name)
		if flag == nil {
			t.Errorf("flag --%s is not declared", name)
			continue
		}
		if flag.DefValue != want {
			t.Errorf("flag --%s default = %q, want %q", name, flag.DefValue, want)
		}
	}
}

// TestProvisionAttestation_ForwardsProfileAndValidityToTheCA verifies the
// issuance flags reach the CA request rather than being accepted and dropped.
func TestProvisionAttestation_ForwardsProfileAndValidityToTheCA(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	var seen *transport.SignCSRRequest
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{
			sign: func(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
				seen = req
				return signWithTestCA(t, ca, testIssueOptions{})(ctx, req)
			},
		}, nil
	})

	if _, err := runProvisionAttestation(t, "--profile", "attestation", "--validity-days", "730"); err != nil {
		t.Fatalf("provision-attestation: %v", err)
	}
	if seen == nil {
		t.Fatal("the CA was never called")
	}
	if seen.Profile != "attestation" {
		t.Errorf("profile = %q, want %q", seen.Profile, "attestation")
	}
	if seen.ValidityDays != 730 {
		t.Errorf("validity days = %d, want 730", seen.ValidityDays)
	}
}

// TestProvisionAttestation_ReportsAnUnusedIdentity verifies an operator is told
// when the device is configured to emit "none", where the identity just
// installed would never be presented.
func TestProvisionAttestation_ReportsAnUnusedIdentity(t *testing.T) {
	newProvisioningDevice(t)
	viper.Set("fido2.attestation", "none")
	setDeviceSOPIN(t)

	ca := newTestAttestationCA(t, false)
	useAttestationCA(t, func(*cobra.Command) (attestationCA, error) {
		return &stubAttestationCA{sign: signWithTestCA(t, ca, testIssueOptions{})}, nil
	})

	output, err := runProvisionAttestation(t)
	if err != nil {
		t.Fatalf("provision-attestation: %v", err)
	}
	if !strings.Contains(output, "will still register with \"none\"") {
		t.Errorf("output does not warn about the unused identity, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Unit coverage for the pieces
// ---------------------------------------------------------------------------

// TestFormatAAGUID_RendersCanonicalForm verifies the AAGUID is reported in the
// RFC 4122 form a relying party's allowlist is written in.
func TestFormatAAGUID_RendersCanonicalForm(t *testing.T) {
	got := formatAAGUID(authenticator.DefaultAAGUID)
	const want = "5150e208-1ab8-5162-bc67-f5e4f24adefa"
	if got != want {
		t.Errorf("formatAAGUID = %q, want %q", got, want)
	}
}

// TestDropSelfSignedRoot verifies the trust anchor is removed from x5c and that
// a chain of issuers that are not anchors is left intact.
func TestDropSelfSignedRoot(t *testing.T) {
	ca := newTestAttestationCA(t, true)

	withRoot := [][]byte{ca.interCert.Raw, ca.rootCert.Raw}
	trimmed := dropSelfSignedRoot(withRoot)
	if len(trimmed) != 1 || !bytes.Equal(trimmed[0], ca.interCert.Raw) {
		t.Errorf("dropSelfSignedRoot kept %d certificates, want only the intermediate", len(trimmed))
	}

	withoutRoot := [][]byte{ca.interCert.Raw}
	if kept := dropSelfSignedRoot(withoutRoot); len(kept) != 1 {
		t.Errorf("dropSelfSignedRoot dropped a non-anchor issuer, kept %d", len(kept))
	}

	if kept := dropSelfSignedRoot(nil); kept != nil {
		t.Errorf("dropSelfSignedRoot(nil) = %v, want nil", kept)
	}
}

// TestAllAttestationPEMBlocks_RejectsAMalformedCertificate verifies a chain
// carrying unparsable DER is refused rather than carried onto the device.
func TestAllAttestationPEMBlocks_RejectsAMalformedCertificate(t *testing.T) {
	malformed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})

	if _, err := allAttestationPEMBlocks(malformed); !errors.Is(err, ErrAttestProvisionCARefused) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCARefused)
	}

	chain, err := allAttestationPEMBlocks(nil)
	if err != nil {
		t.Errorf("allAttestationPEMBlocks(nil) errored: %v", err)
	}
	if len(chain) != 0 {
		t.Errorf("allAttestationPEMBlocks(nil) = %v, want empty", chain)
	}

	// A response that also carries non-certificate PEM yields only the
	// certificates, so unrelated material never reaches the device.
	ca := newTestAttestationCA(t, false)
	mixed := append(
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01}}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.rootCert.Raw})...,
	)
	certificates, err := allAttestationPEMBlocks(mixed)
	if err != nil {
		t.Fatalf("allAttestationPEMBlocks: %v", err)
	}
	if len(certificates) != 1 || !bytes.Equal(certificates[0], ca.rootCert.Raw) {
		t.Errorf("allAttestationPEMBlocks kept %d blocks, want only the certificate", len(certificates))
	}
}

// TestFirstAttestationPEMBlock_RejectsAResponseWithNoCertificate verifies the
// absence of a certificate is reported instead of producing an empty install.
func TestFirstAttestationPEMBlock_RejectsAResponseWithNoCertificate(t *testing.T) {
	if _, err := firstAttestationPEMBlock(nil); !errors.Is(err, ErrAttestProvisionCARefused) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCARefused)
	}

	der := []byte{0x30, 0x01, 0x02}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	got, err := firstAttestationPEMBlock(encoded)
	if err != nil {
		t.Fatalf("firstAttestationPEMBlock: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Errorf("firstAttestationPEMBlock = %x, want %x", got, der)
	}
}

// TestReportAttestationState_RefusesAMismatchedStoredChain verifies the
// post-install read-back is a real check and not a formality: a stored
// certificate that does not certify the device's key is refused even though it
// is already in the state, so the operator learns at provisioning time rather
// than from a silent fallback to "none" at the first registration.
func TestReportAttestationState_RefusesAMismatchedStoredChain(t *testing.T) {
	newProvisioningDevice(t)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	strangerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}

	ca := newTestAttestationCA(t, false)
	csrDER := newTestAttestationCSR(t, strangerKey, authenticator.DefaultAAGUID[:])
	leafPEM, _ := ca.issue(t, csrDER, testIssueOptions{})
	leafDER, err := firstAttestationPEMBlock(leafPEM)
	if err != nil {
		t.Fatalf("decode issued certificate: %v", err)
	}

	storage := saveTestDeviceState(t, leafDER)
	defer func() { _ = storage.Close() }()

	var buf bytes.Buffer
	err = reportAttestationState(&buf, buildFIDO2Config(), storage, &testSignerSource{signer: deviceKey})
	if !errors.Is(err, ErrAttestProvisionVerifyFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionVerifyFailed)
	}
	if strings.Contains(buf.String(), "Attestation: provisioned") {
		t.Errorf("a mismatched chain was reported as provisioned, got:\n%s", buf.String())
	}
}

// TestReportAttestationState_RefusesAnEmptyStoredChain verifies an install that
// stored nothing is reported as a failure rather than as success.
func TestReportAttestationState_RefusesAnEmptyStoredChain(t *testing.T) {
	newProvisioningDevice(t)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	storage := saveTestDeviceState(t, nil)
	defer func() { _ = storage.Close() }()

	var buf bytes.Buffer
	if err := reportAttestationState(&buf, buildFIDO2Config(), storage, &testSignerSource{signer: deviceKey}); !errors.Is(err, ErrAttestProvisionVerifyFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionVerifyFailed)
	}
}

// newTestAttestationCSR builds the PKCS#10 request a device emits, so a
// certificate can be issued for a chosen key.
func newTestAttestationCSR(t *testing.T, key *ecdsa.PrivateKey, aaguid []byte) []byte {
	t.Helper()

	extensionValue, err := keybackend.MarshalAAGUIDExtensionValue(aaguid)
	if err != nil {
		t.Fatalf("marshal AAGUID extension: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{keybackend.AttestationCertificateOU},
			CommonName:         "xkey FIDO2 Attestation test",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{{
			Id:       keybackend.OIDFIDOGenCEAAGUID,
			Critical: false,
			Value:    extensionValue,
		}},
	}, key)
	if err != nil {
		t.Fatalf("create device request: %v", err)
	}
	return csrDER
}

// saveTestDeviceState persists a device state holding the given attestation
// certificate, and returns the open storage. No key travels with it: the state
// struct holds only wrapped key copies, and reportAttestationState reaches the
// key through its signer seam, not through storage.
func saveTestDeviceState(t *testing.T, certDER []byte) authenticator.StatefulCredentialStorage {
	t.Helper()

	storage, err := createFIDO2Storage(buildFIDO2Config(), discardLogger())
	if err != nil {
		t.Fatalf("open device storage: %v", err)
	}

	state := authenticator.NewAuthenticatorState()
	state.AAGUID = authenticator.DefaultAAGUID
	state.AttestationCert = certDER

	if err := storage.SaveState(state); err != nil {
		_ = storage.Close()
		t.Fatalf("save device state: %v", err)
	}
	return storage
}

// testSignerSource stands at reportAttestationState's signer seam in place of
// the SO-unlocked key manager, yielding either a signer over a chosen key or
// the key manager's own refusal.
type testSignerSource struct {
	signer crypto.Signer
	err    error
}

func (s *testSignerSource) AttestationSigner() (crypto.Signer, error) {
	return s.signer, s.err
}

// TestSendVendorCommand_SurfacesDeviceErrors verifies a device refusal reaches
// the caller as the device's own typed error, which is what the command's
// error mapping depends on.
func TestSendVendorCommand_SurfacesDeviceErrors(t *testing.T) {
	newProvisioningDevice(t)

	// On a token that was never initialized, an SO-gated command is refused
	// as uninitialized: there is no Security Officer to be locked out of.
	func() {
		auth, storage := openTestDevice(t)
		defer func() {
			_ = auth.Close()
			_ = storage.Close()
		}()

		if _, err := sendVendorCommand(auth, authenticator.VendorCmdReplaceAttestKey, nil); !errors.Is(err, authenticator.ErrTokenUninitialized) {
			t.Errorf("error = %v, want %v", err, authenticator.ErrTokenUninitialized)
		}

		// An unknown vendor subcommand is refused too.
		if _, err := sendVendorCommand(auth, 0xFE, nil); !errors.Is(err, authenticator.ErrConfigInvalidVendorCmd) {
			t.Errorf("error = %v, want %v", err, authenticator.ErrConfigInvalidVendorCmd)
		}
	}()

	// Once the token has a Security Officer, the same command without SO
	// authentication is refused as locked. Initialization leaves the manager
	// it ran on unlocked, so the locked state is a freshly opened device.
	setDeviceSOPIN(t)

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	if _, err := sendVendorCommand(auth, authenticator.VendorCmdReplaceAttestKey, nil); !errors.Is(err, authenticator.ErrKeyManagerLocked) {
		t.Errorf("error = %v, want %v", err, authenticator.ErrKeyManagerLocked)
	}
}

// TestSendVendorCommand_ReturnsTheDeviceRequest verifies the CSR the device
// emits is decoded out of the CBOR response and signed by the key it certifies,
// which is the property that keeps the private key on the device.
func TestSendVendorCommand_ReturnsTheDeviceRequest(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	if _, err := sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
		"pin": testProvisionSOPIN,
	}); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	csrDER, err := requestAttestationCSR(auth)
	if err != nil {
		t.Fatalf("requestAttestationCSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse device request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("the device request is not self-signed by its own key: %v", err)
	}
	if !bytes.Equal(aaguidFromCSR(t, csr), authenticator.DefaultAAGUID[:]) {
		t.Error("the device request does not vouch for the device's AAGUID")
	}
}

// TestRequestAttestationCSR_RefusesAnUnauthorizedDevice verifies the key
// generation step reports the device's refusal rather than returning an empty
// request that would then be sent to the CA.
func TestRequestAttestationCSR_RefusesAnUnauthorizedDevice(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	csrDER, err := requestAttestationCSR(auth)
	if !errors.Is(err, ErrAttestProvisionKeyFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionKeyFailed)
	}
	if !errors.Is(err, authenticator.ErrKeyManagerLocked) {
		t.Errorf("error = %v, want the device's refusal preserved", err)
	}
	if csrDER != nil {
		t.Error("a certificate request was returned for an unauthorized device")
	}
}

// TestSignAttestationCSR_RefusesAnAbsentResponse verifies a CA that answers
// with nothing at all is an error, not an empty install. It also pins that a
// nil context is tolerated, because a cobra command's context may be nil.
func TestSignAttestationCSR_RefusesAnAbsentResponse(t *testing.T) {
	stub := &stubAttestationCA{
		sign: func(ctx context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
			if ctx == nil {
				t.Error("the CA was called with a nil context")
			}
			return nil, nil
		},
	}

	//nolint:staticcheck // a nil context is exactly what this asserts is handled.
	_, _, err := signAttestationCSR(nil, stub, []byte{0x30, 0x00}, "", 0)
	if !errors.Is(err, ErrAttestProvisionCARefused) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionCARefused)
	}
}

// TestReportAttestationState_RefusesAStateWithNoKey verifies a stored
// certificate with no key behind it is refused. Such a state cannot sign, so
// reporting it as provisioned would promise attestation the device cannot
// deliver. "No key" is what the key manager reports when no wrapped copy can
// be resolved, so that is the refusal exercised here.
func TestReportAttestationState_RefusesAStateWithNoKey(t *testing.T) {
	newProvisioningDevice(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ca := newTestAttestationCA(t, false)
	leafPEM, _ := ca.issue(t, newTestAttestationCSR(t, key, authenticator.DefaultAAGUID[:]), testIssueOptions{})
	leafDER, err := firstAttestationPEMBlock(leafPEM)
	if err != nil {
		t.Fatalf("decode issued certificate: %v", err)
	}

	storage := saveTestDeviceState(t, leafDER)
	defer func() { _ = storage.Close() }()

	source := &testSignerSource{err: authenticator.ErrKeyManagerNoAttestKey}

	var buf bytes.Buffer
	err = reportAttestationState(&buf, buildFIDO2Config(), storage, source)
	if !errors.Is(err, ErrAttestProvisionVerifyFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionVerifyFailed)
	}
	if !errors.Is(err, authenticator.ErrKeyManagerNoAttestKey) {
		t.Errorf("error = %v, want it to carry %v", err, authenticator.ErrKeyManagerNoAttestKey)
	}
	if strings.Contains(buf.String(), "Attestation: provisioned") {
		t.Errorf("a keyless state was reported as provisioned, got:\n%s", buf.String())
	}
}

// TestReportAttestationState_RefusesALockedKeyManager drives the signer seam
// with the real key manager in the state it must never be trusted in: locked.
// A locked manager cannot prove the device still holds the certified key, so
// the read-back refuses rather than reporting a chain it could not check.
func TestReportAttestationState_RefusesALockedKeyManager(t *testing.T) {
	newProvisioningDevice(t)
	setDeviceSOPIN(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ca := newTestAttestationCA(t, false)
	leafPEM, _ := ca.issue(t, newTestAttestationCSR(t, key, authenticator.DefaultAAGUID[:]), testIssueOptions{})
	leafDER, err := firstAttestationPEMBlock(leafPEM)
	if err != nil {
		t.Fatalf("decode issued certificate: %v", err)
	}

	auth, storage := openTestDevice(t)
	defer func() {
		_ = auth.Close()
		_ = storage.Close()
	}()

	state, err := storage.LoadState()
	if err != nil {
		t.Fatalf("load device state: %v", err)
	}
	state.AttestationCert = leafDER
	if err := storage.SaveState(state); err != nil {
		t.Fatalf("save device state: %v", err)
	}

	// No SO unlock happened on this authenticator, so its key manager is
	// locked and AttestationSigner must refuse.
	var buf bytes.Buffer
	err = reportAttestationState(&buf, buildFIDO2Config(), storage, auth.GetKeyManager())
	if !errors.Is(err, ErrAttestProvisionVerifyFailed) {
		t.Errorf("error = %v, want wrapped %v", err, ErrAttestProvisionVerifyFailed)
	}
	if !errors.Is(err, authenticator.ErrKeyManagerLocked) {
		t.Errorf("error = %v, want it to carry %v", err, authenticator.ErrKeyManagerLocked)
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// signWithTestCA adapts the test CA to the stub's signing hook.
func signWithTestCA(t *testing.T, ca *testAttestationCA, opts testIssueOptions) func(context.Context, *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	t.Helper()

	return func(_ context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
		block, _ := pem.Decode(req.CSRPEM)
		if block == nil {
			t.Fatalf("the CA received %q, want PEM", req.CSRPEM)
		}
		certPEM, chainPEM := ca.issue(t, block.Bytes, opts)
		return &transport.SignCSRResponse{CertificatePEM: certPEM, ChainPEM: chainPEM}, nil
	}
}

// makeCredentialAttestation registers a credential against the provisioned
// device and returns the attestation format and x5c chain a relying party
// would receive. This is what "provisioned" has to mean: the identity is not
// merely stored, it is presented.
func makeCredentialAttestation(t *testing.T) (string, [][]byte) {
	t.Helper()

	cfg := buildFIDO2Config()
	storage, err := createFIDO2Storage(cfg, discardLogger())
	if err != nil {
		t.Fatalf("open device storage: %v", err)
	}
	defer func() { _ = storage.Close() }()

	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             storage,
		AttestationFormat:   cfg.AttestationFormat,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// A locked key manager cannot unwrap the attestation key, and the device
	// degrades to "none" by design rather than failing the registration. The
	// daemon presents attestation from a manager unlocked with the user PIN
	// (through the CMK bridge); these tests unlock as Security Officer, since
	// the SO PIN is the credential they establish. A device whose token was
	// never initialized has nothing to unlock, and "none" is the point of the
	// assertion that follows.
	if auth.IsTokenInitialized() {
		if _, err := sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
			"pin": testProvisionSOPIN,
		}); err != nil {
			t.Fatalf("unlock SO: %v", err)
		}
	}

	clientDataHash := make([]byte, 32)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}

	request, err := cbor.Marshal(map[int]interface{}{
		0x01: clientDataHash,
		0x02: map[string]interface{}{"id": "example.com", "name": "Example"},
		0x03: map[string]interface{}{
			"id":          []byte("provisioning-test-user"),
			"name":        "operator",
			"displayName": "Operator",
		},
		0x04: []interface{}{
			map[string]interface{}{"type": "public-key", "alg": -7},
		},
	})
	if err != nil {
		t.Fatalf("encode makeCredential request: %v", err)
	}

	response, err := auth.ProcessCBOR(authenticator.CmdMakeCredential, request)
	if err != nil {
		t.Fatalf("makeCredential: %v", err)
	}
	if len(response) < 2 || response[0] != authenticator.StatusOK {
		t.Fatalf("makeCredential returned status %x", response)
	}

	decoded := make(map[int]interface{})
	if err := cbor.Unmarshal(response[1:], &decoded); err != nil {
		t.Fatalf("decode makeCredential response: %v", err)
	}

	format, _ := decoded[0x01].(string)

	attStmt, ok := decoded[0x03].(map[interface{}]interface{})
	if !ok {
		return format, nil
	}
	rawChain, ok := attStmt["x5c"].([]interface{})
	if !ok {
		return format, nil
	}

	chain := make([][]byte, 0, len(rawChain))
	for _, entry := range rawChain {
		der, ok := entry.([]byte)
		if !ok {
			t.Fatalf("x5c entry is %T, want DER bytes", entry)
		}
		chain = append(chain, der)
	}
	return format, chain
}

// assertChainsToRoot verifies the presented x5c reaches the operator's root,
// which is the property that turns the statement into provenance.
func assertChainsToRoot(t *testing.T, x5c [][]byte, root *x509.Certificate) {
	t.Helper()

	leaf, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		t.Fatalf("parse x5c leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	for _, der := range x5c[1:] {
		intermediate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			t.Fatalf("parse x5c intermediate: %v", parseErr)
		}
		intermediates.AddCert(intermediate)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("the presented chain does not reach the configured root: %v", err)
	}
}
