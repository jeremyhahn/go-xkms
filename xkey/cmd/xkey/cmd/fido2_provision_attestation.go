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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/keybackend"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// This file is the operator-facing half of xKey's Basic attestation: the
// command that turns the device attestation identity on.
//
// The two CTAP vendor commands that provision it — replaceAttestKey, which
// generates the key and returns a PKCS#10 request, and setAttestCert, which
// installs the issued chain — had no caller outside the authenticator package,
// so every device reported fmt:"none" no matter how the rest of the subsystem
// was configured. This drives them, following the shape
// device_enroll_phone_ca.go already established for a different device key:
// the device produces a CSR, the CSR goes to the operator's xkms enterprise CA,
// and the issued chain comes back and is installed.
//
// The private key never leaves the device. That is the whole point of the CSR
// shape, and nothing here reads, prints or transports key material.

// Provisioning errors.
var (
	// ErrAttestProvisionVolatileStorage indicates the authenticator is
	// configured with memory storage, where a provisioned identity would be
	// discarded when the process exits.
	ErrAttestProvisionVolatileStorage = errors.New("provision-attestation: memory storage cannot hold an attestation identity; configure fido2.storage as 'file' or 'barrier'")

	// ErrAttestProvisionAlreadyProvisioned indicates the device already
	// presents an attestation certificate.
	ErrAttestProvisionAlreadyProvisioned = errors.New("provision-attestation: this device already has an attestation certificate; pass --rotate to replace it")

	// ErrAttestProvisionDeviceOpenFailed indicates the device state could not
	// be opened.
	ErrAttestProvisionDeviceOpenFailed = errors.New("provision-attestation: failed to open the device state")

	// ErrAttestProvisionStateReadFailed indicates the persisted device state
	// could not be read back.
	ErrAttestProvisionStateReadFailed = errors.New("provision-attestation: failed to read the device state")

	// ErrAttestProvisionSOAuthFailed indicates Security Officer authentication
	// was refused by the device.
	ErrAttestProvisionSOAuthFailed = errors.New("provision-attestation: Security Officer authentication failed")

	// ErrAttestProvisionSOPINNotSet indicates the device has no Security
	// Officer PIN, so provisioning cannot be authorized.
	ErrAttestProvisionSOPINNotSet = errors.New("provision-attestation: this device has no Security Officer PIN; attestation provisioning is SO-gated")

	// ErrAttestProvisionCAUnreachable indicates the attestation CA could not be
	// reached. The device is left untouched when this is returned.
	ErrAttestProvisionCAUnreachable = errors.New("provision-attestation: the attestation CA is unreachable; the device was left unprovisioned")

	// ErrAttestProvisionCARefused indicates the CA declined to issue a
	// certificate for the device's request.
	ErrAttestProvisionCARefused = errors.New("provision-attestation: the attestation CA refused to issue a certificate")

	// ErrAttestProvisionKeyFailed indicates the device could not generate its
	// attestation key or the request for it.
	ErrAttestProvisionKeyFailed = errors.New("provision-attestation: the device failed to generate an attestation key")

	// ErrAttestProvisionCSRMissing indicates the device's response carried no
	// certificate signing request.
	ErrAttestProvisionCSRMissing = errors.New("provision-attestation: the device returned no certificate signing request")

	// ErrAttestProvisionInstallFailed indicates the issued chain was refused by
	// the device.
	ErrAttestProvisionInstallFailed = errors.New("provision-attestation: the device refused the issued certificate chain")

	// ErrAttestProvisionVerifyFailed indicates the chain read back from the
	// device did not verify.
	ErrAttestProvisionVerifyFailed = errors.New("provision-attestation: the installed chain failed verification")

	// ErrAttestProvisionResponseInvalid indicates a device response could not
	// be decoded.
	ErrAttestProvisionResponseInvalid = errors.New("provision-attestation: the device returned a malformed response")
)

// attestationCA is the slice of the xkms CA this command needs: submit a
// PKCS#10 request, receive the issued certificate and its issuer chain.
//
// The SDK's transport.Client satisfies it structurally. Narrowing it to the one
// verb used keeps the collaborator small enough to substitute in a test, which
// is what makes the CA-unreachable and CA-misissues paths testable at all.
type attestationCA interface {
	SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error)
	Close() error
}

// connectAttestationCA dials the operator's attestation CA and completes the
// connection handshake, so an unreachable CA surfaces here — before the device
// is touched — rather than after a key has been generated.
//
// It is a variable so tests can supply an in-process CA; production always
// resolves xkmsd through the CLI's single endpoint resolver.
var connectAttestationCA = func(cmd *cobra.Command) (attestationCA, error) {
	client, err := connectXKMSdClient(cmd)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// fido2ProvisionAttestationCmd provisions the device attestation identity.
//
// It lives under `fido2` rather than under `device`, because `device` manages
// paired phones (it is aliased "phone") and this provisions xKey's own FIDO2
// attestation key — a different subject entirely.
var fido2ProvisionAttestationCmd = &cobra.Command{
	Use:   "provision-attestation",
	Short: "Provision this device's FIDO2 attestation identity (Security Officer)",
	Long: `Provision the attestation identity that vouches for credentials this device creates.

The device generates an attestation key and a PKCS#10 certificate signing
request for it; the request is submitted to the xkms enterprise CA; and the
issued chain is installed back onto the device. The attestation private key is
generated on the device and never leaves it.

Until a device is provisioned it registers credentials with the "none"
attestation format — it still works, it simply conveys no provenance. After
provisioning it emits a WebAuthn Level 2 packed attestation statement with an
x5c chain, which is what a relying party enforcing a hardware policy requires.

This is a Security Officer operation: the SO PIN gates provisioning the
attestation identity, not using it. The command prompts for the SO PIN.

The FIDO2 daemon owns the device state while it runs, so stop it first
("xkey fido2 status" reports whether it is running) and start it again
afterwards to pick up the new identity.

Set fido2.attestation to "packed" so the daemon presents the identity once it
is installed; the command reports when that setting would leave it unused.

Examples:
  # Provision using the configured xkmsd endpoint
  xkey fido2 provision-attestation

  # Provision against a named CA profile with a two-year validity
  xkey fido2 provision-attestation --profile attestation --validity-days 730

  # Replace an existing attestation identity (invalidates prior statements)
  xkey fido2 provision-attestation --rotate`,
	Args: cobra.NoArgs,
	RunE: runFIDO2ProvisionAttestation,
}

func init() {
	fido2Cmd.AddCommand(fido2ProvisionAttestationCmd)

	fido2ProvisionAttestationCmd.Flags().Bool("rotate", false,
		"Replace an existing attestation identity (invalidates every statement issued under the old key)")
	fido2ProvisionAttestationCmd.Flags().String("profile", "",
		"CA certificate profile to issue the attestation certificate under (default: the CA's own default)")
	fido2ProvisionAttestationCmd.Flags().Int("validity-days", 0,
		"Certificate validity in days (default: the CA's own default)")
	fido2ProvisionAttestationCmd.Flags().String(tlsCAFlagName, "",
		"CA bundle used to verify TLS transports to xkmsd")
}

// runFIDO2ProvisionAttestation provisions the device attestation identity.
//
// The ordering is the safety property. Everything that can fail without
// consequence — volatile storage, a running daemon, an existing identity,
// Security Officer authentication, reaching the CA — is settled before the
// device generates a key, because generating one discards whatever certificate
// was installed before. A CA that cannot be reached therefore leaves the device
// exactly as it was found.
func runFIDO2ProvisionAttestation(cmd *cobra.Command, _ []string) (err error) {
	out := cmd.OutOrStdout()

	rotate, err := cmd.Flags().GetBool("rotate")
	if err != nil {
		return err
	}
	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		return err
	}
	validityDays, err := cmd.Flags().GetInt("validity-days")
	if err != nil {
		return err
	}
	socketPath := resolvedSocketPath(cmd)

	cfg := buildFIDO2Config()

	// A memory-backed authenticator discards its state with the process, so a
	// key generated here would be gone before the daemon ever read it — the
	// device would be told it was provisioned and would still register
	// unattested.
	if cfg.StorageType == FIDO2StorageTypeMemory {
		return ErrAttestProvisionVolatileStorage
	}

	// The running daemon holds the authenticator state in memory and writes it
	// back on its next change, which would silently discard the identity
	// installed here. Refusing is what keeps "provisioned" and "attesting" the
	// same thing.
	running, err := fido2DaemonRunning(socketPath)
	if err != nil {
		return err
	}
	if running {
		return ErrFIDO2DaemonRunning
	}

	storage, err := createFIDO2Storage(cfg, slog.Default())
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionDeviceOpenFailed, Cause: err}
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	// This flow issues only SO-gated authenticatorConfig vendor commands, none
	// of which consult the presence handler, so nothing here prompts for a
	// touch today — authorization is the interactively entered SO PIN, not a
	// presence ceremony. newOfflineAuthenticator still installs an interactive
	// handler rather than an auto-grant, for the reason stated there.
	auth, err := newOfflineAuthenticator(cmd.InOrStdin(), out, storage)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionDeviceOpenFailed, Cause: err}
	}
	defer func() {
		if closeErr := auth.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	replacing, err := checkReprovisioningAllowed(storage, rotate)
	if err != nil {
		return err
	}
	if replacing {
		_, _ = fmt.Fprintln(out,
			"Replacing this device's attestation identity. Every attestation statement\n"+
				"it has issued was signed by the key being replaced; a relying party that\n"+
				"pinned the old certificate will no longer recognise this device.")
	}

	if err := unlockSecurityOfficer(auth, out); err != nil {
		return err
	}

	ca, err := connectAttestationCA(cmd)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionCAUnreachable, Cause: err}
	}
	defer func() {
		if closeErr := ca.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	csrDER, err := requestAttestationCSR(auth)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(out, "Submitting the device's certificate request to the xkms enterprise CA...")

	leafDER, intermediatesDER, err := signAttestationCSR(cmd.Context(), ca, csrDER, profile, validityDays)
	if err != nil {
		return err
	}

	if err := installAttestationChain(auth, leafDER, intermediatesDER); err != nil {
		return err
	}

	// The key manager is still SO-unlocked from unlockSecurityOfficer above,
	// which is what lets the read-back resolve the attestation signer.
	return reportAttestationState(out, cfg, storage, auth.GetKeyManager())
}

// checkReprovisioningAllowed decides whether a device that has already been
// provisioned may be provisioned again.
//
// The default is to refuse. Rotation replaces the attestation key, and every
// attestation statement the device has ever issued was signed by the old one:
// a relying party that pinned the old certificate — which is the entire reason
// to run Basic attestation rather than self attestation — stops recognising the
// device. Rotation is also not atomic here, because generating the new key
// discards the installed certificate before the CA has issued a replacement, so
// a CA failure mid-rotation costs the operator a working identity. Both are
// consequences an operator must accept deliberately, so they are behind
// --rotate and never the default.
//
// The installed certificate, not the key, is what says a device is provisioned.
// Initializing the Security Officer PIN already generates an attestation key
// (KeyManager.InitializeSOPIN), and an interrupted run leaves one behind too;
// in both cases nothing was ever certified under that key, so no statement can
// be invalidated and nothing can be lost. Those proceed without --rotate, which
// is what lets an operator simply run the command again after a CA failure.
// It reports whether an installed identity is about to be replaced, so the
// caller can say so before it happens.
func checkReprovisioningAllowed(storage authenticator.StatefulCredentialStorage, rotate bool) (bool, error) {
	state, err := storage.LoadState()
	if err != nil {
		// A device that has never saved state has nothing to protect.
		if errors.Is(err, authenticator.ErrStateNotFound) {
			return false, nil
		}
		return false, &SentinelCauseError{Sentinel: ErrAttestProvisionStateReadFailed, Cause: err}
	}

	if len(state.AttestationCert) == 0 {
		return false, nil
	}
	if !rotate {
		return false, ErrAttestProvisionAlreadyProvisioned
	}
	return true, nil
}

// unlockSecurityOfficer authenticates the Security Officer to the device.
//
// The PIN is read through the shared prompt, handed straight to the device and
// never logged, echoed or carried in an error.
func unlockSecurityOfficer(auth *authenticator.Authenticator, out io.Writer) error {
	pin, err := readPIN(out, "Enter SO PIN: ")
	if err != nil {
		return err
	}

	_, err = sendVendorCommand(auth, authenticator.VendorCmdUnlockWithSOPIN, map[string]interface{}{
		"pin": pin,
	})
	if err != nil {
		// ErrTokenUninitialized is the token-lifecycle spelling of the same
		// condition: the token has never been initialized with an SO PIN, so
		// there is no Security Officer to authenticate as.
		if errors.Is(err, authenticator.ErrSOPINNotSet) ||
			errors.Is(err, authenticator.ErrKeyManagerNoSOPIN) ||
			errors.Is(err, authenticator.ErrTokenUninitialized) {
			return ErrAttestProvisionSOPINNotSet
		}
		return &SentinelCauseError{Sentinel: ErrAttestProvisionSOAuthFailed, Cause: err}
	}
	return nil
}

// requestAttestationCSR asks the device to generate an attestation key and
// return a PKCS#10 request for it. Only the request crosses the boundary; the
// private key stays on the device.
func requestAttestationCSR(auth *authenticator.Authenticator) ([]byte, error) {
	response, err := sendVendorCommand(auth, authenticator.VendorCmdReplaceAttestKey, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAttestProvisionKeyFailed, Cause: err}
	}

	csrDER, ok := response[attestationResponseKeyCSR].([]byte)
	if !ok || len(csrDER) == 0 {
		return nil, ErrAttestProvisionCSRMissing
	}
	return csrDER, nil
}

// signAttestationCSR submits the device's request to the CA and returns the
// issued leaf and its intermediates, all DER.
func signAttestationCSR(
	ctx context.Context,
	ca attestationCA,
	csrDER []byte,
	profile string,
	validityDays int,
) ([]byte, [][]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	if csrPEM == nil {
		return nil, nil, &DetailError{
			Err:    ErrAttestProvisionCSRMissing,
			Detail: ": the device's request could not be PEM encoded",
		}
	}

	resp, err := ca.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      profile,
		ValidityDays: validityDays,
	})
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrAttestProvisionCARefused, Cause: err}
	}
	if resp == nil {
		return nil, nil, &DetailError{Err: ErrAttestProvisionCARefused, Detail: ": the CA returned no response"}
	}

	leafDER, err := firstAttestationPEMBlock(resp.CertificatePEM)
	if err != nil {
		return nil, nil, err
	}

	// The response chain carries the issuers above the leaf. The root is
	// dropped: a relying party is configured to trust it out of band, and
	// WebAuthn Level 2 §8.2 x5c is the chain up to but excluding it.
	chainDER, err := allAttestationPEMBlocks(resp.ChainPEM)
	if err != nil {
		return nil, nil, err
	}

	return leafDER, dropSelfSignedRoot(chainDER), nil
}

// installAttestationChain hands the issued chain to the device, which validates
// it against the resident key and the WebAuthn Level 2 §8.2.1 certificate
// requirements before storing it.
func installAttestationChain(auth *authenticator.Authenticator, leafDER []byte, intermediatesDER [][]byte) error {
	params := map[string]interface{}{
		"attestCert": leafDER,
	}
	if len(intermediatesDER) > 0 {
		chain := make([]interface{}, 0, len(intermediatesDER))
		for _, der := range intermediatesDER {
			chain = append(chain, der)
		}
		params["attestCertChain"] = chain
	}

	if _, err := sendVendorCommand(auth, authenticator.VendorCmdSetAttestCert, params); err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionInstallFailed, Cause: err}
	}
	return nil
}

// attestationSignerSource yields the signer over the device attestation key.
// It is the one method of *authenticator.KeyManager the read-back verification
// needs: the signer's public key, resolved from the wrapped copy the device
// actually holds. The key material itself never crosses this seam — the state
// struct deliberately carries only AES-GCM wrapped copies, and AttestationSigner
// destroys each unwrapped plaintext before returning.
type attestationSignerSource interface {
	AttestationSigner() (crypto.Signer, error)
}

// reportAttestationState reads the chain back out of the device's persisted
// state and reports what a relying party will now see.
//
// The read-back is the point: it proves the identity survived persistence, that
// the stored leaf certifies the key the device still holds, and that the leaf
// vouches for the AAGUID the device reports. Verifying here means a chain a
// relying party would reject is refused while an operator is watching, not
// discovered as a silent fallback to "none" at the first registration.
//
// The device key comes from signers — the SO-unlocked key manager — because
// resolving it proves the wrapped copy is present and unwrappable, which is
// exactly what "the device still holds the key" means now that no plaintext
// key ever sits in the persisted state.
func reportAttestationState(out io.Writer, cfg *FIDO2Config, storage authenticator.StatefulCredentialStorage, signers attestationSignerSource) error {
	state, err := storage.LoadState()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionStateReadFailed, Cause: err}
	}

	if len(state.AttestationCert) == 0 {
		return &DetailError{Err: ErrAttestProvisionVerifyFailed, Detail: ": no certificate was stored"}
	}

	// A signer that cannot be resolved means the device holds no usable
	// attestation key — absent, locked away, or unwrappable — and each of
	// those is a provisioning failure the operator must see now.
	signer, err := signers.AttestationSigner()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionVerifyFailed, Cause: err}
	}

	leaf, err := x509.ParseCertificate(state.AttestationCert)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionVerifyFailed, Cause: err}
	}

	deviceKey, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !deviceKey.Equal(leaf.PublicKey) {
		return &DetailError{
			Err:    ErrAttestProvisionVerifyFailed,
			Detail: ": the stored certificate does not certify this device's attestation key",
		}
	}

	// keybackend owns the §8.2.1 rules and the AAGUID binding; re-implementing
	// them here would let the two drift apart.
	if err := keybackend.ValidateAttestationCertificate(leaf, state.AAGUID[:]); err != nil {
		return &SentinelCauseError{Sentinel: ErrAttestProvisionVerifyFailed, Cause: err}
	}

	issuer := leaf.Issuer.String()
	for _, der := range state.AttestationCertChain {
		intermediate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return &SentinelCauseError{Sentinel: ErrAttestProvisionVerifyFailed, Cause: parseErr}
		}
		issuer = intermediate.Issuer.String()
	}

	_, _ = fmt.Fprintln(out, "Attestation: provisioned")
	_, _ = fmt.Fprintf(out, "  AAGUID:        %s\n", formatAAGUID(state.AAGUID))
	_, _ = fmt.Fprintf(out, "  Certificate:   %s\n", leaf.Subject.String())
	_, _ = fmt.Fprintf(out, "  Serial:        %s\n", leaf.SerialNumber.Text(16))
	_, _ = fmt.Fprintf(out, "  Intermediates: %d\n", len(state.AttestationCertChain))
	_, _ = fmt.Fprintf(out, "  Root:          %s\n", issuer)

	// A provisioned device that is configured to emit "none" is the same
	// unattested device it was before, so the discrepancy is reported rather
	// than left for a relying party to discover.
	if !strings.EqualFold(cfg.AttestationFormat, keybackend.AttestationFormatPacked) {
		_, _ = fmt.Fprintf(out,
			"\nNote: fido2.attestation is %q, so this device will still register with \"none\".\n"+
				"      Set it to %q for the identity above to be presented.\n",
			cfg.AttestationFormat, keybackend.AttestationFormatPacked)
	}

	return nil
}

// attestationResponseKeyCSR is the authenticatorConfig response key carrying
// the device's PKCS#10 request. It mirrors configResponseKeyAttestCSR, which is
// internal to the authenticator package and holds 0x06 — not 0x04, which #306
// took for configResponseKeyTokenFlags. A drift here is not silent: every
// provisioning happy-path test decodes the real CBOR the authenticator emits,
// so a wrong value fails requestAttestationCSR with ErrAttestProvisionCSRMissing.
const attestationResponseKeyCSR = 0x06

// sendVendorCommand issues one authenticatorConfig vendor subcommand and
// returns its decoded response body.
//
// The command travels as the CTAP2 authenticatorConfig request the device
// answers on the wire, so the CLI exercises exactly the path a Security
// Officer's tooling would, rather than a private back door into the state.
func sendVendorCommand(
	auth *authenticator.Authenticator,
	vendorCmd uint8,
	params map[string]interface{},
) (map[int]interface{}, error) {
	subCommandParams := make(map[string]interface{}, len(params)+1)
	for key, value := range params {
		subCommandParams[key] = value
	}
	subCommandParams["vendorCmd"] = vendorCmd

	request, err := cbor.Marshal(map[int]interface{}{
		0x01: uint8(authenticator.AuthConfigCmdVendorPrototype),
		0x02: subCommandParams,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAttestProvisionResponseInvalid, Cause: err}
	}

	response, err := auth.ProcessCBOR(authenticator.CmdConfig, request)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 || response[0] != authenticator.StatusOK {
		return nil, &DetailError{
			Err:    ErrAttestProvisionResponseInvalid,
			Detail: ": the device returned no success status",
		}
	}
	if len(response) == 1 {
		return map[int]interface{}{}, nil
	}

	decoded := make(map[int]interface{})
	if err := cbor.Unmarshal(response[1:], &decoded); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAttestProvisionResponseInvalid, Cause: err}
	}
	return decoded, nil
}

// formatAAGUID renders an AAGUID in the canonical RFC 4122 form a relying
// party's allowlist is written in.
func formatAAGUID(aaguid [16]byte) string {
	encoded := hex.EncodeToString(aaguid[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:32]
}

// firstAttestationPEMBlock extracts the issued leaf from the CA's response.
func firstAttestationPEMBlock(data []byte) ([]byte, error) {
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
	return nil, &DetailError{Err: ErrAttestProvisionCARefused, Detail: ": the CA returned no certificate"}
}

// allAttestationPEMBlocks extracts every certificate in the CA's issuer chain,
// in the order the CA sent them.
func allAttestationPEMBlocks(data []byte) ([][]byte, error) {
	var chain [][]byte
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAttestProvisionCARefused, Cause: err}
		}
		chain = append(chain, block.Bytes)
	}
	return chain, nil
}

// dropSelfSignedRoot removes a trust anchor the CA included in its chain.
//
// WebAuthn Level 2 §8.2 x5c runs from the leaf up to but excluding the root,
// which the relying party is configured to trust out of band. xkms returns its
// own CA certificate as the chain, so for a single-tier CA that certificate is
// the root and sending it would only grow every registration response.
func dropSelfSignedRoot(chain [][]byte) [][]byte {
	if len(chain) == 0 {
		return nil
	}

	last, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		return chain
	}
	if last.CheckSignatureFrom(last) == nil {
		return chain[:len(chain)-1]
	}
	return chain
}
