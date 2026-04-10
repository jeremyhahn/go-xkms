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

//go:build ble

package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	xkeyAttestation "github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	xkeyTruststore "github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Device attest errors.
var (
	// ErrDeviceAttestKeyRequired indicates a key ID is required for attestation.
	ErrDeviceAttestKeyRequired = errors.New("device: key ID is required for attestation")

	// ErrDeviceAttestNonceFailed indicates random nonce generation failed.
	ErrDeviceAttestNonceFailed = errors.New("device: failed to generate attestation nonce")

	// ErrDeviceAttestFailed indicates the attestation request failed.
	ErrDeviceAttestFailed = errors.New("device: attestation request failed")

	// ErrDeviceAttestVerifyFailed indicates attestation verification failed.
	ErrDeviceAttestVerifyFailed = errors.New("device: attestation verification failed")
)

// Purpose code names for Android Keymaster.
var purposeNames = map[int]string{
	0: "ENCRYPT",
	1: "DECRYPT",
	2: "SIGN",
	3: "VERIFY",
	4: "DERIVE_KEY",
	5: "WRAP_KEY",
	6: "AGREE_KEY",
	7: "ATTEST_KEY",
}

// Algorithm names for Android Keymaster.
var algorithmNames = map[int]string{
	1:   "RSA",
	3:   "EC",
	32:  "AES",
	33:  "TRIPLE_DES",
	128: "HMAC",
}

// EC curve names.
var ecCurveNames = map[int]string{
	0: "P-224",
	1: "P-256",
	2: "P-384",
	3: "P-521",
	4: "Curve25519",
}

// Origin names for key generation.
var originNames = map[int]string{
	0: "GENERATED",
	1: "DERIVED",
	2: "IMPORTED",
	3: "UNKNOWN",
	4: "SECURELY_IMPORTED",
}

// deviceAttestCmd requests key attestation from a paired phone.
var deviceAttestCmd = &cobra.Command{
	Use:   "attest <key-id>",
	Short: "Request key attestation from a paired phone",
	Long: `Request Android Key Attestation proof for a key stored on the phone.

This command connects to the paired phone over BLE, sends a cryptographic
challenge (nonce), and receives an X.509 certificate chain proving the key
is hardware-backed (TEE or StrongBox).

The certificate chain is verified against Google's Hardware Attestation Root CAs
(embedded) and the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) is
parsed to display the key's security properties.

Examples:
  # Attest a key by ID
  xkey device attest my-signing-key

  # Attest with a specific device
  xkey device attest my-signing-key --device "John's Pixel"

  # Skip chain verification (development mode)
  xkey device attest my-signing-key --no-verify`,
	Args: cobra.ExactArgs(1),
	RunE: runDeviceAttest,
}

func init() {
	deviceCmd.AddCommand(deviceAttestCmd)

	deviceAttestCmd.Flags().String("device", "", "Specific paired device to use")
	deviceAttestCmd.Flags().Bool("no-verify", false, "Skip certificate chain verification")
	deviceAttestCmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout (includes biometric wait)")

	_ = viper.BindPFlag("device.attest.device", deviceAttestCmd.Flags().Lookup("device"))
	_ = viper.BindPFlag("device.attest.no-verify", deviceAttestCmd.Flags().Lookup("no-verify"))
	_ = viper.BindPFlag("device.attest.timeout", deviceAttestCmd.Flags().Lookup("timeout"))
}

// runDeviceAttest executes the phone attestation command.
func runDeviceAttest(cmd *cobra.Command, args []string) error {
	keyID := args[0]
	deviceName, _ := cmd.Flags().GetString("device")
	noVerify, _ := cmd.Flags().GetBool("no-verify")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	logger := slog.Default()

	// Load phone config to get pairing info
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrDeviceNotPaired
		}
		return fmt.Errorf("%w: %v", ErrDeviceConfigLoadFailed, err)
	}

	if len(cfg.Devices) == 0 {
		return ErrDeviceNotPaired
	}

	// Select the device
	device := selectDevice(cfg, deviceName)
	if device == nil {
		if deviceName != "" {
			return fmt.Errorf("%w: %s", ErrDeviceNotFound, deviceName)
		}
		return ErrDeviceNotPaired
	}

	fmt.Printf("Attesting key \"%s\" on device \"%s\"...\n\n", keyID, device.Name)

	// Decode the pairing keys
	localPrivateKey, err := base64.StdEncoding.DecodeString(device.LocalNoisePrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}
	remotePublicKey, err := base64.StdEncoding.DecodeString(device.NoisePublicKey)
	if err != nil {
		return fmt.Errorf("invalid phone noise key: %w", err)
	}

	// Reconstruct the Noise DH key pair from the stored private key
	localKey, err := phone.LoadStaticKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid local noise key: %w", err)
	}

	// Connect to phone
	backend, err := phone.NewPhoneKeyBackend(&phone.PhoneKeyBackendConfig{
		DeviceAddress:        device.Address,
		LocalStaticKey:       localKey,
		ExpectedRemoteStatic: remotePublicKey,
		ScanTimeout:          30 * time.Second,
		ConnectTimeout:       30 * time.Second,
		OperationTimeout:     timeout,
		Logger:               logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create phone backend: %w", err)
	}
	defer backend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Println("Connecting to phone...")
	if err := backend.Connect(ctx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	// Generate random nonce (32 bytes)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return ErrDeviceAttestNonceFailed
	}

	fmt.Println("Requesting attestation (check phone for biometric prompt)...")
	fmt.Println()

	// Send attestation request
	req := phone.NewRequest(phone.MethodLocalAttestKey, &phone.LocalAttestKeyParams{
		KeyID: keyID,
		Nonce: nonce,
	})

	resp, err := backend.SendRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceAttestFailed, err)
	}

	if resp.Error != nil {
		return fmt.Errorf("%w: [%d] %s", ErrDeviceAttestFailed, resp.Error.Code, resp.Error.Message)
	}

	// Decode the result
	result, err := phone.DecodeResult[phone.LocalAttestKeyResult](resp)
	if err != nil {
		return fmt.Errorf("failed to decode attestation result: %w", err)
	}

	// Display raw attestation info
	fmt.Println("Attestation Result")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("  Key ID:          %s\n", keyID)
	fmt.Printf("  Format:          %s\n", result.Format)
	fmt.Printf("  Security Level:  %s\n", result.SecurityLevel)
	fmt.Printf("  Chain Length:    %d certificates\n", len(result.CertificateChain))
	fmt.Printf("  Nonce Match:     %v\n", nonceMatches(nonce, result.Nonce))
	fmt.Println()

	if len(result.CertificateChain) == 0 {
		fmt.Println("WARNING: Empty certificate chain returned.")
		return nil
	}

	// Parse certificates
	chain, err := parseDERChain(result.CertificateChain)
	if err != nil {
		fmt.Printf("WARNING: Failed to parse certificate chain: %v\n", err)
		return nil
	}

	// Verify against Google Hardware Attestation root CAs and local trust store
	if !noVerify {
		fmt.Println("Verification")
		fmt.Println(strings.Repeat("=", 70))

		// Build trust pool using the auto-selecting attestation verifier
		xkeyStore, xkeyErr := openTrustStore()
		if xkeyErr != nil {
			return fmt.Errorf("failed to open trust store: %w", xkeyErr)
		}
		defer func() { _ = xkeyStore.Close() }()

		verifier, verifierErr := xkeyAttestation.NewVerifier(xkeyStore, xkeyTruststore.LoadEmbeddedRoots)
		if verifierErr != nil {
			return fmt.Errorf("failed to create attestation verifier: %w", verifierErr)
		}

		rootPool, poolErr := verifier.BuildTrustPool(xkeyTruststore.PurposeAndroidHardware)
		if poolErr != nil {
			return fmt.Errorf("failed to build trust pool: %w", poolErr)
		}

		// Build allRoots slice for findMatchingTrustRoot: xkey store certs + embedded roots
		allRoots := xkeyTruststore.LoadEmbeddedRoots(xkeyTruststore.PurposeAndroidHardware)
		xkeyCerts, certsErr := xkeyStore.Certificates()
		if certsErr == nil && len(xkeyCerts) > 0 {
			allRoots = append(allRoots, xkeyCerts...)
			fmt.Printf("  Trust Sources:       Google Hardware Attestation + %d local certificate(s)\n", len(xkeyCerts))
		}

		verifyOpts := &android.VerifyOptions{
			TrustedRoots:  rootPool,
			ExpectedNonce: nonce,
		}

		desc, err := android.VerifyKeyAttestation(chain, verifyOpts)
		if err != nil {
			fmt.Printf("  Chain Status:        FAILED (%v)\n", err)
			fmt.Println()
			fmt.Println("The certificate chain could not be verified against")
			fmt.Println("Google's Hardware Attestation Root CAs. This may indicate")
			fmt.Println("the key is not hardware-backed or the device is not genuine.")
			return fmt.Errorf("%w: %v", ErrDeviceAttestVerifyFailed, err)
		}

		// Find which root matched from all trust sources
		matchedRoot := findMatchingTrustRoot(chain, allRoots)
		deviceRoot := chain[len(chain)-1]

		fmt.Println("  Chain Status:        VERIFIED")
		fmt.Printf("  Trust Anchor:        %s\n", formatTrustAnchor(matchedRoot))
		fmt.Printf("  Root Key FP:         %s (matches trusted root)\n", certFingerprint(deviceRoot))
		fmt.Println()

		// Show verification explanation
		fmt.Println("  Verification Explanation:")
		if deviceRoot.Subject.SerialNumber != "" {
			fmt.Printf("  - Device root certificate (SERIALNUMBER=%s) verified against\n", deviceRoot.Subject.SerialNumber)
		} else {
			fmt.Printf("  - Device root certificate (CN=%s) verified against\n", deviceRoot.Subject.CommonName)
		}
		fmt.Println("    Google's published Hardware Attestation Root CA certificates")
		fmt.Println("  - The certificate chain cryptographically proves this key was")
		fmt.Println("    generated inside genuine Android secure hardware (StrongBox/TEE)")
		fmt.Println("  - The nonce proves the attestation was freshly generated for this request")
		fmt.Println()

		// Show full certificate chain details with trust anchor annotation
		printAttestationCertificateChainWithTrustInfo(chain, matchedRoot)

		printKeyDescription(desc)
	} else {
		// Always show full certificate chain details without verification
		printAttestationCertificateChain(chain)
	}

	return nil
}

// selectDevice picks a device from config by name, or returns the default.
func selectDevice(cfg *DevicesConfig, deviceName string) *PairedDevice {
	if deviceName != "" {
		return findDeviceByName(cfg, deviceName)
	}
	if cfg.DefaultDevice != "" {
		return findDeviceByName(cfg, cfg.DefaultDevice)
	}
	if len(cfg.Devices) > 0 {
		return &cfg.Devices[0]
	}
	return nil
}

// nonceMatches compares sent and received nonces using constant-time comparison.
func nonceMatches(sent, received []byte) bool {
	if len(sent) != len(received) {
		return false
	}
	result := byte(0)
	for i := range sent {
		result |= sent[i] ^ received[i]
	}
	return result == 0
}

// parseDERChain parses a slice of DER-encoded certificates.
func parseDERChain(derChain [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(derChain))
	for i, der := range derChain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate at index %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// findMatchingTrustRoot finds which trusted root certificate matches the device's root.
func findMatchingTrustRoot(chain []*x509.Certificate, roots []*x509.Certificate) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	deviceRoot := chain[len(chain)-1]
	deviceRootFP := certFingerprint(deviceRoot)

	for _, root := range roots {
		if certFingerprint(root) == deviceRootFP {
			return root
		}
	}
	return nil
}

// formatTrustAnchor returns a human-readable name for a trust anchor certificate.
func formatTrustAnchor(cert *x509.Certificate) string {
	if cert == nil {
		return "Google Hardware Attestation Root (unknown variant)"
	}

	// Prefer Organization + CommonName for clarity
	if len(cert.Subject.Organization) > 0 && cert.Subject.CommonName != "" {
		return fmt.Sprintf("%s - %s", cert.Subject.Organization[0], cert.Subject.CommonName)
	}

	// Fall back to CommonName
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fall back to Organization
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}

	// Use serial number as last resort (Google's RSA roots use this)
	if cert.Subject.SerialNumber != "" {
		return fmt.Sprintf("Google Hardware Attestation Root (SN=%s)", cert.Subject.SerialNumber)
	}

	return "Google Hardware Attestation Root"
}

// formatAttestDN formats a pkix.Name as a full Distinguished Name string.
func formatAttestDN(cert *x509.Certificate, isSubject bool) string {
	var dn []string
	var n = cert.Subject
	if !isSubject {
		n = cert.Issuer
	}

	if len(n.Country) > 0 {
		dn = append(dn, fmt.Sprintf("C=%s", strings.Join(n.Country, ", ")))
	}
	if len(n.Province) > 0 {
		dn = append(dn, fmt.Sprintf("ST=%s", strings.Join(n.Province, ", ")))
	}
	if len(n.Locality) > 0 {
		dn = append(dn, fmt.Sprintf("L=%s", strings.Join(n.Locality, ", ")))
	}
	if len(n.Organization) > 0 {
		dn = append(dn, fmt.Sprintf("O=%s", strings.Join(n.Organization, ", ")))
	}
	if len(n.OrganizationalUnit) > 0 {
		dn = append(dn, fmt.Sprintf("OU=%s", strings.Join(n.OrganizationalUnit, ", ")))
	}
	if n.CommonName != "" {
		dn = append(dn, fmt.Sprintf("CN=%s", n.CommonName))
	}
	if n.SerialNumber != "" {
		dn = append(dn, fmt.Sprintf("SERIALNUMBER=%s", n.SerialNumber))
	}

	if len(dn) == 0 {
		return "(empty)"
	}
	return strings.Join(dn, ", ")
}

// publicKeyInfo returns public key algorithm, size, and curve information.
func publicKeyInfo(cert *x509.Certificate) (algo string, size int, curve string) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen(), ""
	case *ecdsa.PublicKey:
		curveName := pub.Curve.Params().Name
		return "ECDSA", pub.Curve.Params().BitSize, curveName
	default:
		return cert.PublicKeyAlgorithm.String(), 0, ""
	}
}

// publicKeyFingerprint returns the full SHA-256 fingerprint of the public key.
func publicKeyFingerprint(cert *x509.Certificate) string {
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "(error)"
	}
	hash := sha256.Sum256(pubDER)
	return hex.EncodeToString(hash[:])
}

// certFingerprint returns the full SHA-256 fingerprint of the certificate.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// getCertLabel returns a human-readable label for a certificate position in the chain.
func getCertLabel(index, total int) string {
	if index == 0 {
		return "Leaf/Attestation"
	}
	if index == total-1 {
		return "Root"
	}
	if total > 3 {
		return fmt.Sprintf("Intermediate %d", index)
	}
	return "Intermediate"
}

// printAttestationCertificateChain displays comprehensive details of each certificate in the chain.
func printAttestationCertificateChain(chain []*x509.Certificate) {
	printAttestationCertificateChainWithTrustInfo(chain, nil)
}

// printAttestationCertificateChainWithTrustInfo displays certificate chain with optional trust anchor info.
func printAttestationCertificateChainWithTrustInfo(chain []*x509.Certificate, matchedRoot *x509.Certificate) {
	fmt.Println("Certificate Chain")
	fmt.Println(strings.Repeat("=", 70))

	for i, cert := range chain {
		label := getCertLabel(i, len(chain))

		fmt.Printf("\n[%d] %s\n", i, label)
		fmt.Println(strings.Repeat("-", 70))

		// Subject and Issuer
		fmt.Printf("  Subject:             %s\n", formatAttestDN(cert, true))
		fmt.Printf("  Issuer:              %s\n", formatAttestDN(cert, false))

		// Serial number
		fmt.Printf("  Serial Number:       %s\n", cert.SerialNumber.Text(16))

		// Signature algorithm
		fmt.Printf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())

		// Public key info
		algo, size, curve := publicKeyInfo(cert)
		if curve != "" {
			fmt.Printf("  Public Key:          %s %s (%d bits)\n", algo, curve, size)
		} else if size > 0 {
			fmt.Printf("  Public Key:          %s %d bits\n", algo, size)
		} else {
			fmt.Printf("  Public Key:          %s\n", algo)
		}

		// Public key fingerprint
		fmt.Printf("  Public Key FP:       %s\n", publicKeyFingerprint(cert))

		// Validity period
		fmt.Printf("  Not Before:          %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Printf("  Not After:           %s\n", cert.NotAfter.Format(time.RFC3339))

		// Basic constraints
		fmt.Printf("  Is CA:               %v\n", cert.IsCA)
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			fmt.Printf("  Max Path Length:     %d\n", cert.MaxPathLen)
		}

		// Key usage - use existing function from piv.go
		fmt.Printf("  Key Usage:           %s\n", formatKeyUsage(cert.KeyUsage))

		// Extended key usage - use existing function from piv.go
		if len(cert.ExtKeyUsage) > 0 {
			fmt.Printf("  Extended Key Usage:  %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
		}

		// Subject Alternative Names
		if len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 || len(cert.IPAddresses) > 0 || len(cert.URIs) > 0 {
			fmt.Println("  Subject Alt Names:")
			if len(cert.DNSNames) > 0 {
				fmt.Printf("    DNS:               %s\n", strings.Join(cert.DNSNames, ", "))
			}
			if len(cert.EmailAddresses) > 0 {
				fmt.Printf("    Email:             %s\n", strings.Join(cert.EmailAddresses, ", "))
			}
			if len(cert.IPAddresses) > 0 {
				var ips []string
				for _, ip := range cert.IPAddresses {
					ips = append(ips, ip.String())
				}
				fmt.Printf("    IP:                %s\n", strings.Join(ips, ", "))
			}
			if len(cert.URIs) > 0 {
				var uris []string
				for _, uri := range cert.URIs {
					uris = append(uris, uri.String())
				}
				fmt.Printf("    URI:               %s\n", strings.Join(uris, ", "))
			}
		}

		// Certificate fingerprint
		fmt.Printf("  Certificate FP:      %s\n", certFingerprint(cert))

		// For the root certificate, show trust anchor information if matched
		if i == len(chain)-1 && matchedRoot != nil {
			fmt.Println()
			fmt.Printf("  ** TRUST ANCHOR **\n")
			fmt.Printf("  Verified Against:    %s\n", formatTrustAnchor(matchedRoot))
			if len(matchedRoot.Subject.Organization) > 0 {
				fmt.Printf("  Organization:        %s\n", matchedRoot.Subject.Organization[0])
			}
			fmt.Printf("  Embedded Root FP:    %s\n", certFingerprint(matchedRoot))
			fmt.Printf("  Match Status:        FINGERPRINT MATCHES EMBEDDED ROOT\n")
		}
	}

	fmt.Println()
}

// formatPurposeCodes formats purpose codes with human-readable names.
func formatPurposeCodes(purposes []int) string {
	if len(purposes) == 0 {
		return "(none)"
	}

	var names []string
	for _, p := range purposes {
		if name, ok := purposeNames[p]; ok {
			names = append(names, fmt.Sprintf("%s(%d)", name, p))
		} else {
			names = append(names, fmt.Sprintf("UNKNOWN(%d)", p))
		}
	}
	return strings.Join(names, ", ")
}

// formatAlgorithm formats an algorithm code with human-readable name.
func formatAlgorithm(algo int) string {
	if name, ok := algorithmNames[algo]; ok {
		return fmt.Sprintf("%s (%d)", name, algo)
	}
	return fmt.Sprintf("UNKNOWN (%d)", algo)
}

// formatEcCurve formats an EC curve code with human-readable name.
func formatEcCurve(curve int) string {
	if name, ok := ecCurveNames[curve]; ok {
		return fmt.Sprintf("%s (%d)", name, curve)
	}
	return fmt.Sprintf("UNKNOWN (%d)", curve)
}

// formatOrigin formats a key origin code with human-readable name.
func formatOrigin(origin int) string {
	if name, ok := originNames[origin]; ok {
		return fmt.Sprintf("%s (%d)", name, origin)
	}
	return fmt.Sprintf("UNKNOWN (%d)", origin)
}

// truncateHex encodes data as hex and truncates to maxChars, adding "..." if truncated.
func truncateHex(data []byte, maxChars int) string {
	if len(data) == 0 {
		return ""
	}
	hexStr := hex.EncodeToString(data)
	if len(hexStr) <= maxChars {
		return hexStr
	}
	return hexStr[:maxChars] + "..."
}

// printAuthorizationList prints the contents of an AuthorizationList.
func printAuthorizationList(list *android.AuthorizationList, indent string) {
	if list == nil {
		fmt.Printf("%s(empty)\n", indent)
		return
	}

	hasContent := false

	if len(list.Purpose) > 0 {
		fmt.Printf("%sPurpose:           %s\n", indent, formatPurposeCodes(list.Purpose))
		hasContent = true
	}

	if list.Algorithm > 0 {
		fmt.Printf("%sAlgorithm:         %s\n", indent, formatAlgorithm(list.Algorithm))
		hasContent = true
	}

	if list.KeySize > 0 {
		fmt.Printf("%sKey Size:          %d bits\n", indent, list.KeySize)
		hasContent = true
	}

	if list.EcCurve > 0 {
		fmt.Printf("%sEC Curve:          %s\n", indent, formatEcCurve(list.EcCurve))
		hasContent = true
	}

	if list.Origin > 0 {
		fmt.Printf("%sOrigin:            %s\n", indent, formatOrigin(list.Origin))
		hasContent = true
	}

	if !hasContent && list.RootOfTrust == nil {
		fmt.Printf("%s(no parsed fields)\n", indent)
	}
}

// printKeyDescription displays the parsed Android Key Attestation extension.
func printKeyDescription(desc *android.KeyDescription) {
	fmt.Println("Key Attestation Extension (OID 1.3.6.1.4.1.11129.2.1.17)")
	fmt.Println(strings.Repeat("=", 70))

	// Attestation metadata
	fmt.Println("\nAttestation Metadata")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("  Attestation Version:     %d\n", desc.AttestationVersion)
	fmt.Printf("  Attestation Security:    %s\n", desc.AttestationSecurityLevel.String())
	fmt.Printf("  Keymaster/KeyMint Ver:   %d\n", desc.KeymasterVersion)
	fmt.Printf("  Keymaster Security:      %s\n", desc.KeymasterSecurityLevel.String())

	// Challenge (nonce)
	if len(desc.AttestationChallenge) > 0 {
		fmt.Printf("  Challenge (nonce):       %s\n",
			base64.StdEncoding.EncodeToString(desc.AttestationChallenge))
	} else {
		fmt.Printf("  Challenge (nonce):       (empty)\n")
	}

	// Unique ID
	if len(desc.UniqueID) > 0 {
		fmt.Printf("  Unique ID:               %s\n", hex.EncodeToString(desc.UniqueID))
	} else {
		fmt.Printf("  Unique ID:               (not present)\n")
	}

	// Software Enforced authorization list
	fmt.Println("\nSoftware Enforced Authorization")
	fmt.Println(strings.Repeat("-", 70))
	printAuthorizationList(&desc.SoftwareEnforced, "  ")

	// TEE Enforced authorization list
	fmt.Println("\nTEE Enforced Authorization")
	fmt.Println(strings.Repeat("-", 70))
	printAuthorizationList(&desc.TeeEnforced, "  ")

	// Root of Trust
	if desc.TeeEnforced.RootOfTrust != nil {
		rot := desc.TeeEnforced.RootOfTrust

		fmt.Println("\nRoot of Trust")
		fmt.Println(strings.Repeat("-", 70))

		if len(rot.VerifiedBootKey) > 0 {
			fmt.Printf("  Verified Boot Key:       %s\n", hex.EncodeToString(rot.VerifiedBootKey))
		} else {
			fmt.Printf("  Verified Boot Key:       (not present)\n")
		}

		if rot.DeviceLocked {
			fmt.Printf("  Device Locked:           yes\n")
		} else {
			fmt.Printf("  Device Locked:           no\n")
		}

		fmt.Printf("  Verified Boot State:     %s\n", rot.VerifiedBootState.String())

		if len(rot.VerifiedBootHash) > 0 {
			fmt.Printf("  Verified Boot Hash:      %s\n", hex.EncodeToString(rot.VerifiedBootHash))
		} else {
			fmt.Printf("  Verified Boot Hash:      (not present)\n")
		}
	}

	fmt.Println()
}
