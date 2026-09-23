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

//go:build ble

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Phone enrollment errors.
var (
	// ErrEnrollPhoneRefused means policy refused the device. The specific
	// reason travels as the cause.
	ErrEnrollPhoneRefused = errors.New("enroll: the device was refused by policy")

	// ErrEnrollPhoneNoCA means neither a local CA nor an xkms endpoint was
	// available to sign, so there is nothing to enroll against.
	ErrEnrollPhoneNoCA = errors.New("enroll: no certificate authority is configured")

	// ErrEnrollPhoneNonce means the enrollment nonce could not be generated.
	ErrEnrollPhoneNonce = errors.New("enroll: failed to generate an enrollment nonce")

	// ErrEnrollPhoneRejectedCredential means the phone would not accept the
	// certificate this CA issued.
	ErrEnrollPhoneRejectedCredential = errors.New("enroll: the phone rejected the issued credential")
)

// enrollmentNonceSize is 32 bytes: the challenge only has to be unguessable
// and unique, and it travels inside the attestation extension.
const enrollmentNonceSize = 32

var deviceEnrollPhoneCmd = &cobra.Command{
	Use:   "enroll-phone",
	Short: "Issue a device credential to a paired phone",
	Long: `Enroll a paired phone as a client of this enterprise CA.

The phone generates a hardware-backed identity key, and returns a CSR for it
together with the Android Keystore attestation chain covering that key. The
attestation proves, to a Google hardware root:

  1. The key lives in a keystore the OS cannot forge
  2. The device booted verified, with a locked bootloader
  3. Which application is asking, by package name and signing certificate

The challenge this command generates is embedded in that attestation by the
TEE, so the evidence belongs to this exchange and cannot be replayed.

The issued credential is an LDevID in the sense of IEEE 802.1AR: its validity
period is the re-attestation cadence. When it lapses the phone must present
fresh attestation to obtain another.

The signing CA is either this host or an xkms server:

  --ca local   this host signs, using its own CA (the default)
  --ca xkms    an xkms server signs, and applies its own enrollment policy

Examples:
  # Enroll the default device against this host's CA
  xkey device enroll-phone

  # Enroll against an xkms server acting as the enterprise CA
  xkey device enroll-phone --ca xkms

  # Pin the application build that may enroll
  xkey device enroll-phone \
    --allow-package com.automatethethings.xkey \
    --allow-signer 471812d1...aba

  # Shorten the re-attestation cadence to 30 days
  xkey device enroll-phone --validity 720h`,
	RunE: runDeviceEnrollPhone,
}

func init() {
	deviceCmd.AddCommand(deviceEnrollPhoneCmd)

	f := deviceEnrollPhoneCmd.Flags()
	f.String("device", "", "Device name to enroll (uses the default if unset)")
	f.String("ca", "local", "Signing authority: local or xkms")
	f.Duration("validity", 0, "Credential lifetime, and so the re-attestation cadence (default 90 days)")
	f.StringSlice("allow-package", nil, "Android package name permitted to enroll (repeatable)")
	f.StringSlice("allow-signer", nil, "Hex SHA-256 signing certificate digest permitted (repeatable)")
	f.Bool("allow-unpinned", false, "Permit an allow-listed package with no signing digest (development only)")
	f.String("min-security-level", "trusted_environment", "Weakest key protection accepted: software, trusted_environment, strongbox")
	f.Bool("require-verified-boot", true, "Refuse devices that are not verified-boot with a locked bootloader")
	f.String("subject", "", "Subject DN to request on the certificate")

	_ = viper.BindPFlag("device.enroll.ca", f.Lookup("ca"))
	_ = viper.BindPFlag("device.enroll.validity", f.Lookup("validity"))
	_ = viper.BindPFlag("device.enroll.allow_packages", f.Lookup("allow-package"))
	_ = viper.BindPFlag("device.enroll.allow_signers", f.Lookup("allow-signer"))
	_ = viper.BindPFlag("device.enroll.min_security_level", f.Lookup("min-security-level"))
	_ = viper.BindPFlag("device.enroll.require_verified_boot", f.Lookup("require-verified-boot"))
}

// enrollPhoneOptions is the resolved configuration for one enrollment, kept
// separate from cobra so the flow can be exercised without a command line.
type enrollPhoneOptions struct {
	DeviceFilter        string
	CASource            string
	Validity            time.Duration
	AllowPackages       []string
	AllowSigners        []string
	AllowUnpinned       bool
	MinSecurityLevel    string
	RequireVerifiedBoot bool
	Subject             string
}

func runDeviceEnrollPhone(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()
	opts := &enrollPhoneOptions{}
	opts.DeviceFilter, _ = f.GetString("device")
	opts.CASource, _ = f.GetString("ca")
	opts.Validity, _ = f.GetDuration("validity")
	opts.AllowPackages, _ = f.GetStringSlice("allow-package")
	opts.AllowSigners, _ = f.GetStringSlice("allow-signer")
	opts.AllowUnpinned, _ = f.GetBool("allow-unpinned")
	opts.MinSecurityLevel, _ = f.GetString("min-security-level")
	opts.RequireVerifiedBoot, _ = f.GetBool("require-verified-boot")
	opts.Subject, _ = f.GetString("subject")

	return enrollPhone(context.Background(), opts, slog.Default())
}

// buildEnrollmentPolicy turns the flags into the policy applied to the phone's
// evidence.
//
// Failing closed is the default and stays the default: with no --allow-package
// the policy has an empty allow-list, and Evaluate refuses. That is deliberate.
// An operator who has not said which application may enroll has not decided,
// and guessing on their behalf is how a CA ends up certifying anything.
func buildEnrollmentPolicy(opts *enrollPhoneOptions) *pairing.EnrollmentPolicy {
	policy := pairing.NewEnrollmentPolicy()
	policy.Validity = opts.Validity
	policy.AllowUnpinnedSignatures = opts.AllowUnpinned
	policy.RequireVerifiedBoot = opts.RequireVerifiedBoot
	if opts.MinSecurityLevel != "" {
		policy.MinSecurityLevel = opts.MinSecurityLevel
	}

	for _, pkg := range opts.AllowPackages {
		policy.AllowedApplications = append(policy.AllowedApplications, pairing.AllowedApplication{
			PackageName:    pkg,
			SigningDigests: opts.AllowSigners,
		})
	}
	return policy
}

// enrollPhone runs the whole exchange: ask, judge, sign, hand back.
func enrollPhone(ctx context.Context, opts *enrollPhoneOptions, logger *slog.Logger) error {
	cfg, err := loadDevicesConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("No paired devices. Use 'xkey device pair' first.")
			return ErrDeviceNotPaired
		}
		return &SentinelCauseError{Sentinel: ErrDeviceConfigLoadFailed, Cause: err}
	}
	if len(cfg.Devices) == 0 {
		fmt.Println("No paired devices. Use 'xkey device pair' first.")
		return ErrDeviceNotPaired
	}

	device := selectDevice(cfg, opts.DeviceFilter)
	if device == nil {
		return ErrDeviceNotFound
	}

	policy := buildEnrollmentPolicy(opts)

	// The trust anchors are the Google hardware attestation roots. Without
	// them the chain proves nothing, so this is resolved before the phone is
	// disturbed rather than after it has produced a key.
	roots, err := androidAttestationRoots()
	if err != nil {
		return err
	}
	policy.TrustedRoots = roots

	nonce := make([]byte, enrollmentNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return &SentinelCauseError{Sentinel: ErrEnrollPhoneNonce, Cause: err}
	}

	callCtx, cancel := context.WithTimeout(ctx, defaultSessionTimeout)
	defer cancel()

	fmt.Printf("Enrolling device %q...\n", device.Name)
	session, closeSession, err := openDeviceSession(callCtx, device, logger)
	if err != nil {
		return err
	}
	defer closeSession()

	fmt.Println("Requesting a device enrollment package...")
	raw, err := session.Call(callCtx, pairing.MethodLocalGetDeviceEnrollmentRequest,
		&pairing.LocalGetDeviceEnrollmentRequestParams{
			Nonce:   base64.StdEncoding.EncodeToString(nonce),
			Subject: opts.Subject,
		})
	if err != nil {
		return err
	}

	var result pairing.LocalGetDeviceEnrollmentRequestResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return &WrappedError{Msg: "failed to decode the enrollment package", Err: err}
	}

	fmt.Printf("Evidence: format=%s chain=%d securityLevel=%s model=%s\n",
		result.Format, len(result.AttestationChain), result.SecurityLevel, result.PlatformModel)

	fmt.Println("Verifying attestation against policy...")
	decision, err := policy.Evaluate(&result, nonce, time.Now())
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrEnrollPhoneRefused, Cause: err}
	}

	fmt.Printf("Accepted: package=%s signer=%s level=%s locked=%t\n",
		decision.PackageName, decision.SigningDigest,
		decision.SecurityLevel, decision.DeviceLocked)

	certDER, chainDER, err := signEnrollmentCSR(callCtx, opts, &result, nonce, decision)
	if err != nil {
		return err
	}

	issued, err := x509.ParseCertificate(certDER)
	if err != nil {
		return &WrappedError{Msg: "the CA returned an unparsable certificate", Err: err}
	}

	fmt.Println("Delivering the credential to the phone...")
	storeRaw, err := session.Call(callCtx, pairing.MethodLocalStoreDeviceCredential,
		&pairing.LocalStoreDeviceCredentialParams{
			Certificate: base64.StdEncoding.EncodeToString(certDER),
			Chain:       encodeChain(chainDER),
		})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrEnrollPhoneRejectedCredential, Cause: err}
	}

	var stored pairing.LocalStoreDeviceCredentialResult
	if err := json.Unmarshal(storeRaw, &stored); err != nil {
		return &WrappedError{Msg: "failed to decode the store response", Err: err}
	}
	if !stored.Stored {
		return ErrEnrollPhoneRejectedCredential
	}

	fmt.Printf("\nEnrolled %q\n", device.Name)
	fmt.Printf("  Subject:      %s\n", issued.Subject)
	fmt.Printf("  Issuer:       %s\n", issued.Issuer)
	fmt.Printf("  Serial:       %s\n", issued.SerialNumber.Text(16))
	fmt.Printf("  Fingerprint:  %s\n", stored.Fingerprint)
	fmt.Printf("  Re-attest by: %s\n", time.UnixMilli(stored.NotAfter).Format(time.RFC3339))
	return nil
}

// encodeChain renders issuer certificates for the wire.
func encodeChain(chain [][]byte) []string {
	if len(chain) == 0 {
		return nil
	}
	out := make([]string, 0, len(chain))
	for _, der := range chain {
		out = append(out, base64.StdEncoding.EncodeToString(der))
	}
	return out
}
