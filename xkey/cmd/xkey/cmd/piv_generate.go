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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// PIV key generation errors.
var (
	// ErrPIVInvalidAlgorithm indicates an invalid key algorithm was specified.
	ErrPIVInvalidAlgorithm = errors.New("piv: invalid algorithm (must be ECCP256, ECCP384, Ed25519, RSA2048, or RSA4096)")

	// ErrPIVInvalidPINPolicy indicates an invalid PIN policy was specified.
	ErrPIVInvalidPINPolicy = errors.New("piv: invalid PIN policy (must be never, once, or always)")

	// ErrPIVInvalidTouchPolicy indicates an invalid touch policy was specified.
	ErrPIVInvalidTouchPolicy = errors.New("piv: invalid touch policy (must be never, cached, or always)")

	// ErrPIVPublicKeyEncodeFailed indicates public key encoding failed.
	ErrPIVPublicKeyEncodeFailed = errors.New("piv: failed to encode public key")
)

// PIVAlgorithm represents a key algorithm for PIV key generation.
type PIVAlgorithm string

const (
	// PIVAlgorithmECCP256 generates a P-256 ECDSA key pair.
	PIVAlgorithmECCP256 PIVAlgorithm = "ECCP256"

	// PIVAlgorithmECCP384 generates a P-384 ECDSA key pair.
	PIVAlgorithmECCP384 PIVAlgorithm = "ECCP384"

	// PIVAlgorithmRSA2048 generates a 2048-bit RSA key pair.
	PIVAlgorithmRSA2048 PIVAlgorithm = "RSA2048"

	// PIVAlgorithmRSA4096 generates a 4096-bit RSA key pair.
	PIVAlgorithmRSA4096 PIVAlgorithm = "RSA4096"

	// PIVAlgorithmEd25519 generates an Ed25519 key pair.
	PIVAlgorithmEd25519 PIVAlgorithm = "ED25519"
)

// String returns the string representation of the algorithm.
func (a PIVAlgorithm) String() string {
	return string(a)
}

// IsValid returns true if the algorithm is valid.
func (a PIVAlgorithm) IsValid() bool {
	switch a {
	case PIVAlgorithmECCP256, PIVAlgorithmECCP384, PIVAlgorithmEd25519, PIVAlgorithmRSA2048, PIVAlgorithmRSA4096:
		return true
	default:
		return false
	}
}

// PIVPINPolicy represents the PIN policy for a PIV slot.
type PIVPINPolicy string

const (
	// PIVPINPolicyNever means PIN is never required.
	PIVPINPolicyNever PIVPINPolicy = "never"

	// PIVPINPolicyOnce means PIN is required once per session.
	PIVPINPolicyOnce PIVPINPolicy = "once"

	// PIVPINPolicyAlways means PIN is required for every operation.
	PIVPINPolicyAlways PIVPINPolicy = "always"
)

// String returns the string representation of the PIN policy.
func (p PIVPINPolicy) String() string {
	return string(p)
}

// IsValid returns true if the PIN policy is valid.
func (p PIVPINPolicy) IsValid() bool {
	switch p {
	case PIVPINPolicyNever, PIVPINPolicyOnce, PIVPINPolicyAlways:
		return true
	default:
		return false
	}
}

// PIVTouchPolicy represents the touch policy for a PIV slot.
type PIVTouchPolicy string

const (
	// PIVTouchPolicyNever means touch is never required.
	PIVTouchPolicyNever PIVTouchPolicy = "never"

	// PIVTouchPolicyCached means touch is cached for a period.
	PIVTouchPolicyCached PIVTouchPolicy = "cached"

	// PIVTouchPolicyAlways means touch is required for every operation.
	PIVTouchPolicyAlways PIVTouchPolicy = "always"
)

// String returns the string representation of the touch policy.
func (t PIVTouchPolicy) String() string {
	return string(t)
}

// IsValid returns true if the touch policy is valid.
func (t PIVTouchPolicy) IsValid() bool {
	switch t {
	case PIVTouchPolicyNever, PIVTouchPolicyCached, PIVTouchPolicyAlways:
		return true
	default:
		return false
	}
}

// PIVKeyGenerateConfig holds configuration for PIV key generation.
type PIVKeyGenerateConfig struct {
	// Slot is the PIV slot to generate the key in.
	Slot pivcert.PIVSlot

	// Algorithm is the key algorithm to use.
	Algorithm PIVAlgorithm

	// PINPolicy is the PIN policy for the slot.
	PINPolicy PIVPINPolicy

	// TouchPolicy is the touch policy for the slot.
	TouchPolicy PIVTouchPolicy

	// Force overwrites existing key without confirmation.
	Force bool
}

// Validate checks if the key generation configuration is valid.
func (c *PIVKeyGenerateConfig) Validate() error {
	if err := pivcert.ValidateSlot(c.Slot); err != nil {
		return ErrPIVInvalidSlot
	}
	if !c.Algorithm.IsValid() {
		return ErrPIVInvalidAlgorithm
	}
	if !c.PINPolicy.IsValid() {
		return ErrPIVInvalidPINPolicy
	}
	if !c.TouchPolicy.IsValid() {
		return ErrPIVInvalidTouchPolicy
	}
	return nil
}

// pivAlgorithmToXKMS maps CLI algorithm names to xkms algorithm identifiers.
// Provides O(1) constant-time lookup.
var pivAlgorithmToXKMS = map[PIVAlgorithm]string{
	PIVAlgorithmECCP256: "ecdsap256",
	PIVAlgorithmECCP384: "ecdsap384",
	PIVAlgorithmEd25519: "ed25519",
	PIVAlgorithmRSA2048: "rsa2048",
	PIVAlgorithmRSA4096: "rsa4096",
}

// pivGenerateCmd generates a key pair in a PIV slot.
var pivGenerateCmd = &cobra.Command{
	Use:   "generate <slot>",
	Short: "Generate a key pair in a PIV slot",
	Long: `Generate a new key pair in the specified PIV slot.

Valid slots are:
  9a - PIV Authentication
  9c - Digital Signature
  9d - Key Management
  9e - Card Authentication

Supported algorithms:
  ECCP256  - ECDSA with P-256 curve (default, recommended)
  ECCP384  - ECDSA with P-384 curve
  Ed25519  - Ed25519 signature key
  RSA2048  - RSA with 2048-bit key
  RSA4096  - RSA with 4096-bit key

PIN policies:
  never  - PIN is never required
  once   - PIN is required once per session (default)
  always - PIN is required for every operation

Touch policies:
  never  - Touch is never required (default)
  cached - Touch is cached for 15 seconds
  always - Touch is required for every operation

Example:
  xkey piv generate 9a --algorithm ECCP256
  xkey piv generate 9c --algorithm RSA2048
  xkey piv generate 9d --algorithm ECCP384 --pin-policy always
  xkey piv generate 9e --touch-policy cached --force`,
	Args: cobra.ExactArgs(1),
	RunE: runPivGenerate,
}

func init() {
	// Add command to PIV parent command
	PIVCmd.AddCommand(pivGenerateCmd)

	// Add flags
	pivGenerateCmd.Flags().StringP("algorithm", "a", "ECCP256", "Key algorithm (ECCP256, ECCP384, Ed25519, RSA2048, RSA4096)")
	pivGenerateCmd.Flags().String("pin-policy", "once", "PIN policy (never, once, always)")
	pivGenerateCmd.Flags().String("touch-policy", "never", "Touch policy (never, cached, always)")
	pivGenerateCmd.Flags().BoolP("force", "f", false, "Overwrite existing key without confirmation")
}

// runPivGenerate executes the piv generate command.
func runPivGenerate(cmd *cobra.Command, args []string) error {
	logger := slog.Default()
	pivCfg := buildPIVConfig()

	// Parse slot argument
	slot, err := parsePIVSlot(args[0])
	if err != nil {
		return err
	}

	// Get flag values
	algorithmStr, _ := cmd.Flags().GetString("algorithm")
	pinPolicyStr, _ := cmd.Flags().GetString("pin-policy")
	touchPolicyStr, _ := cmd.Flags().GetString("touch-policy")
	force, _ := cmd.Flags().GetBool("force")

	// Parse algorithm
	algorithm, err := parseAlgorithm(algorithmStr)
	if err != nil {
		return err
	}

	// Parse PIN policy
	pinPolicy, err := parsePINPolicy(pinPolicyStr)
	if err != nil {
		return err
	}

	// Parse touch policy
	touchPolicy, err := parseTouchPolicy(touchPolicyStr)
	if err != nil {
		return err
	}

	// Build generation config
	genCfg := &PIVKeyGenerateConfig{
		Slot:        slot,
		Algorithm:   algorithm,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
		Force:       force,
	}

	// Validate configuration
	if err := genCfg.Validate(); err != nil {
		return err
	}

	// Map CLI algorithm to xkms algorithm
	xkmsAlgorithm, ok := pivAlgorithmToXKMS[algorithm]
	if !ok {
		return ErrPIVInvalidAlgorithm
	}

	logger.Info("generating PIV key",
		slog.String("slot", string(slot)),
		slog.String("algorithm", string(algorithm)),
		slog.String("xkms_algorithm", xkmsAlgorithm),
		slog.String("pin_policy", string(pinPolicy)),
		slog.String("touch_policy", string(touchPolicy)),
		slog.String("backend", string(pivCfg.Backend)),
	)

	// Ensure PIV manager is initialized with file storage.
	if err := ensurePIVInitialized(pivCfg, logger); err != nil {
		return err
	}

	// Generate key via xkms package-level function.
	ctx := cmd.Context()
	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   string(pivCfg.Backend),
		Slot:      string(slot),
		Algorithm: xkmsAlgorithm,
		Subject:   pivcert.SlotName(slot),
	})
	if err != nil {
		return err
	}

	// Display the result using the response public key PEM.
	slotName := pivcert.SlotName(slot)
	fmt.Printf("Key generated in slot %s (%s)\n", slot, slotName)
	fmt.Printf("Algorithm: %s\n", algorithm)
	fmt.Printf("PIN Policy: %s\n", pinPolicy)
	fmt.Printf("Touch Policy: %s\n", touchPolicy)
	fmt.Printf("Public Key:\n%s", string(resp.PublicKey))

	return nil
}

// ensurePIVInitialized initializes the xkms PIV manager and registers the
// certificate store for the configured backend.
func ensurePIVInitialized(pivCfg *PIVConfig, logger *slog.Logger) error {
	// Create storage backend.
	storage, err := createPIVStorage(pivCfg, logger)
	if err != nil {
		return errors.Join(ErrPIVStorageCreationFailed, err)
	}

	// Initialize PIV manager (idempotent via sync.Once internally).
	if initErr := xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			string(pivCfg.Backend): storage,
		},
	}); initErr != nil {
		return initErr
	}

	// Register the store for the backend (handles the case where PIV was
	// already initialized but this backend was not yet registered).
	return xkms.RegisterPIVStore(string(pivCfg.Backend), storage)
}

// parsePIVSlot parses a slot string into a PIVSlot.
func parsePIVSlot(slot string) (pivcert.PIVSlot, error) {
	s := pivcert.PIVSlot(strings.ToLower(slot))
	if err := pivcert.ValidateSlot(s); err != nil {
		return "", ErrPIVInvalidSlot
	}
	return s, nil
}

// parseAlgorithm parses an algorithm string into a PIVAlgorithm.
func parseAlgorithm(alg string) (PIVAlgorithm, error) {
	a := PIVAlgorithm(strings.ToUpper(alg))
	if !a.IsValid() {
		return "", ErrPIVInvalidAlgorithm
	}
	return a, nil
}

// parsePINPolicy parses a PIN policy string into a PIVPINPolicy.
func parsePINPolicy(policy string) (PIVPINPolicy, error) {
	p := PIVPINPolicy(strings.ToLower(policy))
	if !p.IsValid() {
		return "", ErrPIVInvalidPINPolicy
	}
	return p, nil
}

// parseTouchPolicy parses a touch policy string into a PIVTouchPolicy.
func parseTouchPolicy(policy string) (PIVTouchPolicy, error) {
	t := PIVTouchPolicy(strings.ToLower(policy))
	if !t.IsValid() {
		return "", ErrPIVInvalidTouchPolicy
	}
	return t, nil
}

// encodePublicKeyToPEM encodes a public key to PEM format.
func encodePublicKeyToPEM(publicKey crypto.PublicKey) (string, error) {
	var derBytes []byte
	var err error

	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		derBytes, err = x509.MarshalPKIXPublicKey(key)
	case *rsa.PublicKey:
		derBytes, err = x509.MarshalPKIXPublicKey(key)
	case ed25519.PublicKey:
		derBytes, err = x509.MarshalPKIXPublicKey(key)
	default:
		return "", errors.Join(ErrPIVPublicKeyEncodeFailed, errors.New("unsupported public key type"))
	}

	if err != nil {
		return "", errors.Join(ErrPIVPublicKeyEncodeFailed, err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
