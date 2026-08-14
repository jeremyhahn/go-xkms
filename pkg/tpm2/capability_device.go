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

package tpm2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DeviceCapabilities is a snapshot of the algorithms and ECC curves a specific
// TPM implements, as the device itself reports them.
//
// A TPM 2.0 implementation is free to implement any subset of the algorithms in
// the TCG Algorithm Registry, and vendors differ: TPM_CAP_ALGS and
// TPM_CAP_ECC_CURVES (TCG TPM 2.0 Library Part 3, section 30.2, and Part 2,
// section 6.12) are the only authoritative answer to "can this chip do X". A
// table compiled into this package would be a guess about somebody else's
// silicon, and being wrong in either direction is a defect: asserting an
// algorithm the device lacks produces an operation that is advertised and then
// fails, and refusing one it has denies the caller a capability it paid for.
//
// The zero value is not usable; obtain one from TPM2.Capabilities.
type DeviceCapabilities struct {
	algorithms map[tpm2.TPMAlgID]struct{}
	curves     map[tpm2.TPMECCCurve]struct{}
}

// SupportsAlgorithm reports whether the TPM implements the algorithm.
func (c *DeviceCapabilities) SupportsAlgorithm(alg tpm2.TPMAlgID) bool {
	_, ok := c.algorithms[alg]
	return ok
}

// SupportsCurve reports whether the TPM implements the ECC curve.
func (c *DeviceCapabilities) SupportsCurve(curve tpm2.TPMECCCurve) bool {
	_, ok := c.curves[curve]
	return ok
}

// AlgorithmNames returns the names of every algorithm the TPM implements, in a
// stable order, for inclusion in the error messages that report a refusal.
func (c *DeviceCapabilities) AlgorithmNames() []string {
	names := make([]string, 0, len(c.algorithms))
	for alg := range c.algorithms {
		names = append(names, algorithmName(alg))
	}
	sort.Strings(names)
	return names
}

// CurveNames returns the names of every ECC curve the TPM implements, in a
// stable order.
func (c *DeviceCapabilities) CurveNames() []string {
	names := make([]string, 0, len(c.curves))
	for curve := range c.curves {
		names = append(names, curveName(curve))
	}
	sort.Strings(names)
	return names
}

// algorithmName renders a TPM algorithm ID for a human, falling back to the
// hex identifier for algorithms this package has no name for -- a vendor
// extension, or an entry added to the registry after this build.
func algorithmName(alg tpm2.TPMAlgID) string {
	if name, ok := algNames[alg]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", uint16(alg))
}

// curveName renders a TPM ECC curve ID for a human, falling back to the hex
// identifier for curves this package has no name for.
func curveName(curve tpm2.TPMECCCurve) string {
	if name, ok := curveNames[curve]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", uint16(curve))
}

// Capabilities reads the algorithm and ECC curve sets this TPM implements.
//
// The answer is a property of the silicon and firmware and cannot change while
// the device is open, so it is read once and cached; every later capability
// check is a map lookup rather than another pair of TPM commands.
func (tpm *TPM2) Capabilities() (*DeviceCapabilities, error) {
	if cached := tpm.deviceCaps.Load(); cached != nil {
		return cached, nil
	}
	if tpm.transport == nil {
		return nil, ErrTransportNotInitialized
	}

	algorithms, err := queryAlgorithms(tpm.transport)
	if err != nil {
		return nil, err
	}
	curves, err := queryECCCurves(tpm.transport)
	if err != nil {
		return nil, err
	}

	caps := &DeviceCapabilities{algorithms: algorithms, curves: curves}
	tpm.deviceCaps.Store(caps)
	return caps, nil
}

// queryAlgorithms reads TPM_CAP_ALGS, following the moreData flag so a device
// with more algorithms than fit in one response is read completely (TCG TPM 2.0
// Library Part 3, section 30.2).
func queryAlgorithms(t transport.TPM) (map[tpm2.TPMAlgID]struct{}, error) {
	result := make(map[tpm2.TPMAlgID]struct{})
	property := uint32(0)
	for {
		resp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapAlgs,
			Property:      property,
			PropertyCount: capabilityPageSize,
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		props, err := resp.CapabilityData.Data.Algorithms()
		if err != nil {
			return nil, err
		}
		if len(props.AlgProperties) == 0 {
			return result, nil
		}
		for _, prop := range props.AlgProperties {
			result[prop.Alg] = struct{}{}
		}
		if !resp.MoreData {
			return result, nil
		}
		last := props.AlgProperties[len(props.AlgProperties)-1]
		property = uint32(last.Alg) + 1
	}
}

// queryECCCurves reads TPM_CAP_ECC_CURVES, following the moreData flag.
func queryECCCurves(t transport.TPM) (map[tpm2.TPMECCCurve]struct{}, error) {
	result := make(map[tpm2.TPMECCCurve]struct{})
	property := uint32(0)
	for {
		resp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapECCCurves,
			Property:      property,
			PropertyCount: capabilityPageSize,
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		curves, err := resp.CapabilityData.Data.ECCCurves()
		if err != nil {
			return nil, err
		}
		if len(curves.ECCCurves) == 0 {
			return result, nil
		}
		for _, curve := range curves.ECCCurves {
			result[curve] = struct{}{}
		}
		if !resp.MoreData {
			return result, nil
		}
		last := curves.ECCCurves[len(curves.ECCCurves)-1]
		property = uint32(last) + 1
	}
}

// capabilityPageSize is the number of entries requested per TPM2_GetCapability
// call. It is a transfer-size choice only: the moreData flag drives the loop, so
// a TPM that returns fewer entries than asked for is read across several calls.
const capabilityPageSize = 100

// SupportsParameters reports whether this TPM can create an object with the
// given public parameters.
//
// TPM2_GetCapability answers which algorithms exist but not which combinations
// of them are usable, and for RSA it cannot answer at all: the TCG fixed
// property list has no property that reports the modulus sizes a device
// supports. TPM2_TestParms is the command that does answer -- it validates a
// TPMT_PUBLIC_PARMS and returns TPM_RC_SUCCESS or an error, without creating
// anything (TCG TPM 2.0 Library Part 3, section 30.3). Asking it is how a
// modulus size is learned from the device instead of assumed.
func (tpm *TPM2) SupportsParameters(parms tpm2.TPMTPublicParms) bool {
	if tpm.transport == nil {
		return false
	}
	_, err := tpm2.TestParms{Parameters: parms}.Execute(tpm.transport)
	return err == nil
}

// SupportedRSAKeyBits returns the RSA modulus sizes this TPM will create, in
// ascending order.
//
// Each size TPM 2.0 defines is offered to TPM2_TestParms and the device's answer
// is recorded, so the result describes the silicon rather than this package's
// expectations. The answer cannot change while the device is open and is cached
// after the first call.
func (tpm *TPM2) SupportedRSAKeyBits() []int {
	if cached := tpm.rsaKeyBits.Load(); cached != nil {
		return *cached
	}

	supported := make([]int, 0, len(definedRSAKeyBits))
	for _, keyBits := range definedRSAKeyBits {
		parms := tpm2.TPMTPublicParms{
			Type: tpm2.TPMAlgRSA,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
					Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
					KeyBits:   tpm2.TPMKeyBits(keyBits),
				},
			),
		}
		if tpm.SupportsParameters(parms) {
			supported = append(supported, keyBits)
		}
	}

	tpm.rsaKeyBits.Store(&supported)
	return supported
}

// ParametersNotSupportedError reports that a TPM declined a combination of
// public parameters that its individual algorithms and curves all appeared to
// allow.
//
// TPM2_TestParms is the device's own verdict on the whole TPMT_PUBLIC_PARMS
// (TCG TPM 2.0 Library Part 3, section 30.3), so a refusal here means the
// combination is unsupported even though every part of it is implemented. It is
// reported rather than passed to TPM2_Create, where the same refusal would
// arrive as a bare response code from inside a key-creation command.
type ParametersNotSupportedError struct {
	// Requested describes the parameters the caller asked for.
	Requested string
}

func (e *ParametersNotSupportedError) Error() string {
	return "tpm: this TPM declined the requested key parameters: " + e.Requested
}

// Unwrap reports ErrAlgorithmNotSupported so callers can classify the refusal
// with errors.Is alongside the other capability refusals.
func (e *ParametersNotSupportedError) Unwrap() error {
	return ErrAlgorithmNotSupported
}

// AlgorithmNotSupportedError reports that the TPM does not implement a
// requested algorithm, and names both what was asked for and what the device
// offers instead.
//
// The device's own list is carried because the caller cannot otherwise act on
// the refusal: "SHA-512 is not supported" leaves an operator guessing, where
// "SHA-512 is not supported; this TPM implements SHA-1, SHA-256, SHA-384" says
// exactly which request would have worked.
type AlgorithmNotSupportedError struct {
	// Requested is the algorithm the caller asked for.
	Requested string

	// Supported lists the algorithms the device reports.
	Supported []string
}

func (e *AlgorithmNotSupportedError) Error() string {
	return fmt.Sprintf(
		"tpm: algorithm %s is not implemented by this TPM; it implements: %s",
		e.Requested, strings.Join(e.Supported, ", "))
}

// Unwrap reports ErrAlgorithmNotSupported so callers can classify the refusal
// with errors.Is without matching on the message.
func (e *AlgorithmNotSupportedError) Unwrap() error {
	return ErrAlgorithmNotSupported
}

// CurveNotSupportedError reports that the TPM does not implement a requested
// ECC curve, and names both what was asked for and what the device offers.
//
// Substituting a curve the device does happen to implement is the failure this
// type exists to prevent: a caller that asked for P-521 and silently received a
// P-256 key gets a key with a security level it did not choose, and finds out
// only if it ever compares the two.
type CurveNotSupportedError struct {
	// Requested is the curve the caller asked for.
	Requested string

	// Supported lists the curves the device reports.
	Supported []string
}

func (e *CurveNotSupportedError) Error() string {
	return fmt.Sprintf(
		"tpm: ECC curve %s is not implemented by this TPM; it implements: %s",
		e.Requested, strings.Join(e.Supported, ", "))
}

// Unwrap reports ErrCurveNotSupported so callers can classify the refusal with
// errors.Is.
func (e *CurveNotSupportedError) Unwrap() error {
	return ErrCurveNotSupported
}

// KeySizeNotSupportedError reports that a requested RSA modulus size is not one
// the TPM can create.
//
// Unlike algorithms and curves, RSA key sizes are not discoverable: the TCG
// fixed-property list has no TPM_PT for them, so TPM2_GetCapability cannot be
// asked which moduli a device supports. What can be checked without guessing is
// the TCG Algorithm Registry's set of legal sizes; a size that is legal but that
// a particular device declines is reported by the TPM itself when the key is
// created, and that error is surfaced rather than pre-empted.
type KeySizeNotSupportedError struct {
	// Requested is the modulus size in bits the caller asked for.
	Requested int

	// Supported lists the modulus sizes TPM 2.0 defines.
	Supported []int
}

func (e *KeySizeNotSupportedError) Error() string {
	sizes := make([]string, 0, len(e.Supported))
	for _, size := range e.Supported {
		sizes = append(sizes, fmt.Sprintf("%d", size))
	}
	return fmt.Sprintf(
		"tpm: RSA key size %d is not defined by TPM 2.0; defined sizes are: %s",
		e.Requested, strings.Join(sizes, ", "))
}

// Unwrap reports ErrInvalidKeySize so callers can classify the refusal with
// errors.Is.
func (e *KeySizeNotSupportedError) Unwrap() error {
	return ErrInvalidKeySize
}

// SchemeNotImplementedError reports that a scheme TPM 2.0 defines, and that the
// device may well implement, is not one this package can operate a key with.
//
// It is deliberately distinct from AlgorithmNotSupportedError: the device is not
// the limitation here, this package is. Creating a key this package could not
// subsequently sign or decrypt with would be the "advertised but broken" shape
// in miniature, so the refusal happens at creation and names the gap.
type SchemeNotImplementedError struct {
	// Requested is the scheme the caller asked for.
	Requested string

	// Implemented lists the schemes this package can operate for the key type.
	Implemented []string
}

func (e *SchemeNotImplementedError) Error() string {
	return fmt.Sprintf(
		"tpm: signature scheme %s is not implemented by this package; implemented schemes are: %s",
		e.Requested, strings.Join(e.Implemented, ", "))
}

// Unwrap reports ErrSchemeNotImplemented so callers can classify the refusal
// with errors.Is.
func (e *SchemeNotImplementedError) Unwrap() error {
	return ErrSchemeNotImplemented
}
