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

package luks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMTokenType is the LUKS2 token type written for a SealParentSSRK seal.
// The value matches systemd-cryptsetup's "systemd-tpm2" token so
// systemd-cryptenroll and crypttab can unlock the volume at boot.
const TPMTokenType = "systemd-tpm2"

// XKMSTPMTokenType is the LUKS2 token type written for a SealParentPSRK
// seal. It is go-xkms's own token: nothing outside go-xkms is expected to
// unseal it, so it does not claim the systemd-tpm2 shape.
const XKMSTPMTokenType = "xkms-tpm2"

// platformSealCN and ssrkSealCN name the sealed keyed-hash object's
// KeyAttributes.CN. They identify the object in TPM logging only; go-xkms
// LUKS tokens are self-contained (the blob travels in the LUKS2 header) and
// never look a sealed object up by CN.
const (
	platformSealCN = "luks-volume-key-psrk"
	ssrkSealCN     = "luks-volume-key-ssrk"
)

// pcrBankAlgIDs maps a TPMSealerConfig.PCRBank string to its go-tpm
// algorithm ID.
var pcrBankAlgIDs = map[string]libtpm2.TPMAlgID{
	"sha1":   libtpm2.TPMAlgSHA1,
	"sha256": libtpm2.TPMAlgSHA256,
	"sha384": libtpm2.TPMAlgSHA384,
	"sha512": libtpm2.TPMAlgSHA512,
}

// pcrBankNames is the reverse of pcrBankAlgIDs, for recording the bank name
// in a token.
var pcrBankNames = map[libtpm2.TPMAlgID]string{
	libtpm2.TPMAlgSHA1:   "sha1",
	libtpm2.TPMAlgSHA256: "sha256",
	libtpm2.TPMAlgSHA384: "sha384",
	libtpm2.TPMAlgSHA512: "sha512",
}

// resolvePCRBank translates a TPMSealerConfig.PCRBank string to a go-tpm
// algorithm ID, defaulting empty to SHA-256.
func resolvePCRBank(name string) (libtpm2.TPMAlgID, error) {
	if name == "" {
		return libtpm2.TPMAlgSHA256, nil
	}
	alg, ok := pcrBankAlgIDs[strings.ToLower(name)]
	if !ok {
		return 0, &errs.Detail{Err: ErrInvalidPCRBank, Detail: name}
	}
	return alg, nil
}

// TPMSealUnsealer is the subset of pkg/tpm2.TPM2's behavior TPMSealer needs:
// PSRK/SSRK-parented sealing and unsealing, plus the raw transport for
// computing an SSRK-parented PolicyPCR digest. Any *pkg/tpm2.TPM2 satisfies
// it; the narrow interface keeps this package from depending on pkg/tpm2's
// full TrustedPlatformModule surface.
type TPMSealUnsealer interface {
	// Seal implements types.Sealer's seal half.
	Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error)

	// Unseal implements types.Sealer's unseal half.
	Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error)

	// PlatformSRKAttributes returns go-xkms's Platform SRK attributes,
	// including its PIN when a PlatformKeyStore is attached and unlocked.
	PlatformSRKAttributes() (*types.KeyAttributes, error)

	// SSRKAttributes returns the TCG-standard Shared SRK attributes.
	SSRKAttributes() (*types.KeyAttributes, error)

	// Transport returns the raw TPM transport, used only to compute an
	// SSRK-parented PolicyPCR digest via a trial session.
	Transport() transport.TPM
}

// TPMSealResult is a TPMSealer.SealPassphrase result: the sealed passphrase
// plus the LUKS2 token to persist in the volume's header and the raw sealed
// blobs.
//
// Passphrase is protected memory: it lives in an mlocked, canary-guarded
// *secure.Buffer rather than a plain []byte, so the LUKS passphrase never
// sits on the ordinary Go heap between SealPassphrase and the caller
// consuming it. Callers MUST call Passphrase.Destroy() once the passphrase
// has been persisted (e.g. handed to a LUKS keyslot add) or otherwise
// consumed.
type TPMSealResult struct {
	Passphrase  *secure.Buffer
	Token       *luks2.Token
	PublicBlob  []byte
	PrivateBlob []byte
}

// TPMSealer seals and unseals LUKS volume passphrases against a TPM 2.0,
// parented to either go-xkms's Platform SRK or the TCG Shared SRK (see
// SealParent). Every seal/unseal is delegated to a TPMSealUnsealer — the
// same pkg/tpm2.TPM2.Seal/Unseal every other go-xkms TPM secret goes
// through — so this package drives no TPM command of its own except the
// PolicyPCR trial session SealParentSSRK needs to compute the digest it
// hands to that Seal call.
type TPMSealer struct {
	tpm     TPMSealUnsealer
	parent  SealParent
	pcrBank libtpm2.TPMAlgID
}

// NewTPMSealer constructs a TPM-backed LUKS passphrase sealer bound to tpm.
// It returns ErrTPMNoTransport when tpm is nil, and validates cfg (see
// TPMSealerConfig.Validate).
func NewTPMSealer(tpm TPMSealUnsealer, cfg TPMSealerConfig) (*TPMSealer, error) {
	if tpm == nil {
		return nil, ErrTPMNoTransport
	}
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	bank, err := resolvePCRBank(cfg.PCRBank)
	if err != nil {
		return nil, err
	}
	return &TPMSealer{tpm: tpm, parent: cfg.Parent, pcrBank: bank}, nil
}

// Parent returns the sealer's configured storage parent.
func (s *TPMSealer) Parent() SealParent { return s.parent }

// SealPassphrase generates a random 32-byte LUKS passphrase and seals it
// under the sealer's configured TPM parent.
//
//   - SealParentPSRK binds the sealed object to go-xkms's platform PCR
//     policy (pkg/tpm2's "platform" policy) under the Platform SRK. pcrs
//     must be empty: the platform policy's PCR selection is fixed by
//     pkg/tpm2 configuration, not chosen per call. The token type is
//     XKMSTPMTokenType.
//   - SealParentSSRK binds the sealed object to a plain PolicyPCR digest
//     over pcrs (bank fixed at construction, default SHA-256) under the
//     Shared SRK with empty parent auth, producing a systemd-tpm2
//     compatible token (TPMTokenType).
func (s *TPMSealer) SealPassphrase(ctx context.Context, pcrs []int32) (*TPMSealResult, error) {
	switch s.parent {
	case SealParentPSRK:
		if len(pcrs) != 0 {
			return nil, ErrTPMPCRSelectionNotSupported
		}
		return s.sealPlatform(ctx)
	case SealParentSSRK:
		return s.sealSSRK(ctx, pcrs)
	default:
		return nil, &SealParentInvalidError{Value: uint8(s.parent)}
	}
}

// randomPassphrase returns 32 cryptographically random bytes for use as a
// LUKS passphrase.
func randomPassphrase() ([]byte, error) {
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("rand: %v", err)}
	}
	return passphrase, nil
}

// sealPlatform seals under the Platform SRK, bound to go-xkms's platform PCR
// policy.
func (s *TPMSealer) sealPlatform(ctx context.Context) (*TPMSealResult, error) {
	parentAttrs, err := s.tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "luks: no usable Platform SRK for sealing", Err: err}
	}

	passphrase, err := randomPassphrase()
	if err != nil {
		return nil, err
	}

	// No password: pkg/tpm2 binds the object to the platform policy's
	// PolicyPCR branch alone, with USERWITHAUTH clear, so only a policy
	// session proving the platform state unseals it.
	keyAttrs := &types.KeyAttributes{
		CN:        platformSealCN,
		Parent:    parentAttrs,
		TPMPolicy: types.TPMPolicyPlatform,
	}

	sealed, err := s.tpm.Seal(ctx, passphrase, &types.SealOptions{KeyAttributes: keyAttrs})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMSealFailed, Cause: err}
	}

	var handle uint64
	if parentAttrs.TPMAttributes != nil {
		handle = uint64(parentAttrs.TPMAttributes.Handle)
	}

	token := &luks2.Token{
		Type:          XKMSTPMTokenType,
		TPM2Blob:      EncodeTPMSealBlobs(sealed.TPMPublic, sealed.TPMPrivate),
		TPM2KeyHandle: handle,
	}

	return s.buildResult(passphrase, token, sealed)
}

// sealSSRK seals under the Shared SRK with empty parent auth, bound to a
// plain PolicyPCR digest over pcrs.
func (s *TPMSealer) sealSSRK(ctx context.Context, pcrs []int32) (*TPMSealResult, error) {
	parentAttrs, err := s.tpm.SSRKAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "luks: no usable Shared SRK for sealing", Err: err}
	}

	pcrSel := buildPCRSelection(s.pcrBank, pcrs)
	policyDigest, err := computePCRPolicyDigest(s.tpm.Transport(), pcrSel)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMPolicyFailed, Detail: fmt.Sprintf("%v", err)}
	}

	passphrase, err := randomPassphrase()
	if err != nil {
		return nil, err
	}

	// The object is bound to the PolicyPCR digest alone: pkg/tpm2 clears
	// USERWITHAUTH on any object with an authPolicy, so only a policy
	// session reaching the digest -- systemd-cryptsetup's, at boot --
	// unseals it. The PCR list itself is recorded in the token below.
	keyAttrs := &types.KeyAttributes{
		CN:     ssrkSealCN,
		Parent: parentAttrs,
	}

	sealed, err := s.tpm.Seal(ctx, passphrase, &types.SealOptions{
		KeyAttributes: keyAttrs,
		AuthPolicy:    policyDigest,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMSealFailed, Cause: err}
	}

	var handle uint64
	if parentAttrs.TPMAttributes != nil {
		handle = uint64(parentAttrs.TPMAttributes.Handle)
	}

	token := &luks2.Token{
		Type:           TPMTokenType,
		TPM2Blob:       EncodeTPMSealBlobs(sealed.TPMPublic, sealed.TPMPrivate),
		TPM2PCRBank:    pcrBankNames[s.pcrBank],
		TPM2PCRs:       int32sToInts(pcrs),
		TPM2KeyHandle:  handle,
		TPM2PolicyHash: base64.StdEncoding.EncodeToString(policyDigest),
	}

	return s.buildResult(passphrase, token, sealed)
}

// buildResult moves passphrase into protected memory and assembles the
// common TPMSealResult shape shared by both seal paths.
func (s *TPMSealer) buildResult(passphrase []byte, token *luks2.Token, sealed *types.SealedData) (*TPMSealResult, error) {
	passBuf, err := secure.NewBufferFromBytes(passphrase)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("seal passphrase enclave: %v", err)}
	}
	return &TPMSealResult{
		Passphrase:  passBuf,
		Token:       token,
		PublicBlob:  sealed.TPMPublic,
		PrivateBlob: sealed.TPMPrivate,
	}, nil
}

// UnsealPassphrase unseals a passphrase from a LUKS2 token previously
// produced by SealPassphrase.
//
// Only SealParentPSRK tokens can be unsealed through this method: it
// dispatches on the sealer's own configured parent, not the token's Type
// field, so a sealer constructed for one parent refuses to touch a token
// shaped for the other. Calling this on a TPMSealer configured for
// SealParentSSRK always returns ErrTPMSSRKUnsealUnsupported — see that
// error's doc comment for why.
func (s *TPMSealer) UnsealPassphrase(ctx context.Context, token *luks2.Token) ([]byte, error) {
	if token == nil {
		return nil, &errs.Detail{Err: ErrTPMInvalidToken, Detail: "nil token"}
	}
	switch s.parent {
	case SealParentPSRK:
		return s.unsealPlatform(ctx, token)
	case SealParentSSRK:
		return nil, ErrTPMSSRKUnsealUnsupported
	default:
		return nil, &SealParentInvalidError{Value: uint8(s.parent)}
	}
}

func (s *TPMSealer) unsealPlatform(ctx context.Context, token *luks2.Token) ([]byte, error) {
	parentAttrs, err := s.tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "luks: no usable Platform SRK for unsealing", Err: err}
	}

	publicBlob, privateBlob, err := DecodeTPMSealBlobs(token.TPM2Blob)
	if err != nil {
		return nil, err
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		TPMPublic:  publicBlob,
		TPMPrivate: privateBlob,
		KeyID:      platformSealCN,
	}
	keyAttrs := &types.KeyAttributes{
		CN:        platformSealCN,
		Parent:    parentAttrs,
		TPMPolicy: types.TPMPolicyPlatform,
	}

	plaintext, err := s.tpm.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: keyAttrs})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMUnsealFailed, Cause: err}
	}
	return plaintext, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildPCRSelection converts a slice of PCR indexes into a TPMLPCRSelection
// for the requested bank. An empty slice yields an empty selection (valid —
// produces a trivial policy that is satisfied unconditionally).
func buildPCRSelection(bank libtpm2.TPMAlgID, pcrs []int32) libtpm2.TPMLPCRSelection {
	sel := make([]byte, 3)
	for _, p := range pcrs {
		if p < 0 || p > 23 {
			continue
		}
		sel[p/8] |= 1 << (uint(p) % 8)
	}
	return libtpm2.TPMLPCRSelection{
		PCRSelections: []libtpm2.TPMSPCRSelection{{
			Hash:      bank,
			PCRSelect: sel,
		}},
	}
}

// computePCRPolicyDigest runs a trial session + PolicyPCR to derive the
// policy digest for the given selection. A trial session lets the TPM
// compute the digest deterministically without requiring a live
// authentication or perturbing real PCR-gated policy sessions.
func computePCRPolicyDigest(tpm transport.TPM, pcrSel libtpm2.TPMLPCRSelection) (digest []byte, err error) {
	trialSession, cleanup, err := libtpm2.PolicySession(tpm, libtpm2.TPMAlgSHA256, 16, libtpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := cleanup(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if _, err := (libtpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs:          pcrSel,
	}).Execute(tpm); err != nil {
		return nil, err
	}

	getDigest, err := (libtpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}).Execute(tpm)
	if err != nil {
		return nil, err
	}
	return getDigest.PolicyDigest.Buffer, nil
}

// int32sToInts converts []int32 to []int for the LUKS2 token's TPM2PCRs
// field.
func int32sToInts(src []int32) []int {
	if len(src) == 0 {
		return nil
	}
	out := make([]int, len(src))
	for i, v := range src {
		out[i] = int(v)
	}
	return out
}

// EncodeTPMSealBlobs packs the public and private portions of a sealed
// object into a single base64 string with a length-prefix separator so both
// halves travel in a single token field without an extra schema.
//
// Wire format:
//
//	base64( uint32BE(len(public)) | public | private )
func EncodeTPMSealBlobs(public, private []byte) string {
	buf := make([]byte, 4+len(public)+len(private))
	pl := len(public)
	buf[0] = byte(pl >> 24)
	buf[1] = byte(pl >> 16)
	buf[2] = byte(pl >> 8)
	buf[3] = byte(pl)
	copy(buf[4:], public)
	copy(buf[4+pl:], private)
	return base64.StdEncoding.EncodeToString(buf)
}

// DecodeTPMSealBlobs reverses EncodeTPMSealBlobs. It returns
// ErrTPMInvalidToken when the blob is not base64 or its length prefix does
// not match the payload.
func DecodeTPMSealBlobs(s string) ([]byte, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTPMInvalidToken, Detail: fmt.Sprintf("tpm2-blob: %v", err)}
	}
	if len(raw) < 4 {
		return nil, nil, &errs.Detail{Err: ErrTPMInvalidToken, Detail: "tpm2-blob too short"}
	}
	pl := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if pl < 0 || 4+pl > len(raw) {
		return nil, nil, &errs.Detail{Err: ErrTPMInvalidToken, Detail: "tpm2-blob length mismatch"}
	}
	return raw[4 : 4+pl], raw[4+pl:], nil
}
