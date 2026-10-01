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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpmdev"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMTokenType is the LUKS2 token type written for TPM-sealed keyslots.
// The value matches systemd-cryptsetup's "systemd-tpm2" token so third
// parties can still recognise the slot.
const TPMTokenType = "systemd-tpm2"

// DefaultTPMParentHandle is the persistent handle used for the sealing
// parent when none is given in the seal request. 0x81000001 is the storage
// SRK defined in the TCG PC Client Platform spec.
const DefaultTPMParentHandle uint32 = 0x81000001

// TPMOpener opens a go-tpm transport for a sealing / unsealing operation.
// The default implementation wraps linuxtpm.Open; tests inject an adapter
// around go-tpm-tools/simulator.
type TPMOpener interface {
	Open(ctx context.Context) (transport.TPMCloser, error)
}

// TPMOpenerFunc adapts a function to the TPMOpener interface.
type TPMOpenerFunc func(ctx context.Context) (transport.TPMCloser, error)

// defaultTPMDevice is the kernel resource-managed TPM the default opener
// uses.
const defaultTPMDevice = "/dev/tpmrm0"

// Open invokes the underlying function.
func (f TPMOpenerFunc) Open(ctx context.Context) (transport.TPMCloser, error) { return f(ctx) }

// DefaultTPMOpener returns a TPMOpener that opens /dev/tpmrm0 on Linux.
// If the TPM device is missing the opener returns ErrTPMNoTransport so
// callers can downgrade cleanly to a "not wired" failure mode.
func DefaultTPMOpener() TPMOpener {
	return TPMOpenerFunc(func(ctx context.Context) (transport.TPMCloser, error) {
		device, err := tpmdev.Open(defaultTPMDevice)
		if err != nil {
			return nil, &errs.Detail{Err: ErrTPMNoTransport, Detail: fmt.Sprintf("%v", err)}
		}
		return transport.FromReadWriteCloser(device), nil
	})
}

// TPMToken is the JSON payload written into the LUKS2 token for a
// TPM-sealed keyslot. Field names are stable with systemd-cryptsetup's
// "systemd-tpm2" token so third parties can still parse the slot.
type TPMToken struct {
	Type         string   `json:"type"`
	Keyslots     []string `json:"keyslots"`
	TPM2Blob     string   `json:"tpm2-blob"` // base64: uint32BE(len(public)) | public | private
	TPM2PCRBank  string   `json:"tpm2-pcr-bank"`
	TPM2PCRs     []int    `json:"tpm2-pcrs"`
	TPM2Handle   uint64   `json:"tpm2-key-handle"`
	TPM2PolicyHA string   `json:"tpm2-policy-hash,omitempty"` // base64
}

// TPMSealResult is the richer seal output: the sealed passphrase plus the
// token payload to persist in the LUKS2 header and the raw sealed blobs.
//
// Passphrase is protected memory: it lives in an mlocked, canary-guarded
// *secure.Buffer rather than a plain []byte, so the LUKS passphrase never
// sits on the ordinary Go heap between SealPassphrase and the caller
// consuming it. Callers MUST call Passphrase.Destroy() once the passphrase
// has been persisted (e.g. handed to a LUKS keyslot add) or otherwise
// consumed.
type TPMSealResult struct {
	Passphrase   *secure.Buffer
	TokenJSON    []byte
	PublicBlob   []byte
	PrivateBlob  []byte
	PolicyDigest []byte
}

// TPMSealer seals and unseals LUKS volume passphrases against a TPM 2.0 by
// driving go-tpm directly. Every operation opens a fresh transport, performs
// its commands, and closes. This keeps the sealer stateless and safe to
// reuse across goroutines.
//
// The passphrase never crosses the TPM bus in plaintext. The sealer owns its
// transport, not a pkg/tpm2 TPM2, so it hands that transport to pkg/tpm2's
// transport-level session layer -- CommandEncryptionSession for TPM2_Create,
// ResponseEncryptionSession for TPM2_Unseal -- which attaches a salted,
// parameter-encrypting session to the command. The session code lives once,
// in pkg/tpm2; this package only chooses the direction.
type TPMSealer struct {
	logger *slog.Logger
	opener TPMOpener
	// parentHandle is the persistent TPM handle used as the sealing parent.
	// When zero the default is DefaultTPMParentHandle.
	parentHandle uint32
	// pcrBank is the PCR hash algorithm to bind the policy to. When zero
	// defaults to SHA-256.
	pcrBank libtpm2.TPMAlgID
}

// NewTPMSealer constructs a TPM-backed LUKS passphrase sealer. Passing a
// nil opener returns ErrTPMNoTransport so callers can fall back to leaving
// their TPM handler unset.
func NewTPMSealer(logger *slog.Logger, opener TPMOpener) (*TPMSealer, error) {
	if opener == nil {
		return nil, ErrTPMNoTransport
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TPMSealer{
		logger:       logger,
		opener:       opener,
		parentHandle: DefaultTPMParentHandle,
		pcrBank:      libtpm2.TPMAlgSHA256,
	}, nil
}

// WithParentHandle overrides the persistent TPM handle used as the sealing
// parent. Zero resets to the default (0x81000001).
func (h *TPMSealer) WithParentHandle(handle uint32) *TPMSealer {
	h.parentHandle = handle
	if h.parentHandle == 0 {
		h.parentHandle = DefaultTPMParentHandle
	}
	return h
}

// Seal generates a random 32-byte passphrase, seals it to the TPM under the
// configured parent handle with a PCR policy bound to the supplied PCRs,
// and returns the passphrase plus a JSON token payload containing the
// sealed blobs. The signature matches the narrow handler interfaces used by
// downstream LUKS backends.
func (h *TPMSealer) Seal(ctx context.Context, handle string, pcrs []int32) ([]byte, []byte, error) {
	res, err := h.SealPassphrase(ctx, handle, pcrs)
	if err != nil {
		return nil, nil, err
	}
	defer res.Passphrase.Destroy()
	var passphrase []byte
	if err := res.Passphrase.WithBytes(func(b []byte) error {
		passphrase = make([]byte, len(b))
		copy(passphrase, b)
		return nil
	}); err != nil {
		return nil, nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("copy passphrase: %v", err)}
	}
	return passphrase, res.TokenJSON, nil
}

// SealPassphrase is the richer API used by callers that need the raw sealed
// blobs + policy digest alongside the passphrase and token JSON.
func (h *TPMSealer) SealPassphrase(ctx context.Context, handle string, pcrs []int32) (*TPMSealResult, error) {
	parent, err := resolveParentHandle(handle, h.parentHandle)
	if err != nil {
		return nil, err
	}

	// 32 random bytes are sealed as the LUKS passphrase.
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("rand: %v", err)}
	}

	tpm, err := h.opener.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer h.closeTPM(tpm)

	// Build PCR selection + policy digest. When no PCRs are requested we
	// still compute an empty policy so the sealed object has an auth policy
	// (keyed-hash objects without policy require userAuth, which we don't
	// want for LUKS).
	pcrSel := buildPCRSelection(h.pcrBank, pcrs)
	policyDigest, err := computePCRPolicyDigest(tpm, pcrSel)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMPolicyFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Seal as a keyed-hash object under the parent SRK.
	pub := libtpm2.New2B(libtpm2.TPMTPublic{
		Type:    libtpm2.TPMAlgKeyedHash,
		NameAlg: libtpm2.TPMAlgSHA256,
		ObjectAttributes: libtpm2.TPMAObject{
			FixedTPM:        true,
			FixedParent:     true,
			AdminWithPolicy: true,
			NoDA:            true,
		},
		AuthPolicy: libtpm2.TPM2BDigest{Buffer: policyDigest},
		Parameters: libtpm2.NewTPMUPublicParms(
			libtpm2.TPMAlgKeyedHash,
			&libtpm2.TPMSKeyedHashParms{
				Scheme: libtpm2.TPMTKeyedHashScheme{
					Scheme: libtpm2.TPMAlgNull,
				},
			},
		),
	})
	sensitive := libtpm2.TPM2BSensitiveCreate{
		Sensitive: &libtpm2.TPMSSensitiveCreate{
			Data: libtpm2.NewTPMUSensitiveCreate(&libtpm2.TPM2BSensitiveData{
				Buffer: passphrase,
			}),
		},
	}

	parentName, err := readObjectName(tpm, libtpm2.TPMHandle(parent))
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("read parent public: %v", err)}
	}

	// The passphrase travels in TPM2_Create's first parameter, the sensitive
	// area. The parent's empty password authorization cannot encrypt it, so
	// a salted session of its own encrypts it on the way in.
	encSession, closeEncSession, err := pkgtpm2.CommandEncryptionSession(tpm)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMSealFailed, Detail: "encryption session", Cause: err}
	}
	defer h.closeSession(closeEncSession, "seal encryption")

	createRsp, err := (libtpm2.Create{
		ParentHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(parent),
			Name:   parentName,
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InSensitive: sensitive,
		InPublic:    pub,
	}).Execute(tpm, encSession)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("%v", err)}
	}

	token := &TPMToken{
		Type:         TPMTokenType,
		TPM2Blob:     EncodeTPMSealBlobs(createRsp.OutPublic.Bytes(), createRsp.OutPrivate.Buffer),
		TPM2PCRBank:  pcrBankName(h.pcrBank),
		TPM2PCRs:     int32sToInts(pcrs),
		TPM2Handle:   uint64(parent),
		TPM2PolicyHA: base64.StdEncoding.EncodeToString(policyDigest),
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("marshal token: %v", err)}
	}

	// passphrase has already been consumed by the TPM2_Create command above;
	// hand it to the enclave now. NewBufferFromBytes copies and wipes the
	// source slice, so the plaintext no longer sits on the ordinary heap
	// once this returns.
	passBuf, err := secure.NewBufferFromBytes(passphrase)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMSealFailed, Detail: fmt.Sprintf("seal passphrase enclave: %v", err)}
	}

	return &TPMSealResult{
		Passphrase:   passBuf,
		TokenJSON:    tokenJSON,
		PublicBlob:   createRsp.OutPublic.Bytes(),
		PrivateBlob:  createRsp.OutPrivate.Buffer,
		PolicyDigest: policyDigest,
	}, nil
}

// UnsealPassphrase reads a TPM LUKS2 token and unseals the passphrase. Used
// by the unlock path — the enroll path receives the passphrase from
// SealPassphrase directly.
func (h *TPMSealer) UnsealPassphrase(ctx context.Context, tokenJSON []byte) ([]byte, error) {
	var token TPMToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, &errs.Detail{Err: ErrTPMInvalidToken, Detail: fmt.Sprintf("%v", err)}
	}
	publicBlob, privateBlob, err := DecodeTPMSealBlobs(token.TPM2Blob)
	if err != nil {
		return nil, err
	}
	parent := uint32(token.TPM2Handle)
	if parent == 0 {
		parent = h.parentHandle
	}

	tpm, err := h.opener.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer h.closeTPM(tpm)

	// Load the sealed object back under the parent. The stored public blob
	// is the TPMTPublic contents (TPM2BPublic.Bytes() strips the size
	// prefix), so it must be re-wrapped with BytesAs2B — Unmarshal would
	// misread the first two content bytes as the 2B size field.
	pub := libtpm2.BytesAs2B[libtpm2.TPMTPublic](publicBlob)
	parentName, err := readObjectName(tpm, libtpm2.TPMHandle(parent))
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMUnsealFailed, Detail: fmt.Sprintf("read parent public: %v", err)}
	}
	loadRsp, err := (libtpm2.Load{
		ParentHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(parent),
			Name:   parentName,
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InPrivate: libtpm2.TPM2BPrivate{Buffer: privateBlob},
		InPublic:  pub,
	}).Execute(tpm)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMUnsealFailed, Detail: fmt.Sprintf("load: %v", err)}
	}
	defer h.flushContext(tpm, loadRsp.ObjectHandle)

	// Start a PCR policy session matching the PCRs recorded in the token.
	pcrSel := buildPCRSelection(h.pcrBank, intsToInt32s(token.TPM2PCRs))
	policySession, policyCloser, err := libtpm2.PolicySession(tpm, libtpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMUnsealFailed, Detail: fmt.Sprintf("policy session: %v", err)}
	}
	defer h.closeSession(policyCloser, "unseal policy")

	if _, err := (libtpm2.PolicyPCR{
		PolicySession: policySession.Handle(),
		Pcrs:          pcrSel,
	}).Execute(tpm); err != nil {
		return nil, &errs.Detail{Err: ErrTPMUnsealFailed, Detail: fmt.Sprintf("policy pcr: %v", err)}
	}

	// The passphrase leaves the TPM in TPM2_Unseal's first response
	// parameter. The unsalted PCR policy session proves no secret and cannot
	// encrypt it, so a salted session of its own encrypts it on the way out.
	encSession, closeEncSession, err := pkgtpm2.ResponseEncryptionSession(tpm)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMUnsealFailed, Detail: "encryption session", Cause: err}
	}
	defer h.closeSession(closeEncSession, "unseal encryption")

	unsealRsp, err := (libtpm2.Unseal{
		ItemHandle: libtpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   policySession,
		},
	}).Execute(tpm, encSession)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTPMUnsealFailed, Detail: fmt.Sprintf("unseal: %v", err)}
	}
	return unsealRsp.OutData.Buffer, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveParentHandle parses the request-supplied handle string, falling
// back to the sealer default when empty. Accepts decimal or 0x-prefixed
// hex.
func resolveParentHandle(requested string, fallback uint32) (uint32, error) {
	if requested == "" {
		return fallback, nil
	}
	s := strings.TrimSpace(requested)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		// Accept decimal as a fallback.
		if dv, derr := strconv.ParseUint(strings.TrimSpace(requested), 10, 32); derr == nil {
			return uint32(dv), nil
		}
		return 0, &errs.Detail{Err: ErrTPMInvalidHandle, Detail: fmt.Sprintf("%q", requested)}
	}
	return uint32(v), nil
}

// buildPCRSelection converts a slice of PCR indexes into a TPMLPCRSelection
// for the requested bank. An empty slice yields an empty selection (valid —
// produces a trivial policy).
func buildPCRSelection(bank libtpm2.TPMAlgID, pcrs []int32) libtpm2.TPMLPCRSelection {
	if len(pcrs) == 0 {
		return libtpm2.TPMLPCRSelection{
			PCRSelections: []libtpm2.TPMSPCRSelection{{
				Hash:      bank,
				PCRSelect: make([]byte, 3),
			}},
		}
	}
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

// readObjectName fetches the TPM name of a loaded or persistent object via
// TPM2_ReadPublic. go-tpm requires the name on AuthHandle for non-permanent
// handles (persistent SRKs included) so it can compute the session HMAC /
// command parameter hash.
func readObjectName(tpm transport.TPM, handle libtpm2.TPMHandle) (libtpm2.TPM2BName, error) {
	readRsp, err := (libtpm2.ReadPublic{
		ObjectHandle: handle,
	}).Execute(tpm)
	if err != nil {
		return libtpm2.TPM2BName{}, err
	}
	return readRsp.Name, nil
}

// computePCRPolicyDigest runs a trial session + PolicyPCR to derive the
// policy digest for the given selection. Uses a trial session so the TPM
// computes the digest deterministically without requiring a live
// authentication.
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

// pcrBankName returns the string representation of a PCR bank suitable for
// the LUKS2 token.
func pcrBankName(alg libtpm2.TPMAlgID) string {
	switch alg {
	case libtpm2.TPMAlgSHA256:
		return "sha256"
	case libtpm2.TPMAlgSHA384:
		return "sha384"
	case libtpm2.TPMAlgSHA512:
		return "sha512"
	case libtpm2.TPMAlgSHA1:
		return "sha1"
	}
	return "sha256"
}

// int32sToInts converts []int32 to []int for JSON encoding.
func int32sToInts(src []int32) []int {
	out := make([]int, len(src))
	for i, v := range src {
		out[i] = int(v)
	}
	return out
}

// intsToInt32s converts []int back to []int32.
func intsToInt32s(src []int) []int32 {
	out := make([]int32, len(src))
	for i, v := range src {
		out[i] = int32(v)
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

// flushContext releases a transient TPM object handle. Errors are logged
// (noisy TPMs) but never surfaced — the caller already has their result.
func (h *TPMSealer) flushContext(tpm transport.TPM, handle libtpm2.TPMHandle) {
	if _, err := (libtpm2.FlushContext{FlushHandle: handle}).Execute(tpm); err != nil {
		h.logger.Warn("luks: tpm flush context failed",
			slog.String("error", err.Error()))
	}
}

// closeTPM closes the transport. The caller has already extracted
// everything of value from it, so a close failure is logged rather than
// surfaced.
func (h *TPMSealer) closeTPM(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		h.logger.Debug("luks: tpm transport close failed",
			slog.String("error", err.Error()))
	}
}

// closeSession runs cleanup (the closer a session constructor returns) and
// logs a failure at debug level, on the same terms as closeTPM: the session
// has already served its purpose by the time the deferred call runs.
func (h *TPMSealer) closeSession(cleanup func() error, what string) {
	if err := cleanup(); err != nil {
		h.logger.Debug("luks: tpm session cleanup failed",
			slog.String("session", what),
			slog.String("error", err.Error()))
	}
}
