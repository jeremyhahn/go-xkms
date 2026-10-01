package tpm2

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// NVWrite seals a secret to an NV RAM index against the Platform Policy.
// The NV index must be defined with NT=Ordinary.
//
// When the secret exceeds the TPM's TPM_PT_NV_BUFFER_MAX, the write is
// issued in chunks with the Offset field incremented per chunk (TCG Part 3
// §31.4.1).  The TPM's buffer maximum is queried via GetCapability; if the
// query fails, a conservative default of 512 bytes is used.
func (tpm *TPM2) NVWrite(
	keyAttrs *types.KeyAttributes) error {

	var hierarchyAuth, secretBytes []byte
	var err error

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	secretBytes = keyAttrs.SealData.Bytes()

	if len(secretBytes) > math.MaxUint16 {
		return ErrNVSecretTooLarge
	}

	policyDigest, policyRead, err := tpm.nvPlatformPolicy(keyAttrs)
	if err != nil {
		return err
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	defs := tpm2.NVDefineSpace{
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   !policyRead,
					AuthWrite:  !policyRead,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: uint16(len(secretBytes)), // #nosec G115 -- Bounds checked above
			}),
	}

	err = tpm.nvDefineSpace(hierarchy, hierarchyAuth, &defs)
	if err != nil {
		tpm.logger.Error("NVDefineSpace failed", slog.String("error", err.Error()))
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public info contents", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to get NV name", slog.String("error", err.Error()))
		return err
	}

	// The secret is written under the hierarchy's authorization; one salted
	// session proves it and encrypts every chunk on its way into the TPM.
	session, closer, err := tpm.hierarchyAuthSession(hierarchy, hierarchyAuth, encryptIn)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closer, "NVWrite")

	// Determine the maximum write chunk size from TPM capabilities.
	// Fall back to 512 bytes on capability query failure (conservative;
	// all compliant TPM 2.0 implementations support at least 512 bytes).
	bufMax := nvWriteChunkSize(tpm.transport)

	offset := uint16(0)
	remaining := secretBytes
	for len(remaining) > 0 {
		chunkSize := bufMax
		if uint16(len(remaining)) < chunkSize {
			chunkSize = uint16(len(remaining))
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		write := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: hierarchy,
				Auth:   session,
			},
			NVIndex: tpm2.NamedHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: chunk,
			},
			Offset: offset,
		}
		if _, err := write.Execute(tpm.transport); err != nil {
			tpm.logger.Error("NVWrite failed",
				slog.String("error", err.Error()),
				slog.Int("offset", int(offset)),
				slog.Int("chunkSize", int(chunkSize)))
			return err
		}
		offset += chunkSize

		// The first write sets TPMA_NV_WRITTEN, which is part of the index's
		// Name. An HMAC session authorizes over that Name (cpHash), so every
		// later chunk must name the index as it now is.
		if !pub.Attributes.Written {
			pub.Attributes.Written = true
			if nvName, err = tpm2.NVName(pub); err != nil {
				tpm.logger.Error("failed to get NV name", slog.String("error", err.Error()))
				return err
			}
		}
	}

	if tpm.debugSecrets {
		tpm.logger.Debug("NVWriteSecret: secret written",
			slog.String("secret", string(secretBytes)))
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	return nil
}

// NVRead reads data from an NV RAM index. When PlatformPolicy is set on the
// key attributes, a policy session is used; otherwise, the authorization path
// is selected by inspecting TPMA_NV attributes (TCG Part 3 §31.13):
//   - TPMA_NV_AUTHREAD with no caller-supplied hierarchy auth → index-self auth
//     (AuthHandle is the NV index itself with empty password authorization).
//   - TPMA_NV_OWNERREAD with caller-supplied hierarchy auth → owner-hierarchy auth.
//   - TPMA_NV_OWNERREAD with no hierarchy auth → owner-hierarchy with empty auth
//     (backward-compatible path for TPMs with empty owner auth).
//
// The NV index must have been defined with NT=Ordinary.
//
// When dataSize is 0 the entire NV index (nvPub.DataSize bytes) is read.
// When the requested size exceeds the TPM's TPM_PT_NV_BUFFER_MAX the read is
// issued in sequential chunks with the Offset field incremented accordingly
// (TCG Part 3 §31.3.1).  The buffer maximum is queried via GetCapability;
// if the query fails a conservative default of 512 bytes is used.
// Password-auth sessions are stateless and safe to reuse across chunks.
// Policy sessions created by PlatformPolicySession use ContinueSession=true
// (go-tpm's PolicySession helper sets this unconditionally) so the same
// session handle remains valid for every chunk within the loop.
func (tpm *TPM2) NVRead(
	keyAttrs *types.KeyAttributes,
	dataSize uint16) ([]byte, error) {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return nil, store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent != nil && keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV public area to obtain the Name and TPMA_NV attributes.
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return nil, err
	}
	tpm.logger.Debug("NV Name",
		slog.String("name", Encode(readPubRsp.NVName.Buffer)))

	nvPub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to parse NV public area", slog.String("error", err.Error()))
		return nil, err
	}
	attrs := nvPub.Attributes

	// Resolve the effective read size.
	// dataSize==0 means "read the full index contents" (caller semantics
	// documented in xkey ReadNVData: "When size is 0 …").
	// In all cases clamp to the index's actual data size so callers that
	// pass the listed size do not exceed what the TPM actually stored.
	effectiveSize := dataSize
	if effectiveSize == 0 || effectiveSize > nvPub.DataSize {
		effectiveSize = nvPub.DataSize
	}

	// When PlatformPolicy is set, build a policy session and use it as the
	// authorization for the NV index itself (TPMA_NV_POLICYREAD path).
	// The policy session is created once and reused across all chunks —
	// go-tpm's PolicySession sets ContinueSession=true so the session
	// handle remains alive until the closer is called.
	// Otherwise, select the password authorization path by inspecting
	// TPMA_NV attributes per TCG Part 3 §31.13:
	//   TPMA_NV_AUTHREAD + empty index auth → index-self auth.
	//   TPMA_NV_OWNERREAD + supplied owner auth → owner-hierarchy auth.
	//   TPMA_NV_OWNERREAD, no auth provided → owner-hierarchy with empty auth.
	// Select the authorization path by inspecting TPMA_NV attributes per
	// TCG Part 3 §31.13.
	//
	// PlatformPolicy only controls the WRITE session (NVWrite creates a
	// policy session for the write command).  For READS the authorization
	// entity is always the NV index itself or the owner hierarchy, selected
	// by the attributes present in the NV public area:
	//
	//   TPMA_NV_POLICYREAD set AND PlatformPolicy=true
	//     → Policy session (PCR branch) against the NV index handle.
	//       This is the secure path that satisfies the policy digest stored
	//       in AuthPolicy.  The PCR branch is always attempted first; if it
	//       fails (PCR state changed) the caller must handle the error.
	//
	//   TPMA_NV_AUTHREAD + empty index auth
	//     → Index-self auth with empty password.
	//
	//   TPMA_NV_OWNERREAD + supplied owner auth
	//     → Owner-hierarchy password auth.
	//
	//   TPMA_NV_OWNERREAD, no owner auth
	//     → Owner-hierarchy with empty auth (backward compat).
	var authHandle tpm2.AuthHandle
	if attrs.PolicyRead {
		var closer func() error
		authHandle, closer, err = tpm.nvPolicyReadAuthorization(handle, readPubRsp.NVName, nvPub.AuthPolicy.Buffer)
		if err != nil {
			return nil, err
		}
		defer tpm.closeSession(closer, "NVRead policy")
	} else {
		var closer func() error
		authHandle, closer, err = tpm.nvReadAuthorization(handle, readPubRsp.NVName, attrs, hierarchyAuth)
		if err != nil {
			return nil, err
		}
		defer tpm.closeSession(closer, "NVRead")
	}

	// The index holds a sealed secret, so every chunk leaves the TPM
	// encrypted under a salted session of its own: the authorization above
	// may be a policy session, which cannot encrypt it.
	encSession, closeEncSession, err := tpm.encryptionSession(encryptOut)
	if err != nil {
		return nil, err
	}
	defer tpm.closeSession(closeEncSession, "NVRead encryption")

	// Issue NVRead in chunks of at most TPM_PT_NV_BUFFER_MAX bytes.
	// A single read of a size exceeding the buffer maximum returns
	// TPM_RC_VALUE (parameter 1).  Fall back to 512 bytes on capability
	// query failure — all compliant TPM 2.0 implementations support at
	// least 512 bytes (TCG Part 2 §4.4).
	bufMax := nvReadChunkSize(tpm.transport)

	result := make([]byte, 0, effectiveSize)
	offset := uint16(0)
	remaining := effectiveSize
	for remaining > 0 {
		chunkSize := bufMax
		if remaining < chunkSize {
			chunkSize = remaining
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: authHandle,
			NVIndex: tpm2.NamedHandle{
				Handle: handle,
				Name:   readPubRsp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}.Execute(tpm.transport, encSession)
		if err != nil {
			tpm.logger.Error("NVRead failed",
				slog.String("error", err.Error()),
				slog.Int("offset", int(offset)),
				slog.Int("chunkSize", int(chunkSize)))
			return nil, err
		}

		result = append(result, readRsp.Data.Buffer...)
		offset += uint16(len(readRsp.Data.Buffer)) // #nosec G115 -- chunkSize ≤ bufMax ≤ MaxUint16
		remaining -= uint16(len(readRsp.Data.Buffer))
	}

	tpm.logger.Debug("NVRead: retrieved data",
		slog.Int("bytes", len(result)))

	return result, nil
}

// NVDefineCounter defines a counter NV index at the specified handle.
// Counter NV indices are initialized to 0 and can only be incremented.
// The NV index is created with NT=Counter attribute.
func (tpm *TPM2) NVDefineCounter(keyAttrs *types.KeyAttributes) error {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	policyDigest, policyRead, err := tpm.nvPlatformPolicy(keyAttrs)
	if err != nil {
		return err
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	// Counter NV indices have a fixed size of 8 bytes (uint64)
	defs := tpm2.NVDefineSpace{
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   !policyRead,
					AuthWrite:  !policyRead,
					NT:         tpm2.TPMNTCounter,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: 8, // Counter is always 8 bytes (uint64)
			}),
	}

	err = tpm.nvDefineSpace(hierarchy, hierarchyAuth, &defs)
	if err != nil {
		tpm.logger.Error("NVDefineSpace for counter failed", slog.String("error", err.Error()))
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public info contents", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to get NV name", slog.String("error", err.Error()))
		return err
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	tpm.logger.Debug("NVDefineCounter: defined counter",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
}

// NVDefineExtend defines an extend NV index at the specified handle.
// Extend NV indices can only be modified by extending a hash into them.
// The NV index is created with NT=Extend attribute.
// The data size is set to the hash algorithm's digest size.
func (tpm *TPM2) NVDefineExtend(keyAttrs *types.KeyAttributes) error {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	policyDigest, policyRead, err := tpm.nvPlatformPolicy(keyAttrs)
	if err != nil {
		return err
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	// Determine the data size based on the hash algorithm
	dataSize, err := hashAlgDigestSize(hashAlg)
	if err != nil {
		return err
	}

	defs := tpm2.NVDefineSpace{
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   !policyRead,
					AuthWrite:  !policyRead,
					NT:         tpm2.TPMNTExtend,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: dataSize,
			}),
	}

	err = tpm.nvDefineSpace(hierarchy, hierarchyAuth, &defs)
	if err != nil {
		tpm.logger.Error("NVDefineSpace for extend failed", slog.String("error", err.Error()))
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get public info contents", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to get NV name", slog.String("error", err.Error()))
		return err
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	tpm.logger.Debug("NVDefineExtend: defined extend index",
		slog.String("handle", fmt.Sprintf("0x%x", handle)),
		slog.Int("digestSize", int(dataSize)))

	return nil
}

// NVIncrement increments a counter NV index and returns the new value.
// The NV index must have been defined with NT=Counter (use NVDefineCounter).
func (tpm *TPM2) NVIncrement(keyAttrs *types.KeyAttributes) (uint64, error) {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return 0, store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return 0, store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV public area to get the name
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return 0, err
	}

	// Increment the counter
	err = tpm.withHierarchyAuth(hierarchy, hierarchyAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.NVIncrement{
			AuthHandle: authHandle,
			NVIndex: tpm2.NamedHandle{
				Handle: handle,
				Name:   readPubRsp.NVName,
			},
		}.Execute(tpm.transport)
		return err
	})
	if err != nil {
		tpm.logger.Error("NVIncrement failed", slog.String("error", err.Error()))
		return 0, err
	}

	// Read back the new counter value
	// Need to re-read public info as name may have changed
	readPubRsp, err = tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed after increment", slog.String("error", err.Error()))
		return 0, err
	}

	nvPub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to parse NV public area", slog.String("error", err.Error()))
		return 0, err
	}
	attrs := nvPub.Attributes

	// Select the authorization path per TCG Part 3 §31.13.
	readAuthHandle, closeReadAuth, err := tpm.nvReadAuthorization(handle, readPubRsp.NVName, attrs, hierarchyAuth)
	if err != nil {
		return 0, err
	}
	defer tpm.closeSession(closeReadAuth, "NVIncrement read")

	readRsp, err := tpm2.NVRead{
		AuthHandle: readAuthHandle,
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
		},
		Size: 8, // Counter is always 8 bytes
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVRead failed after increment", slog.String("error", err.Error()))
		return 0, err
	}

	// Parse the counter value (big endian uint64)
	counterValue := binary.BigEndian.Uint64(readRsp.Data.Buffer)

	tpm.logger.Debug("NVIncrement: counter incremented",
		slog.String("handle", fmt.Sprintf("0x%x", handle)),
		slog.Uint64("value", counterValue))

	return counterValue, nil
}

// NVExtend extends data into an extend NV index.
// The NV index must have been defined with NT=Extend (use NVDefineExtend).
// The data is hashed with the NV index's hash algorithm and extended into the index.
func (tpm *TPM2) NVExtend(keyAttrs *types.KeyAttributes, data []byte) error {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return store.ErrInvalidParentAttributes
	}

	if len(data) == 0 {
		return ErrInvalidNVExtendData
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV public area to get the name
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return err
	}

	// Extend the data into the NV index (go-tpm does not implement
	// TPM2_NV_Extend; nvExtendExecute authorizes it through the session).
	err = tpm.withHierarchyAuth(hierarchy, hierarchyAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		return nvExtendExecute(tpm.transport, authHandle, tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
		}, data)
	})
	if err != nil {
		tpm.logger.Error("NVExtend failed", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("NVExtend: extended data into handle",
		slog.Int("dataSize", len(data)),
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
}

// NVReadCounter reads the current value of a counter NV index.
// The NV index must have been defined with NT=Counter.
// Authorization path is selected by inspecting TPMA_NV attributes per
// TCG Part 3 §31.13 (same rules as NVRead).
func (tpm *TPM2) NVReadCounter(keyAttrs *types.KeyAttributes) (uint64, error) {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return 0, store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return 0, store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV public area to get the name and TPMA_NV attributes.
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return 0, err
	}

	nvPub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to parse NV public area", slog.String("error", err.Error()))
		return 0, err
	}
	attrs := nvPub.Attributes

	// Select the authorization path per TCG Part 3 §31.13.
	var authHandle tpm2.AuthHandle
	if attrs.PolicyRead {
		var closer func() error
		authHandle, closer, err = tpm.nvPolicyReadAuthorization(handle, readPubRsp.NVName, nvPub.AuthPolicy.Buffer)
		if err != nil {
			return 0, err
		}
		defer tpm.closeSession(closer, "NV policy read")
	} else {
		var closer func() error
		authHandle, closer, err = tpm.nvReadAuthorization(handle, readPubRsp.NVName, attrs, hierarchyAuth)
		if err != nil {
			return 0, err
		}
		defer tpm.closeSession(closer, "NV read")
	}

	readRsp, err := tpm2.NVRead{
		AuthHandle: authHandle,
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
		},
		Size: 8, // Counter is always 8 bytes
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVRead failed", slog.String("error", err.Error()))
		return 0, err
	}

	// Parse the counter value (big endian uint64)
	counterValue := binary.BigEndian.Uint64(readRsp.Data.Buffer)

	tpm.logger.Debug("NVReadCounter: counter value read",
		slog.String("handle", fmt.Sprintf("0x%x", handle)),
		slog.Uint64("value", counterValue))

	return counterValue, nil
}

// NVReadExtend reads the current digest value of an extend NV index.
// The NV index must have been defined with NT=Extend.
// Authorization path is selected by inspecting TPMA_NV attributes per
// TCG Part 3 §31.13 (same rules as NVRead).
func (tpm *TPM2) NVReadExtend(keyAttrs *types.KeyAttributes) ([]byte, error) {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return nil, store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return nil, store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	// Determine the data size based on the hash algorithm.
	dataSize, err := hashAlgDigestSize(hashAlg)
	if err != nil {
		return nil, err
	}

	// Read the NV public area to get the name and TPMA_NV attributes.
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return nil, err
	}

	nvPub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		tpm.logger.Error("failed to parse NV public area", slog.String("error", err.Error()))
		return nil, err
	}
	attrs := nvPub.Attributes

	// Select the authorization path per TCG Part 3 §31.13.
	var authHandle tpm2.AuthHandle
	if attrs.PolicyRead {
		var closer func() error
		authHandle, closer, err = tpm.nvPolicyReadAuthorization(handle, readPubRsp.NVName, nvPub.AuthPolicy.Buffer)
		if err != nil {
			return nil, err
		}
		defer tpm.closeSession(closer, "NV policy read")
	} else {
		var closer func() error
		authHandle, closer, err = tpm.nvReadAuthorization(handle, readPubRsp.NVName, attrs, hierarchyAuth)
		if err != nil {
			return nil, err
		}
		defer tpm.closeSession(closer, "NV read")
	}

	readRsp, err := tpm2.NVRead{
		AuthHandle: authHandle,
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
		},
		Size: dataSize,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVRead failed", slog.String("error", err.Error()))
		return nil, err
	}

	tpm.logger.Debug("NVReadExtend: read digest",
		slog.Int("digestSize", len(readRsp.Data.Buffer)),
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return readRsp.Data.Buffer, nil
}

// NVUndefine removes an NV index definition.
// This can be used to clean up counter or extend indices.
func (tpm *TPM2) NVUndefine(keyAttrs *types.KeyAttributes) error {

	var hierarchyAuth []byte

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent == nil {
		return store.ErrInvalidParentAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV public area to get the name
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return err
	}

	err = tpm.withHierarchyAuth(hierarchy, hierarchyAuth, encryptNone, func(authHandle tpm2.AuthHandle) error {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: authHandle,
			NVIndex: tpm2.NamedHandle{
				Handle: handle,
				Name:   readPubRsp.NVName,
			},
		}.Execute(tpm.transport)
		return err
	})
	if err != nil {
		tpm.logger.Error("NVUndefineSpace failed", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("NVUndefine: undefined NV index",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
}

// nvDefineSpace executes defs under hierarchy, proving hierarchyAuth through
// a salted session that also encrypts the new index's authValue on its way
// into the TPM (see hierarchyAuthSession). Any AuthHandle already set on defs
// is replaced.
func (tpm *TPM2) nvDefineSpace(
	hierarchy tpm2.TPMHandle,
	hierarchyAuth []byte,
	defs *tpm2.NVDefineSpace) error {

	return tpm.withHierarchyAuth(hierarchy, hierarchyAuth, encryptIn, func(authHandle tpm2.AuthHandle) error {
		defs.AuthHandle = authHandle
		_, err := defs.Execute(tpm.transport)
		return err
	})
}

// nvReadAuthorization selects the TPM2_NV_Read authorization for the index
// at handle from its TPMA_NV attributes (TCG Part 3 §31.13):
//
//   - TPMA_NV_AUTHREAD with no hierarchy auth: the index itself, whose
//     authValue is empty.
//   - TPMA_NV_OWNERREAD with hierarchy auth: the owner hierarchy, proven
//     through a salted session (hierarchyAuthSession).
//   - TPMA_NV_OWNERREAD with no hierarchy auth: the owner hierarchy with an
//     empty authorization.
//
// The returned closer flushes the session, if one was started.
func (tpm *TPM2) nvReadAuthorization(
	handle tpm2.TPMHandle,
	name tpm2.TPM2BName,
	attrs tpm2.TPMANV,
	hierarchyAuth []byte) (tpm2.AuthHandle, func() error, error) {

	switch {
	case attrs.AuthRead && len(hierarchyAuth) == 0:
		return tpm2.AuthHandle{
			Handle: handle,
			Name:   name,
			Auth:   tpm2.PasswordAuth(nil),
		}, noopCloser, nil
	case attrs.OwnerRead:
		session, closer, err := tpm.hierarchyAuthSession(tpm2.TPMRHOwner, hierarchyAuth, encryptNone)
		if err != nil {
			return tpm2.AuthHandle{}, noopCloser, err
		}
		return tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   session,
		}, closer, nil
	default:
		return tpm2.AuthHandle{}, noopCloser, ErrNVReadNotAuthorized
	}
}

// nvPlatformPolicy returns the authPolicy of a new NV index keyAttrs binds to
// the platform policy, and whether it is bound. An NV index defined here
// never has an auth value, so its policy is the PolicyPCR branch alone
// (platformPCRPolicyDigest): a PolicyAuthValue branch would open it to an
// empty one. A bound index is defined without TPMA_NV_AUTHREAD and
// TPMA_NV_AUTHWRITE, so its empty auth value authorizes nothing: it is read
// through its policy (TPMA_NV_POLICYREAD) or by the owner, and written by
// the owner.
func (tpm *TPM2) nvPlatformPolicy(keyAttrs *types.KeyAttributes) (tpm2.TPM2BDigest, bool, error) {
	if keyAttrs.TPMPolicy != types.TPMPolicyPlatform {
		return tpm2.TPM2BDigest{}, false, nil
	}
	digest, err := tpm.platformPCRPolicyDigest()
	if err != nil {
		return tpm2.TPM2BDigest{}, false, err
	}
	return digest, true, nil
}

// nvPolicyReadAuthorization returns the authorization for reading an NV
// index through its read policy (TPMA_NV_POLICYREAD), authPolicy: the
// PolicyPCR branch of the platform policy (platformPCRBranchSession). The
// returned closer flushes the policy session.
func (tpm *TPM2) nvPolicyReadAuthorization(
	handle tpm2.TPMHandle,
	name tpm2.TPM2BName,
	authPolicy []byte) (tpm2.AuthHandle, func() error, error) {

	session, closer, err := tpm.platformPCRBranchSession(authPolicy)
	if err != nil {
		return tpm2.AuthHandle{}, noopCloser, err
	}
	return tpm2.AuthHandle{Handle: handle, Name: name, Auth: session}, closer, nil
}

// nvChunkSizeFallback is the conservative default chunk size used when the
// TPM_PT_NV_BUFFER_MAX capability query fails.  All compliant TPM 2.0
// implementations must support at least 512 bytes (TCG Part 2 §4.4).
const nvChunkSizeFallback = uint16(512)

// nvReadChunkSize returns the maximum number of bytes that may be transferred
// in a single TPM2_NV_Read command.  It queries TPM_PT_NV_BUFFER_MAX via
// TPM2_GetCapability (reusing the existing nvBufferMax helper in
// capabilities.go) and converts to uint16.  On failure nvChunkSizeFallback
// is returned.
func nvReadChunkSize(t transport.TPM) uint16 {
	return nvBufferMaxUint16(t)
}

// nvWriteChunkSize returns the maximum number of bytes that may be transferred
// in a single TPM2_NV_Write command.  Same query as nvReadChunkSize; both
// NV_Read and NV_Write are constrained by TPM_PT_NV_BUFFER_MAX.
func nvWriteChunkSize(t transport.TPM) uint16 {
	return nvBufferMaxUint16(t)
}

// nvBufferMaxUint16 wraps nvBufferMax (capabilities.go) and converts the
// result to uint16, clamping at math.MaxUint16.  Returns nvChunkSizeFallback
// on error or zero result.
func nvBufferMaxUint16(t transport.TPM) uint16 {
	v, err := nvBufferMax(t)
	if err != nil || v == 0 {
		return nvChunkSizeFallback
	}
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v) // #nosec G115 -- clamped to MaxUint16 above
}

// nvIndexMaxSize returns the largest data area a single NV index may be
// defined with, as reported by TPM_PT_NV_INDEX_MAX ("the maximum size of an
// NV Index data area", TCG Part 2 §6.13).  It is distinct from
// TPM_PT_NV_BUFFER_MAX, which bounds a single NV_Read or NV_Write transfer
// and is what the chunking loops use.  The result is clamped to uint16
// because TPMS_NV_PUBLIC.dataSize is a UINT16.
//
// A TPM that cannot answer the query, or answers zero, leaves the caller with
// no way to distinguish an oversized certificate from a malformed index
// definition (the TPM reports both as a bare TPM_RC_SIZE on publicInfo), so
// the condition is reported rather than assumed away.
func nvIndexMaxSize(t transport.TPM) (uint16, error) {
	v, err := nvIndexesMax(t)
	if err != nil {
		return 0, err
	}
	if v == 0 {
		return 0, ErrNVIndexMaxUnavailable
	}
	if v > math.MaxUint16 {
		return math.MaxUint16, nil
	}
	return uint16(v), nil // #nosec G115 -- clamped to MaxUint16 above
}

// hashAlgDigestSize returns the digest size for a given TPM hash algorithm.
func hashAlgDigestSize(hashAlg tpm2.TPMIAlgHash) (uint16, error) {
	switch hashAlg {
	case tpm2.TPMAlgSHA1:
		return 20, nil
	case tpm2.TPMAlgSHA256:
		return 32, nil
	case tpm2.TPMAlgSHA384:
		return 48, nil
	case tpm2.TPMAlgSHA512:
		return 64, nil
	default:
		return 0, ErrHashAlgorithmNotSupported
	}
}

// writeCertToNVRAM writes a DER-encoded certificate to TPM NVRAM.
//
// The index is defined as TPM_NT_ORDINARY (TCG Part 2 §13.4): opaque data
// that TPM2_NV_Write stores verbatim.  Every other index type is unusable
// for certificate storage — TPM_NT_COUNTER, TPM_NT_BITS and TPM_NT_PIN_*
// indices are fixed at 8 octets and are modified only by NV_Increment,
// NV_SetBits or an authorization, so defining one at certificate size is
// rejected with TPM_RC_SIZE on publicInfo, and writing to one at its legal
// size is rejected with TPM_RC_ATTRIBUTES.
//
// The write is issued in chunks of at most TPM_PT_NV_BUFFER_MAX bytes so
// that certificates larger than the TPM's NV buffer maximum are handled
// correctly (TCG Part 3 §31.4.1).  The whole certificate must still fit in
// one index, which TPM_PT_NV_INDEX_MAX bounds; that is checked up front so
// the caller gets ErrNVCertTooLarge instead of a bare TPM_RC_SIZE.
func (tpm *TPM2) writeCertToNVRAM(nvIndex tpm2.TPMHandle, certDER []byte) error {
	tpm.logger.Debug("writing certificate to NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)),
		slog.Int("size_bytes", len(certDER)))

	if len(certDER) == 0 {
		return ErrNVCertEmpty
	}

	indexMax, err := nvIndexMaxSize(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to query maximum NV index data size",
			slog.String("error", err.Error()))
		return err
	}
	if len(certDER) > int(indexMax) {
		tpm.logger.Error("certificate exceeds the maximum NV index data size",
			slog.Int("size_bytes", len(certDER)),
			slog.Int("nv_index_max", int(indexMax)))
		return ErrNVCertTooLarge
	}

	// Define NV space
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: nvIndex,
				NameAlg: tpm.algID,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					AuthWrite:  true,
					OwnerRead:  true,
					AuthRead:   true,
					NoDA:       true,
					NT:         tpm2.TPMNTOrdinary,
				},
				DataSize: uint16(len(certDER)), // #nosec G115 -- bounded by indexMax (uint16) above
			}),
	}

	_, err = defs.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to define NV space", slog.String("error", err.Error()))
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error("failed to get NV public info", slog.String("error", err.Error()))
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error("failed to compute NV name", slog.String("error", err.Error()))
		return err
	}

	bufMax := nvWriteChunkSize(tpm.transport)
	offset := uint16(0)
	remaining := certDER
	for len(remaining) > 0 {
		chunkSize := int(bufMax)
		if len(remaining) < chunkSize {
			chunkSize = len(remaining)
		}
		chunk := remaining[:chunkSize]
		remaining = remaining[chunkSize:]

		write := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: chunk,
			},
			Offset: offset,
		}
		if _, err := write.Execute(tpm.transport); err != nil {
			tpm.logger.Error("failed to write NV data",
				slog.String("error", err.Error()),
				slog.Int("offset", int(offset)))
			return err
		}
		offset += uint16(chunkSize) // #nosec G115 -- chunkSize ≤ bufMax ≤ MaxUint16
	}

	return nil
}

// readCertFromNVRAM reads a DER-encoded certificate from TPM NVRAM.
// The read is issued in chunks of at most TPM_PT_NV_BUFFER_MAX bytes so
// that certificates larger than the TPM's NV buffer maximum are handled
// correctly (TCG Part 3 §31.3.1).
func (tpm *TPM2) readCertFromNVRAM(nvIndex tpm2.TPMHandle) ([]byte, error) {
	tpm.logger.Debug("reading certificate from NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)))

	// Read NV public to get the Name and DataSize
	nvPubRsp, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpm.transport)
	if err != nil {
		return nil, err
	}

	pub, err := nvPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	bufMax := nvReadChunkSize(tpm.transport)
	authHandle := tpm2.AuthHandle{
		Handle: tpm2.TPMRHOwner,
		Auth:   tpm2.PasswordAuth(nil),
	}

	result := make([]byte, 0, pub.DataSize)
	offset := uint16(0)
	remaining := pub.DataSize
	for remaining > 0 {
		chunkSize := bufMax
		if remaining < chunkSize {
			chunkSize = remaining
		}

		nvRead, err := tpm2.NVRead{
			AuthHandle: authHandle,
			NVIndex: tpm2.NamedHandle{
				Handle: nvIndex,
				Name:   nvPubRsp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}.Execute(tpm.transport)
		if err != nil {
			return nil, err
		}

		result = append(result, nvRead.Data.Buffer...)
		offset += uint16(len(nvRead.Data.Buffer)) // #nosec G115 -- chunkSize ≤ bufMax ≤ MaxUint16
		remaining -= uint16(len(nvRead.Data.Buffer))
	}

	return result, nil
}

// deleteCertFromNVRAM undefines an NV index from TPM NVRAM.
//
// TPM2_NV_UndefineSpace authorizes over the Name of the index, which is
// computed from its public area rather than from the handle alone, so the
// public area is read back first.  Supplying the bare handle fails in the
// client with "missing Name for 'NVIndex' parameter" before any command
// reaches the TPM, which is indistinguishable from a genuinely undefined
// index unless the caller inspects the message.
func (tpm *TPM2) deleteCertFromNVRAM(nvIndex tpm2.TPMHandle) error {
	tpm.logger.Debug("deleting certificate from NV index",
		slog.String("nv_index", fmt.Sprintf("0x%08X", nvIndex)))

	nvPubRsp, err := tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to read NV public area", slog.String("error", err.Error()))
		return err
	}

	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nvIndex,
			Name:   nvPubRsp.NVName,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("failed to undefine NV space", slog.String("error", err.Error()))
	}

	return err
}
