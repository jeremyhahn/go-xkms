package tpm2

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// NVWrite seals a secret to an NV RAM index against the Platform Policy.
// The NV index must be defined with NT=Ordinary.
func (tpm *TPM2) NVWrite(
	keyAttrs *types.KeyAttributes) error {

	var hierarchyAuth, secretBytes []byte
	var closer func() error
	var session tpm2.Session
	var err error

	if keyAttrs.TPMAttributes == nil {
		return store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	secretBytes = keyAttrs.SealData.Bytes()

	var policyDigest tpm2.TPM2BDigest
	var policyRead bool
	if keyAttrs.PlatformPolicy {
		policyDigest = tpm.PlatformPolicyDigest()
		policyRead = true
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: func() uint16 {
					if len(secretBytes) > math.MaxUint16 {
						panic("secretBytes too large")
					}
					return uint16(len(secretBytes))
				}(),
			}),
	}

	_, err = defs.Execute(tpm.transport)
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

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		return err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   session,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: secretBytes,
		},
		Offset: 0,
	}
	if _, err := write.Execute(tpm.transport); err != nil {
		tpm.logger.Error("NVWrite failed", slog.String("error", err.Error()))
		return err
	}

	if tpm.debugSecrets {
		tpm.logger.Debug("NVWriteSecret: secret written",
			slog.String("secret", string(secretBytes)))
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	return nil
}

// NVRead unseals data from NV RAM index protected by the Platform PCR policy.
// The NV index must have been defined with NT=Ordinary.
func (tpm *TPM2) NVRead(
	keyAttrs *types.KeyAttributes,
	dataSize uint16) ([]byte, error) {

	var hierarchyAuth []byte
	var err error

	if keyAttrs.TPMAttributes == nil {
		return nil, store.ErrInvalidKeyAttributes
	}

	if keyAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = keyAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}

	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle

	// Read the NV RAM bytes
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return nil, err
	}
	tpm.logger.Debug("NV Name",
		slog.String("name", Encode(readPubRsp.NVName.Buffer)))

	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
		},
		Size: dataSize,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVRead failed", slog.String("error", err.Error()))
		return nil, err
	}

	tpm.logger.Debug("NVReadSecret: retrieved secret",
		slog.String("secret", string(readRsp.Data.Buffer)))

	return readRsp.Data.Buffer, nil
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

	var policyDigest tpm2.TPM2BDigest
	var policyRead bool
	if keyAttrs.PlatformPolicy {
		policyDigest = tpm.PlatformPolicyDigest()
		policyRead = true
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	// Counter NV indices have a fixed size of 8 bytes (uint64)
	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTCounter,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: 8, // Counter is always 8 bytes (uint64)
			}),
	}

	_, err := defs.Execute(tpm.transport)
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

	var policyDigest tpm2.TPM2BDigest
	var policyRead bool
	if keyAttrs.PlatformPolicy {
		policyDigest = tpm.PlatformPolicyDigest()
		policyRead = true
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
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    hashAlg,
				AuthPolicy: policyDigest,
				Attributes: tpm2.TPMANV{
					AuthRead:   true,
					AuthWrite:  true,
					NT:         tpm2.TPMNTExtend,
					NoDA:       true,
					OwnerRead:  true,
					OwnerWrite: true,
					PolicyRead: policyRead,
				},
				DataSize: dataSize,
			}),
	}

	_, err = defs.Execute(tpm.transport)
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

	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

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
	_, err = tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
		},
	}.Execute(tpm.transport)
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

	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
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

	// Extend the data into the NV index using raw TPM command
	// (go-tpm does not expose NV_Extend command)
	err = nvExtendExecute(
		tpm.transport,
		hierarchy,
		handle,
		readPubRsp.NVName,
		hierarchyAuth,
		data,
	)
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

	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

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

	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
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

	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closer(); err != nil {
			tpm.logger.Error("failed to close session", slog.String("error", err.Error()))
		}
	}()

	hierarchy := keyAttrs.TPMAttributes.Hierarchy
	handle := keyAttrs.TPMAttributes.Handle
	hashAlg := keyAttrs.TPMAttributes.HashAlg

	// Determine the data size based on the hash algorithm
	dataSize, err := hashAlgDigestSize(hashAlg)
	if err != nil {
		return nil, err
	}

	// Read the NV public area to get the name
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVReadPublic failed", slog.String("error", err.Error()))
		return nil, err
	}

	readRsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
			Auth:   session,
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

	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   tpm2.PasswordAuth(hierarchyAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubRsp.NVName,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error("NVUndefineSpace failed", slog.String("error", err.Error()))
		return err
	}

	tpm.logger.Debug("NVUndefine: undefined NV index",
		slog.String("handle", fmt.Sprintf("0x%x", handle)))

	return nil
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
