package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"math"
)

// Seals a secret to an NV RAM index against the Platform Policy
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

	secretBytes = keyAttrs.Secret.Bytes()

	var policyDigest tpm2.TPM2BDigest
	var policyRead bool
	if keyAttrs.PlatformPolicy {
		policyDigest = tpm.PlatformPolicyDigest()
		policyRead = true
	}

	hierarchy := keyAttrs.TPMAttributes.Hierarchy.(tpm2.TPMHandle)
	handle := keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)
	hashAlg := keyAttrs.TPMAttributes.HashAlg.(tpm2.TPMIAlgHash)

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
		tpm.logger.Error(err)
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		tpm.logger.Error(err)
		return err
	}

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

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
		tpm.logger.Error(err)
		return err
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf("NVWriteSecret: secret: %s", string(secretBytes))
	}

	keyAttrs.TPMAttributes.Handle = pub.NVIndex
	keyAttrs.TPMAttributes.Name = *nvName

	return nil
}

// Unseals data from NV RAM index protected by the Platform PCR policy
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
	defer func() { _ = closer() }()

	hierarchy := keyAttrs.TPMAttributes.Hierarchy.(tpm2.TPMHandle)
	handle := keyAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)

	// Read the NV RAM bytes
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: handle,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	tpm.logger.Debugf("Name: %x", Encode(readPubRsp.NVName.Buffer))

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
		tpm.logger.Error(err)
		return nil, err
	}

	tpm.logger.Debugf("NVReadSecret: retrieved secret: %s", string(readRsp.Data.Buffer))

	return readRsp.Data.Buffer, nil
}
