//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test/tpmbus"
	"github.com/stretchr/testify/require"
)

// errInjectedFlush is the failure flushFailingTransport answers
// TPM2_FlushContext with.
var errInjectedFlush = tpm2.TPMRCFailure

// flushFailingTransport forwards every command to inner except
// TPM2_FlushContext, which it refuses.
type flushFailingTransport struct {
	inner transport.TPM
}

func (f flushFailingTransport) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 && tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == tpm2.TPMCCFlushContext {
		return nil, errInjectedFlush
	}
	return f.inner.Send(cmd)
}

// TestHierarchyAuthSession_SOPINNeverCrossesTheBus defines and undefines an
// NV index under an owner hierarchy protected by an SO PIN, authorized
// through HierarchyAuthSession on the raw transport: both commands succeed,
// each is authorized by a salted session, and the PIN never crosses the bus.
func TestHierarchyAuthSession_SOPINNeverCrossesTheBus(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-transport-6a90c2")
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(t, soPIN), &owner))

	bus := tpmbus.New(h.TPM.transport)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	nvPublic := tpm2.New2B(tpm2.TPMSNVPublic{
		NVIndex: index,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NoDA:       true,
		},
		DataSize: 8,
	})

	withOwner := func(execute func(tpm2.AuthHandle) error) {
		session, closer, err := HierarchyAuthSession(bus, owner, soPIN)
		require.NoError(t, err)
		require.NoError(t, execute(tpm2.AuthHandle{Handle: owner, Auth: session}))
		require.NoError(t, closer())
	}
	withOwner(func(auth tpm2.AuthHandle) error {
		_, err := tpm2.NVDefineSpace{AuthHandle: auth, PublicInfo: nvPublic}.Execute(bus)
		return err
	})
	readPub, err := tpm2.NVReadPublic{NVIndex: index}.Execute(bus)
	require.NoError(t, err)
	withOwner(func(auth tpm2.AuthHandle) error {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: auth,
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: readPub.NVName},
		}.Execute(bus)
		return err
	})

	bus.RequireAbsent(t, "the SO PIN", soPIN)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVDefineSpace)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVUndefineSpace)
	bus.RequireAllSessionsSalted(t)
}

// TestHierarchyAuthSession_EmptyAuthIsPasswordSession proves an empty
// hierarchy auth, which has nothing to protect, costs no session round trip.
func TestHierarchyAuthSession_EmptyAuthIsPasswordSession(t *testing.T) {
	session, closer, err := HierarchyAuthSession(failingTransport{}, tpm2.TPMRHOwner, nil)
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMRSPW, session.Handle())
	require.NoError(t, closer())
}

// TestCommandEncryptionSession_EncryptsCommandParameter hashes a secret in
// the TPM with a CommandEncryptionSession attached: the command succeeds and
// the secret never crosses the bus.
func TestCommandEncryptionSession_EncryptsCommandParameter(t *testing.T) {
	h := newSimHarness(t, nil)
	bus := tpmbus.New(h.TPM.transport)
	secret := []byte("command-parameter-SECRET-3e71")

	session, closer, err := CommandEncryptionSession(bus)
	require.NoError(t, err)
	_, err = tpm2.Hash{
		Data:      tpm2.TPM2BMaxBuffer{Buffer: secret},
		HashAlg:   tpm2.TPMAlgSHA256,
		Hierarchy: tpm2.TPMRHOwner,
	}.Execute(bus, session)
	require.NoError(t, err)
	require.NoError(t, closer())

	bus.RequireAbsent(t, "the command parameter", secret)
	bus.RequireAllSessionsSalted(t)
}

// TestResponseEncryptionSession_EncryptsResponseParameter draws random bytes
// with a ResponseEncryptionSession attached: the bytes returned to the
// caller never appear in the response.
func TestResponseEncryptionSession_EncryptsResponseParameter(t *testing.T) {
	h := newSimHarness(t, nil)
	bus := tpmbus.New(h.TPM.transport)

	session, closer, err := ResponseEncryptionSession(bus)
	require.NoError(t, err)
	rsp, err := tpm2.GetRandom{BytesRequested: 32}.Execute(bus, session)
	require.NoError(t, err)
	require.NoError(t, closer())

	bus.RequireAbsent(t, "the random bytes", rsp.RandomBytes.Buffer)
	bus.RequireSessionAttr(t, tpm2.TPMCCGetRandom, tpmbus.SessionAttrEncrypt)
}

// TestResponseEncryptionSession_SaltKeyReleaseFailure proves a salt key the
// TPM refuses to flush does not fail the session it salted, and is reported
// by the session's closer instead of being dropped.
func TestResponseEncryptionSession_SaltKeyReleaseFailure(t *testing.T) {
	h := newSimHarness(t, nil)
	tpm := flushFailingTransport{inner: h.TPM.transport}

	session, closer, err := ResponseEncryptionSession(tpm)
	require.NoError(t, err)
	_, err = tpm2.GetRandom{BytesRequested: 16}.Execute(tpm, session)
	require.NoError(t, err)

	err = closer()
	require.ErrorIs(t, err, ErrSaltKey)
	require.ErrorIs(t, err, errInjectedFlush)
}
