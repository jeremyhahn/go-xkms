//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TPMA_SESSION bits (TCG TPM 2.0 Part 2, section 8.4).
const (
	sessionAttrDecrypt = byte(0x20)
	sessionAttrEncrypt = byte(0x40)
)

// tpmRSPW is TPM_RS_PW, the handle of a password pseudo-session.
const tpmRSPW = uint32(0x40000009)

// busExchange is one command and its response as they crossed the transport.
type busExchange struct {
	cmd []byte
	rsp []byte
}

// busCapture records every command and response a TPM2 sends through it: the
// bytes a passive observer of the TPM bus would see.
type busCapture struct {
	inner     transport.TPM
	exchanges []busExchange
}

// Send records cmd before forwarding it: the in-process simulator decrypts
// an encrypted parameter in place, in the very buffer it is handed, so a copy
// taken afterwards would show the TPM's view rather than the bus's.
func (c *busCapture) Send(cmd []byte) ([]byte, error) {
	sent := bytes.Clone(cmd)
	rsp, err := c.inner.Send(cmd)
	c.exchanges = append(c.exchanges, busExchange{
		cmd: sent,
		rsp: bytes.Clone(rsp),
	})
	return rsp, err
}

// capture routes h's TPM through a new busCapture.
func capture(h *simHarness) *busCapture {
	c := &busCapture{inner: h.TPM.transport}
	h.TPM.transport = c
	return c
}

// requireAbsent fails if secret appears anywhere in the captured traffic.
func (c *busCapture) requireAbsent(t *testing.T, name string, secret []byte) {
	t.Helper()
	require.NotEmpty(t, c.exchanges, "the operation must have talked to the TPM")
	for i, ex := range c.exchanges {
		require.Falsef(t, bytes.Contains(ex.cmd, secret),
			"%s crossed the bus in plaintext in command %d (cc 0x%x)", name, i, commandCode(ex.cmd))
		require.Falsef(t, bytes.Contains(ex.rsp, secret),
			"%s crossed the bus in plaintext in the response to command %d (cc 0x%x)", name, i, commandCode(ex.cmd))
	}
}

// commands returns every captured command with code cc, leaving out those
// addressed to the NULL hierarchy: its authorization is always empty, and
// the only such command this package issues is the creation of the ephemeral
// salt key, which carries no secret.
func (c *busCapture) commands(cc tpm2.TPMCC) [][]byte {
	var out [][]byte
	for _, ex := range c.exchanges {
		if commandCode(ex.cmd) != cc {
			continue
		}
		if len(ex.cmd) >= 14 && binary.BigEndian.Uint32(ex.cmd[10:14]) == uint32(tpm2.TPMRHNull) &&
			cc != tpm2.TPMCCStartAuthSession {
			continue
		}
		out = append(out, ex.cmd)
	}
	return out
}

func commandCode(cmd []byte) tpm2.TPMCC {
	if len(cmd) < 10 {
		return 0
	}
	return tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
}

// commandHandles is the number of handles in the handle area of each command
// these tests inspect (TCG TPM 2.0 Part 3).
var commandHandles = map[tpm2.TPMCC]int{
	tpm2.TPMCCCreate:              1,
	tpm2.TPMCCCreatePrimary:       1,
	tpm2.TPMCCEvictControl:        2,
	tpm2.TPMCCGetRandom:           0,
	tpm2.TPMCCHierarchyChanegAuth: 1,
	tpm2.TPMCCLoad:                1,
	tpm2.TPMCCNVDefineSpace:       1,
	tpm2.TPMCCNVRead:              2,
	tpm2.TPMCCNVWrite:             2,
	tpm2.TPMCCStartAuthSession:    2,
	tpm2.TPMCCUnseal:              1,
}

// capturedSession is one session of a command's authorization area.
type capturedSession struct {
	handle uint32
	attrs  byte
}

// commandSessions parses the authorization area of cmd.
func commandSessions(t *testing.T, cmd []byte) []capturedSession {
	t.Helper()
	handles, ok := commandHandles[commandCode(cmd)]
	require.Truef(t, ok, "no handle count for cc 0x%x", commandCode(cmd))
	if binary.BigEndian.Uint16(cmd[0:2]) != tpmSTSessions {
		return nil
	}
	buf := bytes.NewReader(cmd[10+4*handles:])
	var authSize uint32
	require.NoError(t, binary.Read(buf, binary.BigEndian, &authSize))
	area := make([]byte, authSize)
	_, err := buf.Read(area)
	require.NoError(t, err)

	var sessions []capturedSession
	r := bytes.NewReader(area)
	for r.Len() > 0 {
		var s capturedSession
		var size uint16
		require.NoError(t, binary.Read(r, binary.BigEndian, &s.handle))
		require.NoError(t, binary.Read(r, binary.BigEndian, &size))
		_, err := r.Seek(int64(size), 1)
		require.NoError(t, err)
		s.attrs, err = r.ReadByte()
		require.NoError(t, err)
		require.NoError(t, binary.Read(r, binary.BigEndian, &size))
		_, err = r.Seek(int64(size), 1)
		require.NoError(t, err)
		sessions = append(sessions, s)
	}
	return sessions
}

// requireSessionAttr fails unless every command with code cc carries a
// session with attr set.
func (c *busCapture) requireSessionAttr(t *testing.T, cc tpm2.TPMCC, attr byte) {
	t.Helper()
	cmds := c.commands(cc)
	require.NotEmptyf(t, cmds, "expected at least one command 0x%x", uint32(cc))
	for _, cmd := range cmds {
		found := false
		for _, s := range commandSessions(t, cmd) {
			if s.attrs&attr != 0 {
				found = true
			}
		}
		require.Truef(t, found, "command 0x%x carries no session with attribute 0x%x", uint32(cc), attr)
	}
}

// requireNoPasswordSession fails if any command with code cc proves an auth
// value through a password session: its authorization would be the value
// itself, in plaintext.
func (c *busCapture) requireNoPasswordSession(t *testing.T, cc tpm2.TPMCC) {
	t.Helper()
	cmds := c.commands(cc)
	require.NotEmptyf(t, cmds, "expected at least one command 0x%x", uint32(cc))
	for _, cmd := range cmds {
		for _, s := range commandSessions(t, cmd) {
			require.NotEqualf(t, tpmRSPW, s.handle,
				"command 0x%x proves its authorization with a password session", uint32(cc))
		}
	}
}

// requireAllSessionsSalted fails if any session started in the captured
// traffic is unsalted (tpmKey TPM_RH_NULL). An unsalted session's key is
// derived from public nonces alone, so it neither hides the parameters it
// encrypts nor keeps the auth value behind its HMAC from an offline brute
// force.
func (c *busCapture) requireAllSessionsSalted(t *testing.T) {
	t.Helper()
	starts := c.commands(tpm2.TPMCCStartAuthSession)
	require.NotEmpty(t, starts, "expected sessions to be started")
	for _, cmd := range starts {
		tpmKey := binary.BigEndian.Uint32(cmd[10:14])
		require.NotEqual(t, uint32(tpm2.TPMRHNull), tpmKey, "a session was started unsalted")
	}
}

// requireSaltedAuthorization fails unless every session authorizing a
// command with code cc was started salted. Session handles are recycled once
// flushed, so each is resolved against the StartAuthSession that most
// recently returned it.
func (c *busCapture) requireSaltedAuthorization(t *testing.T, cc tpm2.TPMCC) {
	t.Helper()
	salted := make(map[uint32]bool)
	checked := 0
	for _, ex := range c.exchanges {
		switch commandCode(ex.cmd) {
		case tpm2.TPMCCStartAuthSession:
			if len(ex.rsp) >= 14 && binary.BigEndian.Uint32(ex.rsp[6:10]) == 0 {
				tpmKey := binary.BigEndian.Uint32(ex.cmd[10:14])
				salted[binary.BigEndian.Uint32(ex.rsp[10:14])] = tpmKey != uint32(tpm2.TPMRHNull)
			}
		case cc:
			if len(ex.cmd) >= 14 && binary.BigEndian.Uint32(ex.cmd[10:14]) == uint32(tpm2.TPMRHNull) {
				continue
			}
			for _, s := range commandSessions(t, ex.cmd) {
				require.NotEqualf(t, tpmRSPW, s.handle,
					"command 0x%x proves its authorization with a password session", uint32(cc))
				require.Truef(t, salted[s.handle],
					"command 0x%x is authorized by unsalted session 0x%x", uint32(cc), s.handle)
				checked++
			}
		}
	}
	require.NotZerof(t, checked, "expected command 0x%x to be authorized by a session", uint32(cc))
}

// createPSRK creates a Platform SRK whose authValue is userPIN under an owner
// hierarchy whose authorization has been changed to soPIN.
func createPSRK(t *testing.T, h *simHarness, soPIN, userPIN []byte) *types.KeyAttributes {
	t.Helper()
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(soPIN), &owner))

	psrkAttrs, err := PlatformSRKAttributesFromConfig(h.TPM.config)
	require.NoError(t, err)
	require.True(t, psrkAttrs.PlatformPolicy, "the harness Platform SRK must carry the platform policy")
	psrkAttrs.Password = mustPassword(userPIN)
	psrkAttrs.TPMAttributes.HierarchyAuth = mustPassword(soPIN)
	require.NoError(t, h.TPM.CreateSRK(psrkAttrs))
	return psrkAttrs
}

// TestSessionEncryption_SOPINNeverCrossesTheBus provisions a TPM from scratch
// with an SO PIN and proves the PIN never appears on the bus. Provisioning
// changes the lockout, endorsement and owner authorizations before any EK
// exists -- so those sessions are salted against the ephemeral NULL-hierarchy
// key -- then creates and persists the EK, SSRK and IAK under the new
// authorization.
func TestSessionEncryption_SOPINNeverCrossesTheBus(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-3f9a1c77e2")
	bus := capture(h)

	require.NoError(t, h.TPM.Provision(mustPassword(soPIN)))

	bus.requireAbsent(t, "the SO PIN", soPIN)
	bus.requireSessionAttr(t, tpm2.TPMCCHierarchyChanegAuth, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCCreatePrimary, sessionAttrDecrypt)
	bus.requireSaltedAuthorization(t, tpm2.TPMCCHierarchyChanegAuth)
	bus.requireSaltedAuthorization(t, tpm2.TPMCCCreatePrimary)
	bus.requireSaltedAuthorization(t, tpm2.TPMCCEvictControl)
}

// TestSessionEncryption_PSRKCreationProtectsBothPINs proves that creating the
// Platform SRK sends neither its USER PIN (the sensitive area's userAuth) nor
// the SO PIN (the owner hierarchy authorization) in plaintext.
func TestSessionEncryption_PSRKCreationProtectsBothPINs(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-8b41d0e9aa")
	userPIN := []byte("user-pin-5c2e77f031")
	bus := capture(h)

	createPSRK(t, h, soPIN, userPIN)

	bus.requireAbsent(t, "the SO PIN", soPIN)
	bus.requireAbsent(t, "the USER PIN", userPIN)
	bus.requireSessionAttr(t, tpm2.TPMCCCreatePrimary, sessionAttrDecrypt)
	bus.requireNoPasswordSession(t, tpm2.TPMCCCreatePrimary)
	bus.requireNoPasswordSession(t, tpm2.TPMCCEvictControl)
	bus.requireAllSessionsSalted(t)
}

// TestSessionEncryption_SealUnderPSRKWithPINs seals a secret under the
// Platform SRK through the PolicyAuthValue (PIN) branch of the platform
// policy -- both for the PSRK and for the sealed object -- and unseals it,
// proving the secret, the USER PIN and the object PIN never cross the bus in
// plaintext and that every PIN-bearing policy session is salted.
func TestSessionEncryption_SealUnderPSRKWithPINs(t *testing.T) {
	h := newSimHarness(t, nil)
	userPIN := []byte("user-pin-a7d3e1f094")
	objectPIN := []byte("object-pin-19c0b6e2d8")
	secret := []byte("pkcs11-user-pin-SECRET-6e1d")
	psrkAttrs := createPSRK(t, h, []byte("so-pin-2d7c90e1b4"), userPIN)

	keyAttrs := &types.KeyAttributes{
		CN:             "session-encryption-pin-seal",
		KeyType:        types.KeyTypeHMAC,
		Parent:         psrkAttrs,
		Password:       mustPassword(objectPIN),
		PlatformPolicy: true,
		SealData:       types.NewSealData(secret),
		StoreType:      types.StoreTPM2,
	}

	bus := capture(h)
	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)
	unsealed, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, unsealed)

	bus.requireAbsent(t, "the sealed secret", secret)
	bus.requireAbsent(t, "the USER PIN", userPIN)
	bus.requireAbsent(t, "the object PIN", objectPIN)
	bus.requireSessionAttr(t, tpm2.TPMCCCreate, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCUnseal, sessionAttrEncrypt)
	bus.requireAllSessionsSalted(t)
}

// TestSessionEncryption_AutoUnsealThroughPCRBranch reproduces the auto-unseal
// of a pre-barrier secret such as the PKCS#11 PIN: sealed under the Platform
// SRK with the platform policy and unsealed through the PCR branch, with no
// PIN presented. The PCR-branch policy sessions cannot encrypt, so the secret
// must still leave the TPM encrypted under a separate salted session.
func TestSessionEncryption_AutoUnsealThroughPCRBranch(t *testing.T) {
	h := newSimHarness(t, nil)
	secret := []byte("pkcs11-user-pin-AUTO-UNSEAL-4b8f")
	psrkAttrs := createPSRK(t, h, []byte("so-pin-e0a4c9173b"), []byte("user-pin-7f21c3a8d6"))

	// The auto-unseal path holds no PIN for the PSRK: it is authorized
	// through the PCR branch of its platform policy.
	pcrBranchParent := *psrkAttrs
	pcrBranchParent.Password = nil

	keyAttrs := &types.KeyAttributes{
		CN:             "session-encryption-auto-unseal",
		KeyType:        types.KeyTypeHMAC,
		Parent:         &pcrBranchParent,
		PlatformPolicy: true,
		SealData:       types.NewSealData(secret),
		StoreType:      types.StoreTPM2,
	}

	bus := capture(h)
	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)
	unsealed, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, unsealed)

	bus.requireAbsent(t, "the auto-unsealed secret", secret)
	bus.requireSessionAttr(t, tpm2.TPMCCCreate, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCUnseal, sessionAttrEncrypt)
}

// TestSessionEncryption_NVSecretUnderOwnerAuth writes a secret to an NV index
// under the owner hierarchy's SO PIN and reads it back, proving neither the
// secret nor the SO PIN crosses the bus in plaintext.
func TestSessionEncryption_NVSecretUnderOwnerAuth(t *testing.T) {
	h := newSimHarness(t, nil)
	soPIN := []byte("so-pin-c61e0f2a97")
	secret := []byte("nv-sealed-SECRET-0b7d52")
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(soPIN), &owner))

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	parent := *ekAttrs
	tpmAttrs := *ekAttrs.TPMAttributes
	tpmAttrs.HierarchyAuth = mustPassword(soPIN)
	parent.TPMAttributes = &tpmAttrs

	keyAttrs := &types.KeyAttributes{
		Parent:   &parent,
		SealData: types.NewSealData(secret),
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramOwnerIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	bus := capture(h)
	require.NoError(t, h.TPM.NVWrite(keyAttrs))
	got, err := h.TPM.NVRead(keyAttrs, uint16(len(secret)))
	require.NoError(t, err)
	require.Equal(t, secret, got)

	bus.requireAbsent(t, "the NV secret", secret)
	bus.requireAbsent(t, "the SO PIN", soPIN)
	bus.requireSessionAttr(t, tpm2.TPMCCNVDefineSpace, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCNVWrite, sessionAttrDecrypt)
	bus.requireSessionAttr(t, tpm2.TPMCCNVRead, sessionAttrEncrypt)
	bus.requireNoPasswordSession(t, tpm2.TPMCCNVWrite)
}

// TestSessionEncryption_GetRandomEncrypted proves random bytes drawn from the
// TPM -- key material wherever the TPM is the entropy source -- leave it
// encrypted: the bytes returned to the caller never appear in the response.
func TestSessionEncryption_GetRandomEncrypted(t *testing.T) {
	h := newSimHarness(t, nil)
	bus := capture(h)

	random := make([]byte, 32)
	n, err := h.TPM.readChunk(random, len(random))
	require.NoError(t, err)
	require.Equal(t, len(random), n)

	bus.requireAbsent(t, "the random bytes", random)
	bus.requireSessionAttr(t, tpm2.TPMCCGetRandom, sessionAttrEncrypt)
	bus.requireAllSessionsSalted(t)
}

// TestSessionEncryption_SaltKeyWithoutEK proves saltKey falls back to an
// ephemeral NULL-hierarchy key only when no EK is resident, and releases it:
// with the EK handle pointed at an empty slot, the session still starts and
// no transient object is left behind.
func TestSessionEncryption_SaltKeyWithoutEK(t *testing.T) {
	h := newSimHarness(t, nil)
	h.TPM.config.EK.Handle = 0x81010FFF // an unpopulated persistent handle

	handle, pub, release, err := h.TPM.saltKey()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMHTTransient, tpm2.TPMHT(handle>>24),
		"without an EK the salt key is a transient NULL-hierarchy key")
	require.Equal(t, tpm2.TPMAlgECC, pub.Type)
	require.NoError(t, release())

	_, _, err = h.TPM.ReadHandle(handle)
	require.Error(t, err, "release must flush the ephemeral salt key")

	session, closer, err := h.TPM.HMACSession([]byte("auth"))
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, closer())
}

// TestSessionEncryption_SaltKeyReadFailure proves a salt key lookup that fails
// for any reason other than an absent EK is returned, never answered with an
// unsalted session.
func TestSessionEncryption_SaltKeyReadFailure(t *testing.T) {
	h := newSimHarness(t, nil)
	h.TPM.transport = failingTransport{}

	_, _, _, err := h.TPM.saltKey()
	require.ErrorIs(t, err, ErrSaltKey)

	_, _, err = h.TPM.HMACSession([]byte("auth"))
	require.ErrorIs(t, err, ErrSaltKey)
}
