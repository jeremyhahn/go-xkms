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

// Package tpmbus records the traffic of a TPM 2.0 transport -- the bytes a
// passive observer of the TPM bus would see -- and asserts what that traffic
// must not reveal: a secret in plaintext, an authorization proven through a
// password session, or an unsalted session.
//
// It is test support in the same sense as its parent tpm2test, but imports
// nothing from go-xkms, so pkg/tpm2's own in-package tests can use it as well
// as every package that drives go-tpm on a transport of its own.
package tpmbus

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// TPMA_SESSION bits (TCG TPM 2.0 Part 2, section 8.4).
const (
	// SessionAttrDecrypt is the session's decrypt attribute: the command's
	// first parameter crosses the bus encrypted.
	SessionAttrDecrypt = byte(0x20)

	// SessionAttrEncrypt is the session's encrypt attribute: the response's
	// first parameter crosses the bus encrypted.
	SessionAttrEncrypt = byte(0x40)
)

// tpmRSPW is TPM_RS_PW, the handle of a password pseudo-session.
const tpmRSPW = uint32(0x40000009)

// commandHandles is the number of handles in the handle area of each command
// the assertions inspect (TCG TPM 2.0 Part 3).
var commandHandles = map[tpm2.TPMCC]int{
	tpm2.TPMCCCreate:              1,
	tpm2.TPMCCCreatePrimary:       1,
	tpm2.TPMCCEvictControl:        2,
	tpm2.TPMCCGetRandom:           0,
	tpm2.TPMCCHierarchyChanegAuth: 1,
	tpm2.TPMCCLoad:                1,
	tpm2.TPMCCNVDefineSpace:       1,
	tpm2.TPMCCNVRead:              2,
	tpm2.TPMCCNVUndefineSpace:     2,
	tpm2.TPMCCNVWrite:             2,
	tpm2.TPMCCStartAuthSession:    2,
	tpm2.TPMCCUnseal:              1,
}

// exchange is one command and its response as they crossed the transport.
type exchange struct {
	cmd []byte
	rsp []byte
}

// session is one session of a command's authorization area.
type session struct {
	handle uint32
	attrs  byte
}

// Capture is a transport.TPMCloser that records every command and response
// sent through it before handing them on.
type Capture struct {
	inner     transport.TPM
	exchanges []exchange
}

// New returns a Capture forwarding to inner.
func New(inner transport.TPM) *Capture {
	return &Capture{inner: inner}
}

// Send records cmd before forwarding it: the in-process simulator decrypts
// an encrypted parameter in place, in the very buffer it is handed, so a copy
// taken afterwards would show the TPM's view rather than the bus's.
func (c *Capture) Send(cmd []byte) ([]byte, error) {
	sent := bytes.Clone(cmd)
	rsp, err := c.inner.Send(cmd)
	c.exchanges = append(c.exchanges, exchange{
		cmd: sent,
		rsp: bytes.Clone(rsp),
	})
	return rsp, err
}

// Close closes the inner transport when it is closable.
func (c *Capture) Close() error {
	if closer, ok := c.inner.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// RequireAbsent fails if secret appears anywhere in the recorded traffic.
func (c *Capture) RequireAbsent(t testing.TB, name string, secret []byte) {
	t.Helper()
	require.NotEmpty(t, secret, "an empty secret proves nothing")
	require.NotEmpty(t, c.exchanges, "the operation must have talked to the TPM")
	for i, ex := range c.exchanges {
		require.Falsef(t, bytes.Contains(ex.cmd, secret),
			"%s crossed the bus in plaintext in command %d (cc 0x%x)", name, i, commandCode(ex.cmd))
		require.Falsef(t, bytes.Contains(ex.rsp, secret),
			"%s crossed the bus in plaintext in the response to command %d (cc 0x%x)", name, i, commandCode(ex.cmd))
	}
}

// RequireSessionAttr fails unless every command with code cc carries a
// session with attr set, and every such session was started salted: an
// unsalted session's key is derived from public nonces alone, so the
// parameter it encrypts could be decrypted from the recorded traffic.
func (c *Capture) RequireSessionAttr(t testing.TB, cc tpm2.TPMCC, attr byte) {
	t.Helper()
	visited := c.walk(cc, func(cmd []byte, salted map[uint32]bool) {
		found := false
		for _, s := range commandSessions(t, cmd) {
			if s.attrs&attr == 0 {
				continue
			}
			require.Truef(t, salted[s.handle],
				"command 0x%x carries attribute 0x%x on unsalted session 0x%x", uint32(cc), attr, s.handle)
			found = true
		}
		require.Truef(t, found, "command 0x%x carries no session with attribute 0x%x", uint32(cc), attr)
	})
	require.NotZerof(t, visited, "expected at least one command 0x%x", uint32(cc))
}

// RequireNoPasswordSession fails if any command with code cc proves an auth
// value through a password session: its authorization would be the value
// itself, in plaintext.
func (c *Capture) RequireNoPasswordSession(t testing.TB, cc tpm2.TPMCC) {
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

// RequireAllSessionsSalted fails if any session started in the recorded
// traffic is unsalted (tpmKey TPM_RH_NULL), or if none was started. An
// unsalted session's key is derived from public nonces alone, so it neither
// hides the parameters it encrypts nor keeps the auth value behind its HMAC
// from an offline brute force.
func (c *Capture) RequireAllSessionsSalted(t testing.TB) {
	t.Helper()
	starts := c.commands(tpm2.TPMCCStartAuthSession)
	require.NotEmpty(t, starts, "expected sessions to be started")
	for _, cmd := range starts {
		tpmKey := binary.BigEndian.Uint32(cmd[10:14])
		require.NotEqual(t, uint32(tpm2.TPMRHNull), tpmKey, "a session was started unsalted")
	}
}

// RequireSaltedAuthorization fails unless every session authorizing a
// command with code cc was started salted.
func (c *Capture) RequireSaltedAuthorization(t testing.TB, cc tpm2.TPMCC) {
	t.Helper()
	checked := 0
	c.walk(cc, func(cmd []byte, salted map[uint32]bool) {
		for _, s := range commandSessions(t, cmd) {
			require.NotEqualf(t, tpmRSPW, s.handle,
				"command 0x%x proves its authorization with a password session", uint32(cc))
			require.Truef(t, salted[s.handle],
				"command 0x%x is authorized by unsalted session 0x%x", uint32(cc), s.handle)
			checked++
		}
	})
	require.NotZerof(t, checked, "expected command 0x%x to be authorized by a session", uint32(cc))
}

// walk calls visit, in recorded order, for every command with code cc not
// addressed to the NULL hierarchy, together with whether each session live
// at that point was started salted, and returns the number of commands
// visited. Session handles are recycled once flushed, so each is resolved
// against the TPM2_StartAuthSession that most recently returned it.
func (c *Capture) walk(cc tpm2.TPMCC, visit func(cmd []byte, salted map[uint32]bool)) int {
	salted := make(map[uint32]bool)
	visited := 0
	for _, ex := range c.exchanges {
		switch commandCode(ex.cmd) {
		case tpm2.TPMCCStartAuthSession:
			if len(ex.rsp) >= 14 && binary.BigEndian.Uint32(ex.rsp[6:10]) == 0 {
				tpmKey := binary.BigEndian.Uint32(ex.cmd[10:14])
				salted[binary.BigEndian.Uint32(ex.rsp[10:14])] = tpmKey != uint32(tpm2.TPMRHNull)
			}
		case cc:
			if addressesNull(ex.cmd) {
				continue
			}
			visit(ex.cmd, salted)
			visited++
		}
	}
	return visited
}

// commands returns every recorded command with code cc, leaving out those
// addressed to the NULL hierarchy: its authorization is always empty, and
// the only such command the session layer issues is the creation of the
// ephemeral salt key, which carries no secret.
func (c *Capture) commands(cc tpm2.TPMCC) [][]byte {
	var out [][]byte
	for _, ex := range c.exchanges {
		if commandCode(ex.cmd) != cc {
			continue
		}
		if cc != tpm2.TPMCCStartAuthSession && addressesNull(ex.cmd) {
			continue
		}
		out = append(out, ex.cmd)
	}
	return out
}

// addressesNull reports whether cmd's first handle is the NULL hierarchy.
func addressesNull(cmd []byte) bool {
	return len(cmd) >= 14 && binary.BigEndian.Uint32(cmd[10:14]) == uint32(tpm2.TPMRHNull)
}

// commandCode returns the command code of cmd, or zero for a truncated one.
func commandCode(cmd []byte) tpm2.TPMCC {
	if len(cmd) < 10 {
		return 0
	}
	return tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
}

// commandSessions parses the authorization area of cmd.
func commandSessions(t testing.TB, cmd []byte) []session {
	t.Helper()
	handles, ok := commandHandles[commandCode(cmd)]
	require.Truef(t, ok, "no handle count for cc 0x%x", commandCode(cmd))
	if binary.BigEndian.Uint16(cmd[0:2]) != uint16(tpm2.TPMSTSessions) {
		return nil
	}
	buf := bytes.NewReader(cmd[10+4*handles:])
	var authSize uint32
	require.NoError(t, binary.Read(buf, binary.BigEndian, &authSize))
	area := make([]byte, authSize)
	_, err := io.ReadFull(buf, area)
	require.NoError(t, err)

	var sessions []session
	r := bytes.NewReader(area)
	for r.Len() > 0 {
		var s session
		var size uint16
		require.NoError(t, binary.Read(r, binary.BigEndian, &s.handle))
		require.NoError(t, binary.Read(r, binary.BigEndian, &size))
		_, err := r.Seek(int64(size), io.SeekCurrent)
		require.NoError(t, err)
		s.attrs, err = r.ReadByte()
		require.NoError(t, err)
		require.NoError(t, binary.Read(r, binary.BigEndian, &size))
		_, err = r.Seek(int64(size), io.SeekCurrent)
		require.NoError(t, err)
		sessions = append(sessions, s)
	}
	return sessions
}
