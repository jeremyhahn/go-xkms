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

//go:build tpm_simulator

package luks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// This file drives the TPM 2.0 command-error branches of tpm.go (failed
// TPM2_ReadPublic, TPM2_Create, TPM2_Load, TPM2_StartAuthSession,
// TPM2_PolicyPCR, TPM2_PolicyGetDigest, TPM2_FlushContext) against the real
// go-tpm-tools software simulator. A faultTPM decorator inspects the TPM
// command code embedded in every request (bytes [6:10] of the TPM2 command
// header — tag(2) + commandSize(4) + commandCode(4)) and substitutes an
// injected error for one specific command, letting every other command run
// against the genuine simulator so the protocol state stays valid up to the
// point of failure.

// errInjectedFault is the sentinel returned by faultTPM for the targeted
// command code.
var errInjectedFault = errors.New("gaps: injected tpm command failure")

// faultTPM wraps a real transport.TPM and fails exactly one TPM command
// code, forwarding every other command to the underlying transport.
type faultTPM struct {
	tpm    transport.TPM
	failCC libtpm2.TPMCC
}

// commandCode extracts the TPM_CC from a raw TPM2 command buffer. The
// command header is tag(2) + commandSize(4) + commandCode(4); returns 0 if
// the buffer is too short to contain a command code.
func commandCode(input []byte) libtpm2.TPMCC {
	if len(input) < 10 {
		return 0
	}
	return libtpm2.TPMCC(binary.BigEndian.Uint32(input[6:10]))
}

// Send forwards to the real TPM unless the request matches the configured
// fault command code, in which case it returns errInjectedFault instead of
// touching the simulator.
func (f *faultTPM) Send(input []byte) ([]byte, error) {
	if commandCode(input) == f.failCC {
		return nil, errInjectedFault
	}
	return f.tpm.Send(input)
}

// faultOpener hands out a TPMCloser wrapping a faultTPM over a shared
// simulator transport.
type faultOpener struct {
	tpm    transport.TPM
	failCC libtpm2.TPMCC
}

func (o *faultOpener) Open(context.Context) (transport.TPMCloser, error) {
	return nopTPMCloser{tpm: &faultTPM{tpm: o.tpm, failCC: o.failCC}}, nil
}

// newFaultSimulator provisions a fresh simulator + persistent SRK and
// returns the shared transport plus a cleanup func. Callers derive as many
// faultOpener values as they need from the returned transport.TPM.
func newFaultSimulator(t *testing.T) transport.TPM {
	t.Helper()
	simLock.Lock()
	sim, err := simulator.Get()
	if err != nil {
		simLock.Unlock()
		t.Fatalf("simulator.Get: %v", err)
	}
	t.Cleanup(func() {
		sim.Close()
		simLock.Unlock()
	})

	sharedTPM := transport.FromReadWriter(sim)
	provisionPersistentSRK(t, sharedTPM, libtpm2.TPMHandle(0x81000001))
	return sharedTPM
}

// ---------------------------------------------------------------------------
// SealPassphrase / Seal command-failure branches
// ---------------------------------------------------------------------------

// TestTPMSealer_SealPassphrase_CommandFailures drives every TPM command
// SealPassphrase depends on into failure, one at a time, and asserts the
// resulting error is wrapped in the documented sentinel.
func TestTPMSealer_SealPassphrase_CommandFailures(t *testing.T) {
	sharedTPM := newFaultSimulator(t)

	tests := []struct {
		name    string
		failCC  libtpm2.TPMCC
		wantErr error
	}{
		{"policy digest: start session fails", libtpm2.TPMCCStartAuthSession, ErrTPMPolicyFailed},
		{"policy digest: policy pcr fails", libtpm2.TPMCCPolicyPCR, ErrTPMPolicyFailed},
		{"policy digest: get digest fails", libtpm2.TPMCCPolicyGetDigest, ErrTPMPolicyFailed},
		{"read parent public fails", libtpm2.TPMCCReadPublic, ErrTPMSealFailed},
		{"create fails", libtpm2.TPMCCCreate, ErrTPMSealFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewTPMSealer(nil, &faultOpener{tpm: sharedTPM, failCC: tc.failCC})
			if err != nil {
				t.Fatalf("construct sealer: %v", err)
			}
			_, err = h.SealPassphrase(context.Background(), "", []int32{7})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("SealPassphrase() err = %v, want wrapped %v", err, tc.wantErr)
			}
		})
	}
}

// TestTPMSealer_Seal_Success proves the narrow Seal() wrapper returns the
// same passphrase/token pair SealPassphrase produces.
func TestTPMSealer_Seal_Success(t *testing.T) {
	sharedTPM := newFaultSimulator(t)

	h, err := NewTPMSealer(nil, &sharedSimOpener{tpm: sharedTPM})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	passphrase, tokenJSON, err := h.Seal(context.Background(), "", []int32{7})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(passphrase) != 32 {
		t.Fatalf("passphrase length = %d, want 32", len(passphrase))
	}
	if len(tokenJSON) == 0 {
		t.Fatal("empty token json")
	}
}

// ---------------------------------------------------------------------------
// UnsealPassphrase command-failure branches
// ---------------------------------------------------------------------------

// TestTPMSealer_UnsealPassphrase_CommandFailures seals a passphrase once
// against a healthy TPM connection, then replays the unseal against a
// faulty connection that fails one command at a time.
func TestTPMSealer_UnsealPassphrase_CommandFailures(t *testing.T) {
	sharedTPM := newFaultSimulator(t)

	good, err := NewTPMSealer(nil, &sharedSimOpener{tpm: sharedTPM})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	res, err := good.SealPassphrase(context.Background(), "", []int32{7})
	if err != nil {
		t.Fatalf("SealPassphrase: %v", err)
	}

	tests := []struct {
		name    string
		failCC  libtpm2.TPMCC
		wantErr error
	}{
		{"read parent public fails", libtpm2.TPMCCReadPublic, ErrTPMUnsealFailed},
		{"load fails", libtpm2.TPMCCLoad, ErrTPMUnsealFailed},
		{"policy session start fails", libtpm2.TPMCCStartAuthSession, ErrTPMUnsealFailed},
		{"policy pcr fails", libtpm2.TPMCCPolicyPCR, ErrTPMUnsealFailed},
		{"unseal fails", libtpm2.TPMCCUnseal, ErrTPMUnsealFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewTPMSealer(nil, &faultOpener{tpm: sharedTPM, failCC: tc.failCC})
			if err != nil {
				t.Fatalf("construct sealer: %v", err)
			}
			_, err = h.UnsealPassphrase(context.Background(), res.TokenJSON)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("UnsealPassphrase() err = %v, want wrapped %v", err, tc.wantErr)
			}
		})
	}
}

// TestTPMSealer_UnsealPassphrase_FlushContextErrorIsLoggedNotFatal proves
// that a failing TPM2_FlushContext during teardown is swallowed — the
// unsealed passphrase must still be returned correctly — but the failure is
// surfaced through the sealer's logger so operators can see a noisy TPM.
func TestTPMSealer_UnsealPassphrase_FlushContextErrorIsLoggedNotFatal(t *testing.T) {
	sharedTPM := newFaultSimulator(t)

	good, err := NewTPMSealer(nil, &sharedSimOpener{tpm: sharedTPM})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}
	res, err := good.SealPassphrase(context.Background(), "", []int32{7})
	if err != nil {
		t.Fatalf("SealPassphrase: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	faulty, err := NewTPMSealer(logger, &faultOpener{tpm: sharedTPM, failCC: libtpm2.TPMCCFlushContext})
	if err != nil {
		t.Fatalf("construct sealer: %v", err)
	}

	unsealed, err := faulty.UnsealPassphrase(context.Background(), res.TokenJSON)
	if err != nil {
		t.Fatalf("UnsealPassphrase returned error despite flush-only failure: %v", err)
	}
	if !bytes.Equal(unsealed, res.Passphrase) {
		t.Fatalf("unseal mismatch:\n  got  %x\n  want %x", unsealed, res.Passphrase)
	}
	if !strings.Contains(logBuf.String(), "tpm flush context failed") {
		t.Fatalf("expected flush-context warning in log output, got: %s", logBuf.String())
	}
}
