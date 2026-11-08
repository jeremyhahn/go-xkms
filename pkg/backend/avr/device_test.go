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

package avr

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceErrorIsNilForSuccess(t *testing.T) {
	assert.NoError(t, deviceError(nil))
}

// Every status the device can answer with has to land somewhere a caller can
// act on. These are the ones this package names.
func TestDeviceErrorMapsEveryNamedStatus(t *testing.T) {
	tests := []struct {
		status   tfw.Status
		sentinel error
	}{
		{tfw.StatusErrUnknownCmd, ErrCommandUnavailable},
		{tfw.StatusErrNotProvisioned, ErrNotProvisioned},
		{tfw.StatusErrCrypto, ErrDeviceCrypto},
		{tfw.StatusErrAuthRequired, ErrAuthRequired},
		{tfw.StatusErrBusy, ErrDeviceBusy},
		{tfw.StatusErrProtectedRegion, ErrProtectedRegion},
		{tfw.StatusErrInternal, ErrDeviceInternal},
		{tfw.StatusErrTimeout, ErrDeviceUnreachable},
		{tfw.StatusErrCRC, ErrDeviceProtocol},
		{tfw.StatusErrFraming, ErrDeviceProtocol},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			err := deviceError(tt.status)
			assert.ErrorIs(t, err, tt.sentinel)
			assert.Contains(t, err.Error(), tt.status.String(),
				"the device's own wording is the detail, so a log says what it said")
		})
	}
}

// A status this build has no mapping for degrades to the generic refusal.
// Status codes extend and never renumber, so reading an unknown one as the
// nearest known one would turn a version skew into a specific, wrong
// diagnosis.
func TestDeviceErrorDegradesAnUnknownStatusToARefusal(t *testing.T) {
	err := deviceError(tfw.Status(200))

	assert.ErrorIs(t, err, ErrDeviceRefused)
	assert.NotErrorIs(t, err, ErrCommandUnavailable)
	assert.NotErrorIs(t, err, ErrNotProvisioned)
}

func TestDeviceErrorClassifiesTransportAndFramingFailures(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"link closed", &tfw.LinkError{Op: "read", Err: io.EOF}, ErrDeviceUnreachable},
		{"no answer", &tfw.TimeoutError{Cmd: tfw.CmdCaps, Elapsed: time.Second}, ErrDeviceUnreachable},
		{"short reply", &tfw.ShortReplyError{Cmd: tfw.CmdCaps, Got: 9, Need: 14}, ErrDeviceProtocol},
		{"bad checksum", &tfw.CRCError{Computed: 1, Claimed: 2}, ErrDeviceProtocol},
		{"not a frame", &tfw.FrameError{Reason: "does not begin with the start byte"}, ErrDeviceProtocol},
		{"oversized payload", &tfw.PayloadSizeError{Size: 100, Limit: 64}, ErrDeviceProtocol},
		{"protocol major", &tfw.ProtocolVersionError{DeviceMajor: 3, HostMajor: 2}, ErrProtocolVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, deviceError(tt.err), tt.sentinel)
		})
	}
}

// A closed link must stay reachable through errors.Is(err, io.EOF): that is
// how a caller tells a port that went away, which needs a reconnect, from a
// device that simply refused.
func TestDeviceErrorKeepsTheTransportCauseReachable(t *testing.T) {
	err := deviceError(&tfw.LinkError{Op: "read", Err: io.EOF})

	assert.ErrorIs(t, err, ErrDeviceUnreachable)
	assert.ErrorIs(t, err, io.EOF)
}

// A cancelled context is the caller's own decision and is returned unchanged,
// so a caller's select on context.Canceled still works through this layer.
func TestDeviceErrorPassesContextFailuresThrough(t *testing.T) {
	assert.Equal(t, context.Canceled, deviceError(context.Canceled))
	assert.Equal(t, context.DeadlineExceeded, deviceError(context.DeadlineExceeded))
	assert.NotErrorIs(t, deviceError(context.Canceled), ErrDeviceUnreachable)
}

// Anything with no classification at all is still an error and still says the
// device did not answer usefully -- never nil.
func TestDeviceErrorNeverSwallowsAnUnclassifiedFailure(t *testing.T) {
	err := deviceError(errors.New("something else entirely"))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceUnreachable)
	assert.Contains(t, err.Error(), "something else entirely")
}

// The SDK's typed error stays reachable through the translation, so a caller
// diagnosing a bad link can read the two checksums that say which side to
// suspect: one that is stable across retries points at a sender writing the
// wrong bytes, one that differs every time points at the line.
func TestDeviceErrorKeepsTheSDKErrorReachable(t *testing.T) {
	err := deviceError(&tfw.CRCError{Computed: 0x1234, Claimed: 0x5678})

	var crc *tfw.CRCError
	require.ErrorAs(t, err, &crc)
	assert.Equal(t, uint16(0x1234), crc.Computed)
	assert.Equal(t, uint16(0x5678), crc.Claimed)
	assert.ErrorIs(t, err, ErrDeviceProtocol)
}

// An argument the SDK refused before it built a frame -- the wrong nonce width,
// an oversized EEPROM chunk -- must not be reported as a device that did not
// answer. That would send a caller to look at the cable for a fault in its own
// call.
func TestDeviceErrorClassifiesAnArgumentItNeverSent(t *testing.T) {
	err := deviceError(&tfw.ArgRangeError{
		Cmd: tfw.CmdAttestCert, Arg: "nonce", Value: 16,
		Min: 32, Max: 32, Unit: "bytes",
	})

	require.ErrorIs(t, err, ErrInvalidArgument)
	assert.NotErrorIs(t, err, ErrDeviceUnreachable)
}
