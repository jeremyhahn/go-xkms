// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package phone

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strconv"
)

// bleNotifyOverhead is the number of bytes reserved out of the peripheral's
// MTU when sizing outbound fragments.
//
// An ATT_HANDLE_VALUE_NTF PDU carries a 3 byte header (1 byte opcode plus a
// 2 byte attribute handle), so the largest value a peripheral may notify is
// ATT_MTU-3 bytes. The GATT server side of tinygo.org/x/bluetooth v0.15.0
// exposes no way to observe the ATT MTU that the central negotiated -
// GetMTU exists only on DeviceCharacteristic (the central/client side) - so
// the peripheral cannot size fragments from the live connection. We
// therefore reserve 7 bytes rather than the strictly required 3: the extra 4
// bytes of headroom keep every fragment comfortably inside the negotiated
// PDU on stacks that shave a few bytes for their own bookkeeping, and cost
// nothing measurable because a message is at most a few fragments long.
const bleNotifyOverhead = 7

// ErrNotifyUnavailable indicates the peripheral's notify path is not usable:
// the GATT service has not been registered yet, or the response
// characteristic handle was never bound.
var ErrNotifyUnavailable = errors.New("phone: notify characteristic unavailable")

// FragmentWriter transmits a single BLE fragment to the connected peer.
//
// On a GATT server, writing a characteristic value is what emits the
// notification to subscribed clients, so *bluetooth.Characteristic satisfies
// this interface directly. It exists so the notify path can be exercised
// without Bluetooth hardware.
type FragmentWriter interface {
	// Write transmits p and returns the number of bytes accepted.
	Write(p []byte) (n int, err error)
}

// ShortWriteError reports that the transport accepted only part of a
// fragment. A partially transmitted fragment is unrecoverable because the
// peer reassembles by fragment boundary, so the send is aborted.
// It unwraps to io.ErrShortWrite.
type ShortWriteError struct {
	// Index is the zero-based position of the fragment within the message.
	Index int
	// Total is the number of fragments in the message.
	Total int
	// Written is the number of bytes the transport accepted.
	Written int
	// Size is the number of bytes the fragment contained.
	Size int
}

// Error implements the error interface.
func (e *ShortWriteError) Error() string {
	return "phone: short notify write on fragment " + strconv.Itoa(e.Index) + "/" +
		strconv.Itoa(e.Total) + ": wrote " + strconv.Itoa(e.Written) + " of " +
		strconv.Itoa(e.Size) + " bytes"
}

// Unwrap returns io.ErrShortWrite so callers can match with errors.Is.
func (e *ShortWriteError) Unwrap() error {
	return io.ErrShortWrite
}

// FragmentWriteError reports that a fragment could not be transmitted. It
// identifies which fragment of the message failed so a truncated transfer
// can be diagnosed from the log alone.
type FragmentWriteError struct {
	// Index is the zero-based position of the fragment within the message.
	Index int
	// Total is the number of fragments in the message.
	Total int
	// Err is the underlying transport failure.
	Err error
}

// Error implements the error interface.
func (e *FragmentWriteError) Error() string {
	return "phone: failed to notify fragment " + strconv.Itoa(e.Index) + "/" +
		strconv.Itoa(e.Total) + ": " + e.Err.Error()
}

// Unwrap returns the underlying transport failure.
func (e *FragmentWriteError) Unwrap() error {
	return e.Err
}

// fragmentSender fragments outbound messages and notifies each fragment to
// the peer over a FragmentWriter.
type fragmentSender struct {
	writer     FragmentWriter
	fragmenter *Fragmenter
	log        *slog.Logger
}

// newFragmentSender binds a fragmenter to the characteristic that carries
// outbound notifications.
func newFragmentSender(writer FragmentWriter, fragmenter *Fragmenter, log *slog.Logger) *fragmentSender {
	if log == nil {
		log = slog.Default()
	}
	return &fragmentSender{
		writer:     writer,
		fragmenter: fragmenter,
		log:        log,
	}
}

// send fragments message and transmits every fragment in order. It aborts on
// the first failed or partial write and returns a typed error identifying the
// offending fragment; a nil return means every fragment was accepted by the
// transport.
func (s *fragmentSender) send(ctx context.Context, message []byte) error {
	if s == nil || s.writer == nil || s.fragmenter == nil {
		return ErrNotifyUnavailable
	}

	fragments, err := s.fragmenter.Fragment(message)
	if err != nil {
		return &WrappedError{Msg: "fragmentation failed", Err: err}
	}

	total := len(fragments)
	for i, frag := range fragments {
		if err := ctx.Err(); err != nil {
			return &FragmentWriteError{Index: i, Total: total, Err: err}
		}

		n, err := s.writer.Write(frag)
		if err != nil {
			s.log.Error("failed to notify fragment",
				slog.Int("index", i),
				slog.Int("total", total),
				slog.String("error", err.Error()),
			)
			return &FragmentWriteError{Index: i, Total: total, Err: err}
		}
		if n != len(frag) {
			s.log.Error("short notify write",
				slog.Int("index", i),
				slog.Int("total", total),
				slog.Int("written", n),
				slog.Int("size", len(frag)),
			)
			return &ShortWriteError{Index: i, Total: total, Written: n, Size: len(frag)}
		}

		s.log.Debug("notified fragment",
			slog.Int("index", i),
			slog.Int("total", total),
			slog.Int("size", len(frag)),
			slog.String("hex_prefix", hex.EncodeToString(safeSlice(frag, 0, 16))),
		)
	}

	s.log.Debug("message notified",
		slog.Int("message_size", len(message)),
		slog.Int("fragments", total),
	)
	return nil
}

// safeSlice returns a slice of data up to maxLen bytes starting at start, or
// the remaining data if shorter. Used for debug logging of BLE payloads.
func safeSlice(data []byte, start, maxLen int) []byte {
	if start >= len(data) {
		return nil
	}
	end := start + maxLen
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}
