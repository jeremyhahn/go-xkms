// Package fido2hid tracks CTAPHID packets so a CTAPHID_CANCEL reaches its channel's work.
package fido2hid

import (
	"context"
	"encoding/binary"
	"sync"
)

// ctaphidCancelInit is the CTAPHID_CANCEL init packet command byte.
const ctaphidCancelInit byte = 0x11 | 0x80

// IsCTAPHIDCancel reports whether packet is a CTAPHID_CANCEL init packet.
func IsCTAPHIDCancel(packet []byte) bool {
	return len(packet) > 4 && packet[4] == ctaphidCancelInit
}

// HIDWork is one HID packet on its way from a reader to a worker. A queued
// CTAPHID_CANCEL carries no cancel function and is not tracked.
type HIDWork struct {
	Packet []byte
	Ctx    context.Context
	cid    uint32
	cancel context.CancelFunc
}

// NewHIDCancelWork wraps a CTAPHID_CANCEL packet queued behind its channel's work.
func NewHIDCancelWork(ctx context.Context, packet []byte) *HIDWork {
	return &HIDWork{Packet: packet, Ctx: ctx}
}

// hidChannelWork is the work of one CTAPHID channel the worker has not
// finished: waiting counts the packets it has not started.
type hidChannelWork struct {
	waiting int
	live    map[*HIDWork]struct{}
}

// HIDPending tracks queued and running packets per channel so a
// CTAPHID_CANCEL reaches every command of its channel, started or not.
type HIDPending struct {
	mu    sync.Mutex
	byCID map[uint32]*hidChannelWork
}

// NewHIDPending returns an empty tracker.
func NewHIDPending() *HIDPending {
	return &HIDPending{byCID: make(map[uint32]*hidChannelWork)}
}

// Add registers a packet before it is queued.
func (p *HIDPending) Add(parent context.Context, packet []byte) *HIDWork {
	ctx, cancel := context.WithCancel(parent)
	w := &HIDWork{Packet: packet, cid: binary.BigEndian.Uint32(packet[0:4]), Ctx: ctx, cancel: cancel}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.byCID[w.cid]
	if st == nil {
		st = &hidChannelWork{live: make(map[*HIDWork]struct{})}
		p.byCID[w.cid] = st
	}
	st.waiting++
	st.live[w] = struct{}{}
	return w
}

// Start marks a queued packet as taken by the worker.
func (p *HIDPending) Start(w *HIDWork) {
	if w.cancel == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.byCID[w.cid]; st != nil {
		st.waiting--
	}
}

// Finish forgets a packet the worker has handled.
func (p *HIDPending) Finish(w *HIDWork) {
	if w.cancel == nil {
		return
	}
	p.mu.Lock()
	p.forgetLocked(w)
	p.mu.Unlock()
	w.cancel()
}

// Drop forgets a packet that never made it into the queue.
func (p *HIDPending) Drop(w *HIDWork) {
	p.mu.Lock()
	if st := p.byCID[w.cid]; st != nil {
		st.waiting--
	}
	p.forgetLocked(w)
	p.mu.Unlock()
	w.cancel()
}

func (p *HIDPending) forgetLocked(w *HIDWork) {
	st := p.byCID[w.cid]
	if st == nil {
		return
	}
	delete(st.live, w)
	if st.waiting <= 0 && len(st.live) == 0 {
		delete(p.byCID, w.cid)
	}
}

// Cancel cancels every queued and running packet of the CANCEL packet's
// channel and reports whether some of them have not started yet.
func (p *HIDPending) Cancel(packet []byte) bool {
	cid := binary.BigEndian.Uint32(packet[0:4])
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.byCID[cid]
	if st == nil {
		return false
	}
	for w := range st.live {
		w.cancel()
	}
	return st.waiting > 0
}
