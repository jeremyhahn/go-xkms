package cmd

import (
	"context"
	"encoding/binary"
	"sync"
)

// hidWork is one HID packet on its way from the reader to the worker.
// cancel is nil for a queued CTAPHID_CANCEL, which is not tracked.
type hidWork struct {
	packet []byte
	cid    uint32
	ctx    context.Context
	cancel context.CancelFunc
}

// hidChannelWork is the work of one CTAPHID channel the worker has not
// finished: waiting counts the packets it has not started.
type hidChannelWork struct {
	waiting int
	live    map[*hidWork]struct{}
}

// hidPending tracks queued and running packets per channel so a
// CTAPHID_CANCEL reaches every command of its channel, started or not.
type hidPending struct {
	mu    sync.Mutex
	byCID map[uint32]*hidChannelWork
}

func newHIDPending() *hidPending {
	return &hidPending{byCID: make(map[uint32]*hidChannelWork)}
}

// add registers a packet before it is queued.
func (p *hidPending) add(parent context.Context, packet []byte) *hidWork {
	ctx, cancel := context.WithCancel(parent)
	w := &hidWork{packet: packet, cid: binary.BigEndian.Uint32(packet[0:4]), ctx: ctx, cancel: cancel}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.byCID[w.cid]
	if st == nil {
		st = &hidChannelWork{live: make(map[*hidWork]struct{})}
		p.byCID[w.cid] = st
	}
	st.waiting++
	st.live[w] = struct{}{}
	return w
}

// start marks a queued packet as taken by the worker.
func (p *hidPending) start(w *hidWork) {
	if w.cancel == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.byCID[w.cid]; st != nil {
		st.waiting--
	}
}

// finish forgets a packet the worker has handled.
func (p *hidPending) finish(w *hidWork) {
	if w.cancel == nil {
		return
	}
	p.mu.Lock()
	p.forgetLocked(w)
	p.mu.Unlock()
	w.cancel()
}

// drop forgets a packet that never made it into the queue.
func (p *hidPending) drop(w *hidWork) {
	p.mu.Lock()
	if st := p.byCID[w.cid]; st != nil {
		st.waiting--
	}
	p.forgetLocked(w)
	p.mu.Unlock()
	w.cancel()
}

func (p *hidPending) forgetLocked(w *hidWork) {
	st := p.byCID[w.cid]
	if st == nil {
		return
	}
	delete(st.live, w)
	if st.waiting <= 0 && len(st.live) == 0 {
		delete(p.byCID, w.cid)
	}
}

// cancel cancels every queued and running packet of the CANCEL packet's
// channel and reports whether some of them have not started yet.
func (p *hidPending) cancel(packet []byte) bool {
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
