package fido2hid

import (
	"context"
	"testing"
)

func packet(cid uint32, cmd byte) []byte {
	p := make([]byte, 64)
	p[0], p[1], p[2], p[3] = byte(cid>>24), byte(cid>>16), byte(cid>>8), byte(cid)
	p[4] = cmd
	return p
}

func TestIsCTAPHIDCancel(t *testing.T) {
	if !IsCTAPHIDCancel(packet(1, 0x91)) {
		t.Fatal("CANCEL init packet not recognised")
	}
	if IsCTAPHIDCancel(packet(1, 0x90)) {
		t.Fatal("CBOR init packet taken for CANCEL")
	}
	if IsCTAPHIDCancel([]byte{0, 0, 0, 1}) {
		t.Fatal("short packet taken for CANCEL")
	}
}

func TestCancelInFlightWork(t *testing.T) {
	p := NewHIDPending()
	w := p.Add(context.Background(), packet(7, 0x90))
	p.Start(w)
	if p.Cancel(packet(7, 0x91)) {
		t.Fatal("started work reported as pending")
	}
	if w.Ctx.Err() == nil {
		t.Fatal("in-flight work not cancelled")
	}
	p.Finish(w)
	if p.Cancel(packet(7, 0x91)) {
		t.Fatal("finished channel still tracked")
	}
}

func TestCancelPendingWork(t *testing.T) {
	p := NewHIDPending()
	w := p.Add(context.Background(), packet(9, 0x90))
	other := p.Add(context.Background(), packet(10, 0x90))
	if !p.Cancel(packet(9, 0x91)) {
		t.Fatal("queued work not reported as pending")
	}
	if w.Ctx.Err() == nil {
		t.Fatal("queued work not cancelled")
	}
	if other.Ctx.Err() != nil {
		t.Fatal("work of another channel cancelled")
	}
	p.Start(w)
	p.Finish(w)
	if p.Cancel(packet(9, 0x91)) {
		t.Fatal("channel still tracked after Finish")
	}
}

func TestDropForgetsWork(t *testing.T) {
	p := NewHIDPending()
	w := p.Add(context.Background(), packet(3, 0x90))
	p.Drop(w)
	if w.Ctx.Err() == nil {
		t.Fatal("dropped work context not released")
	}
	if p.Cancel(packet(3, 0x91)) {
		t.Fatal("dropped work still pending")
	}
}

func TestCancelWorkIsUntracked(t *testing.T) {
	p := NewHIDPending()
	w := NewHIDCancelWork(context.Background(), packet(5, 0x91))
	p.Start(w)
	p.Finish(w)
	if w.Ctx.Err() != nil {
		t.Fatal("queued CANCEL context cancelled")
	}
	if p.Cancel(packet(5, 0x91)) {
		t.Fatal("queued CANCEL tracked as work")
	}
}
