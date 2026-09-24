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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"
	"time"

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/stretchr/testify/require"
)

// The tests in this package talk to a FAKE LINK and a REAL CODEC.
//
// Every byte a test sends is framed by the SDK's own EncodeResponse and every
// byte the backend sends is parsed by the SDK's own Decode, so what is under
// test is this package against the protocol as arduino-generic implements it.
// Mocking *aggeneric.Device instead would replace the one thing worth
// exercising — a reply's layout, a status code's meaning, the length a command
// needs — with this package's own opinion of it, and the tests would pass for a
// device that does not exist.

// linkTimeout bounds one command in a test. It is short because these tests
// must never block: the SDK's read loop spins until its deadline when a link
// returns a non-EOF error, and ten seconds of that is not a unit test.
const linkTimeout = 50 * time.Millisecond

// reply is one canned response.
type reply struct {
	status  aggeneric.Status
	payload []byte
}

// fakeLink answers requests from a per-command table, framing each answer with
// the SDK's encoder and echoing the sequence number so the SDK accepts it.
//
// A command with no entry is answered with StatusErrUnknownCmd, which is what
// a firmware built without that feature actually does — the absence of a reply
// in the table models the absence of a handler in the image.
type fakeLink struct {
	replies map[aggeneric.Cmd]reply

	// pagedReplies answers successive requests for one command with successive
	// entries, which is how a paged command reads on the wire.
	pagedReplies map[aggeneric.Cmd][][]byte
	pageCursor   map[aggeneric.Cmd]int

	// repeatPages starts the page sequence over instead of answering a range
	// error past the end, which is a device that can be attested more than
	// once. Off by default: the range error at the end is what stops a host
	// looping forever, and that is worth testing on its own.
	repeatPages bool

	// requests records what the backend asked for, so a test can assert that a
	// refusal cost no round trip.
	requests []aggeneric.Frame

	// writeErr, when set, fails the write. readEOF closes the link on the next
	// read, which is how a device that went away is modelled.
	writeErr error
	readEOF  bool

	// corrupt flips a byte of every response, so the CRC no longer holds.
	corrupt bool

	rx bytes.Buffer
}

func newFakeLink() *fakeLink {
	return &fakeLink{
		replies:      map[aggeneric.Cmd]reply{},
		pagedReplies: map[aggeneric.Cmd][][]byte{},
		pageCursor:   map[aggeneric.Cmd]int{},
	}
}

func (l *fakeLink) answer(cmd aggeneric.Cmd, payload []byte) *fakeLink {
	l.replies[cmd] = reply{payload: payload}
	return l
}

func (l *fakeLink) refuse(cmd aggeneric.Cmd, status aggeneric.Status) *fakeLink {
	l.replies[cmd] = reply{status: status}
	return l
}

func (l *fakeLink) Write(p []byte) (int, error) {
	if l.writeErr != nil {
		return 0, l.writeErr
	}
	f, _, err := aggeneric.Decode(p)
	if err != nil {
		return 0, err
	}
	l.requests = append(l.requests, f)

	r, ok := l.replies[f.Cmd()]
	if !ok {
		if pages, paged := l.pagedReplies[f.Cmd()]; paged {
			at := l.pageCursor[f.Cmd()]
			if l.repeatPages && len(pages) > 0 {
				at %= len(pages)
			}
			if at >= len(pages) {
				// Past the end the device answers a range error rather than an
				// empty success, so a host cannot loop forever on it.
				r = reply{status: aggeneric.StatusErrRange}
			} else {
				r = reply{payload: pages[at]}
				l.pageCursor[f.Cmd()] = at + 1
			}
		} else {
			r = reply{status: aggeneric.StatusErrUnknownCmd}
		}
	}
	resp, err := aggeneric.EncodeResponse(f.Seq, f.Cmd(), r.status, r.payload)
	if err != nil {
		return 0, err
	}
	if l.corrupt {
		resp[len(resp)-1] ^= 0xFF
	}
	l.rx.Write(resp)
	return len(p), nil
}

func (l *fakeLink) Read(p []byte) (int, error) {
	if l.readEOF {
		return 0, io.EOF
	}
	n, err := l.rx.Read(p)
	if err == io.EOF {
		// An exhausted buffer is a device that has stopped talking. Reporting
		// EOF makes the SDK give up at once instead of spinning to its
		// deadline, which keeps every negative test fast.
		return n, io.EOF
	}
	return n, err
}

// capsPayload builds the board header a current firmware sends, mirroring the
// layout in include/ag/protocol.h: the fourteen-byte header every version has,
// then the algorithm bitmap appended after it.
func capsPayload(tier aggeneric.CryptoTier, features uint32, algorithms aggeneric.AlgorithmSet) []byte {
	p := make([]byte, 16)
	p[0], p[1] = 1, 0 // protocol 1.0
	p[2], p[3], p[4] = 0, 2, 0
	p[5] = 0x01 // board id
	p[6] = 22   // pin count
	p[7] = 8    // scheduler slots
	p[8] = aggeneric.MaxPayload
	p[9] = byte(tier)
	binary.LittleEndian.PutUint32(p[10:14], features)
	binary.LittleEndian.PutUint16(p[14:16], uint16(algorithms))
	return p
}

// legacyCapsPayload is what firmware built before the algorithm bitmap existed
// sends: the header and nothing after it.
func legacyCapsPayload(tier aggeneric.CryptoTier) []byte {
	return capsPayload(tier, 0x0F, 0)[:14]
}

// capsPayloadWithProtocol builds a header claiming a specific protocol version.
func capsPayloadWithProtocol(major, minor uint8) []byte {
	p := capsPayload(aggeneric.CryptoSecureElement, 0x0F, aggeneric.AlgECDSAP256SHA256)
	p[0], p[1] = major, minor
	return p
}

// provInfoPayload builds a PROV_INFO reply: four revision bytes, config block
// 0, then the two lock bytes.
//
// The lock bytes are sent EXPLICITLY and are not inside block 0 -- the element
// puts them at config bytes 86 and 87, which is block 2. The first is
// LockValue, governing the data zone; the second is LockConfig. And the
// polarity inverts: 0x55 is the element's UNLOCKED value, so the byte that
// looks like a flag being set is the zone being open.
func provInfoPayload(serial []byte, configLocked, dataLocked bool) []byte {
	p := make([]byte, 4+32+2)
	p[0], p[1], p[2], p[3] = 0x00, 0x00, 0x60, 0x02 // a 608-family revision
	// The element splits its nine-byte serial across config bytes 0..3 and
	// 8..12, which land at offsets 4 and 12 of this reply.
	copy(p[4:8], serial[0:4])
	copy(p[12:17], serial[4:9])

	const unlocked = 0x55
	p[36], p[37] = unlocked, unlocked
	if dataLocked {
		p[36] = 0x00
	}
	if configLocked {
		p[37] = 0x00
	}
	return p
}

// sysInfoPayload builds a SYS_INFO reply.
func sysInfoPayload(uptime time.Duration, freeRAM uint16, cause aggeneric.ResetCause) []byte {
	p := make([]byte, 7)
	binary.LittleEndian.PutUint32(p[0:4], uint32(uptime.Milliseconds()))
	binary.LittleEndian.PutUint16(p[4:6], freeRAM)
	p[6] = byte(cause)
	return p
}

// testPoint returns a valid P-256 public point in the element's wire form:
// the affine X and Y coordinates, 32 bytes each, with no SEC 1 prefix.
func testPoint(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	point := make([]byte, devicePointLen)
	key.X.FillBytes(point[:32])
	key.Y.FillBytes(point[32:])
	return point, &key.PublicKey
}

// attestCertReply frames one page of an ATTEST_CERT answer:
// [page:1][total:2 little-endian][bytes]. The device pages because a
// certificate is seven times a frame payload and longer than a byte can count.
func attestCertReply(page byte, total int, chunk []byte) []byte {
	out := make([]byte, 3, 3+len(chunk))
	out[0] = page
	binary.LittleEndian.PutUint16(out[1:3], uint16(total))
	return append(out, chunk...)
}

// answerAttestCert loads a whole certificate into the link, paged the way the
// device pages it. The link answers pages in order as they are requested.
func (l *fakeLink) answerAttestCert(der []byte) *fakeLink {
	const page = 60 // AG_ALIAS_PAGE
	var pages [][]byte
	for off := 0; off < len(der); off += page {
		end := off + page
		if end > len(der) {
			end = len(der)
		}
		pages = append(pages, attestCertReply(byte(off/page), len(der), der[off:end]))
	}
	l.pagedReplies[aggeneric.CmdAttestCert] = pages
	return l
}

// answerAttestCertRepeating is answerAttestCert for a link that is asked for
// the same certificate more than once, as a concurrency test does.
func (l *fakeLink) answerAttestCertRepeating(der []byte) *fakeLink {
	l.repeatPages = true
	return l.answerAttestCert(der)
}

// newTestDevice wraps a link in an SDK Device with a deadline short enough for
// a unit test.
func newTestDevice(link io.ReadWriter) *aggeneric.Device {
	return aggeneric.New(link, aggeneric.WithTimeout(linkTimeout))
}

// testConfig is a valid configuration with a logger that discards.
func testConfig() *Config {
	return &Config{
		KeyCN:          DefaultKeyCN,
		Slot:           aggeneric.SlotDeviceID,
		RequestTimeout: linkTimeout,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// newTestBackend attaches a backend to a link that answers CAPS as described
// and nothing else.
func newTestBackend(t *testing.T, link *fakeLink) *Backend {
	t.Helper()
	b, err := NewBackend(context.Background(), testConfig(), newTestDevice(link))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	return b
}

// secureElementLink is the ordinary device these tests are written against: a
// secure element, attestation compiled in, ECDSA P-256 and HMAC-SHA256 and --
// as the ATECC608A really is -- NO Ed25519.
func secureElementLink() *fakeLink {
	return newFakeLink().answer(aggeneric.CmdCaps, capsPayload(
		aggeneric.CryptoSecureElement,
		aggeneric.FeatureGPIO|aggeneric.FeatureAttest,
		aggeneric.AlgECDSAP256SHA256|aggeneric.AlgHMACSHA256,
	))
}
