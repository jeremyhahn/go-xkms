// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * protocol.test.ts — the WebSocket console control-frame wire format
 * (src/protocol.ts): resize / hostkey-response encoding and server→client
 * control frame parsing, including the fail-closed hostkey mode default.
 *
 * This content previously lived (mislabeled) in ssh-console.test.ts, which
 * imported only './protocol.js' and never exercised src/ssh-console.ts at
 * all — hence ssh-console.ts showing 0% coverage despite a same-named test
 * file existing. See ssh-console.test.ts for the actual SSHConsoleClient
 * tests.
 */

import { describe, it, expect } from 'vitest';
import { parseControl, encodeResize, encodeHostKeyResponse } from './protocol.js';

describe('console protocol', () => {
  it('encodeResize produces a resize control frame', () => {
    const frame = encodeResize(40, 120);
    expect(JSON.parse(frame)).toEqual({ type: 'resize', rows: 40, cols: 120 });
  });

  it('parseControl parses an error frame', () => {
    expect(parseControl('{"type":"error","message":"boom"}')).toEqual({
      type: 'error',
      message: 'boom',
    });
  });

  it('parseControl parses an error frame without a message', () => {
    expect(parseControl('{"type":"error"}')).toEqual({ type: 'error', message: undefined });
  });

  it('parseControl parses an exit frame', () => {
    expect(parseControl('{"type":"exit"}')).toEqual({ type: 'exit' });
  });

  it('parseControl returns null for non-control JSON', () => {
    expect(parseControl('{"foo":"bar"}')).toBeNull();
  });

  it('parseControl returns null for non-JSON (e.g. stray text)', () => {
    expect(parseControl('not json')).toBeNull();
  });

  it('parseControl ignores unknown control types', () => {
    expect(parseControl('{"type":"whatever"}')).toBeNull();
  });

  it('encodeHostKeyResponse produces an accept frame', () => {
    expect(JSON.parse(encodeHostKeyResponse(true))).toEqual({
      type: 'hostkey-response',
      accept: true,
    });
  });

  it('encodeHostKeyResponse produces a reject frame', () => {
    expect(JSON.parse(encodeHostKeyResponse(false))).toEqual({
      type: 'hostkey-response',
      accept: false,
    });
  });

  it('parseControl parses a full hostkey confirm frame', () => {
    expect(
      parseControl(
        '{"type":"hostkey","host":"example.com:22","key_type":"ssh-ed25519","fingerprint":"SHA256:abc","known":false,"mode":"confirm"}',
      ),
    ).toEqual({
      type: 'hostkey',
      host: 'example.com:22',
      key_type: 'ssh-ed25519',
      fingerprint: 'SHA256:abc',
      known: false,
      mode: 'confirm',
    });
  });

  it('parseControl parses a hostkey notify frame', () => {
    expect(
      parseControl(
        '{"type":"hostkey","host":"example.com:22","key_type":"ssh-rsa","fingerprint":"SHA256:def","known":true,"mode":"notify"}',
      ),
    ).toEqual({
      type: 'hostkey',
      host: 'example.com:22',
      key_type: 'ssh-rsa',
      fingerprint: 'SHA256:def',
      known: true,
      mode: 'notify',
    });
  });

  it('parseControl defaults a missing hostkey mode to "confirm" (fail-closed)', () => {
    expect(
      parseControl(
        '{"type":"hostkey","host":"example.com:22","key_type":"ssh-ed25519","fingerprint":"SHA256:abc","known":false}',
      ),
    ).toEqual({
      type: 'hostkey',
      host: 'example.com:22',
      key_type: 'ssh-ed25519',
      fingerprint: 'SHA256:abc',
      known: false,
      mode: 'confirm',
    });
  });

  it('parseControl defaults an invalid hostkey mode value to "confirm" (fail-closed)', () => {
    expect(
      parseControl(
        '{"type":"hostkey","host":"example.com:22","key_type":"ssh-ed25519","fingerprint":"SHA256:abc","known":false,"mode":"bogus"}',
      ),
    ).toEqual({
      type: 'hostkey',
      host: 'example.com:22',
      key_type: 'ssh-ed25519',
      fingerprint: 'SHA256:abc',
      known: false,
      mode: 'confirm',
    });
  });

  it('parseControl returns null for a hostkey frame missing required string fields', () => {
    expect(parseControl('{"type":"hostkey","host":"example.com:22"}')).toBeNull();
  });

  it('parseControl returns null for a hostkey frame with wrong-typed known field', () => {
    expect(
      parseControl(
        '{"type":"hostkey","host":"example.com:22","key_type":"ssh-ed25519","fingerprint":"SHA256:abc","known":"false"}',
      ),
    ).toBeNull();
  });
});
