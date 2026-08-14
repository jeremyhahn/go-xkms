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
 * wails.test.ts — isWailsRuntime (src/wails.ts): the desktop-shell probe
 * that lets a web UI pick between the REST client and native Wails
 * bindings.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { isWailsRuntime } from './wails.js';

type Bindable = Record<string, unknown>;

afterEach(() => {
  delete (globalThis as Bindable)['go'];
  delete (globalThis as Bindable)['runtime'];
});

describe('isWailsRuntime', () => {
  it('returns false when neither window.go nor window.runtime is present', () => {
    expect(isWailsRuntime()).toBe(false);
  });

  it('returns true when window.go is present (Wails-generated bindings)', () => {
    (globalThis as Bindable)['go'] = {};
    expect(isWailsRuntime()).toBe(true);
  });

  it('returns true when window.runtime is present (Wails JS runtime bridge)', () => {
    (globalThis as Bindable)['runtime'] = {};
    expect(isWailsRuntime()).toBe(true);
  });

  it('returns true when both are present', () => {
    (globalThis as Bindable)['go'] = {};
    (globalThis as Bindable)['runtime'] = {};
    expect(isWailsRuntime()).toBe(true);
  });
});
