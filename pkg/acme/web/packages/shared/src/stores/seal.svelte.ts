/**
 * Copyright (C) 2024 Trusted CA Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0, or alternatively, under the terms of the
 * GNU Affero General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any
 * later version. A commercial license is available from the authors.
 *
 * Reactive store for barrier seal/unseal state using Svelte 5 runes.
 * Update via updateSealStatus after each API call to keep the UI in sync.
 */

import type { BarrierStatusResponse, BarrierMode } from '../api/barrier-types';

/** SealState holds the runtime barrier seal/unseal state. */
export interface SealState {
  mode: BarrierMode;
  sealed: boolean;
  initialized: boolean;
  sharesProvided: number;
  sharesRequired: number;
  sharesTotal: number;
  polling: boolean;
}

/** sealStore is the reactive singleton for barrier state. */
export const sealStore: SealState = $state({
  mode: 'embedded',
  sealed: true,
  initialized: false,
  sharesProvided: 0,
  sharesRequired: 0,
  sharesTotal: 0,
  polling: false,
});

/**
 * updateSealStatus synchronises sealStore with a fresh BarrierStatusResponse
 * from the server.
 */
export function updateSealStatus(status: BarrierStatusResponse): void {
  sealStore.mode = status.mode;
  sealStore.sealed = status.sealed;
  sealStore.sharesProvided = status.shares_provided;
  sealStore.sharesRequired = status.shares_required;
  sealStore.sharesTotal = status.shares_total;
  sealStore.initialized = status.shares_total > 0;
}

/**
 * addShare increments the local share count by one, up to the required
 * threshold. Call this after a successful unsealWithShare response.
 */
export function addShare(): void {
  if (sealStore.sharesProvided < sealStore.sharesRequired) {
    sealStore.sharesProvided += 1;
  }
}
