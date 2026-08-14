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

/** Toast store: a small transient-notification queue. */

export type ToastKind = "info" | "success" | "warning" | "error";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

let _toasts = $state<Toast[]>([]);
let _nextID = 0;

export const toastStore = {
  get toasts(): Toast[] {
    return _toasts;
  },
};

/** showToast enqueues a toast and auto-dismisses it after `ttlMs`. */
export function showToast(kind: ToastKind, message: string, ttlMs = 5000): number {
  const id = _nextID++;
  _toasts = [..._toasts, { id, kind, message }];
  if (ttlMs > 0 && typeof setTimeout !== "undefined") {
    setTimeout(() => dismissToast(id), ttlMs);
  }
  return id;
}

/** dismissToast removes a toast by id. */
export function dismissToast(id: number): void {
  _toasts = _toasts.filter((t) => t.id !== id);
}
