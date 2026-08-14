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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { toastStore, showToast, dismissToast } from "../src/stores/toast.svelte.ts";

describe("toast store", () => {
  beforeEach(() => {
    for (const t of [...toastStore.toasts]) dismissToast(t.id);
  });

  it("enqueues a toast with an incrementing id and the given kind/message", () => {
    const id = showToast("success", "saved", 0);
    expect(toastStore.toasts.at(-1)).toMatchObject({ id, kind: "success", message: "saved" });
  });

  it("dismisses a toast by id without touching the others", () => {
    const id1 = showToast("info", "one", 0);
    const id2 = showToast("info", "two", 0);

    dismissToast(id1);

    const ids = toastStore.toasts.map((t) => t.id);
    expect(ids).not.toContain(id1);
    expect(ids).toContain(id2);
  });

  it("dismissing an id that is not present is a harmless no-op", () => {
    showToast("info", "still here", 0);
    const before = toastStore.toasts.length;

    dismissToast(999999);

    expect(toastStore.toasts.length).toBe(before);
  });

  describe("with fake timers", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("auto-dismisses a toast once its ttlMs elapses", () => {
      const id = showToast("warning", "expiring", 1000);
      expect(toastStore.toasts.some((t) => t.id === id)).toBe(true);

      vi.advanceTimersByTime(999);
      expect(toastStore.toasts.some((t) => t.id === id)).toBe(true);

      vi.advanceTimersByTime(1);
      expect(toastStore.toasts.some((t) => t.id === id)).toBe(false);
    });

    it("does not schedule a dismissal at all when ttlMs is 0", () => {
      const id = showToast("error", "sticky", 0);

      vi.advanceTimersByTime(1_000_000);

      expect(toastStore.toasts.some((t) => t.id === id)).toBe(true);
    });
  });
});
