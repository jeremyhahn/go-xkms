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

// Key Safety against the real session store: the page can mount before the
// caller's permissions arrive, and must load its report once they do.

import { describe, it, expect, vi } from "vitest";
import { render, waitFor } from "@testing-library/svelte";

const request = vi.fn();
const me = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request }, auth: { me } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: () => {},
}));

import { loadSession, clearSession } from "../src/stores/session.svelte.ts";
import KeySafetyView from "../src/views/KeySafetyView.svelte";

describe("KeySafetyView session timing", () => {
  it("loads the report when keys:get arrives after mount", async () => {
    clearSession();
    request.mockImplementation((_method: string, path: string) =>
      Promise.resolve(path === "/api/v1/safety/report" ? { all_items: [], timestamp: 1 } : { warnings: [], timestamp: 1 }),
    );
    me.mockResolvedValue({ permissions: { "keys:get": true } });

    render(KeySafetyView);
    await new Promise((r) => setTimeout(r, 0));
    expect(request).not.toHaveBeenCalled();

    await loadSession();

    await waitFor(() => expect(request.mock.calls.map((c) => c[0])).toEqual(["GET", "GET"]));
  });
});
