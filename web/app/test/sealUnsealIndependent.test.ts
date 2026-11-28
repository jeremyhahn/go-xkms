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

// Codex P1 on #2200: Unseal needs no backend list. A caller without
// backends:list (403 on GET /api/v1/backends) or a list still loading must
// not hide the Unseal form.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { ListBackendsResponse, UnsealRequest, UnsealResponse } from "@go-xkms/sdk";
import { textToB64 } from "../src/lib/b64.ts";

const unseal = vi.fn<(req: UnsealRequest) => Promise<UnsealResponse>>();
const backendsList = vi.fn<() => Promise<ListBackendsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ seal: { seal: vi.fn(), unseal, capability: vi.fn() }, backends: { list: backendsList } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({ showToast: () => {} }));

import SealView from "../src/views/SealView.svelte";

const sealed = { backend: "software", ciphertext: textToB64("c"), nonce: textToB64("n"), key_id: "k1" };

beforeEach(() => {
  vi.clearAllMocks();
});

async function unsealWorks(): Promise<void> {
  unseal.mockResolvedValue({ plaintext: textToB64("secret") });
  await fireEvent.input(await screen.findByLabelText("Seal result JSON"), { target: { value: JSON.stringify(sealed) } });
  await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));
  await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
  expect(unseal.mock.calls[0]![0]).toEqual(sealed);
  expect((await screen.findByLabelText("Plaintext")).textContent).toBe("secret");
}

describe("SealView Unseal without backend enumeration", () => {
  it("keeps Unseal usable when listing backends is forbidden", async () => {
    backendsList.mockRejectedValue(new Error("forbidden: missing permission backends:list"));
    render(SealView);

    expect(await screen.findByText(/backends:list/)).toBeInTheDocument();
    await unsealWorks();
  });

  it("keeps Unseal usable while the backend list is still loading", async () => {
    backendsList.mockReturnValue(new Promise(() => {}));
    render(SealView);

    await unsealWorks();
  });
});
