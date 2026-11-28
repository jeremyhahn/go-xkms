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

// Codex P1 on #2200: a verify verdict belongs to the inputs it was computed
// from. Editing the data, MAC, key, backend, hash or encoding clears it, and
// a response for inputs that are no longer current is discarded.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({ showToast: () => {} }));

import KeyHmacView from "../src/views/KeyHmacView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
});

async function fillAll(): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "mac1" } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
  await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abc" } });
  await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "deadbeef" } });
}

function verifyBtn(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Verify" }) as HTMLButtonElement;
}

const edits: Array<[string, () => Promise<unknown>]> = [
  ["data", () => fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abd" } })],
  ["MAC", () => fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "deadbeee" } })],
  ["key", () => fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "mac2" } })],
  ["backend", () => fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "pkcs11" } })],
  ["hash", () => fireEvent.change(screen.getByLabelText("Hash"), { target: { value: "sha512" } })],
  ["encoding", () => fireEvent.click(screen.getByLabelText("Data is base64"))],
];

describe("KeyHmacView verdict invalidation", () => {
  for (const [field, edit] of edits) {
    it(`clears a completed verdict when the ${field} changes`, async () => {
      request.mockResolvedValue({ valid: true });
      render(KeyHmacView);
      await fillAll();
      await fireEvent.click(verifyBtn());
      expect(await screen.findByText("valid")).toBeInTheDocument();

      await edit();

      expect(screen.queryByText("valid")).toBeNull();
      expect(screen.queryByText("invalid")).toBeNull();
    });
  }

  for (const [field, edit] of edits) {
    it(`discards a pending verdict when the ${field} changes before it lands`, async () => {
      let resolve: (v: { valid: boolean }) => void = () => {};
      request.mockReturnValue(new Promise((r) => (resolve = r)));
      render(KeyHmacView);
      await fillAll();
      await fireEvent.click(verifyBtn());
      await waitFor(() => expect(request).toHaveBeenCalledOnce());

      await edit();
      resolve({ valid: true });
      await new Promise((r) => setTimeout(r, 0));

      expect(screen.queryByText("valid")).toBeNull();
    });
  }
});
