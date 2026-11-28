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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import KeyRewrapView from "../src/views/KeyRewrapView.svelte";

const response = {
  source_key_version: 1,
  wrapped: { ciphertext: "bmV3", nonce: "bjI=", tag: "dDI=", key_version: 2 },
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function fill(label: string, value: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(label), { target: { value } });
}

async function fillSource(ciphertext = "Y3Q="): Promise<void> {
  await fill("Source backend", "software");
  await fill("Source key ID", "k1");
  await fill("Ciphertext", ciphertext);
}

function rewrapButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Rewrap" }) as HTMLButtonElement;
}

describe("KeyRewrapView", () => {
  it("rewraps in place under the source key's current version", async () => {
    request.mockResolvedValue(response);
    render(KeyRewrapView);
    await fillSource();
    await fill("Nonce", "bm4=");
    await fill("Tag", "dGc=");
    await fireEvent.click(rewrapButton());
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/rewrap", {
      body: { source: { backend: "software", key_id: "k1", ciphertext: "Y3Q=", nonce: "bm4=", tag: "dGc=" } },
    });
    await waitFor(() => expect(screen.getByTestId("source-version").textContent).toBe("1"));
    expect(screen.getByTestId("new-version").textContent).toBe("2");
    expect(screen.getByTestId("new-ciphertext").textContent).toBe("bmV3");
    expect(screen.getByTestId("new-nonce").textContent).toBe("bjI=");
    expect(screen.getByTestId("new-tag").textContent).toBe("dDI=");
  });

  it("rewraps to another key with additional data", async () => {
    request.mockResolvedValue(response);
    render(KeyRewrapView);
    await fillSource();
    await fill("Additional data", "ctx");
    await fill("Target backend", "pkcs11");
    await fill("Target key ID", "k2");
    await fireEvent.click(rewrapButton());
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/rewrap", {
      body: {
        source: { backend: "software", key_id: "k1", ciphertext: "Y3Q=", additional_data: "Y3R4" },
        target_key_id: "k2",
        target_backend: "pkcs11",
      },
    });
  });

  it("takes a pasted EncryptResponse JSON as the ciphertext", async () => {
    request.mockResolvedValue(response);
    render(KeyRewrapView);
    await fillSource('{"ciphertext":"Y3Q=","nonce":"bm4=","tag":"dGc=","gcm_nonce_mode":"random"}');
    await fireEvent.click(rewrapButton());
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/rewrap", {
      body: {
        source: {
          backend: "software",
          key_id: "k1",
          ciphertext: "Y3Q=",
          nonce: "bm4=",
          tag: "dGc=",
          gcm_nonce_mode: "random",
        },
      },
    });
  });

  it("copies the wrapped result as JSON", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    request.mockResolvedValue(response);
    render(KeyRewrapView);
    await fillSource();
    await fireEvent.click(rewrapButton());
    const copy = await screen.findByRole("button", { name: "Copy as JSON" });
    await fireEvent.click(copy);
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(JSON.parse(writeText.mock.calls[0]?.[0] as string)).toEqual(response.wrapped);
  });

  it("keeps Rewrap disabled until backend, key ID and ciphertext are set", async () => {
    render(KeyRewrapView);
    expect(rewrapButton().disabled).toBe(true);
    await fill("Source backend", "software");
    expect(rewrapButton().disabled).toBe(true);
    await fill("Source key ID", "k1");
    expect(rewrapButton().disabled).toBe(true);
    await fill("Ciphertext", "Y3Q=");
    expect(rewrapButton().disabled).toBe(false);
  });

  it("shows an inline error for a ciphertext that is neither base64 nor JSON", async () => {
    render(KeyRewrapView);
    await fillSource("not base64!");
    await fireEvent.click(rewrapButton());
    expect(screen.getByText(/ciphertext must be base64 or an EncryptResponse JSON/i)).toBeTruthy();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows an inline error for invalid base64 in nonce or tag", async () => {
    render(KeyRewrapView);
    await fillSource();
    await fill("Nonce", "!!");
    await fireEvent.click(rewrapButton());
    expect(screen.getByText(/nonce must be base64/i)).toBeTruthy();
    await fill("Nonce", "");
    await fill("Tag", "%%");
    await fireEvent.click(rewrapButton());
    expect(screen.getByText(/tag must be base64/i)).toBeTruthy();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows an error Alert when the call fails", async () => {
    request.mockRejectedValue(new Error("key not found"));
    render(KeyRewrapView);
    await fillSource();
    await fireEvent.click(rewrapButton());
    await waitFor(() => expect(screen.getByText("key not found")).toBeTruthy());
  });
});
