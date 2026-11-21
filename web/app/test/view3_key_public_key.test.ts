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

import KeyPublicKeyView from "../src/views/KeyPublicKeyView.svelte";
import { toPem } from "../src/lib/keyPublicKey.ts";

const resp = {
  key_id: "sig1",
  public_key: "MFkw",
  algorithm: "ECDSA-P256",
  version: 4,
  timestamp: "2026-11-12T00:00:00Z",
};

const pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n";

async function fill(keyId: string, backend: string, version?: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: keyId } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
  if (version !== undefined) {
    await fireEvent.input(screen.getByLabelText("Version"), { target: { value: version } });
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("toPem", () => {
  it("wraps the base64 at 64 characters between the PUBLIC KEY armour", () => {
    const b64 = "A".repeat(130);
    const lines = toPem(b64).trimEnd().split("\n");
    expect(lines[0]).toBe("-----BEGIN PUBLIC KEY-----");
    expect(lines[lines.length - 1]).toBe("-----END PUBLIC KEY-----");
    const body = lines.slice(1, -1);
    expect(body).toHaveLength(3);
    expect(body[0]).toHaveLength(64);
    expect(body[1]).toHaveLength(64);
    expect(body[2]).toHaveLength(2);
    expect(body.join("")).toBe(b64);
  });
});

describe("KeyPublicKeyView", () => {
  it("fetches the latest public key and renders algorithm, version, base64 and PEM", async () => {
    request.mockResolvedValue(resp);
    render(KeyPublicKeyView);

    await fill("sig1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Fetch" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("GET", "/api/v1/keys/sig1/public-key", {
      query: { backend: "software" },
    });
    expect(await screen.findByText("ECDSA-P256")).toBeInTheDocument();
    expect(screen.getByTestId("pk-version").textContent).toBe("4");
    expect(screen.getByTestId("pk-b64").textContent).toBe("MFkw");
    expect(screen.getByTestId("pk-pem").textContent).toBe(pem);
  });

  it("sends a positive version and keeps Fetch disabled for 0 or -1", async () => {
    request.mockResolvedValue(resp);
    render(KeyPublicKeyView);

    await fill("sig1", "software", "0");
    expect(screen.getByRole("button", { name: "Fetch" })).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Version"), { target: { value: "-1" } });
    expect(screen.getByRole("button", { name: "Fetch" })).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Version"), { target: { value: "2" } });
    expect(screen.getByRole("button", { name: "Fetch" })).toBeEnabled();
    await fireEvent.click(screen.getByRole("button", { name: "Fetch" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("GET", "/api/v1/keys/sig1/public-key", {
        query: { backend: "software", version: "2" },
      }),
    );
  });

  it("copies the PEM to the clipboard and confirms with a toast", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    request.mockResolvedValue(resp);
    render(KeyPublicKeyView);

    await fill("sig1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Fetch" }));
    await screen.findByText("ECDSA-P256");
    await fireEvent.click(screen.getByRole("button", { name: "Copy PEM" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(pem));
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("URL-encodes a key ID with a slash", async () => {
    request.mockResolvedValue({ ...resp, key_id: "team/sig1" });
    render(KeyPublicKeyView);

    await fill("team/sig1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Fetch" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("GET", "/api/v1/keys/team%2Fsig1/public-key", {
        query: { backend: "software" },
      }),
    );
  });

  it("shows an error alert when the call fails", async () => {
    request.mockRejectedValue(new Error("key not found"));
    render(KeyPublicKeyView);

    await fill("missing", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Fetch" }));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
    expect(screen.queryByTestId("pk-pem")).not.toBeInTheDocument();
  });
});
