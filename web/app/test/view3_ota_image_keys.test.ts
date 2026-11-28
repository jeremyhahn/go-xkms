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

import OtaImageKeysView from "../src/views/OtaImageKeysView.svelte";

const PEM = "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----";
const DIGEST_HEX = "ab".repeat(32);
// Standard base64 of the 32 bytes 0xab.
const DIGEST_B64 = "q6ur".repeat(10) + "q6s=";

async function fillBoard(board = "board-7", backend = "software"): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Board"), { target: { value: board } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("OtaImageKeysView", () => {
  it("creates a board key and renders its ID and public key", async () => {
    request.mockResolvedValue({ key_id: "ota-board-7", key_type: "ecdsa", public_key_pem: PEM });

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/ota-image-keys/board-7", { body: { backend: "software" } });
    expect(await screen.findByText("ota-board-7")).toBeInTheDocument();
    const pem = screen.getByTestId("ota-key-pem");
    expect(pem).toHaveTextContent("-----BEGIN PUBLIC KEY-----");
    expect(pem).toHaveTextContent("-----END PUBLIC KEY-----");
    expect(pem.textContent).not.toContain("PRIVATE");
  });

  it("rotates a board key after a confirm and shows the new version", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    request.mockResolvedValue({ success: true, key_id: "ota-board-7", key_version: 7, public_key_pem: PEM });

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/ota-image-keys/board-7/rotate", { body: { backend: "software" } });
    expect(await screen.findByTestId("ota-key-version")).toHaveTextContent("7");
  });

  it("sends nothing when the rotate confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));

    expect(window.confirm).toHaveBeenCalledOnce();
    expect(request).not.toHaveBeenCalled();
  });

  it("signs a SHA-256 digest as its bytes in base64", async () => {
    request.mockResolvedValue({ signature: "c2lnbmF0dXJl", algorithm: "ES256", key_version: 2 });

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.input(screen.getByLabelText("Digest (hex)"), { target: { value: DIGEST_HEX } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/ota-image-keys/board-7/sign", {
      body: { backend: "software", data: DIGEST_B64, data_is_digest: true },
    });
    expect(await screen.findByText("c2lnbmF0dXJl")).toBeInTheDocument();
    expect(screen.getByText("ES256")).toBeInTheDocument();
  });

  it("signs raw base64 data as is without data_is_digest", async () => {
    request.mockResolvedValue({ signature: "c2ln", algorithm: "ES256" });

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByLabelText("Raw data (base64)"));
    await fireEvent.input(screen.getByLabelText("Data (base64)"), { target: { value: "aGVsbG8=" } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/ota-image-keys/board-7/sign", {
      body: { backend: "software", data: "aGVsbG8=" },
    });
  });

  it("disables the three buttons without a board or backend", async () => {
    render(OtaImageKeysView);
    for (const name of ["Create key", "Rotate key", "Sign"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    await fireEvent.input(screen.getByLabelText("Board"), { target: { value: "board-7" } });
    for (const name of ["Create key", "Rotate key", "Sign"]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    expect(screen.getByRole("button", { name: "Create key" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Rotate key" })).toBeEnabled();
  });

  it("rejects a digest that is not 64 hex characters", async () => {
    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.input(screen.getByLabelText("Digest (hex)"), { target: { value: "xyz" } });

    expect(await screen.findByText("The digest must be 64 hex characters.")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects invalid base64 in raw mode", async () => {
    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByLabelText("Raw data (base64)"));
    await fireEvent.input(screen.getByLabelText("Data (base64)"), { target: { value: "not base64!" } });

    expect(await screen.findByText("The data must be standard base64.")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));
    expect(request).not.toHaveBeenCalled();
  });

  it("URL-encodes a board with a slash", async () => {
    request.mockResolvedValue({ key_id: "k", key_type: "ecdsa" });

    render(OtaImageKeysView);
    await fillBoard("lab/board-7");
    await fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request.mock.calls[0]![1]).toBe("/api/v1/ota-image-keys/lab%2Fboard-7");
  });

  it("shows an error alert when create is rejected", async () => {
    request.mockRejectedValue(new Error("backend not found"));

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    expect(await screen.findByText("backend not found")).toBeInTheDocument();
  });

  it("shows an error alert when sign is rejected", async () => {
    request.mockRejectedValue(new Error("no key for board"));

    render(OtaImageKeysView);
    await fillBoard();
    await fireEvent.input(screen.getByLabelText("Digest (hex)"), { target: { value: DIGEST_HEX } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByText("no key for board")).toBeInTheDocument();
  });
});
