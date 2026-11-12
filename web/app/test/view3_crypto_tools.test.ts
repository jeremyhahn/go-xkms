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

import CryptoToolsView from "../src/views/CryptoToolsView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function setLength(v: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Length (bytes)"), { target: { value: v } });
}

describe("CryptoToolsView random", () => {
  it("draws random bytes from POST /api/v1/random and shows hex and base64", async () => {
    request.mockResolvedValue({ random: "3q2+7w==" });
    render(CryptoToolsView);

    await setLength("4");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/random", { body: { length: 4 } });
    expect(await screen.findByText("deadbeef")).toBeInTheDocument();
    expect(screen.getByText("3q2+7w==")).toBeInTheDocument();
  });

  it.each(["0", "1025", "2.5"])("rejects length %s inline and sends nothing", async (v) => {
    render(CryptoToolsView);

    await setLength(v);
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    expect(await screen.findByText("Length must be a whole number from 1 to 1024.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows an error alert when the random call fails", async () => {
    request.mockRejectedValue(new Error("rng unavailable"));
    render(CryptoToolsView);

    await setLength("16");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    expect(await screen.findByText("rng unavailable")).toBeInTheDocument();
  });
});

describe("CryptoToolsView hash", () => {
  it("hashes text through POST /api/v1/hash with the chosen algorithm", async () => {
    // SHA-256("abc") prefix is enough to pin the hex rendering.
    request.mockResolvedValue({ digest: "ungWv48=", hash: "sha256" });
    render(CryptoToolsView);

    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abc" } });
    await fireEvent.change(screen.getByLabelText("Algorithm"), { target: { value: "sha256" } });
    await fireEvent.click(screen.getByRole("button", { name: "Hash" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/hash", { body: { data: "YWJj", hash: "sha256" } });
    expect(await screen.findByText("ba7816bf8f")).toBeInTheDocument();
    expect(screen.getByText("ungWv48=")).toBeInTheDocument();
    expect(screen.getByText("sha256")).toBeInTheDocument();
  });

  it("sends no hash field with the server default", async () => {
    request.mockResolvedValue({ digest: "AAE=", hash: "sha512" });
    render(CryptoToolsView);

    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abc" } });
    await fireEvent.click(screen.getByRole("button", { name: "Hash" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/hash", { body: { data: "YWJj" } });
    expect(await screen.findByText("0001")).toBeInTheDocument();
  });

  it("sends base64 input as is when the toggle is on", async () => {
    request.mockResolvedValue({ digest: "AAE=", hash: "sha384" });
    render(CryptoToolsView);

    await fireEvent.click(screen.getByLabelText("Input is base64"));
    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "3q2+7w==" } });
    await fireEvent.click(screen.getByRole("button", { name: "Hash" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/hash", { body: { data: "3q2+7w==" } });
  });

  it("rejects invalid base64 inline and sends nothing", async () => {
    render(CryptoToolsView);

    await fireEvent.click(screen.getByLabelText("Input is base64"));
    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "not base64!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Hash" }));

    expect(await screen.findByText("Data is not valid base64.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows an error alert when the hash call fails", async () => {
    request.mockRejectedValue(new Error("hash algorithm not supported"));
    render(CryptoToolsView);

    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "abc" } });
    await fireEvent.click(screen.getByRole("button", { name: "Hash" }));

    expect(await screen.findByText("hash algorithm not supported")).toBeInTheDocument();
  });
});
