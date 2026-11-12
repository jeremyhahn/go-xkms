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
import { render, screen, fireEvent, waitFor, within } from "@testing-library/svelte";

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

import KeyBatchView from "../src/views/KeyBatchView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function setKey(id: string, backend: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: id } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
}

function runButton(): HTMLElement {
  return screen.getByRole("button", { name: "Run" });
}

function resultRows(): HTMLElement[] {
  const table = screen.getByRole("table", { name: "Results" });
  return within(table).getAllByRole("row").slice(1);
}

describe("KeyBatchView", () => {
  it("encrypts every row in one call and shows a result or an error per item", async () => {
    request.mockResolvedValue({
      results: [{ result: { ciphertext: "Y3Q=", nonce: "bm4=", key_version: 2 } }, { error: "key disabled" }],
    });

    render(KeyBatchView);
    await setKey("k1", "software");
    await fireEvent.input(screen.getByLabelText("Plaintext 1"), { target: { value: "a" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add row" }));
    await fireEvent.input(screen.getByLabelText("Plaintext 2"), { target: { value: "b" } });
    await fireEvent.click(runButton());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/k1/encrypt-batch", {
      body: { backend: "software", items: [{ plaintext: "YQ==" }, { plaintext: "Yg==" }] },
    });

    await screen.findByRole("table", { name: "Results" });
    const rows = resultRows();
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText("Y3Q=")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("bm4=")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("2")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("key disabled")).toBeInTheDocument();
  });

  it("decrypts a row and shows the plaintext as text, or as base64 when it is not UTF-8", async () => {
    request.mockResolvedValueOnce({ results: [{ plaintext: "aGk=", key_version: 2 }] });

    render(KeyBatchView);
    await setKey("k1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));
    await fireEvent.input(screen.getByLabelText("Ciphertext 1"), { target: { value: "Y3Q=" } });
    await fireEvent.input(screen.getByLabelText("Nonce 1"), { target: { value: "bm4=" } });
    await fireEvent.input(screen.getByLabelText("Key version 1"), { target: { value: "2" } });
    await fireEvent.click(runButton());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/k1/decrypt-batch", {
      body: { backend: "software", items: [{ ciphertext: "Y3Q=", nonce: "bm4=", key_version: 2 }] },
    });
    await screen.findByRole("table", { name: "Results" });
    expect(within(resultRows()[0]!).getByText("hi")).toBeInTheDocument();

    request.mockResolvedValueOnce({ results: [{ plaintext: "/w==" }] });
    await fireEvent.click(runButton());
    await waitFor(() => expect(within(resultRows()[0]!).getByText("/w==")).toBeInTheDocument());
  });

  it("disables Run with no items and Add row at 100 items", async () => {
    render(KeyBatchView);
    await setKey("k1", "software");
    await fireEvent.click(screen.getByRole("button", { name: "Remove row 1" }));
    expect(runButton()).toBeDisabled();

    const add = screen.getByRole("button", { name: "Add row" });
    for (let i = 0; i < 100; i++) {
      await fireEvent.click(add);
    }
    expect(screen.getByLabelText("Plaintext 100")).toBeInTheDocument();
    expect(screen.queryByLabelText("Plaintext 101")).toBeNull();
    expect(add).toBeDisabled();
  });

  it("keeps Run disabled until key ID and backend are set and marks a non-base64 ciphertext invalid", async () => {
    render(KeyBatchView);
    await fireEvent.input(screen.getByLabelText("Plaintext 1"), { target: { value: "a" } });
    expect(runButton()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    expect(runButton()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    expect(runButton()).toBeEnabled();

    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));
    const ct = screen.getByLabelText("Ciphertext 1");
    await fireEvent.input(ct, { target: { value: "not base64!" } });
    expect(ct).toHaveAttribute("aria-invalid", "true");
    expect(runButton()).toBeDisabled();
  });

  it("URL-encodes a key ID with a slash", async () => {
    request.mockResolvedValue({ results: [{ result: { ciphertext: "Y3Q=" } }] });

    render(KeyBatchView);
    await setKey("team/k1", "software");
    await fireEvent.input(screen.getByLabelText("Plaintext 1"), { target: { value: "a" } });
    await fireEvent.click(runButton());

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request.mock.calls[0]![1]).toBe("/api/v1/keys/team%2Fk1/encrypt-batch");
  });

  it("shows an error alert when the call is rejected", async () => {
    request.mockRejectedValue(new Error("permission denied"));

    render(KeyBatchView);
    await setKey("k1", "software");
    await fireEvent.input(screen.getByLabelText("Plaintext 1"), { target: { value: "a" } });
    await fireEvent.click(runButton());

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: "Results" })).toBeNull();
  });
});
