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
import type { FrostImportKeyRequest, FrostImportKeyResponse, FrostKeyInfo, FrostKeyPackage } from "@go-xkms/sdk";

const importKey = vi.fn<(req: FrostImportKeyRequest) => Promise<FrostImportKeyResponse>>();
const getKey = vi.fn<(id: string) => Promise<FrostKeyInfo>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ frost: { importKey, getKey } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import FrostKeyImportView from "../src/views/FrostKeyImportView.svelte";

const SECRET = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e7aaaa";
const GPK = "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

function pkg(): FrostKeyPackage {
  return {
    key_id: "frost-key-1",
    algorithm: "FROST-ED25519-SHA512-v1",
    threshold: 2,
    total: 3,
    participant_id: 2,
    participant_name: "node-b",
    secret_share: SECRET,
    group_public_key: GPK,
    verification_shares: { "1": "aa11", "2": "bb22", "3": "cc33" },
  };
}

function textarea(): HTMLTextAreaElement {
  return screen.getByLabelText("Key package JSON") as HTMLTextAreaElement;
}

async function paste(text: string): Promise<void> {
  await fireEvent.input(textarea(), { target: { value: text } });
}

function assertNoSecret(): void {
  expect(document.body.textContent ?? "").not.toContain(SECRET);
  for (const t of toasts) expect(t.message).not.toContain(SECRET);
  expect(textarea().value).toBe("");
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("FrostKeyImportView", () => {
  it("calls nothing on mount", () => {
    render(FrostKeyImportView);
    expect(screen.getByText("FROST Key Import")).toBeInTheDocument();
    expect(importKey).not.toHaveBeenCalled();
    expect(getKey).not.toHaveBeenCalled();
  });

  it("rejects invalid JSON inline without calling importKey", async () => {
    render(FrostKeyImportView);
    await paste("{not json");
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/not valid JSON/)).toBeInTheDocument();
    expect(importKey).not.toHaveBeenCalled();
  });

  it("rejects a package missing secret_share", async () => {
    render(FrostKeyImportView);
    const p: Partial<FrostKeyPackage> = pkg();
    delete p.secret_share;
    await paste(JSON.stringify(p));
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/secret_share/)).toBeInTheDocument();
    expect(importKey).not.toHaveBeenCalled();
  });

  it("rejects a package missing participant_id", async () => {
    render(FrostKeyImportView);
    const p: Partial<FrostKeyPackage> = pkg();
    delete p.participant_id;
    await paste(JSON.stringify(p));
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/participant_id/)).toBeInTheDocument();
    expect(importKey).not.toHaveBeenCalled();
    expect(document.body.textContent ?? "").not.toContain(SECRET);
  });

  it("imports a valid package and renders the result without the secret", async () => {
    importKey.mockResolvedValue({
      success: true,
      message: "imported",
      key_id: "frost-key-1",
      participant_id: 2,
      group_public_key: GPK,
    });
    render(FrostKeyImportView);
    await paste(JSON.stringify(pkg()));
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(importKey).toHaveBeenCalledOnce());
    expect(importKey.mock.calls[0]![0]).toEqual({ package: pkg() });

    const result = await screen.findByTestId("import-result");
    expect(result.textContent).toContain("frost-key-1");
    expect(result.textContent).toContain("2");
    expect(result.textContent).toContain(GPK);
    assertNoSecret();
  });

  it("surfaces a rejected import and clears the secret", async () => {
    importKey.mockRejectedValue(new Error("key already exists"));
    render(FrostKeyImportView);
    await paste(JSON.stringify(pkg()));
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    expect(await screen.findByText("key already exists")).toBeInTheDocument();
    expect(importKey).toHaveBeenCalledOnce();
    assertNoSecret();
  });

  it("looks up a key and renders its details", async () => {
    getKey.mockResolvedValue({
      key_id: "frost-key-1",
      algorithm: "FROST-ED25519-SHA512-v1",
      threshold: 2,
      total: 3,
      participant_id: 2,
      group_public_key: GPK,
      created_at: "2026-11-12T00:00:00Z",
    });
    render(FrostKeyImportView);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "frost-key-1" } });
    await fireEvent.click(screen.getByRole("button", { name: "Look up" }));

    await waitFor(() => expect(getKey).toHaveBeenCalledOnce());
    expect(getKey).toHaveBeenCalledWith("frost-key-1");
    const details = await screen.findByTestId("key-details");
    expect(details.textContent).toContain("FROST-ED25519-SHA512-v1");
    expect(details.textContent).toContain("2 of 3");
    const gpk = screen.getByTestId("key-details-gpk");
    expect(gpk.textContent).toBe(GPK);
    expect(gpk.className).toContain("font-mono");
  });

  it("surfaces a rejected lookup", async () => {
    getKey.mockRejectedValue(new Error("frost key not found"));
    render(FrostKeyImportView);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "missing" } });
    await fireEvent.click(screen.getByRole("button", { name: "Look up" }));

    expect(await screen.findByText("frost key not found")).toBeInTheDocument();
    expect(screen.queryByTestId("key-details")).toBeNull();
  });
});
