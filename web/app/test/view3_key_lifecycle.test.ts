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

import KeyLifecycleView from "../src/views/KeyLifecycleView.svelte";

const TS = "2026-11-12T00:00:00Z";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function fillKey(id: string, backend = "software"): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: id } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: backend } });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

describe("KeyLifecycleView", () => {
  it("disables the whole key without a version and renders the returned status", async () => {
    request.mockResolvedValue({ key_id: "k1", status: "disabled", timestamp: TS });

    render(KeyLifecycleView);
    await fillKey("k1");
    await fireEvent.click(button("Disable"));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/k1/status", {
      body: { backend: "software", status: "disabled" },
    });
    expect(await screen.findByText("disabled")).toBeInTheDocument();
    expect(screen.getByText(TS)).toBeInTheDocument();
  });

  it("enables one version and blocks a version below 1", async () => {
    request.mockResolvedValue({ key_id: "k1", version: 3, status: "enabled", timestamp: TS });

    render(KeyLifecycleView);
    await fillKey("k1");
    const version = screen.getByLabelText("Version");

    for (const bad of ["0", "-1"]) {
      await fireEvent.input(version, { target: { value: bad } });
      expect(button("Enable").disabled).toBe(true);
      expect(button("Disable").disabled).toBe(true);
    }

    await fireEvent.input(version, { target: { value: "3" } });
    expect(button("Enable").disabled).toBe(false);
    await fireEvent.click(button("Enable"));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/k1/status", {
      body: { backend: "software", version: 3, status: "enabled" },
    });
    expect(await screen.findByText("enabled")).toBeInTheDocument();
  });

  it("revokes only after the confirmation equals the key ID", async () => {
    request.mockResolvedValue({ key_id: "k1", status: "revoked", timestamp: TS });

    render(KeyLifecycleView);
    await fillKey("k1");
    await fireEvent.input(screen.getByLabelText("Reason"), { target: { value: "retired" } });

    const confirm = screen.getByLabelText("Confirm key ID");
    expect(button("Revoke").disabled).toBe(true);
    await fireEvent.input(confirm, { target: { value: "k" } });
    expect(button("Revoke").disabled).toBe(true);
    await fireEvent.click(button("Revoke"));
    expect(request).not.toHaveBeenCalled();

    await fireEvent.input(confirm, { target: { value: "k1" } });
    expect(button("Revoke").disabled).toBe(false);
    await fireEvent.click(button("Revoke"));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("POST", "/api/v1/keys/k1/revoke", {
      body: { backend: "software", reason: "retired" },
    });
    expect(await screen.findByText("revoked")).toBeInTheDocument();
  });

  it("sets no status other than enabled or disabled", async () => {
    request.mockResolvedValue({ key_id: "k1", status: "enabled", timestamp: TS });

    render(KeyLifecycleView);
    await fillKey("k1");
    await fireEvent.click(button("Enable"));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    await fireEvent.click(button("Disable"));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));

    const sent = request.mock.calls.map((c) => (c[2] as { body: { status: string } }).body.status);
    expect(sent).toEqual(["enabled", "disabled"]);
    for (const s of ["pending_deletion", "deleted", "rotating", "compromised"]) {
      expect(screen.queryByText(s)).toBeNull();
    }
  });

  it("URL-encodes a key ID with a slash in both paths", async () => {
    request.mockResolvedValue({ key_id: "a/b", status: "disabled", timestamp: TS });

    render(KeyLifecycleView);
    await fillKey("a/b");
    await fireEvent.click(button("Disable"));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request.mock.calls[0]![1]).toBe("/api/v1/keys/a%2Fb/status");

    await fireEvent.input(screen.getByLabelText("Confirm key ID"), { target: { value: "a/b" } });
    await fireEvent.click(button("Revoke"));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request.mock.calls[1]![1]).toBe("/api/v1/keys/a%2Fb/revoke");
    expect(request.mock.calls[1]![2]).toEqual({ body: { backend: "software" } });
  });

  it("shows an error alert when the call is rejected", async () => {
    request.mockRejectedValue(new Error("key not found"));

    render(KeyLifecycleView);
    await fillKey("k1");
    await fireEvent.click(button("Disable"));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
  });
});
