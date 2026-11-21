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
import { XkmsApiError } from "@go-xkms/sdk";

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

import BootstrapKeysView from "../src/views/BootstrapKeysView.svelte";

const DISABLED = "The trust-bootstrap listener is not enabled on this server.";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("BootstrapKeysView", () => {
  it("loads both keys from GET /api/v1/bootstrap/keys", async () => {
    request.mockResolvedValue({ noise_public_key: "ab01", p256_public_key: "04cd" });

    render(BootstrapKeysView);

    const noise = await screen.findByText("ab01");
    expect(noise.tagName).toBe("CODE");
    expect(noise).toHaveClass("font-mono");
    const p256 = screen.getByText("04cd");
    expect(p256).toHaveClass("font-mono");
    expect(screen.getByText("Noise_NK (X25519)")).toBeInTheDocument();
    expect(screen.getByText("P-256 (FIPS suite)")).toBeInTheDocument();
    expect(request).toHaveBeenCalledOnce();
    expect(request).toHaveBeenCalledWith("GET", "/api/v1/bootstrap/keys");
  });

  it("shows not configured for an absent P-256 key", async () => {
    request.mockResolvedValue({ noise_public_key: "ab01" });

    render(BootstrapKeysView);

    expect(await screen.findByText("ab01")).toBeInTheDocument();
    expect(screen.getByText("not configured")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy P-256 (FIPS suite)" })).toBeNull();
  });

  it("copies each key's exact value and toasts", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    request.mockResolvedValue({ noise_public_key: "ab01", p256_public_key: "04cd" });

    render(BootstrapKeysView);
    await screen.findByText("ab01");

    await fireEvent.click(screen.getByRole("button", { name: "Copy Noise_NK (X25519)" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("ab01"));
    await fireEvent.click(screen.getByRole("button", { name: "Copy P-256 (FIPS suite)" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("04cd"));
    await waitFor(() => expect(toasts.filter((t) => t.kind === "success")).toHaveLength(2));
  });

  it.each([503, 404])("reports a disabled listener (%i) as information", async (status) => {
    request.mockRejectedValue(new XkmsApiError(status, "service_unavailable", "bootstrap listener not enabled"));

    render(BootstrapKeysView);

    const msg = await screen.findByText(DISABLED);
    expect(msg.closest('[role="status"]')).not.toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows any other failure as an error alert", async () => {
    request.mockRejectedValue(new XkmsApiError(500, "internal", "listener exploded"));

    render(BootstrapKeysView);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("listener exploded");
    expect(screen.queryByText(DISABLED)).toBeNull();
  });

  it("sends the GET again on Refresh", async () => {
    request.mockResolvedValue({ noise_public_key: "ab01" });

    render(BootstrapKeysView);
    await screen.findByText("ab01");

    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request).toHaveBeenLastCalledWith("GET", "/api/v1/bootstrap/keys");
  });
});
