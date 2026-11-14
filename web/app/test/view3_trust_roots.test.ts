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

import TrustRootsView from "../src/views/TrustRootsView.svelte";

const FP = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";

const root = {
  fingerprint: FP,
  purpose: "tpm-manufacturer",
  subject: "CN=Example TPM Root",
  issuer: "CN=Example TPM Issuer",
  algorithm: "ECDSA-P384",
  not_before: "2025-01-01T00:00:00Z",
  not_after: "2045-01-01T00:00:00Z",
  added_at: "2026-11-01T00:00:00Z",
};

const PEM = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";

function listCalls(): unknown[][] {
  return request.mock.calls.filter((c) => c[0] === "GET" && c[1] === "/api/v1/trust-roots");
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.restoreAllMocks();
  request.mockReset();
  toasts.length = 0;
});

describe("TrustRootsView", () => {
  it("lists trust roots on mount without a purpose filter", async () => {
    request.mockResolvedValue({ roots: [root] });

    render(TrustRootsView);

    expect(await screen.findByText("CN=Example TPM Root", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText("tpm-manufacturer", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByTitle(FP)).toBeInTheDocument();
    expect(listCalls()).toHaveLength(1);
    const opts = listCalls()[0]![2] as { query?: Record<string, string> } | undefined;
    expect(opts?.query?.purpose).toBeUndefined();
  });

  it("shows the empty state", async () => {
    request.mockResolvedValue({ roots: [] });

    render(TrustRootsView);

    expect(await screen.findByText(/No trust roots/)).toBeInTheDocument();
  });

  it("reloads the list with the chosen purpose", async () => {
    request.mockResolvedValue({ roots: [] });

    render(TrustRootsView);
    await screen.findByText(/No trust roots/);

    await fireEvent.change(screen.getByLabelText("Filter by purpose"), { target: { value: "tpm-manufacturer" } });

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("GET", "/api/v1/trust-roots", { query: { purpose: "tpm-manufacturer" } }),
    );
  });

  it("imports a PEM with a purpose, shows the result and reloads", async () => {
    request.mockImplementation((method: string) =>
      Promise.resolve(method === "POST" ? { added: 1, skipped: 0 } : { roots: [] }),
    );

    render(TrustRootsView);
    await screen.findByText(/No trust roots/);

    const importBtn = screen.getByRole("button", { name: "Import" });
    expect(importBtn).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("PEM"), { target: { value: PEM } });
    await fireEvent.change(screen.getByLabelText("Import purpose"), { target: { value: "user-ca" } });
    expect(importBtn).not.toBeDisabled();
    await fireEvent.click(importBtn);

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("POST", "/api/v1/trust-roots", { body: { pem: PEM, purpose: "user-ca" } }),
    );
    expect(await screen.findByText(/added 1, skipped 0/)).toBeInTheDocument();
    await waitFor(() => expect(listCalls()).toHaveLength(2));
  });

  it("quarantines a root after a confirm and reloads", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    request.mockImplementation((method: string) =>
      Promise.resolve(method === "POST" ? { ...root, purpose: "synced" } : { roots: [root] }),
    );

    render(TrustRootsView);
    await screen.findByTitle(FP);

    await fireEvent.click(screen.getByRole("button", { name: "Quarantine" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("POST", `/api/v1/trust-roots/${FP}/quarantine`),
    );
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
    await waitFor(() => expect(listCalls()).toHaveLength(2));
  });

  it("deletes a root after a confirm", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    request.mockImplementation((method: string) =>
      Promise.resolve(method === "DELETE" ? undefined : { roots: [root] }),
    );

    render(TrustRootsView);
    await screen.findByTitle(FP);

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("DELETE", `/api/v1/trust-roots/${FP}`, { parse: "void" }),
    );
  });

  it("sends nothing when the delete confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    request.mockResolvedValue({ roots: [root] });

    render(TrustRootsView);
    await screen.findByTitle(FP);

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    expect(window.confirm).toHaveBeenCalled();
    expect(request.mock.calls.filter((c) => c[0] === "DELETE")).toHaveLength(0);
  });

  it("shows a list failure in an error alert", async () => {
    request.mockRejectedValue(new Error("trust store unavailable"));

    render(TrustRootsView);

    expect(await screen.findByText("trust store unavailable")).toBeInTheDocument();
  });

  it("shows an import failure in an error alert", async () => {
    request.mockImplementation((method: string) =>
      method === "POST" ? Promise.reject(new Error("no certificate in PEM")) : Promise.resolve({ roots: [] }),
    );

    render(TrustRootsView);
    await screen.findByText(/No trust roots/);

    await fireEvent.input(screen.getByLabelText("PEM"), { target: { value: PEM } });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    expect(await screen.findByText("no certificate in PEM")).toBeInTheDocument();
  });
});
