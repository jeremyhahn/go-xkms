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
import type { ListTenantsResponse, WrappedTenantResponse } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListTenantsResponse>>();
const get = vi.fn<(id: string) => Promise<WrappedTenantResponse>>();
const del = vi.fn<(id: string) => Promise<void>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, get, delete: del } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TenantDetailView from "../src/views/TenantDetailView.svelte";

const acmeList = { tenants: [{ id: "acme", name: "Acme", sealed: false }], pagination: {} } as unknown as ListTenantsResponse;
const acme: WrappedTenantResponse = {
  tenant: { id: "acme", name: "Acme", sealed: true, isolation_type: "prefix", created_at: "2026-11-12T00:00:00Z" },
};

async function loadAcme(): Promise<void> {
  render(TenantDetailView);
  await screen.findByRole("option", { name: "acme" });
  await fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "acme" } });
  await fireEvent.click(screen.getByRole("button", { name: "Load" }));
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  list.mockResolvedValue(acmeList);
});

describe("TenantDetailView", () => {
  it("fills the tenant select from list on mount", async () => {
    render(TenantDetailView);

    expect(await screen.findByRole("option", { name: "acme" })).toBeInTheDocument();
    expect(list).toHaveBeenCalledOnce();
  });

  it("loads the chosen tenant and renders its record", async () => {
    get.mockResolvedValue(acme);

    await loadAcme();

    await waitFor(() => expect(get).toHaveBeenCalledWith("acme"));
    expect(await screen.findByText("Acme")).toBeInTheDocument();
    expect(screen.getByText("sealed")).toBeInTheDocument();
    expect(screen.getByText("prefix")).toBeInTheDocument();
    expect(screen.getByText("2026-11-12T00:00:00Z")).toBeInTheDocument();
  });

  it("passes the raw typed ID to get; the SDK encodes it", async () => {
    get.mockResolvedValue({ tenant: { id: "t/1", sealed: false } });

    render(TenantDetailView);
    await screen.findByRole("option", { name: "acme" });
    await fireEvent.input(screen.getByLabelText("Tenant ID"), { target: { value: "t/1" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(get).toHaveBeenCalledWith("t/1"));
  });

  it("deletes only after the typed confirmation, then clears and relists", async () => {
    get.mockResolvedValue(acme);
    del.mockResolvedValue(undefined);

    render(TenantDetailView);
    await screen.findByRole("option", { name: "acme" });
    const button = screen.getByRole("button", { name: "Delete tenant" });
    expect(button).toBeDisabled();

    await fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "acme" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await screen.findByText("Acme");
    expect(button).toBeDisabled();

    const confirm = screen.getByLabelText("Confirm tenant ID");
    await fireEvent.input(confirm, { target: { value: "acm" } });
    expect(button).toBeDisabled();
    await fireEvent.input(confirm, { target: { value: "acme" } });
    expect(button).toBeEnabled();

    await fireEvent.click(button);

    await waitFor(() => expect(del).toHaveBeenCalledOnce());
    expect(del).toHaveBeenCalledWith("acme");
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(toasts).toContainEqual({ kind: "success", message: 'Tenant "acme" deleted.' });
    expect(screen.queryByText("Acme")).not.toBeInTheDocument();
  });

  it("shows Tenant not found on a 404", async () => {
    get.mockRejectedValue(Object.assign(new Error("nope"), { status: 404 }));

    await loadAcme();

    expect(await screen.findByText("Tenant not found")).toBeInTheDocument();
    expect(screen.queryByText("nope")).not.toBeInTheDocument();
  });

  it("surfaces any other load error", async () => {
    get.mockRejectedValue(Object.assign(new Error("barrier sealed"), { status: 503 }));

    await loadAcme();

    expect(await screen.findByText("barrier sealed")).toBeInTheDocument();
  });

  it("surfaces a list error", async () => {
    list.mockRejectedValue(new Error("list failed"));

    render(TenantDetailView);

    expect(await screen.findByText("list failed")).toBeInTheDocument();
  });

  it("surfaces a delete error", async () => {
    get.mockResolvedValue(acme);
    del.mockRejectedValue(new Error("delete refused"));

    await loadAcme();
    await screen.findByText("Acme");
    await fireEvent.input(screen.getByLabelText("Confirm tenant ID"), { target: { value: "acme" } });
    await fireEvent.click(screen.getByRole("button", { name: "Delete tenant" }));

    expect(await screen.findByText("delete refused")).toBeInTheDocument();
  });
});
