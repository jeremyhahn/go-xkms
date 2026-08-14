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
import type { TenantInfoResponse, CreateTenantRequest } from "@go-xkms/sdk";

const list = vi.fn<() => Promise<{ tenants: TenantInfoResponse[]; pagination: unknown }>>();
const create = vi.fn<(req: CreateTenantRequest) => Promise<{ tenant: TenantInfoResponse }>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, create } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TenantsView from "../src/views/TenantsView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TenantsView", () => {
  it("renders id, name, isolation and sealed state", async () => {
    list.mockResolvedValue({
      tenants: [{ id: "acme", name: "Acme Corp", isolation_type: "dedicated", sealed: true }],
      pagination: {},
    });

    render(TenantsView);

    expect(await screen.findByText("acme")).toBeInTheDocument();
    expect(screen.getByText("Acme Corp")).toBeInTheDocument();
    expect(screen.getByText("dedicated")).toBeInTheDocument();
    expect(screen.getByText("sealed")).toBeInTheDocument();
  });

  it("shows unsealed when the tenant barrier is open", async () => {
    list.mockResolvedValue({ tenants: [{ id: "acme", sealed: false }], pagination: {} });

    render(TenantsView);

    expect(await screen.findByText("unsealed")).toBeInTheDocument();
  });

  it("shows the empty state with no tenants", async () => {
    list.mockResolvedValue({ tenants: [], pagination: {} });

    render(TenantsView);

    expect(await screen.findByText("No tenants.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    list.mockRejectedValue(new Error("tenant service unreachable"));

    render(TenantsView);

    expect(await screen.findByText("tenant service unreachable")).toBeInTheDocument();
  });

  it("creates a tenant with the shared isolation default", async () => {
    list.mockResolvedValue({ tenants: [], pagination: {} });
    create.mockResolvedValue({ tenant: { id: "widgets", name: "Widgets Inc", sealed: false } });

    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Tenant ID"), { target: { value: "widgets" } });
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "Widgets Inc" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({ id: "widgets", name: "Widgets Inc", isolation_type: "shared" });
  });

  it("creates a tenant with a dedicated isolation type when selected", async () => {
    list.mockResolvedValue({ tenants: [], pagination: {} });
    create.mockResolvedValue({ tenant: { id: "widgets", sealed: false } });

    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Tenant ID"), { target: { value: "widgets" } });
    await fireEvent.change(screen.getByRole("combobox", { hidden: true }), { target: { value: "dedicated" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toMatchObject({ isolation_type: "dedicated" });
  });

  it("surfaces a create failure inside the dialog", async () => {
    list.mockResolvedValue({ tenants: [], pagination: {} });
    create.mockRejectedValue(new Error("tenant id already in use"));

    render(TenantsView);
    await screen.findByText("No tenants.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
    await fireEvent.input(screen.getByPlaceholderText("Tenant ID"), { target: { value: "dup" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    expect(await screen.findByText("tenant id already in use")).toBeInTheDocument();
  });
});
