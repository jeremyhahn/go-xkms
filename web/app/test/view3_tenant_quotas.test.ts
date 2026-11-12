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
import type {
  ListTenantsResponse,
  TenantQuotas,
  UpdateTenantQuotasRequest,
  UpdateTenantQuotasResponse,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListTenantsResponse>>();
const updateQuotas = vi.fn<(id: string, req: UpdateTenantQuotasRequest) => Promise<UpdateTenantQuotasResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, updateQuotas } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TenantQuotasView from "../src/views/TenantQuotasView.svelte";

const fields: Array<keyof TenantQuotas> = [
  "max_databases",
  "max_raft_groups",
  "max_replicas_per_group",
  "max_total_replicas",
  "max_collections",
  "max_keys",
  "max_storage_bytes",
  "max_database_size_bytes",
  "max_users",
  "max_roles",
  "max_certificates",
  "max_backups",
  "max_vector_dims",
  "max_ts_metrics",
  "system_barrier_quota",
  "max_dedicated_wal_groups",
];

function zeroQuotas(): TenantQuotas {
  const q = {} as TenantQuotas;
  for (const f of fields) q[f] = 0;
  return q;
}

const tenantsReply: ListTenantsResponse = {
  tenants: [
    { id: "t-acme", name: "Acme", sealed: false },
    { id: "t-beta", name: "Beta", sealed: false },
  ],
};

async function chooseTenant(id: string): Promise<void> {
  const select = await screen.findByLabelText("Tenant");
  await waitFor(() => expect(within(select).getByRole("option", { name: /Acme/ })).toBeInTheDocument());
  await fireEvent.change(select, { target: { value: id } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TenantQuotasView", () => {
  it("loads the tenants into the select and keeps Save disabled until one is chosen", async () => {
    list.mockResolvedValue(tenantsReply);

    render(TenantQuotasView);

    const select = await screen.findByLabelText("Tenant");
    await waitFor(() => expect(within(select).getByRole("option", { name: /Beta/ })).toBeInTheDocument());
    expect(list).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

    await fireEvent.change(select, { target: { value: "t-acme" } });
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("sends the whole quota set with unset fields as 0 and toasts success", async () => {
    list.mockResolvedValue(tenantsReply);
    const quotas = { ...zeroQuotas(), max_keys: 100, max_users: 5 };
    updateQuotas.mockResolvedValue({
      tenant: { id: "t-acme", name: "Acme", quotas, created_at: "", updated_at: "" },
    });

    render(TenantQuotasView);
    await chooseTenant("t-acme");
    await fireEvent.input(screen.getByLabelText("max_keys"), { target: { value: "100" } });
    await fireEvent.input(screen.getByLabelText("max_users"), { target: { value: "5" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(updateQuotas).toHaveBeenCalledTimes(1));
    expect(updateQuotas).toHaveBeenCalledWith("t-acme", { tenant_id: "t-acme", quotas });
    expect(Object.keys(updateQuotas.mock.calls[0][1].quotas)).toHaveLength(16);
    await waitFor(() => expect(toasts).toEqual([{ kind: "success", message: expect.any(String) }]));
  });

  it("renders the quotas the server returned", async () => {
    list.mockResolvedValue(tenantsReply);
    updateQuotas.mockResolvedValue({
      tenant: { id: "t-acme", name: "Acme", quotas: { ...zeroQuotas(), max_keys: 100 }, created_at: "", updated_at: "" },
    });

    render(TenantQuotasView);
    await chooseTenant("t-acme");
    await fireEvent.input(screen.getByLabelText("max_keys"), { target: { value: "100" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const result = await screen.findByRole("region", { name: "Stored quotas" });
    const row = within(result).getByText("max_keys").closest("div");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText("100")).toBeInTheDocument();
  });

  it("says none returned when the reply carries no quotas", async () => {
    list.mockResolvedValue(tenantsReply);
    updateQuotas.mockResolvedValue({ tenant: { id: "t-acme", name: "Acme", created_at: "", updated_at: "" } });

    render(TenantQuotasView);
    await chooseTenant("t-acme");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const result = await screen.findByRole("region", { name: "Stored quotas" });
    expect(within(result).getByText("none returned")).toBeInTheDocument();
    expect(result.textContent).not.toContain("undefined");
  });

  it.each(["-1", "1.5"])("rejects %s inline and does not call updateQuotas", async (bad) => {
    list.mockResolvedValue(tenantsReply);

    render(TenantQuotasView);
    await chooseTenant("t-acme");
    await fireEvent.input(screen.getByLabelText("max_keys"), { target: { value: bad } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("max_keys must be a whole number of 0 or more.")).toBeInTheDocument();
    expect(updateQuotas).not.toHaveBeenCalled();
  });

  it("shows an error when the tenant list fails", async () => {
    list.mockRejectedValue(new Error("tenants unavailable"));

    render(TenantQuotasView);

    expect(await screen.findByText("tenants unavailable")).toBeInTheDocument();
  });

  it("shows an error when the quota update fails", async () => {
    list.mockResolvedValue(tenantsReply);
    updateQuotas.mockRejectedValue(new Error("permission denied"));

    render(TenantQuotasView);
    await chooseTenant("t-acme");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(toasts).toEqual([]);
  });
});
