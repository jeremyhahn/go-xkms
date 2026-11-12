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
  UpdateTenantEntitlementsRequest,
  UpdateTenantEntitlementsResponse,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListTenantsResponse>>();
const updateEntitlements =
  vi.fn<(id: string, req: UpdateTenantEntitlementsRequest) => Promise<UpdateTenantEntitlementsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, updateEntitlements } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TenantEntitlementsView from "../src/views/TenantEntitlementsView.svelte";

const tenants: ListTenantsResponse = {
  tenants: [
    { id: "t-acme", name: "acme", sealed: false },
    { id: "t-beta", sealed: false },
  ],
};

function tenantInfo(entitlements?: UpdateTenantEntitlementsResponse["tenant"]["entitlements"]): UpdateTenantEntitlementsResponse {
  return {
    tenant: {
      id: "t-acme",
      name: "acme",
      entitlements,
      created_at: "2026-11-12T00:00:00Z",
      updated_at: "2026-11-12T00:00:00Z",
    },
  };
}

async function chooseTenant(id: string): Promise<void> {
  const select = await screen.findByLabelText("Tenant");
  await waitFor(() => expect(within(select).getAllByRole("option").length).toBeGreaterThan(1));
  await fireEvent.change(select, { target: { value: id } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("TenantEntitlementsView", () => {
  it("loads the tenants into the select and keeps Save disabled until one is chosen", async () => {
    list.mockResolvedValue(tenants);

    render(TenantEntitlementsView);

    const select = await screen.findByLabelText("Tenant");
    await waitFor(() => expect(within(select).getByRole("option", { name: "acme" })).toBeInTheDocument());
    expect(within(select).getByRole("option", { name: "t-beta" })).toBeInTheDocument();
    expect(list).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

    await fireEvent.change(select, { target: { value: "t-acme" } });
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it("sends the whole entitlement set and toasts on success", async () => {
    list.mockResolvedValue(tenants);
    updateEntitlements.mockResolvedValue(tenantInfo({ allow_dedicated_raft: true }));

    render(TenantEntitlementsView);
    await chooseTenant("t-acme");

    await fireEvent.click(screen.getByLabelText("allow_dedicated_raft"));
    await fireEvent.click(screen.getByLabelText("allow_dedicated_wal"));
    await fireEvent.input(screen.getByLabelText("allowed_isolation_modes"), {
      target: { value: " shared, dedicated ," },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(updateEntitlements).toHaveBeenCalledOnce());
    expect(updateEntitlements).toHaveBeenCalledWith("t-acme", {
      tenant_id: "t-acme",
      entitlements: {
        allowed_isolation_modes: ["shared", "dedicated"],
        allow_dedicated_raft: true,
        allow_volume_storage: false,
        allow_system_managed_barrier: false,
        allowed_barrier_modes: [],
        allow_dedicated_wal: true,
      },
    });
    await waitFor(() => expect(toasts).toEqual([{ kind: "success", message: expect.stringContaining("acme") }]));
  });

  it("renders the entitlements the server returned", async () => {
    list.mockResolvedValue(tenants);
    updateEntitlements.mockResolvedValue(
      tenantInfo({
        allowed_isolation_modes: ["shared", "dedicated"],
        allow_dedicated_raft: true,
        allow_volume_storage: false,
        allowed_barrier_modes: ["kek"],
      }),
    );

    render(TenantEntitlementsView);
    await chooseTenant("t-acme");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const result = await screen.findByRole("region", { name: "Returned entitlements" });
    expect(within(result).getByText("shared, dedicated")).toBeInTheDocument();
    expect(within(result).getByText("kek")).toBeInTheDocument();
    expect(within(result).getByTestId("allow_dedicated_raft")).toHaveTextContent("true");
    expect(within(result).getByTestId("allow_volume_storage")).toHaveTextContent("false");
    expect(within(result).getByTestId("allow_dedicated_wal")).toHaveTextContent("not set");
    expect(result).not.toHaveTextContent("undefined");
  });

  it("says none returned when the reply carries no entitlements", async () => {
    list.mockResolvedValue(tenants);
    updateEntitlements.mockResolvedValue(tenantInfo(undefined));

    render(TenantEntitlementsView);
    await chooseTenant("t-acme");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    const result = await screen.findByRole("region", { name: "Returned entitlements" });
    expect(within(result).getByText("none returned")).toBeInTheDocument();
    expect(result).not.toHaveTextContent("undefined");
  });

  it("shows an error alert when listing tenants fails", async () => {
    list.mockRejectedValue(new Error("tenants not wired"));

    render(TenantEntitlementsView);

    expect(await screen.findByText("tenants not wired")).toBeInTheDocument();
    expect(toasts).toEqual([]);
  });

  it("shows an error alert and no success toast when the save fails", async () => {
    list.mockResolvedValue(tenants);
    updateEntitlements.mockRejectedValue(new Error("permission denied"));

    render(TenantEntitlementsView);
    await chooseTenant("t-acme");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(toasts.filter((t) => t.kind === "success")).toEqual([]);
    expect(screen.queryByRole("region", { name: "Returned entitlements" })).not.toBeInTheDocument();
  });
});
