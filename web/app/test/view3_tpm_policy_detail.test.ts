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
import type { TPMPolicy } from "@go-xkms/sdk";

const tenantsList = vi.fn();
const list = vi.fn();
const get = vi.fn();
const objects = vi.fn();
const verify = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    tenants: { list: tenantsList },
    tpmPolicies: { list, get, objects, verify },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TpmPolicyDetailView from "../src/views/TpmPolicyDetailView.svelte";

const boot: TPMPolicy = {
  name: "boot",
  tenant_id: "acme",
  branches: [],
  index: 1,
  approved: true,
  created_at: "2026-11-12T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  tenantsList.mockResolvedValue({ tenants: [{ id: "acme", sealed: false }], pagination: {} });
  list.mockImplementation(async (tenantId?: string) =>
    tenantId === "acme" ? { policies: [boot] } : { policies: [] },
  );
});

async function pickBoot(): Promise<void> {
  render(TpmPolicyDetailView);
  await screen.findByRole("option", { name: "acme" });
  await fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "acme" } });
  await screen.findByRole("option", { name: "boot" });
  await fireEvent.change(screen.getByLabelText("Policy"), { target: { value: "boot" } });
}

describe("TpmPolicyDetailView", () => {
  it("lists the own scope and the tenants on mount", async () => {
    render(TpmPolicyDetailView);

    expect(await screen.findByRole("option", { name: "acme" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Own scope" })).toBeInTheDocument();
    expect(tenantsList).toHaveBeenCalledOnce();
    expect(list).toHaveBeenCalledOnce();
    expect(list).toHaveBeenCalledWith(undefined);
  });

  it("keeps only the own scope when the tenant list is refused", async () => {
    tenantsList.mockRejectedValue(new Error("forbidden"));

    render(TpmPolicyDetailView);

    await waitFor(() => expect(list).toHaveBeenCalledWith(undefined));
    expect(screen.getAllByRole("option").map((o) => o.textContent)).toContain("Own scope");
    expect(screen.queryByText("forbidden")).not.toBeInTheDocument();
  });

  it("lists a tenant's policies when the scope changes", async () => {
    render(TpmPolicyDetailView);
    await screen.findByRole("option", { name: "acme" });

    await fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "acme" } });

    await waitFor(() => expect(list).toHaveBeenCalledWith("acme"));
    expect(await screen.findByRole("option", { name: "boot" })).toBeInTheDocument();
  });

  it("loads a policy with its captured PCR values, digest and localities", async () => {
    get.mockResolvedValue({
      ...boot,
      index: 3,
      branches: [
        {
          conditions: [
            { type: "pcr", bank: "sha256", pcrs: [0, 7], pcr_values: { "7": "bb", "0": "aa" }, pcr_digest: "cc" },
            { type: "locality", localities: [0] },
          ],
        },
      ],
    });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(get).toHaveBeenCalledWith("boot", "acme"));
    expect(await screen.findByText("sha256")).toBeInTheDocument();
    const rows = screen.getAllByTestId("pcr-row").map((r) => r.textContent?.replace(/\s+/g, " ").trim());
    expect(rows).toEqual(["PCR 0 aa", "PCR 7 bb"]);
    expect(screen.getByText("cc")).toBeInTheDocument();
    expect(screen.getByText("Localities: 0")).toBeInTheDocument();
    expect(screen.getByTestId("policy-index").textContent).toBe("3");
    expect(screen.getByText("approved")).toBeInTheDocument();
  });

  it("lists the objects bound to the policy", async () => {
    objects.mockResolvedValue({ name: "boot", objects: ["key/k1", "sealed/s1"] });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Objects" }));

    await waitFor(() => expect(objects).toHaveBeenCalledWith("boot", "acme"));
    expect(await screen.findByText("key/k1")).toBeInTheDocument();
    expect(screen.getByText("sealed/s1")).toBeInTheDocument();
  });

  it("says so when no objects are bound", async () => {
    objects.mockResolvedValue({ name: "boot", objects: [] });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Objects" }));

    expect(await screen.findByText("No objects bound")).toBeInTheDocument();
  });

  it("verifies the policy and names the mismatched PCRs", async () => {
    verify.mockResolvedValue({
      name: "boot",
      match: false,
      approved: true,
      branches: [{ match: false, mismatched: [7], approved: true }],
    });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verify).toHaveBeenCalledWith("boot", "acme"));
    expect(await screen.findAllByText("mismatch")).not.toHaveLength(0);
    expect(screen.getByText("PCR 7")).toBeInTheDocument();
  });

  it.each([
    ["Load", get, "policy not found"],
    ["Objects", objects, "objects refused"],
    ["Verify", verify, "tpm unavailable"],
  ] as const)("shows an error when %s fails", async (button, fn, message) => {
    fn.mockRejectedValue(new Error(message));
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: button }));

    const alert = await screen.findByText(message);
    expect(alert.closest('[role="alert"]')).not.toBeNull();
  });
});
