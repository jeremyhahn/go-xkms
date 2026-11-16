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
      branches: [{ name: "branch-1", match: false, mismatched: [7], approved: true }],
    });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verify).toHaveBeenCalledWith("boot", "acme"));
    expect(await screen.findAllByText("mismatch")).not.toHaveLength(0);
    expect(screen.getByText("PCR 7")).toBeInTheDocument();
  });

  // Server-shaped: transport.TPMPolicyBranch / TPMPolicyBranchVerification
  // carry name, approved and a reference whose digest is base64 SHA-256.
  const corimDigest = "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const reference = { id: "corim-fw-2", profile: "tag:example.com,2026:fw", signer: "Acme Firmware", digest: corimDigest };

  it("shows each branch's name, approval and reference in the loaded policy", async () => {
    get.mockResolvedValue({
      ...boot,
      approved: false,
      branches: [
        { name: "current", approved: false, conditions: [{ type: "auth_value" }] },
        { name: "next", approved: true, reference, conditions: [{ type: "locality", localities: [0] }] },
      ],
    });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    const current = await screen.findByTestId("policy-branch-current");
    expect(within(current).getByText("current")).toBeInTheDocument();
    expect(within(current).getByText("not approved")).toBeInTheDocument();
    expect(within(current).getByText("captured live")).toBeInTheDocument();
    const next = screen.getByTestId("policy-branch-next");
    expect(within(next).getByText("next")).toBeInTheDocument();
    expect(within(next).getByText("approved")).toBeInTheDocument();
    expect(within(next).getByText("corim-fw-2")).toBeInTheDocument();
    expect(within(next).getByText("tag:example.com,2026:fw")).toBeInTheDocument();
    expect(within(next).getByText("Acme Firmware")).toBeInTheDocument();
    expect(within(next).getByText(corimDigest)).toBeInTheDocument();
  });

  it("shows each branch's name, approval and reference in verify", async () => {
    verify.mockResolvedValue({
      name: "boot",
      match: true,
      approved: true,
      branches: [
        { name: "current", match: true, approved: false },
        { name: "next", match: true, approved: true, reference },
      ],
    });
    await pickBoot();

    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    const current = await screen.findByTestId("verify-branch-current");
    expect(within(current).getByText("current")).toBeInTheDocument();
    expect(within(current).getByText("not approved")).toBeInTheDocument();
    expect(within(current).getByText("captured live")).toBeInTheDocument();
    const next = screen.getByTestId("verify-branch-next");
    expect(within(next).getByText("approved")).toBeInTheDocument();
    expect(within(next).getByText("corim-fw-2")).toBeInTheDocument();
    expect(within(next).getByText(corimDigest)).toBeInTheDocument();
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

describe("TpmPolicyDetailView stale replies", () => {
  async function settle(): Promise<void> {
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
  }

  async function toOwnScope(): Promise<void> {
    await fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "" } });
  }

  it("drops a policy reply that lands after the scope changed", async () => {
    let resolveGet: (p: TPMPolicy) => void = () => {};
    get.mockImplementation(() => new Promise<TPMPolicy>((r) => (resolveGet = r)));
    await pickBoot();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(get).toHaveBeenCalledOnce());

    await toOwnScope();
    resolveGet({ ...boot, index: 9 });
    await settle();

    expect(screen.queryByTestId("policy-index")).not.toBeInTheDocument();
  });

  it("drops an objects reply that lands after the scope changed", async () => {
    let resolveObjects: (v: unknown) => void = () => {};
    objects.mockImplementation(() => new Promise((r) => (resolveObjects = r)));
    await pickBoot();
    await fireEvent.click(screen.getByRole("button", { name: "Objects" }));
    await waitFor(() => expect(objects).toHaveBeenCalledOnce());

    await toOwnScope();
    resolveObjects({ name: "boot", objects: ["key/k1"] });
    await settle();

    expect(screen.queryByText("Bound objects")).not.toBeInTheDocument();
  });

  it("drops a verify reply that lands after the scope changed", async () => {
    let resolveVerify: (v: unknown) => void = () => {};
    verify.mockImplementation(() => new Promise((r) => (resolveVerify = r)));
    await pickBoot();
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(verify).toHaveBeenCalledOnce());

    await toOwnScope();
    resolveVerify({ name: "boot", match: true, approved: true, branches: [] });
    await settle();

    expect(screen.queryByText("Live PCR check")).not.toBeInTheDocument();
  });

  it("drops a policy-name list for an earlier scope", async () => {
    let resolveAcme: (v: unknown) => void = () => {};
    list.mockImplementation((tenantId?: string) =>
      tenantId === "acme" ? new Promise((r) => (resolveAcme = r)) : Promise.resolve({ policies: [] }),
    );
    render(TpmPolicyDetailView);
    await screen.findByRole("option", { name: "acme" });
    await fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "acme" } });
    await waitFor(() => expect(list).toHaveBeenCalledWith("acme"));

    await toOwnScope();
    await waitFor(() => expect(list).toHaveBeenCalledTimes(3));
    resolveAcme({ policies: [boot] });
    await settle();

    expect(screen.queryByRole("option", { name: "boot" })).not.toBeInTheDocument();
  });
});
