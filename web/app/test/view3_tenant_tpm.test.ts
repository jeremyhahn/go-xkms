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
import type {
  ListTenantsResponse,
  SetTenantTPMModeRequest,
  TenantTPMModeResponse,
  TenantVTPMStatusResponse,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<ListTenantsResponse>>();
const getTPMMode = vi.fn<(id: string) => Promise<TenantTPMModeResponse>>();
const setTPMMode = vi.fn<(id: string, req: SetTenantTPMModeRequest) => Promise<TenantTPMModeResponse>>();
const vtpmStatus = vi.fn<(id: string) => Promise<TenantVTPMStatusResponse>>();
const vtpmStart = vi.fn<(id: string) => Promise<TenantVTPMStatusResponse>>();
const vtpmStop = vi.fn<(id: string) => Promise<TenantVTPMStatusResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ tenants: { list, getTPMMode, setTPMMode, vtpmStatus, vtpmStart, vtpmStop } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import TenantTpmView from "../src/views/TenantTpmView.svelte";

const tenantList = {
  tenants: [
    { id: "t1", name: "Acme", sealed: false },
    { id: "t2", name: "", sealed: false },
  ],
  pagination: {},
} as unknown as ListTenantsResponse;

async function choose(id: string): Promise<void> {
  render(TenantTpmView);
  const sel = await screen.findByLabelText("Tenant");
  await screen.findByRole("option", { name: "Acme (t1)" });
  await fireEvent.change(sel, { target: { value: id } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  list.mockResolvedValue(tenantList);
});

describe("TenantTpmView", () => {
  it("lists tenants as name (id), or id when the name is empty", async () => {
    render(TenantTpmView);
    expect(await screen.findByRole("option", { name: "Acme (t1)" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "t2" })).toBeInTheDocument();
    expect(getTPMMode).not.toHaveBeenCalled();
  });

  it("shows the mode and the vTPM status of a vtpm tenant", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "vtpm" });
    vtpmStatus.mockResolvedValue({ tenant_id: "t1", running: true, pid: 4242, socket: "/run/vtpm/t1.sock", restarts: 3 });

    await choose("t1");

    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("vtpm"));
    expect(getTPMMode).toHaveBeenCalledWith("t1");
    await waitFor(() => expect(vtpmStatus).toHaveBeenCalledWith("t1"));
    expect(await screen.findByText("running")).toBeInTheDocument();
    expect(screen.getByText("4242")).toBeInTheDocument();
    expect(screen.getByText("/run/vtpm/t1.sock")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("shows no vTPM panel for none or shared", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t2", mode: "shared" });

    await choose("t2");

    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("shared"));
    expect(getTPMMode).toHaveBeenCalledWith("t2");
    expect(vtpmStatus).not.toHaveBeenCalled();
    expect(screen.queryByText("Virtual TPM")).not.toBeInTheDocument();
  });

  it("sets the mode after a confirm that names the refusal", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "none" });
    setTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "shared" });

    await choose("t1");
    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("none"));

    await fireEvent.change(screen.getByLabelText("New mode"), { target: { value: "shared" } });
    await fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText(/refused while the tenant holds TPM keys or policies/)).toBeInTheDocument();
    expect(setTPMMode).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole("button", { name: "Change mode", hidden: true }));

    await waitFor(() => expect(setTPMMode).toHaveBeenCalledWith("t1", { tenant_id: "t1", mode: "shared" }));
    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("shared"));
  });

  it("sends owner_auth base64-encoded only when filled", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "none" });
    setTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "shared" });

    await choose("t1");
    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("none"));

    await fireEvent.change(screen.getByLabelText("New mode"), { target: { value: "shared" } });
    await fireEvent.input(screen.getByLabelText("Owner auth (optional)"), { target: { value: "secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Change mode", hidden: true }));

    await waitFor(() =>
      expect(setTPMMode).toHaveBeenCalledWith("t1", { tenant_id: "t1", mode: "shared", owner_auth: "c2VjcmV0" }),
    );
  });

  it("cancelling the mode confirm calls nothing", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "none" });

    await choose("t1");
    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("none"));

    await fireEvent.change(screen.getByLabelText("New mode"), { target: { value: "shared" } });
    await fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Cancel", hidden: true }));

    await waitFor(() => expect(screen.queryByText(/refused while the tenant holds/)).not.toBeInTheDocument());
    expect(setTPMMode).not.toHaveBeenCalled();
    expect(screen.getByTestId("current-mode")).toHaveTextContent("none");
  });

  it("a rejected mode change shows an error toast and keeps the old mode", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "none" });
    setTPMMode.mockRejectedValue(new Error("tenant scope holds TPM objects"));

    await choose("t1");
    await waitFor(() => expect(screen.getByTestId("current-mode")).toHaveTextContent("none"));

    await fireEvent.change(screen.getByLabelText("New mode"), { target: { value: "vtpm" } });
    await fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await fireEvent.click(await screen.findByRole("button", { name: "Change mode", hidden: true }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "tenant scope holds TPM objects" }));
    expect(screen.getByTestId("current-mode")).toHaveTextContent("none");
  });

  it("starts a stopped vTPM and shows the returned status", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "vtpm" });
    vtpmStatus.mockResolvedValue({ tenant_id: "t1", running: false });
    vtpmStart.mockResolvedValue({ tenant_id: "t1", running: true, pid: 777, socket: "/run/vtpm/t1.sock", restarts: 0 });

    await choose("t1");
    expect(await screen.findByText("stopped")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop" })).not.toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Start" }));

    await waitFor(() => expect(vtpmStart).toHaveBeenCalledWith("t1"));
    expect(await screen.findByText("running")).toBeInTheDocument();
    expect(screen.getByText("777")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start" })).not.toBeInTheDocument();
  });

  it("stops a running vTPM after a confirm", async () => {
    getTPMMode.mockResolvedValue({ tenant_id: "t1", mode: "vtpm" });
    vtpmStatus.mockResolvedValue({ tenant_id: "t1", running: true, pid: 4242 });
    vtpmStop.mockResolvedValue({ tenant_id: "t1", running: false });

    await choose("t1");
    expect(await screen.findByText("running")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start" })).not.toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(vtpmStop).not.toHaveBeenCalled();
    await fireEvent.click(await screen.findByRole("button", { name: "Stop vTPM", hidden: true }));

    await waitFor(() => expect(vtpmStop).toHaveBeenCalledWith("t1"));
    expect(await screen.findByText("stopped")).toBeInTheDocument();
  });

  it("a rejected list shows an error alert", async () => {
    list.mockRejectedValue(new Error("tenants unavailable"));

    render(TenantTpmView);

    expect(await screen.findByText("tenants unavailable")).toBeInTheDocument();
  });

  it("a rejected getTPMMode shows an error alert for that tenant", async () => {
    getTPMMode.mockRejectedValue(new Error("tpm policies not wired"));

    await choose("t1");

    expect(await screen.findByText("tpm policies not wired")).toBeInTheDocument();
    expect(vtpmStatus).not.toHaveBeenCalled();
  });
});
