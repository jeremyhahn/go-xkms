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
import { render, screen, waitFor } from "@testing-library/svelte";
import type { HealthResponse, ListBackendsResponse } from "@go-xkms/sdk";

const health = vi.fn<() => Promise<HealthResponse>>();
const backendsList = vi.fn<() => Promise<ListBackendsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    health: { health },
    backends: { list: backendsList },
  }),
  resetSDKClient: () => {},
}));

const hasCapabilityMock = vi.fn<(name: string) => boolean>();
vi.mock("../src/stores/session.svelte.ts", () => ({
  can: () => true,
  hasCapability: (name: string) => hasCapabilityMock(name),
}));

import DashboardView from "../src/views/DashboardView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  hasCapabilityMock.mockReturnValue(false);
});

describe("DashboardView", () => {
  it("shows a loading spinner then health and backend count", async () => {
    health.mockResolvedValue({ status: "ok", version: "1.2.3" });
    backendsList.mockResolvedValue({
      backends: [
        { id: "a", type: "software", hardware_backed: false, capabilities: {} as never },
        { id: "b", type: "tpm2", hardware_backed: true, capabilities: {} as never },
      ],
      pagination: { page: 1, page_size: 50, total: 2, has_more: false },
    });

    render(DashboardView);
    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("ok")).toBeInTheDocument());
    expect(screen.getByText("1.2.3")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    // Not a clustered deployment: standalone shown.
    expect(screen.getByText("standalone")).toBeInTheDocument();
  });

  it("surfaces the health error while still attempting the best-effort panels", async () => {
    health.mockRejectedValue(new Error("health check failed"));
    backendsList.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });

    render(DashboardView);

    expect(await screen.findByText("health check failed")).toBeInTheDocument();
    // The backend panel is an independent try/catch block — a health failure
    // must not blank it.
    expect(backendsList).toHaveBeenCalledOnce();
  });

  it("shows '—' for backends when their call fails, without an error banner", async () => {
    health.mockResolvedValue({ status: "ok" });
    backendsList.mockRejectedValue(new Error("backends unreachable"));

    render(DashboardView);

    await waitFor(() => expect(screen.getByText("ok")).toBeInTheDocument());
    expect(screen.queryByText("backends unreachable")).toBeNull();
    // StatCard renders the em-dash placeholder for the backend count.
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThanOrEqual(1);
  });

  it("shows clustered when the deployment reports the cluster capability", async () => {
    health.mockResolvedValue({ status: "ok" });
    backendsList.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    hasCapabilityMock.mockImplementation((name) => name === "cluster");

    render(DashboardView);

    expect(await screen.findByText("clustered")).toBeInTheDocument();
  });
});
