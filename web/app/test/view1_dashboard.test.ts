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
import type {
  HealthResponse,
  BarrierStatusResponse,
  ClusterStatusResponse,
  ListBackendsResponse,
} from "@go-xkms/sdk";

const health = vi.fn<() => Promise<HealthResponse>>();
const barrierStatus = vi.fn<() => Promise<BarrierStatusResponse>>();
const backendsList = vi.fn<() => Promise<ListBackendsResponse>>();
const clusterStatus = vi.fn<() => Promise<ClusterStatusResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    health: { health },
    barrier: { status: barrierStatus },
    backends: { list: backendsList },
    cluster: { status: clusterStatus },
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
  it("shows a loading spinner then health, backend count and barrier posture", async () => {
    health.mockResolvedValue({ status: "ok", version: "1.2.3" });
    barrierStatus.mockResolvedValue({
      sealed: false,
      strategy: "shamir",
      hardware_backed: true,
      initialized_at: "2026-01-01T00:00:00Z",
    });
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
    expect(screen.getByText("unsealed")).toBeInTheDocument();
    expect(screen.getByText("hardware-backed")).toBeInTheDocument();
    // Not a cluster-capable deployment: no cluster call, standalone shown.
    expect(clusterStatus).not.toHaveBeenCalled();
    expect(screen.getByText("standalone")).toBeInTheDocument();
  });

  it("surfaces the health error while still attempting the best-effort panels", async () => {
    health.mockRejectedValue(new Error("health check failed"));
    barrierStatus.mockResolvedValue({
      sealed: true,
      strategy: "none",
      hardware_backed: false,
      initialized_at: "2026-01-01T00:00:00Z",
    });
    backendsList.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });

    render(DashboardView);

    expect(await screen.findByText("health check failed")).toBeInTheDocument();
    // Barrier and backend panels are independent try/catch blocks — a health
    // failure must not blank them.
    expect(screen.getByText("sealed")).toBeInTheDocument();
    expect(barrierStatus).toHaveBeenCalledOnce();
    expect(backendsList).toHaveBeenCalledOnce();
  });

  it("shows '—' for backends and barrier when their calls fail, without an error banner", async () => {
    health.mockResolvedValue({ status: "ok" });
    barrierStatus.mockRejectedValue(new Error("barrier unreachable"));
    backendsList.mockRejectedValue(new Error("backends unreachable"));

    render(DashboardView);

    await waitFor(() => expect(screen.getByText("ok")).toBeInTheDocument());
    expect(screen.queryByText("barrier unreachable")).toBeNull();
    expect(screen.queryByText("backends unreachable")).toBeNull();
    // StatCard renders the em-dash placeholder for backend count and barrier.
    const dashes = screen.getAllByText("—");
    expect(dashes.length).toBeGreaterThanOrEqual(1);
  });

  it("queries cluster status only when the deployment reports the cluster capability", async () => {
    health.mockResolvedValue({ status: "ok" });
    barrierStatus.mockResolvedValue({
      sealed: false,
      strategy: "shamir",
      hardware_backed: false,
      initialized_at: "2026-01-01T00:00:00Z",
    });
    backendsList.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    hasCapabilityMock.mockImplementation((name) => name === "cluster");
    clusterStatus.mockResolvedValue({
      status: { shard_id: 0, leader_id: 1, has_leader: true, node_id: 1, clustered: true },
    });

    render(DashboardView);

    await waitFor(() => expect(clusterStatus).toHaveBeenCalledOnce());
    expect(await screen.findByText("clustered")).toBeInTheDocument();
    expect(screen.getByText("leader elected")).toBeInTheDocument();
  });

  it("falls back to standalone without an error banner when cluster.status fails", async () => {
    health.mockResolvedValue({ status: "ok" });
    barrierStatus.mockResolvedValue({
      sealed: false,
      strategy: "shamir",
      hardware_backed: false,
      initialized_at: "2026-01-01T00:00:00Z",
    });
    backendsList.mockResolvedValue({ backends: [], pagination: { page: 1, page_size: 50, total: 0, has_more: false } });
    hasCapabilityMock.mockImplementation((name) => name === "cluster");
    clusterStatus.mockRejectedValue(new Error("cluster status unavailable"));

    render(DashboardView);

    await waitFor(() => expect(clusterStatus).toHaveBeenCalledOnce());
    expect(screen.queryByText("cluster status unavailable")).toBeNull();
    expect(await screen.findByText("standalone")).toBeInTheDocument();
  });
});
