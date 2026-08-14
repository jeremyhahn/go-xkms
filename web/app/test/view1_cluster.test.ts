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
import type { ClusterStatusResponse, ListClusterMembersResponse } from "@go-xkms/sdk";

const status = vi.fn<() => Promise<ClusterStatusResponse>>();
const members = vi.fn<() => Promise<ListClusterMembersResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ cluster: { status, members } }),
  resetSDKClient: () => {},
}));

import ClusterView from "../src/views/ClusterView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ClusterView", () => {
  it("always shows the read-only banner, even while loading", () => {
    status.mockReturnValue(new Promise(() => {})); // never resolves
    members.mockReturnValue(new Promise(() => {}));

    render(ClusterView);

    expect(
      screen.getByText(/Cluster membership changes are performed over the Raft admin plane/),
    ).toBeInTheDocument();
  });

  it("shows a loading spinner then cluster status and members", async () => {
    status.mockResolvedValue({
      status: { shard_id: 0, leader_id: 2, has_leader: true, node_id: 2, clustered: true },
    });
    members.mockResolvedValue({
      members: [
        { node_id: 1, address: "10.0.0.1:9443", is_leader: false },
        { node_id: 2, address: "10.0.0.2:9443", is_leader: true },
      ],
    });

    render(ClusterView);
    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("clustered")).toBeInTheDocument());
    expect(screen.getByText("leader elected")).toBeInTheDocument();
    expect(screen.getByText("node 2")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1:9443")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2:9443")).toBeInTheDocument();
  });

  it("shows the standalone empty message when there are no members", async () => {
    status.mockResolvedValue({
      status: { shard_id: 0, leader_id: 0, has_leader: false, node_id: 0, clustered: false },
    });
    members.mockResolvedValue({ members: [] });

    render(ClusterView);

    expect(await screen.findByText("No cluster members (standalone node).")).toBeInTheDocument();
    expect(screen.getByText("standalone")).toBeInTheDocument();
    expect(screen.getByText("no leader")).toBeInTheDocument();
  });

  it("surfaces a status error", async () => {
    status.mockRejectedValue(new Error("cluster status unavailable"));
    members.mockResolvedValue({ members: [] });

    render(ClusterView);

    expect(await screen.findByText("cluster status unavailable")).toBeInTheDocument();
  });
});
