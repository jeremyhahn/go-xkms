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
import type { InitStatusResponse, CredentialStrategyResponse } from "@go-xkms/sdk";

const initStatus = vi.fn<() => Promise<InitStatusResponse>>();
const strategy = vi.fn<() => Promise<CredentialStrategyResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    init: { status: initStatus },
    credentials: { strategy },
  }),
  resetSDKClient: () => {},
}));

import CeremonyView from "../src/views/CeremonyView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CeremonyView", () => {
  it("shows a loading spinner then the ceremony state and credential strategy", async () => {
    initStatus.mockResolvedValue({ state: "unsealed" });
    strategy.mockResolvedValue({ strategy: "shamir", auto_unseal: false });

    render(CeremonyView);

    expect(document.querySelector(".loading-spinner")).not.toBeNull();

    await waitFor(() => expect(screen.getByText("unsealed")).toBeInTheDocument());
    expect(screen.getByText("shamir")).toBeInTheDocument();
    expect(screen.getByText("no")).toBeInTheDocument();
  });

  it("surfaces an init-status error", async () => {
    initStatus.mockRejectedValue(new Error("init service unreachable"));
    strategy.mockResolvedValue({ strategy: "shamir", auto_unseal: false });

    render(CeremonyView);

    expect(await screen.findByText("init service unreachable")).toBeInTheDocument();
    // The error blocks the whole view (unlike the strategy call, which is
    // best-effort), so neither panel renders.
    expect(screen.queryByText("Ceremony state")).toBeNull();
  });

  it("degrades gracefully when the credential-strategy call fails", async () => {
    initStatus.mockResolvedValue({ state: "sealed" });
    strategy.mockRejectedValue(new Error("strategy not configured"));

    render(CeremonyView);

    await waitFor(() => expect(screen.getByText("sealed")).toBeInTheDocument());
    // A failed best-effort call must not surface an error or block the
    // ceremony-state panel.
    expect(screen.queryByText("strategy not configured")).toBeNull();
    expect(screen.queryByText("Credential strategy")).toBeNull();
  });
});
