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
import type { AlgorithmsResponse, HealthCheckResponse } from "@go-xkms/sdk";

const live = vi.fn<() => Promise<HealthCheckResponse>>();
const ready = vi.fn<() => Promise<HealthCheckResponse>>();
const startup = vi.fn<() => Promise<HealthCheckResponse>>();
const algorithms = vi.fn<() => Promise<AlgorithmsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ health: { live, ready, startup, algorithms } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SystemHealthView from "../src/views/SystemHealthView.svelte";

const liveResp: HealthCheckResponse = {
  status: "alive",
  checks: [{ name: "process", status: "pass", message: "running" }],
};
const readyResp: HealthCheckResponse = {
  status: "ready",
  checks: [
    { name: "backend:pkcs8", status: "healthy", message: "keystore open" },
    { name: "storage", status: "healthy", message: "writable" },
  ],
};
const startupResp: HealthCheckResponse = {
  status: "started",
  checks: [{ name: "migrations", status: "healthy", message: "applied" }],
};
const algResp: AlgorithmsResponse = {
  signing: [
    { algorithm: "ECDSA", curves: ["P-256", "P-384"], backends: ["pkcs8", "tpm2"] },
    { algorithm: "RSA", key_sizes: [2048, 4096], backends: ["pkcs11"] },
    { algorithm: "ML-DSA-65", backends: ["quantum"], post_quantum: true },
  ],
  key_encapsulation: [{ algorithm: "ML-KEM-768", backends: ["quantum"], post_quantum: true }],
};

function allOk(): void {
  live.mockResolvedValue(liveResp);
  ready.mockResolvedValue(readyResp);
  startup.mockResolvedValue(startupResp);
  algorithms.mockResolvedValue(algResp);
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("SystemHealthView", () => {
  it("loads the three probes and the algorithms on mount and shows each check", async () => {
    allOk();

    render(SystemHealthView);

    const readiness = await screen.findByRole("region", { name: "Readiness" });
    expect(live).toHaveBeenCalledOnce();
    expect(ready).toHaveBeenCalledOnce();
    expect(startup).toHaveBeenCalledOnce();
    expect(algorithms).toHaveBeenCalledOnce();

    const liveness = screen.getByRole("region", { name: "Liveness" });
    expect(await within(liveness).findByText("alive")).toBeInTheDocument();
    expect(within(liveness).getByText("process")).toBeInTheDocument();
    expect(within(liveness).getByText("running")).toBeInTheDocument();

    expect(within(readiness).getByText("ready")).toBeInTheDocument();
    expect(within(readiness).getByText("backend:pkcs8")).toBeInTheDocument();
    expect(within(readiness).getByText("keystore open")).toBeInTheDocument();
    expect(within(readiness).getByText("storage")).toBeInTheDocument();
    expect(within(readiness).getByText("writable")).toBeInTheDocument();
    expect(within(readiness).getAllByRole("row")).toHaveLength(3); // header + 2 checks

    const start = screen.getByRole("region", { name: "Startup" });
    expect(within(start).getByText("started")).toBeInTheDocument();
    expect(within(start).getByText("migrations")).toBeInTheDocument();
    expect(within(start).getByText("applied")).toBeInTheDocument();
  });

  it("shows a rejected probe as down with its message, not as a page error", async () => {
    allOk();
    ready.mockRejectedValue({ status: 503, message: "backend tpm not ready" });

    render(SystemHealthView);

    const readiness = await screen.findByRole("region", { name: "Readiness" });
    expect(await within(readiness).findByText("down")).toBeInTheDocument();
    expect(within(readiness).getByText("backend tpm not ready")).toBeInTheDocument();

    const liveness = screen.getByRole("region", { name: "Liveness" });
    expect(await within(liveness).findByText("process")).toBeInTheDocument();
    const start = screen.getByRole("region", { name: "Startup" });
    expect(within(start).getByText("migrations")).toBeInTheDocument();

    expect(screen.queryAllByRole("alert")).toHaveLength(0);
  });

  it("lists signing and key-encapsulation algorithms with a post-quantum badge only where set", async () => {
    allOk();

    render(SystemHealthView);

    const signing = await screen.findByRole("table", { name: "Signing algorithms" });
    await within(signing).findByText("ECDSA");
    expect(within(signing).getAllByRole("row")).toHaveLength(4); // header + 3
    const ecdsa = within(signing).getByText("ECDSA").closest("tr")!;
    expect(within(ecdsa).getByText("P-256, P-384")).toBeInTheDocument();
    expect(within(ecdsa).getByText("pkcs8, tpm2")).toBeInTheDocument();
    expect(within(ecdsa).queryByText("post-quantum")).toBeNull();
    const rsa = within(signing).getByText("RSA").closest("tr")!;
    expect(within(rsa).getByText("2048, 4096")).toBeInTheDocument();
    expect(within(rsa).queryByText("post-quantum")).toBeNull();
    const mldsa = within(signing).getByText("ML-DSA-65").closest("tr")!;
    expect(within(mldsa).getByText("post-quantum")).toBeInTheDocument();

    const kem = screen.getByRole("table", { name: "Key encapsulation algorithms" });
    const mlkem = within(kem).getByText("ML-KEM-768").closest("tr")!;
    expect(within(mlkem).getByText("quantum")).toBeInTheDocument();
    expect(within(mlkem).getByText("post-quantum")).toBeInTheDocument();
  });

  it("shows an empty-state line for an empty algorithm list", async () => {
    allOk();
    algorithms.mockResolvedValue({ signing: algResp.signing, key_encapsulation: [] });

    render(SystemHealthView);

    expect(await screen.findByText("No key encapsulation algorithms.")).toBeInTheDocument();
    expect(screen.getByText("ECDSA")).toBeInTheDocument();
  });

  it("reloads all four on Refresh", async () => {
    allOk();

    render(SystemHealthView);
    await screen.findByText("ECDSA");

    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => expect(algorithms).toHaveBeenCalledTimes(2));
    expect(live).toHaveBeenCalledTimes(2);
    expect(ready).toHaveBeenCalledTimes(2);
    expect(startup).toHaveBeenCalledTimes(2);
  });

  it("confines an algorithms failure to the algorithms section", async () => {
    allOk();
    algorithms.mockRejectedValue(new Error("algorithms unavailable"));

    render(SystemHealthView);

    const algSection = await screen.findByRole("region", { name: "Algorithms" });
    expect(await within(algSection).findByText("algorithms unavailable")).toBeInTheDocument();

    const readiness = screen.getByRole("region", { name: "Readiness" });
    expect(await within(readiness).findByText("backend:pkcs8")).toBeInTheDocument();
    expect(within(readiness).queryByText("algorithms unavailable")).toBeNull();
    expect(screen.queryByRole("table", { name: "Signing algorithms" })).toBeNull();
  });
});
