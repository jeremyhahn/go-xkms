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

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/svelte";
import { createRawSnippet } from "svelte";

import EmptyState from "../src/components/EmptyState.svelte";
import PageHeader from "../src/components/PageHeader.svelte";
import PlaceholderView from "../src/components/PlaceholderView.svelte";
import StatCard from "../src/components/StatCard.svelte";
import StatusBadge from "../src/components/StatusBadge.svelte";

describe("EmptyState", () => {
  it("renders the title and an optional message", () => {
    render(EmptyState, { props: { title: "No keys", message: "Generate one to get started." } });
    expect(screen.getByText("No keys")).toBeInTheDocument();
    expect(screen.getByText("Generate one to get started.")).toBeInTheDocument();
  });

  it("omits the message paragraph entirely when none is given", () => {
    render(EmptyState, { props: { title: "No keys" } });
    expect(screen.getByText("No keys")).toBeInTheDocument();
    // A falsy `message` must not render an empty <p> — assert it's absent, not just empty.
    expect(screen.queryByText("", { selector: "p" })).not.toBeInTheDocument();
  });
});

describe("PageHeader", () => {
  it("renders the title and subtitle when provided", () => {
    render(PageHeader, { props: { title: "Keys", subtitle: "Manage backend keys" } });
    expect(screen.getByRole("heading", { name: "Keys" })).toBeInTheDocument();
    expect(screen.getByText("Manage backend keys")).toBeInTheDocument();
  });

  it("omits the subtitle paragraph when none is given", () => {
    render(PageHeader, { props: { title: "Keys" } });
    expect(screen.getByRole("heading", { name: "Keys" })).toBeInTheDocument();
    expect(screen.queryByText("Manage backend keys")).not.toBeInTheDocument();
  });

  it("renders the actions snippet inside the header", () => {
    const actions = createRawSnippet(() => ({
      render: () => `<button>New key</button>`,
    }));
    render(PageHeader, { props: { title: "Keys", actions } });
    expect(screen.getByRole("button", { name: "New key" })).toBeInTheDocument();
  });

  it("renders no actions wrapper when the actions snippet is omitted", () => {
    render(PageHeader, { props: { title: "Keys" } });
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("PlaceholderView", () => {
  it("names the phase in the notice when given", () => {
    render(PlaceholderView, { props: { title: "Ceremony", phase: "Phase 7" } });
    expect(screen.getByRole("heading", { name: "Ceremony" })).toBeInTheDocument();
    expect(screen.getByText(/later delivery phase \(Phase 7\)/)).toBeInTheDocument();
  });

  it("omits the parenthetical when no phase is given", () => {
    render(PlaceholderView, { props: { title: "Ceremony" } });
    expect(screen.getByText(/later delivery phase\./)).toBeInTheDocument();
  });
});

describe("StatCard", () => {
  it("renders label, value and an optional hint", () => {
    render(StatCard, { props: { label: "Total keys", value: 42, hint: "across 3 backends" } });
    expect(screen.getByText("Total keys")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("across 3 backends")).toBeInTheDocument();
  });

  it("omits the hint line when none is given", () => {
    render(StatCard, { props: { label: "Total keys", value: "0" } });
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.queryByText("across 3 backends")).not.toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("resolves an explicit kind over the ok flag", () => {
    const { container } = render(StatusBadge, { props: { label: "Degraded", ok: true, kind: "warning" } });
    expect(container.querySelector(".badge-warning")).not.toBeNull();
    expect(container.querySelector(".badge-success")).toBeNull();
  });

  it("falls back to neutral when neither kind nor ok is given", () => {
    const { container } = render(StatusBadge, { props: { label: "Unknown" } });
    expect(container.querySelector(".badge-neutral")).not.toBeNull();
  });

  it("derives success from ok=true and error from ok=false when kind is absent", () => {
    const okCase = render(StatusBadge, { props: { label: "Up", ok: true } });
    expect(okCase.container.querySelector(".badge-success")).not.toBeNull();
    okCase.unmount();

    const badCase = render(StatusBadge, { props: { label: "Down", ok: false } });
    expect(badCase.container.querySelector(".badge-error")).not.toBeNull();
  });
});
