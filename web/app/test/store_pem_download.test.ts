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

// test/pem.test.ts (owned by another agent) covers decodePEM/encodePEM/
// reasonLabel. downloadText() is untested there; jsdom has no real
// createObjectURL/anchor-click download pipeline, so it is stubbed here.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { downloadText } from "../src/lib/pem.ts";

describe("downloadText", () => {
  let createObjectURLSpy: ReturnType<typeof vi.fn>;
  let revokeObjectURLSpy: ReturnType<typeof vi.fn>;
  let clickSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers();
    createObjectURLSpy = vi.fn(() => "blob:mock-url");
    revokeObjectURLSpy = vi.fn();
    (URL as unknown as { createObjectURL: typeof createObjectURLSpy }).createObjectURL = createObjectURLSpy;
    (URL as unknown as { revokeObjectURL: typeof revokeObjectURLSpy }).revokeObjectURL = revokeObjectURLSpy;
    clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    clickSpy.mockRestore();
  });

  it("builds a Blob with the given mime type, clicks a temporary anchor, and revokes the URL afterward", () => {
    downloadText("cert.pem", "-----BEGIN CERTIFICATE-----", "application/x-pem-file");

    expect(createObjectURLSpy).toHaveBeenCalledOnce();
    const blobArg = createObjectURLSpy.mock.calls[0]![0] as Blob;
    expect(blobArg.type).toBe("application/x-pem-file");

    expect(clickSpy).toHaveBeenCalledOnce();
    // The anchor is removed from the DOM right after the click.
    expect(document.body.querySelector("a[download='cert.pem']")).toBeNull();

    expect(revokeObjectURLSpy).not.toHaveBeenCalled();
    vi.advanceTimersByTime(0);
    expect(revokeObjectURLSpy).toHaveBeenCalledWith("blob:mock-url");
  });

  it("defaults to the PEM mime type and tolerates empty text without throwing", () => {
    expect(() => downloadText("empty.pem", "")).not.toThrow();
    const blobArg = createObjectURLSpy.mock.calls[0]![0] as Blob;
    expect(blobArg.type).toBe("application/x-pem-file");
    expect(blobArg.size).toBe(0);
  });
});
