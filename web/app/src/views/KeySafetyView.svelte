<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    safetyCheck,
    safetyReport,
    setKeySafety,
    clearKeySafety,
    type SafetyWarning,
    type SafetyReportResponse,
    type SetKeySafetyRequest,
  } from "$lib/keySafety.ts";

  let warnings = $state<SafetyWarning[]>([]);
  let report = $state<SafetyReportResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);

  let keyId = $state("");
  let backend = $state("");
  let maxOps = $state("");
  let maxBytes = $state("");
  let warnPct = $state("");
  let formErr = $state<string | null>(null);
  let actionErr = $state<string | null>(null);
  let busy = $state(false);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function statusKind(s: string): "success" | "warning" | "error" | "neutral" {
    if (s === "critical" || s === "exceeded") return "error";
    if (s === "warning") return "warning";
    if (s === "ok") return "success";
    return "neutral";
  }

  function limit(w: SafetyWarning): string {
    const parts: string[] = [];
    if (w.max_operations) parts.push(`${w.operations_used} / ${w.max_operations} ops`);
    if (w.max_bytes) parts.push(`${w.bytes_used} / ${w.max_bytes} bytes`);
    return parts.join(", ") || "-";
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const [check, rep] = await Promise.all([safetyCheck(), safetyReport()]);
      warnings = check.warnings ?? [];
      report = rep;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  // Parses an optional whole-number field: undefined when empty, null when invalid.
  function wholeNumber(raw: string): number | undefined | null {
    const s = raw.trim();
    if (s === "") return undefined;
    if (!/^\d+$/.test(s)) return null;
    return Number(s);
  }

  function target(): boolean {
    formErr = null;
    actionErr = null;
    if (keyId.trim() === "" || backend.trim() === "") {
      formErr = "Key ID and backend are required.";
      return false;
    }
    return true;
  }

  function buildRequest(): SetKeySafetyRequest | null {
    if (!target()) return null;
    const ops = wholeNumber(maxOps);
    if (ops === null) {
      formErr = "Max operations must be a whole number of 0 or more.";
      return null;
    }
    const bytes = wholeNumber(maxBytes);
    if (bytes === null) {
      formErr = "Max bytes must be a whole number of 0 or more.";
      return null;
    }
    const pct = wholeNumber(warnPct);
    if (pct === null || (pct !== undefined && (pct < 1 || pct > 100))) {
      formErr = "Warning percent must be a whole number from 1 to 100.";
      return null;
    }
    const req: SetKeySafetyRequest = { backend: backend.trim(), key_id: keyId.trim() };
    if (ops !== undefined) req.max_operations = ops;
    if (bytes !== undefined) req.max_bytes = bytes;
    if (pct !== undefined) req.warning_percent = pct;
    return req;
  }

  async function run(action: () => Promise<unknown>, done: string): Promise<void> {
    busy = true;
    try {
      await action();
      showToast("success", done);
      await load();
    } catch (e) {
      actionErr = message(e);
    } finally {
      busy = false;
    }
  }

  async function setLimits(): Promise<void> {
    const req = buildRequest();
    if (!req) return;
    await run(() => setKeySafety(req), `Usage limits set for "${req.key_id}".`);
  }

  async function clearLimits(): Promise<void> {
    if (!target()) return;
    const id = keyId.trim();
    const be = backend.trim();
    if (!window.confirm(`Clear the usage limits of "${id}" on ${be}?`)) return;
    await run(() => clearKeySafety(id, be), `Usage limits cleared for "${id}".`);
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Key Safety" subtitle="Key usage limits and warnings" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  {#if report}
    <div class="card bg-base-100 border border-base-300 mb-4">
      <div class="card-body py-4 flex flex-row flex-wrap gap-6 text-sm">
        <span>Total keys: {report.total_keys}</span>
        <span>Keys at warning: {report.keys_at_warning}</span>
        <span>Keys at critical: {report.keys_at_critical}</span>
        <span>Total DEKs: {report.total_deks}</span>
        <span>DEKs at warning: {report.deks_at_warning}</span>
        <span>DEKs at critical: {report.deks_at_critical}</span>
      </div>
    </div>
  {/if}

  <h2 class="text-lg font-semibold mb-2">Warnings</h2>
  <div class="overflow-x-auto mb-6">
    <table class="table table-sm">
      <caption class="sr-only">Key usage warnings</caption>
      <thead><tr><th scope="col">Path</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Usage</th><th scope="col">Limit</th></tr></thead>
      <tbody>
        {#each warnings as w (w.path)}
          <tr>
            <td>{w.path}</td>
            <td>{w.type}</td>
            <td><StatusBadge label={w.status} kind={statusKind(w.status)} /></td>
            <td>{w.usage_percent.toFixed(1)}%</td>
            <td>{limit(w)}</td>
          </tr>
        {/each}
        {#if warnings.length === 0}
          <tr><td colspan="5" class="text-center text-base-content/60 py-6">No keys near their limits</td></tr>
        {/if}
      </tbody>
    </table>
  </div>

  {#if report}
    <h2 class="text-lg font-semibold mb-2">Usage report</h2>
    <div class="overflow-x-auto mb-6">
      <table class="table table-sm">
        <caption class="sr-only">Key usage report</caption>
        <thead><tr><th scope="col">Path</th><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Usage</th><th scope="col">Limit</th></tr></thead>
        <tbody>
          {#each report.all_items as item (item.path)}
            <tr>
              <td>{item.path}</td>
              <td>{item.type}</td>
              <td><StatusBadge label={item.status} kind={statusKind(item.status)} /></td>
              <td>{item.usage_percent.toFixed(1)}%</td>
              <td>{limit(item)}</td>
            </tr>
          {/each}
          {#if report.all_items.length === 0}
            <tr><td colspan="5" class="text-center text-base-content/60 py-6">No tracked keys.</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<h2 class="text-lg font-semibold mb-2">Usage limits</h2>
{#if actionErr}<Alert kind="error" class="mb-3"><span>{actionErr}</span></Alert>{/if}
<div class="grid gap-3 md:grid-cols-5 mb-2">
  <input class="input input-bordered" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
  <input class="input input-bordered" aria-label="Backend" placeholder="Backend" bind:value={backend} />
  <input class="input input-bordered" aria-label="Max operations" placeholder="Max operations" inputmode="numeric" bind:value={maxOps} />
  <input class="input input-bordered" aria-label="Max bytes" placeholder="Max bytes" inputmode="numeric" bind:value={maxBytes} />
  <input class="input input-bordered" aria-label="Warning percent" placeholder="Warning percent" inputmode="numeric" bind:value={warnPct} />
</div>
{#if formErr}<p class="text-error text-sm mb-2">{formErr}</p>{/if}
<div class="flex gap-2">
  <button class="btn btn-primary btn-sm" onclick={setLimits} disabled={busy}>Set limits</button>
  <button class="btn btn-ghost btn-sm text-error" onclick={clearLimits} disabled={busy}>Clear limits</button>
</div>
