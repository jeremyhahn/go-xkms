<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import type { AlgorithmInfo, AlgorithmsResponse, HealthCheckResponse } from "@go-xkms/sdk";

  type ProbeKey = "live" | "ready" | "startup";
  type ProbeState = { resp: HealthCheckResponse | null; error: string | null };

  const probes: Array<{ key: ProbeKey; title: string }> = [
    { key: "live", title: "Liveness" },
    { key: "ready", title: "Readiness" },
    { key: "startup", title: "Startup" },
  ];

  // Statuses the server reports for a passing probe or check.
  const OK_STATUSES = new Set(["ok", "up", "pass", "healthy", "alive", "ready", "started"]);

  let results = $state<Record<ProbeKey, ProbeState> | null>(null);
  let algs = $state<AlgorithmsResponse | null>(null);
  let algError = $state<string | null>(null);
  let loading = $state(true);

  // A probe that is not ready rejects with an XkmsApiError (503), and a test or
  // a proxy may reject with a plain {status, message} object: take its message.
  function messageOf(e: unknown): string {
    if (e instanceof Error) return e.message;
    if (typeof e === "object" && e !== null && "message" in e) return String((e as { message: unknown }).message);
    return String(e);
  }

  function isOk(status: string): boolean {
    return OK_STATUSES.has(status.toLowerCase());
  }

  function params(a: AlgorithmInfo): string {
    if (a.curves && a.curves.length > 0) return a.curves.join(", ");
    if (a.key_sizes && a.key_sizes.length > 0) return a.key_sizes.join(", ");
    return "";
  }

  async function load(): Promise<void> {
    loading = true;
    const health = getSDKClient().health;
    // allSettled: one failed probe must not hide the others or the algorithms.
    const [l, r, s, a] = await Promise.allSettled([health.live(), health.ready(), health.startup(), health.algorithms()]);
    const settle = (p: PromiseSettledResult<HealthCheckResponse>): ProbeState =>
      p.status === "fulfilled" ? { resp: p.value, error: null } : { resp: null, error: messageOf(p.reason) };
    results = { live: settle(l), ready: settle(r), startup: settle(s) };
    if (a.status === "fulfilled") {
      algs = a.value;
      algError = null;
    } else {
      algs = null;
      algError = messageOf(a.reason);
    }
    loading = false;
  }

  // Mount-time load: the view has no reactive inputs.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="System Health" subtitle="Server probes and supported algorithms">
  {#snippet actions()}
    <button class="btn btn-sm" onclick={() => void load()} disabled={loading}>Refresh</button>
  {/snippet}
</PageHeader>

{#if results === null}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <div class="grid gap-4 md:grid-cols-3 mb-6">
    {#each probes as probe (probe.key)}
      {@const st = results[probe.key]}
      <section class="card bg-base-100 shadow-sm" aria-labelledby={`probe-${probe.key}`}>
        <div class="card-body p-4">
          <div class="flex items-center justify-between">
            <h2 id={`probe-${probe.key}`} class="card-title text-base">{probe.title}</h2>
            {#if st.resp}
              <StatusBadge label={st.resp.status} ok={isOk(st.resp.status)} />
            {:else}
              <StatusBadge label="down" ok={false} />
            {/if}
          </div>
          {#if st.error}
            <p class="text-sm text-error">{st.error}</p>
          {:else if st.resp}
            {#if st.resp.message}<p class="text-sm text-base-content/70">{st.resp.message}</p>{/if}
            {#if st.resp.checks && st.resp.checks.length > 0}
              <table class="table table-xs">
                <caption class="sr-only">{probe.title} checks</caption>
                <thead><tr><th scope="col">Check</th><th scope="col">Status</th><th scope="col">Message</th></tr></thead>
                <tbody>
                  {#each st.resp.checks as check (check.name)}
                    <tr>
                      <td>{check.name}</td>
                      <td><StatusBadge label={check.status} ok={isOk(check.status)} /></td>
                      <td>{check.message ?? ""}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <p class="text-sm text-base-content/60">No checks reported.</p>
            {/if}
          {/if}
        </div>
      </section>
    {/each}
  </div>

  <section aria-labelledby="algorithms-heading">
    <h2 id="algorithms-heading" class="text-lg font-semibold mb-2">Algorithms</h2>
    {#if algError}
      <Alert kind="error"><span>{algError}</span></Alert>
    {:else if algs}
      {#each [{ title: "Signing", list: algs.signing, empty: "No signing algorithms." }, { title: "Key encapsulation", list: algs.key_encapsulation, empty: "No key encapsulation algorithms." }] as group (group.title)}
        <h3 class="font-medium mt-4 mb-1">{group.title}</h3>
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <caption class="sr-only">{group.title} algorithms</caption>
            <thead>
              <tr><th scope="col">Algorithm</th><th scope="col">Curves / key sizes</th><th scope="col">Backends</th><th scope="col"><span class="sr-only">Post-quantum</span></th></tr>
            </thead>
            <tbody>
              {#each group.list as a (a.algorithm)}
                <tr>
                  <td>{a.algorithm}</td>
                  <td>{params(a)}</td>
                  <td>{a.backends.join(", ")}</td>
                  <td>{#if a.post_quantum}<StatusBadge label="post-quantum" kind="neutral" />{/if}</td>
                </tr>
              {/each}
              {#if group.list.length === 0}
                <tr><td colspan="4" class="text-center text-base-content/60 py-6">{group.empty}</td></tr>
              {/if}
            </tbody>
          </table>
        </div>
      {/each}
    {/if}
  </section>
{/if}
