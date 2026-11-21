<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { getBootstrapKeys, isListenerDisabled, type BootstrapListenerKeysResponse } from "$lib/bootstrapKeys.ts";

  let keys = $state<BootstrapListenerKeysResponse | null>(null);
  let error = $state<string | null>(null);
  let disabled = $state(false);
  let loading = $state(true);

  const cards = $derived([
    { label: "Noise_NK (X25519)", value: keys?.noise_public_key, setting: "Client setting: --noise-key or trust.bootstrap.noise.server_key" },
    { label: "P-256 (FIPS suite)", value: keys?.p256_public_key, setting: "Client setting: --p256-key (suite TSBOOT1_P256_AESGCM_SHA256)" },
  ]);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    disabled = false;
    try {
      keys = await getBootstrapKeys();
    } catch (e) {
      keys = null;
      if (isListenerDisabled(e)) disabled = true;
      else error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function copy(label: string, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      showToast("success", `${label} key copied.`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Bootstrap Keys" subtitle="Trust-bootstrap listener public keys for first-contact clients">
  {#snippet actions()}
    <button class="btn btn-ghost btn-sm" onclick={load} disabled={loading}>Refresh</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if disabled}
  <Alert kind="info"><span>The trust-bootstrap listener is not enabled on this server.</span></Alert>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if keys}
  <div class="grid gap-4">
    {#each cards as card (card.label)}
      <div class="card bg-base-100 border border-base-300">
        <div class="card-body p-4 gap-2">
          <h2 class="card-title text-base">{card.label}</h2>
          {#if card.value}
            <div class="flex items-start gap-2">
              <code class="font-mono text-sm break-all bg-base-200 rounded p-2 flex-1">{card.value}</code>
              <button class="btn btn-ghost btn-xs" aria-label={`Copy ${card.label}`} onclick={() => copy(card.label, card.value!)}>Copy</button>
            </div>
          {:else}
            <span class="text-base-content/60">not configured</span>
          {/if}
          <p class="text-sm text-base-content/70">{card.setting}</p>
        </div>
      </div>
    {/each}
  </div>
{/if}
