<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { textToB64 } from "$lib/b64.ts";
  import type { CredentialStrategyResponse } from "@go-xkms/sdk";

  let info = $state<CredentialStrategyResponse | null>(null);
  let unavailable = $state(false);
  let loading = $state(true);
  let busy = $state(false);

  let name = $state("");
  // The secret lives only in the bound input: it is cleared after every
  // attempt and never interpolated into text, a toast or an alert.
  let secret = $state("");
  let submitErr = $state<string | null>(null);

  async function load(): Promise<void> {
    loading = true;
    try {
      info = await getSDKClient().credentials.strategy();
    } catch {
      // No capability flag exists: the routes are absent when the server
      // does not wait for a boot credential, so the call rejects.
      unavailable = true;
    } finally {
      loading = false;
    }
  }

  async function submit(): Promise<void> {
    busy = true;
    submitErr = null;
    const value = textToB64(secret);
    secret = "";
    try {
      const res = await getSDKClient().credentials.submit({ name, value });
      showToast("success", `Boot credential ${name}: ${res.status}`);
    } catch (e) {
      submitErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Boot Credentials" subtitle="Credential the server waits for at boot" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if unavailable}
  <Alert kind="info"><span>Boot credentials are not available on this server</span></Alert>
{:else if info}
  <div class="card bg-base-100 border border-base-300 mb-4">
    <div class="card-body">
      <h2 class="card-title text-base">Strategy</h2>
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono">{info.strategy}</span>
        <StatusBadge label={info.auto_unseal ? "auto-unseal on" : "auto-unseal off"} ok={info.auto_unseal} />
      </div>
    </div>
  </div>

  <form
    class="card bg-base-100 border border-base-300"
    onsubmit={(e) => {
      e.preventDefault();
      void submit();
    }}
  >
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Submit a boot credential</h2>
      {#if submitErr}<Alert kind="error"><span>{submitErr}</span></Alert>{/if}
      <input class="input input-bordered w-full" aria-label="Credential name" placeholder="Credential name" bind:value={name} />
      <input
        class="input input-bordered w-full"
        type="password"
        autocomplete="off"
        aria-label="Secret"
        placeholder="Secret"
        bind:value={secret}
      />
      <div class="card-actions justify-end">
        <button class="btn btn-primary" type="submit" disabled={busy || name === "" || secret === ""}>Submit</button>
      </div>
    </div>
  </form>
{/if}
