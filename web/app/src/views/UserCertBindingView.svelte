<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { UserCredentialItem } from "@go-xkms/sdk";

  let username = $state("");
  let creds = $state<UserCredentialItem[] | null>(null);
  let loadedFor = $state("");
  let loading = $state(false);
  let error = $state<string | null>(null);

  let thumbprint = $state("");
  let notAfter = $state("");
  let busy = $state(false);
  let thumbErr = $state<string | null>(null);

  const user = $derived(username.trim());

  function errMsg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function load(name: string = user): Promise<void> {
    loading = true;
    error = null;
    try {
      const res = await getSDKClient().users.credentials(name);
      creds = res.credentials;
      loadedFor = name;
    } catch (e) {
      creds = null;
      error = errMsg(e);
    } finally {
      loading = false;
    }
  }

  async function bind(): Promise<void> {
    thumbErr = null;
    const tp = thumbprint.trim().replace(/[:\s]/g, "");
    if (!/^[0-9a-fA-F]+$/.test(tp)) {
      thumbErr = "Thumbprint must be hexadecimal.";
      return;
    }
    const notAfterUnix = Math.floor(Date.parse(notAfter) / 1000);
    if (!Number.isFinite(notAfterUnix)) {
      thumbErr = "Not after must be a valid date.";
      return;
    }
    const name = user;
    busy = true;
    error = null;
    try {
      const res = await getSDKClient().users.bindCert(name, { thumbprint: tp, not_after_unix: notAfterUnix });
      showToast("success", `Certificate for "${name}": ${res.status}.`);
      thumbprint = "";
      notAfter = "";
      await load(name);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="Certificate Binding" subtitle="Bind a client certificate thumbprint to a user for certificate login" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered" aria-label="Username" placeholder="Username" bind:value={username} />
  <button class="btn btn-primary btn-sm" onclick={() => load()} disabled={loading || user === ""}>Load</button>
</div>

{#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}

{#if loading}
  <div class="flex justify-center py-6"><span class="loading loading-spinner loading-lg"></span></div>
{:else if creds}
  <div class="overflow-x-auto mb-6">
    <table class="table table-sm">
      <caption class="sr-only">Credentials of {loadedFor}</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">ID</th></tr></thead>
      <tbody>
        {#each creds as c (c.id)}
          <tr><td>{c.name}</td><td class="font-mono text-xs">{c.id}</td></tr>
        {/each}
        {#if creds.length === 0}
          <tr><td colspan="2" class="text-center text-base-content/60 py-6">No credentials</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

<section class="space-y-3 max-w-xl">
  <h2 class="text-lg font-semibold">Bind certificate</h2>
  {#if thumbErr}<Alert kind="error"><span>{thumbErr}</span></Alert>{/if}
  <input class="input input-bordered w-full font-mono" aria-label="Thumbprint" placeholder="Thumbprint (hex)" bind:value={thumbprint} />
  <input class="input input-bordered w-full" type="date" aria-label="Not after" bind:value={notAfter} />
  <button class="btn btn-primary" onclick={bind} disabled={busy || user === "" || thumbprint.trim() === "" || notAfter === ""}>
    {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
    Bind
  </button>
</section>
