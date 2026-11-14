<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { keyId, signDigest, signLabel, signWithKey } from "$lib/sshSign.ts";
  import type { SSHKey, SSHSignResponse } from "@go-xkms/sdk";

  let keys = $state<SSHKey[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let busy = $state(false);

  let selected = $state("");
  let message = $state("");
  let isBase64 = $state(false);
  let result = $state<SSHSignResponse | null>(null);

  const key = $derived(keys.find((k) => keyId(k) === selected) ?? null);
  const digest = $derived(signDigest(message, isBase64));
  const canSign = $derived(key !== null && digest !== null && !busy);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      keys = (await getSDKClient().ssh.listKeys()).items;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function doSign(): Promise<void> {
    if (key === null || digest === null) return;
    busy = true;
    error = null;
    result = null;
    try {
      result = await signWithKey(key, digest);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(label: string, value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      showToast("success", `${label} copied.`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="SSH Sign" subtitle="Sign a message with a stored SSH key; the private key stays on the server" />

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <div class="card bg-base-100 shadow mb-4">
    <div class="card-body space-y-3">
      <select id="ssh-sign-key" class="select select-bordered w-full" aria-label="Key" bind:value={selected}>
          <option value="">Choose a key</option>
          {#each keys as k (keyId(k))}
            <option value={keyId(k)}>{signLabel(k)}</option>
          {/each}
        </select>
      <textarea class="textarea textarea-bordered w-full font-mono" aria-label="Message" placeholder="Message" rows="4" bind:value={message}></textarea>
      <label class="label cursor-pointer justify-start gap-2">
        <input type="checkbox" class="checkbox checkbox-sm" bind:checked={isBase64} />
        <span class="label-text">Message is base64</span>
      </label>
      <div class="card-actions justify-end">
        <button class="btn btn-primary" onclick={doSign} disabled={!canSign}>
          {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
          Sign
        </button>
      </div>
    </div>
  </div>

  {#if result}
    <div class="card bg-base-100 shadow">
      <div class="card-body space-y-2">
        <h2 class="card-title">Result</h2>
        <div class="flex items-center gap-2">
          <span class="font-semibold w-16">Format</span>
          <code class="font-mono break-all flex-1" data-testid="sign-format">{result.format}</code>
          <button class="btn btn-ghost btn-xs" aria-label="Copy format" onclick={() => copy("Format", result!.format)}>Copy</button>
        </div>
        <div class="flex items-center gap-2">
          <span class="font-semibold w-16">Blob</span>
          <code class="font-mono break-all flex-1">{result.blob}</code>
          <button class="btn btn-ghost btn-xs" aria-label="Copy blob" onclick={() => copy("Blob", result!.blob)}>Copy</button>
        </div>
        {#if result.rest}
          <div class="flex items-center gap-2">
            <span class="font-semibold w-16">Rest</span>
            <code class="font-mono break-all flex-1">{result.rest}</code>
            <button class="btn btn-ghost btn-xs" aria-label="Copy rest" onclick={() => copy("Rest", result!.rest ?? "")}>Copy</button>
          </div>
        {/if}
      </div>
    </div>
  {/if}
{/if}
