<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64, textToB64 } from "$lib/b64.ts";
  import { RANDOM_MAX, RANDOM_MIN, b64ToHex, generateRandom, hashData } from "$lib/cryptoTools.ts";

  const HASHES = [
    { value: "", label: "Server default" },
    { value: "sha256", label: "SHA-256" },
    { value: "sha384", label: "SHA-384" },
    { value: "sha512", label: "SHA-512" },
  ];

  let length = $state<number | null>(32);
  let randBusy = $state(false);
  let randErr = $state<string | null>(null);
  let randInvalid = $state<string | null>(null);
  let randB64 = $state<string | null>(null);

  let data = $state("");
  let dataIsB64 = $state(false);
  let algo = $state("");
  let hashBusy = $state(false);
  let hashErr = $state<string | null>(null);
  let hashInvalid = $state<string | null>(null);
  let digest = $state<{ b64: string; hash: string } | null>(null);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function copy(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      showToast("success", "Copied.");
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function generate(): Promise<void> {
    randErr = null;
    const n = Number(length);
    if (length === null || !Number.isInteger(n) || n < RANDOM_MIN || n > RANDOM_MAX) {
      randInvalid = `Length must be a whole number from ${RANDOM_MIN} to ${RANDOM_MAX}.`;
      return;
    }
    randInvalid = null;
    randBusy = true;
    try {
      randB64 = (await generateRandom(n)).random;
    } catch (e) {
      randErr = message(e);
    } finally {
      randBusy = false;
    }
  }

  async function hash(): Promise<void> {
    hashErr = null;
    if (dataIsB64 && !isB64(data)) {
      hashInvalid = "Data is not valid base64.";
      return;
    }
    hashInvalid = null;
    hashBusy = true;
    try {
      const res = await hashData(dataIsB64 ? data.trim() : textToB64(data), algo || undefined);
      digest = { b64: res.digest, hash: res.hash };
    } catch (e) {
      hashErr = message(e);
    } finally {
      hashBusy = false;
    }
  }
</script>

<PageHeader title="Random & Hash" subtitle="Random bytes from the server's backend and server-side digests" />

<div class="grid gap-4 lg:grid-cols-2">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title">Random</h2>
      {#if randErr}<Alert kind="error"><span>{randErr}</span></Alert>{/if}
      <label class="form-control">
        <span class="label-text">Length (bytes)</span>
        <input class="input input-bordered" type="number" min={RANDOM_MIN} max={RANDOM_MAX} step="1" bind:value={length} />
      </label>
      {#if randInvalid}<p class="text-error text-sm">{randInvalid}</p>{/if}
      <div>
        <button class="btn btn-primary btn-sm" onclick={generate} disabled={randBusy}>
          {#if randBusy}<span class="loading loading-spinner loading-xs"></span>{/if}Generate
        </button>
      </div>
      {#if randB64 !== null}
        {@render result(randB64)}
      {/if}
    </div>
  </section>

  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title">Hash</h2>
      {#if hashErr}<Alert kind="error"><span>{hashErr}</span></Alert>{/if}
      <label class="form-control">
        <span class="label-text">Data</span>
        <textarea class="textarea textarea-bordered font-mono" rows="4" bind:value={data}></textarea>
      </label>
      <label class="label cursor-pointer justify-start gap-2">
        <input type="checkbox" class="checkbox checkbox-sm" bind:checked={dataIsB64} />
        <span class="label-text">Input is base64</span>
      </label>
      {#if hashInvalid}<p class="text-error text-sm">{hashInvalid}</p>{/if}
      <label class="form-control">
        <span class="label-text">Algorithm</span>
        <select class="select select-bordered" bind:value={algo}>
          {#each HASHES as h (h.value)}<option value={h.value}>{h.label}</option>{/each}
        </select>
      </label>
      <div>
        <button class="btn btn-primary btn-sm" onclick={hash} disabled={hashBusy}>
          {#if hashBusy}<span class="loading loading-spinner loading-xs"></span>{/if}Hash
        </button>
      </div>
      {#if digest !== null}
        <p class="text-sm">Algorithm: <span class="font-mono">{digest.hash}</span></p>
        {@render result(digest.b64)}
      {/if}
    </div>
  </section>
</div>

{#snippet result(b64: string)}
  <dl class="text-sm space-y-2">
    <div>
      <dt class="font-semibold">Hex</dt>
      <dd class="flex items-start gap-2">
        <code class="break-all">{b64ToHex(b64)}</code>
        <button class="btn btn-ghost btn-xs" aria-label="Copy hex" onclick={() => copy(b64ToHex(b64))}>Copy</button>
      </dd>
    </div>
    <div>
      <dt class="font-semibold">Base64</dt>
      <dd class="flex items-start gap-2">
        <code class="break-all">{b64}</code>
        <button class="btn btn-ghost btn-xs" aria-label="Copy base64" onclick={() => copy(b64)}>Copy</button>
      </dd>
    </div>
  </dl>
{/snippet}
