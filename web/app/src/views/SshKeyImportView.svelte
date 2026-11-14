<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SSHImportKeyRequest, SSHKey, SSHPublicKey } from "@go-xkms/sdk";

  // Import form. The PEM and passphrase live only here and are cleared
  // after every attempt; they never reach a toast, an error or the console.
  let scope = $state("");
  let owner = $state("");
  let name = $state("");
  let comment = $state("");
  let pem = $state("");
  let passphrase = $state("");
  let busy = $state(false);
  let importErr = $state<string | null>(null);
  let result = $state<SSHKey | null>(null);

  // Public-line lookup.
  let lScope = $state("");
  let lOwner = $state("");
  let lName = $state("");
  let looking = $state(false);
  let lookupErr = $state<string | null>(null);
  let pub = $state<SSHPublicKey | null>(null);

  const canImport = $derived(!busy && scope !== "" && owner !== "" && name !== "" && pem !== "");
  const canLookup = $derived(!looking && lScope !== "" && lOwner !== "" && lName !== "");

  function toB64(s: string): string {
    let bin = "";
    for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function doImport(): Promise<void> {
    busy = true;
    importErr = null;
    result = null;
    const req: SSHImportKeyRequest = { scope, owner, name, pem: toB64(pem) };
    if (comment !== "") req.comment = comment;
    if (passphrase !== "") req.passphrase_b64 = toB64(passphrase);
    pem = "";
    passphrase = "";
    try {
      result = await getSDKClient().ssh.importKey(req);
      showToast("success", `SSH key "${name}" imported.`);
    } catch (e) {
      importErr = message(e);
    } finally {
      busy = false;
    }
  }

  async function showPublic(): Promise<void> {
    looking = true;
    lookupErr = null;
    pub = null;
    try {
      pub = await getSDKClient().ssh.exportPublic(lScope, lOwner, lName);
    } catch (e) {
      lookupErr = message(e);
    } finally {
      looking = false;
    }
  }
</script>

<PageHeader title="SSH Key Import" subtitle="Bring an existing SSH private key under custody and print a key's authorized_keys line" />

<section class="card bg-base-100 shadow-sm mb-6">
  <div class="card-body space-y-3">
    <h2 class="card-title text-base">Import a private key</h2>
    {#if importErr}<Alert kind="error"><span>{importErr}</span></Alert>{/if}
    <div class="grid gap-3 md:grid-cols-3">
      <input class="input input-bordered w-full" aria-label="Scope" placeholder="Scope" bind:value={scope} />
      <input class="input input-bordered w-full" aria-label="Owner" placeholder="Owner" bind:value={owner} />
      <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={name} />
    </div>
    <input class="input input-bordered w-full" aria-label="Comment" placeholder="Comment (optional)" bind:value={comment} />
    <textarea class="textarea textarea-bordered w-full font-mono" aria-label="Private key (PEM)" placeholder="Paste the PEM private key" rows="6" autocomplete="off" spellcheck="false" bind:value={pem}></textarea>
    <input class="input input-bordered w-full" type="password" aria-label="Passphrase" placeholder="Passphrase (optional)" autocomplete="off" bind:value={passphrase} />
    <div>
      <button class="btn btn-primary" onclick={doImport} disabled={!canImport}>
        {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}Import
      </button>
    </div>
    {#if result}
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="font-semibold">Algorithm</dt><dd>{result.algorithm}</dd>
        <dt class="font-semibold">Fingerprint</dt><dd class="font-mono break-all">{result.fingerprint}</dd>
      </dl>
    {/if}
  </div>
</section>

<section class="card bg-base-100 shadow-sm">
  <div class="card-body space-y-3">
    <h2 class="card-title text-base">Public key</h2>
    {#if lookupErr}<Alert kind="error"><span>{lookupErr}</span></Alert>{/if}
    <div class="grid gap-3 md:grid-cols-3">
      <input class="input input-bordered w-full" aria-label="Lookup scope" placeholder="Scope" bind:value={lScope} />
      <input class="input input-bordered w-full" aria-label="Lookup owner" placeholder="Owner" bind:value={lOwner} />
      <input class="input input-bordered w-full" aria-label="Lookup name" placeholder="Name" bind:value={lName} />
    </div>
    <div>
      <button class="btn btn-outline" onclick={showPublic} disabled={!canLookup}>
        {#if looking}<span class="loading loading-spinner loading-sm"></span>{/if}Show public key
      </button>
    </div>
    {#if pub}
      <p class="text-sm">authorized_keys line ({pub.algorithm}, <span class="font-mono">{pub.fingerprint}</span>):</p>
      <pre class="bg-base-200 rounded p-3 font-mono text-sm whitespace-pre-wrap break-all">{pub.line}</pre>
    {/if}
  </div>
</section>
