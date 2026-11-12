<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import type { TPMObjectPolicyResponse } from "@go-xkms/sdk";

  type Kind = "key" | "sealed";

  let objectId = $state("");
  let kind = $state<Kind>("key");
  let tenantId = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state<TPMObjectPolicyResponse | null>(null);

  async function lookUp(): Promise<void> {
    busy = true;
    error = null;
    result = null;
    try {
      const tenant = tenantId.trim();
      result = await getSDKClient().tpmPolicies.keyPolicy(objectId.trim(), {
        tenantId: tenant === "" ? undefined : tenant,
        kind,
      });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="TPM Key Policy" subtitle="Which named TPM policy a key or sealed object was created under" />

<form
  class="flex flex-wrap items-end gap-3 mb-4"
  onsubmit={(e) => {
    e.preventDefault();
    void lookUp();
  }}
>
  <label class="form-control">
    <span class="label-text">Object ID</span>
    <input class="input input-bordered input-sm" placeholder="Key or sealed object id" bind:value={objectId} />
  </label>
  <label class="form-control">
    <span class="label-text">Kind</span>
    <select class="select select-bordered select-sm" bind:value={kind}>
      <option value="key">key</option>
      <option value="sealed">sealed</option>
    </select>
  </label>
  <label class="form-control">
    <span class="label-text">Tenant ID</span>
    <input class="input input-bordered input-sm" placeholder="Optional" bind:value={tenantId} />
  </label>
  <button type="submit" class="btn btn-primary btn-sm" disabled={busy || objectId.trim() === ""}>Look up</button>
</form>

{#if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if result}
  <div class="card bg-base-100 border border-base-300">
    <div class="card-body">
      <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2">
        <dt class="font-semibold">Object ID</dt>
        <dd>{result.object_id}</dd>
        <dt class="font-semibold">Kind</dt>
        <dd data-testid="tpm-key-policy-kind">{result.kind}</dd>
        <dt class="font-semibold">Policy</dt>
        <dd>{result.policy}</dd>
        <dt class="font-semibold">Auth policy</dt>
        <dd data-testid="tpm-key-policy-auth">
          {#if result.auth_policy}
            <pre class="font-mono text-xs bg-base-200 rounded p-2 break-all whitespace-pre-wrap">{result.auth_policy}</pre>
          {:else}
            —
          {/if}
        </dd>
        <dt class="font-semibold">Created</dt>
        <dd>{result.created_at}</dd>
      </dl>
    </div>
  </div>
{/if}
