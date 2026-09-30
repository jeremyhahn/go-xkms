<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import IndexPicker from "$components/IndexPicker.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    BANKS,
    LOCALITIES,
    PCR_INDICES,
    describeBranch,
    draftError,
    draftToBranch,
    newBranchDraft,
    toggleIndex,
    type BranchDraft,
  } from "$lib/tpmPolicy.ts";
  import { pcrBranch, type TPMPolicy, type TPMPolicyVerifyResponse } from "@go-xkms/sdk";

  let policies = $state<TPMPolicy[]>([]);
  let objectCounts = $state<Record<string, number>>({});
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);

  // The create dialog: simple mode builds one pcr branch from cBank and
  // cPCRs; advanced mode sends every draft in cBranches as a branch.
  let showCreate = $state(false);
  let cName = $state("");
  let cDescription = $state("");
  let cAdvanced = $state(false);
  let cBank = $state("sha256");
  let cPCRs = $state<number[]>([0, 7]);
  let cBranches = $state<BranchDraft[]>([newBranchDraft()]);
  let cAutoUnseal = $state(false);
  let cErr = $state<string | null>(null);

  const cInvalid = $derived(
    cName === "" ||
      (cAdvanced ? cBranches.length === 0 || cBranches.some((b) => draftError(b) !== null) : cPCRs.length === 0),
  );

  let verifyResult = $state<TPMPolicyVerifyResponse | null>(null);

  let describeName = $state<string | null>(null);
  let describeText = $state("");
  let describeBusy = $state(false);
  let describeErr = $state<string | null>(null);

  let showObjects = $state(false);
  let objectsName = $state("");
  let objectsList = $state<string[]>([]);
  let objectsLoading = $state(false);
  let objectsErr = $state<string | null>(null);

  let showRotateConfirm = $state(false);
  let rotateBusy = $state(false);

  /** load fetches the policy list, then each policy's bound-object count. */
  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().tpmPolicies.list();
      policies = resp.policies;
      const counts: Record<string, number> = {};
      await Promise.all(
        policies.map(async (p) => {
          try {
            const objs = await getSDKClient().tpmPolicies.objects(p.name);
            counts[p.name] = objs.objects.length;
          } catch {
            // Object counting is advisory; a failed lookup leaves it unknown
            // rather than blocking the whole list from rendering.
            counts[p.name] = 0;
          }
        }),
      );
      objectCounts = counts;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  function resetCreate(): void {
    cName = "";
    cDescription = "";
    cAdvanced = false;
    cBank = "sha256";
    cPCRs = [0, 7];
    cBranches = [newBranchDraft()];
    cAutoUnseal = false;
  }

  /** updateBranch replaces the draft at index i with change applied. */
  function updateBranch(i: number, change: Partial<BranchDraft>): void {
    cBranches = cBranches.map((b, j) => (j === i ? { ...b, ...change } : b));
  }

  async function create(): Promise<void> {
    busy = true;
    cErr = null;
    try {
      await getSDKClient().tpmPolicies.create({
        name: cName,
        description: cDescription,
        branches: cAdvanced ? cBranches.map(draftToBranch) : [pcrBranch(cBank, cPCRs)],
        auto_unseal: cAutoUnseal,
      });
      showToast("success", `TPM policy "${cName}" created.`);
      showCreate = false;
      resetCreate();
      await load();
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function openDescribe(p: TPMPolicy): void {
    describeName = p.name;
    describeText = p.description ?? "";
    describeErr = null;
  }

  async function saveDescription(): Promise<void> {
    if (describeName === null) return;
    describeBusy = true;
    describeErr = null;
    try {
      await getSDKClient().tpmPolicies.setDescription(describeName, describeText);
      showToast("success", `Description of "${describeName}" saved.`);
      describeName = null;
      await load();
    } catch (e) {
      describeErr = e instanceof Error ? e.message : String(e);
    } finally {
      describeBusy = false;
    }
  }

  async function verify(name: string): Promise<void> {
    try {
      verifyResult = await getSDKClient().tpmPolicies.verify(name);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function update(name: string): Promise<void> {
    try {
      await getSDKClient().tpmPolicies.update(name);
      showToast("success", `TPM policy "${name}" re-captured and re-approved.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function revoke(name: string): Promise<void> {
    try {
      await getSDKClient().tpmPolicies.revoke(name);
      showToast("success", `TPM policy "${name}" revoked.`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function toggleAutoUnseal(p: TPMPolicy): Promise<void> {
    try {
      await getSDKClient().tpmPolicies.setAutoUnseal(p.name, !p.auto_unseal);
      showToast("success", `Auto-unseal ${p.auto_unseal ? "disabled" : "enabled"} for "${p.name}".`);
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function openObjects(name: string): Promise<void> {
    showObjects = true;
    objectsName = name;
    objectsLoading = true;
    objectsErr = null;
    objectsList = [];
    try {
      const resp = await getSDKClient().tpmPolicies.objects(name);
      objectsList = resp.objects;
    } catch (e) {
      objectsErr = e instanceof Error ? e.message : String(e);
    } finally {
      objectsLoading = false;
    }
  }

  async function del(name: string): Promise<void> {
    try {
      await getSDKClient().tpmPolicies.delete(name);
      showToast("success", `TPM policy "${name}" deleted.`);
      await load();
    } catch (e) {
      // A policy still assigned to objects is refused with 409; the
      // server's message lists them, so surfacing it verbatim tells the
      // operator exactly what to unassign first.
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function confirmRotate(): Promise<void> {
    rotateBusy = true;
    try {
      const resp = await getSDKClient().tpmPolicies.rotateAuthority();
      showToast(
        "success",
        `Policy authority rotated to generation ${resp.generation} (${resp.authority_name}).`,
      );
      showRotateConfirm = false;
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      rotateBusy = false;
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="TPM Policies" subtitle="Named policies of PCR, password and locality conditions bound to keys and sealed objects">
  {#snippet actions()}
    <button class="btn btn-sm" onclick={() => (showRotateConfirm = true)}>Rotate authority</button>
    <button class="btn btn-primary btn-sm" onclick={() => (showCreate = true)}>+ Create</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">TPM policies</caption>
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Description</th>
          <th scope="col">Branches</th>
          <th scope="col">Status</th>
          <th scope="col">Auto-unseal</th>
          <th scope="col">Objects</th>
          <th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each policies as p (p.name)}
          <tr>
            <td>{p.name}</td>
            <td>
              <span class="text-sm">{p.description ?? ""}</span>
              <button
                class="btn btn-ghost btn-xs"
                aria-label={`Edit description of ${p.name}`}
                onclick={() => openDescribe(p)}
              >
                Edit
              </button>
            </td>
            <td class="text-sm">
              {#each p.branches as b, i (i)}
                <div>{#if i > 0}<span class="text-base-content/60">or </span>{/if}{describeBranch(b)}</div>
              {/each}
            </td>
            <td><StatusBadge label={p.approved ? "approved" : "revoked"} ok={p.approved} /></td>
            <td>
              <button
                class="btn btn-ghost btn-xs"
                aria-label={`Toggle auto-unseal for ${p.name}`}
                onclick={() => toggleAutoUnseal(p)}
              >
                {p.auto_unseal ? "On" : "Off"}
              </button>
            </td>
            <td>
              <button
                class="btn btn-ghost btn-xs"
                aria-label={`Objects bound to ${p.name}`}
                onclick={() => openObjects(p.name)}
              >
                {objectCounts[p.name] ?? 0}
              </button>
            </td>
            <td class="text-right whitespace-nowrap">
              <button class="btn btn-ghost btn-xs" onclick={() => verify(p.name)}>Verify</button>
              <button class="btn btn-ghost btn-xs" onclick={() => update(p.name)}>Update</button>
              <button class="btn btn-ghost btn-xs" onclick={() => revoke(p.name)}>Revoke</button>
              <button class="btn btn-ghost btn-xs text-error" onclick={() => del(p.name)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if policies.length === 0}
          <tr><td colspan="7" class="text-center text-base-content/60 py-6">No TPM policies.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} onClose={() => (showCreate = false)} labelledby="create-tpm-policy-title">
      <h3 id="create-tpm-policy-title" class="text-lg font-semibold mb-4">Create TPM policy</h3>
      {#if cErr}<Alert kind="error" class="mb-3"><span>{cErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={cName} />
        <input
          class="input input-bordered w-full"
          aria-label="Description"
          placeholder="Description"
          bind:value={cDescription}
        />
        <div role="tablist" class="tabs tabs-boxed">
          <button role="tab" class="tab" class:tab-active={!cAdvanced} aria-selected={!cAdvanced} onclick={() => (cAdvanced = false)}>
            Simple
          </button>
          <button role="tab" class="tab" class:tab-active={cAdvanced} aria-selected={cAdvanced} onclick={() => (cAdvanced = true)}>
            Advanced
          </button>
        </div>
        {#if !cAdvanced}
          <p class="text-sm text-base-content/70">Approves the live values of the selected PCRs.</p>
          <select class="select select-bordered w-full" aria-label="Bank" bind:value={cBank}>
            {#each BANKS as b (b)}<option value={b}>{b}</option>{/each}
          </select>
          <IndexPicker legend="PCRs" label="PCR" indices={PCR_INDICES} selected={cPCRs} onToggle={(i) => (cPCRs = toggleIndex(cPCRs, i))} />
        {:else}
          <p class="text-sm text-base-content/70">
            An object is usable when any branch holds; a branch holds when all of its conditions do.
          </p>
          {#each cBranches as b, i (i)}
            <fieldset class="border border-base-300 rounded p-3 space-y-2">
              <legend class="font-semibold text-sm px-1">Branch {i + 1}</legend>
              <label class="label cursor-pointer justify-start gap-2">
                <input
                  type="checkbox"
                  class="checkbox checkbox-sm"
                  aria-label={`Branch ${i + 1} PCR condition`}
                  checked={b.pcr}
                  onchange={() => updateBranch(i, { pcr: !b.pcr })}
                />
                <span class="label-text">PCR values</span>
              </label>
              {#if b.pcr}
                <select
                  class="select select-bordered select-sm w-full"
                  aria-label={`Branch ${i + 1} bank`}
                  value={b.bank}
                  onchange={(e) => updateBranch(i, { bank: e.currentTarget.value })}
                >
                  {#each BANKS as bank (bank)}<option value={bank}>{bank}</option>{/each}
                </select>
                <IndexPicker
                  legend="PCRs"
                  label={`Branch ${i + 1} PCR`}
                  indices={PCR_INDICES}
                  selected={b.pcrs}
                  onToggle={(pcr) => updateBranch(i, { pcrs: toggleIndex(b.pcrs, pcr) })}
                />
              {/if}
              <label class="label cursor-pointer justify-start gap-2">
                <input
                  type="checkbox"
                  class="checkbox checkbox-sm"
                  aria-label={`Branch ${i + 1} password condition`}
                  checked={b.authValue}
                  onchange={() => updateBranch(i, { authValue: !b.authValue })}
                />
                <span class="label-text">Object password</span>
              </label>
              <label class="label cursor-pointer justify-start gap-2">
                <input
                  type="checkbox"
                  class="checkbox checkbox-sm"
                  aria-label={`Branch ${i + 1} locality condition`}
                  checked={b.locality}
                  onchange={() => updateBranch(i, { locality: !b.locality })}
                />
                <span class="label-text">TPM locality</span>
              </label>
              {#if b.locality}
                <IndexPicker
                  legend="Localities"
                  label={`Branch ${i + 1} locality`}
                  indices={LOCALITIES}
                  selected={b.localities}
                  columns={5}
                  onToggle={(l) => updateBranch(i, { localities: toggleIndex(b.localities, l) })}
                />
              {/if}
              {#if draftError(b)}<p class="text-xs text-error">{draftError(b)}</p>{/if}
              {#if cBranches.length > 1}
                <button
                  class="btn btn-ghost btn-xs text-error"
                  aria-label={`Remove branch ${i + 1}`}
                  onclick={() => (cBranches = cBranches.filter((_, j) => j !== i))}
                >
                  Remove branch
                </button>
              {/if}
            </fieldset>
          {/each}
          <button class="btn btn-sm" onclick={() => (cBranches = [...cBranches, newBranchDraft()])}>+ Add branch</button>
        {/if}
        <label class="label cursor-pointer justify-start gap-2">
          <input type="checkbox" class="checkbox" bind:checked={cAutoUnseal} />
          <span class="label-text">Auto-unseal</span>
        </label>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showCreate = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={create} disabled={busy || cInvalid}>
          {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
          Create
        </button>
      </div>
  </Modal>
{/if}

{#if describeName !== null}
  <Modal open={describeName !== null} onClose={() => (describeName = null)} labelledby="describe-policy-title">
      <h3 id="describe-policy-title" class="text-lg font-semibold mb-4">Description of "{describeName}"</h3>
      {#if describeErr}<Alert kind="error" class="mb-3"><span>{describeErr}</span></Alert>{/if}
      <textarea
        class="textarea textarea-bordered w-full"
        aria-label="Policy description"
        rows="3"
        bind:value={describeText}
      ></textarea>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (describeName = null)} disabled={describeBusy}>Cancel</button>
        <button class="btn btn-primary" onclick={saveDescription} disabled={describeBusy}>
          {#if describeBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
          Save
        </button>
      </div>
  </Modal>
{/if}

{#if verifyResult}
  <Modal open={verifyResult !== null} onClose={() => (verifyResult = null)} labelledby="verify-result-title">
      <h3 id="verify-result-title" class="text-lg font-semibold mb-4">Verify "{verifyResult.name}"</h3>
      <div class="space-y-2">
        <StatusBadge label={verifyResult.match ? "PCRs match" : "PCRs mismatched"} ok={verifyResult.match} />
        <StatusBadge label={verifyResult.approved ? "approved" : "revoked"} ok={verifyResult.approved} />
        <ul class="space-y-1">
          {#each verifyResult.branches as b, i (i)}
            <li class="text-sm">
              Branch {i + 1}:
              {b.match ? "PCRs match" : `PCRs ${(b.mismatched ?? []).join(", ")} changed`},
              {b.approved ? "approved" : "not approved"}
            </li>
          {/each}
        </ul>
      </div>
      <div class="modal-action">
        <button class="btn btn-primary" onclick={() => (verifyResult = null)}>Close</button>
      </div>
  </Modal>
{/if}

{#if showObjects}
  <Modal open={showObjects} onClose={() => (showObjects = false)} labelledby="policy-objects-title">
      <h3 id="policy-objects-title" class="text-lg font-semibold mb-4">Objects bound to "{objectsName}"</h3>
      {#if objectsLoading}
        <div class="flex justify-center py-6"><span class="loading loading-spinner"></span></div>
      {:else if objectsErr}
        <Alert kind="error"><span>{objectsErr}</span></Alert>
      {:else if objectsList.length === 0}
        <p class="text-base-content/60">No objects are bound to this policy.</p>
      {:else}
        <ul class="list-disc list-inside space-y-1">
          {#each objectsList as o (o)}<li class="font-mono text-sm">{o}</li>{/each}
        </ul>
      {/if}
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showObjects = false)}>Close</button>
      </div>
  </Modal>
{/if}

{#if showRotateConfirm}
  <Modal open={showRotateConfirm} onClose={() => (showRotateConfirm = false)} labelledby="rotate-authority-title">
      <h3 id="rotate-authority-title" class="text-lg font-semibold mb-4">Rotate policy authority?</h3>
      <p class="text-sm text-base-content/70">
        Every existing policy approval is invalidated. Approved policies must be re-approved
        (update) before their objects can be used again.
      </p>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showRotateConfirm = false)} disabled={rotateBusy}>
          Cancel
        </button>
        <button class="btn btn-error" onclick={confirmRotate} disabled={rotateBusy}>
          {#if rotateBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
          Rotate
        </button>
      </div>
  </Modal>
{/if}
