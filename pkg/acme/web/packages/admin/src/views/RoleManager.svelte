<!--
  Copyright (c) 2025 Jeremy Hahn
  Copyright (c) 2025 Automate The Things, LLC
  SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { adminApi } from '../lib/api/admin-api';
  import { tenants, fetchTenants } from '../lib/stores/tenants';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';

  // Role shape returned from the API
  interface Role {
    id: string;
    name: string;
    permissions?: string[];
    created_at?: string;
  }

  const AVAILABLE_PERMISSIONS = [
    'certificates:read',
    'certificates:issue',
    'certificates:revoke',
    'accounts:read',
    'accounts:manage',
    'orders:read',
    'orders:manage',
    'eab:read',
    'eab:create',
    'eab:revoke',
    'ca:read',
    'ca:manage',
    'roles:read',
    'roles:manage',
    'users:read',
    'users:manage',
    'audit:read',
  ];

  let selectedTenantId = $state('');
  let roles = $state<Role[]>([]);
  let rolesLoading = $state(false);

  // Create modal
  let showCreateModal = $state(false);
  let createName = $state('');
  let createPermissions = $state<string[]>([]);
  let createSubmitting = $state(false);

  // Edit modal
  let showEditModal = $state(false);
  let editRole = $state<Role | null>(null);
  let editName = $state('');
  let editPermissions = $state<string[]>([]);
  let editSubmitting = $state(false);

  // Delete confirmation
  let showDeleteModal = $state(false);
  let deleteRole = $state<Role | null>(null);
  let deleteSubmitting = $state(false);

  async function loadRoles() {
    if (!selectedTenantId) return;
    rolesLoading = true;
    try {
      const res = await adminApi.listRoles(selectedTenantId);
      roles = (res.data ?? []) as Role[];
    } catch (e) {
      notifyError(`Failed to load roles: ${(e as Error).message}`);
      roles = [];
    } finally {
      rolesLoading = false;
    }
  }

  function onTenantChange() {
    roles = [];
    loadRoles();
  }

  function toggleCreatePermission(perm: string) {
    if (createPermissions.includes(perm)) {
      createPermissions = createPermissions.filter((p) => p !== perm);
    } else {
      createPermissions = [...createPermissions, perm];
    }
  }

  function toggleEditPermission(perm: string) {
    if (editPermissions.includes(perm)) {
      editPermissions = editPermissions.filter((p) => p !== perm);
    } else {
      editPermissions = [...editPermissions, perm];
    }
  }

  async function handleCreateRole() {
    if (!createName.trim()) {
      notifyError('Role name is required.');
      return;
    }
    createSubmitting = true;
    try {
      await adminApi.createRole(selectedTenantId, {
        name: createName.trim(),
        permissions: createPermissions,
      });
      showCreateModal = false;
      createName = '';
      createPermissions = [];
      notifySuccess('Role created successfully.');
      await loadRoles();
    } catch (e) {
      notifyError(`Failed to create role: ${(e as Error).message}`);
    } finally {
      createSubmitting = false;
    }
  }

  function openEditModal(role: Role) {
    editRole = role;
    editName = role.name;
    editPermissions = [...(role.permissions ?? [])];
    showEditModal = true;
  }

  async function handleEditRole() {
    if (!editRole || !editName.trim()) {
      notifyError('Role name is required.');
      return;
    }
    editSubmitting = true;
    try {
      await adminApi.updateRole(selectedTenantId, editRole.id, {
        name: editName.trim(),
        permissions: editPermissions,
      });
      showEditModal = false;
      editRole = null;
      notifySuccess('Role updated successfully.');
      await loadRoles();
    } catch (e) {
      notifyError(`Failed to update role: ${(e as Error).message}`);
    } finally {
      editSubmitting = false;
    }
  }

  function openDeleteModal(role: Role) {
    deleteRole = role;
    showDeleteModal = true;
  }

  async function handleDeleteRole() {
    if (!deleteRole) return;
    deleteSubmitting = true;
    try {
      await adminApi.deleteRole(selectedTenantId, deleteRole.id);
      showDeleteModal = false;
      deleteRole = null;
      notifySuccess('Role deleted.');
      await loadRoles();
    } catch (e) {
      notifyError(`Failed to delete role: ${(e as Error).message}`);
    } finally {
      deleteSubmitting = false;
    }
  }

  onMount(async () => {
    await fetchTenants({ per_page: 100 });
    if ($tenants.length > 0) {
      selectedTenantId = $tenants[0].id;
      loadRoles();
    }
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">Role Manager</h1>

    <div class="flex items-center gap-3">
      <select
        class="select select-bordered"
        bind:value={selectedTenantId}
        onchange={onTenantChange}
      >
        <option value="">Select Tenant</option>
        {#each $tenants as tenant (tenant.id)}
          <option value={tenant.id}>{tenant.name} ({tenant.id})</option>
        {/each}
      </select>

      <button
        class="btn btn-primary btn-sm"
        disabled={!selectedTenantId}
        onclick={() => { showCreateModal = true; }}
      >
        + Create Role
      </button>
    </div>
  </div>

  <Card>
    {#if !selectedTenantId}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        Select a tenant to manage its roles.
      </div>
    {:else if rolesLoading}
      <div class="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    {:else if roles.length === 0}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        No roles defined for this tenant.
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="table w-full">
          <thead>
            <tr>
              <th>Name</th>
              <th>Permissions</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each roles as role (role.id)}
              <tr class="hover">
                <td class="font-medium">{role.name}</td>
                <td>
                  <div class="flex flex-wrap gap-1">
                    {#if role.permissions && role.permissions.length > 0}
                      {#each role.permissions as perm}
                        <span class="badge badge-outline badge-sm">{perm}</span>
                      {/each}
                    {:else}
                      <span class="text-sm text-slate-400 dark:text-slate-500">No permissions</span>
                    {/if}
                  </div>
                </td>
                <td>
                  <div class="flex justify-end gap-2">
                    <button
                      class="btn btn-ghost btn-xs"
                      onclick={() => openEditModal(role)}
                    >
                      Edit
                    </button>
                    <button
                      class="btn btn-ghost btn-xs text-error"
                      onclick={() => openDeleteModal(role)}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </Card>
</div>

<!-- Create Role Modal -->
<dialog class="modal" class:modal-open={showCreateModal}>
  <div class="modal-box max-w-lg">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Create Role</h3>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="role-name">
          <span class="label-text">Role Name <span class="text-error">*</span></span>
        </label>
        <input
          id="role-name"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. certificate-manager"
          bind:value={createName}
        />
      </div>

      <div class="form-control w-full">
        <label class="label">
          <span class="label-text">Permissions</span>
        </label>
        <div class="rounded-lg border border-base-300 p-3 max-h-60 overflow-y-auto">
          <div class="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {#each AVAILABLE_PERMISSIONS as perm}
              <label class="flex cursor-pointer items-center gap-2 rounded p-1.5 hover:bg-base-200">
                <input
                  class="checkbox checkbox-primary checkbox-sm"
                  type="checkbox"
                  checked={createPermissions.includes(perm)}
                  onchange={() => toggleCreatePermission(perm)}
                />
                <span class="text-sm">{perm}</span>
              </label>
            {/each}
          </div>
        </div>
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showCreateModal = false; createName = ''; createPermissions = []; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={createSubmitting}
        disabled={createSubmitting}
        onclick={handleCreateRole}
      >
        Create
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showCreateModal = false; }}>close</button>
  </form>
</dialog>

<!-- Edit Role Modal -->
<dialog class="modal" class:modal-open={showEditModal}>
  <div class="modal-box max-w-lg">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Edit Role</h3>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="edit-role-name">
          <span class="label-text">Role Name <span class="text-error">*</span></span>
        </label>
        <input
          id="edit-role-name"
          class="input input-bordered w-full"
          type="text"
          bind:value={editName}
        />
      </div>

      <div class="form-control w-full">
        <label class="label">
          <span class="label-text">Permissions</span>
        </label>
        <div class="rounded-lg border border-base-300 p-3 max-h-60 overflow-y-auto">
          <div class="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {#each AVAILABLE_PERMISSIONS as perm}
              <label class="flex cursor-pointer items-center gap-2 rounded p-1.5 hover:bg-base-200">
                <input
                  class="checkbox checkbox-primary checkbox-sm"
                  type="checkbox"
                  checked={editPermissions.includes(perm)}
                  onchange={() => toggleEditPermission(perm)}
                />
                <span class="text-sm">{perm}</span>
              </label>
            {/each}
          </div>
        </div>
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showEditModal = false; editRole = null; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={editSubmitting}
        disabled={editSubmitting}
        onclick={handleEditRole}
      >
        Save Changes
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showEditModal = false; }}>close</button>
  </form>
</dialog>

<!-- Delete Confirmation Modal -->
<dialog class="modal" class:modal-open={showDeleteModal}>
  <div class="modal-box">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Delete Role</h3>
    <p class="py-4 text-sm text-slate-600 dark:text-slate-300">
      Are you sure you want to delete role <strong>{deleteRole?.name}</strong>?
      This action cannot be undone.
    </p>
    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showDeleteModal = false; deleteRole = null; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-error"
        class:loading={deleteSubmitting}
        disabled={deleteSubmitting}
        onclick={handleDeleteRole}
      >
        Delete
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showDeleteModal = false; }}>close</button>
  </form>
</dialog>
