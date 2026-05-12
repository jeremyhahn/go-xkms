<!--
  Copyright (c) 2025 Jeremy Hahn
  Copyright (c) 2025 Automate The Things, LLC
  SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { formatDateTime } from '@trustedca/shared/utils/formatters';
  import { adminApi } from '../lib/api/admin-api';
  import { tenants, fetchTenants } from '../lib/stores/tenants';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';

  interface Role {
    id: string;
    name: string;
  }

  interface User {
    id: string;
    username: string;
    email?: string;
    status?: string;
    role_ids?: string[];
    created_at?: string;
  }

  let selectedTenantId = $state('');
  let users = $state<User[]>([]);
  let usersLoading = $state(false);
  let roles = $state<Role[]>([]);
  let rolesLoading = $state(false);

  // Create modal
  let showCreateModal = $state(false);
  let createUsername = $state('');
  let createEmail = $state('');
  let createRoleIds = $state<string[]>([]);
  let createSubmitting = $state(false);

  // Edit modal
  let showEditModal = $state(false);
  let editUser = $state<User | null>(null);
  let editUsername = $state('');
  let editRoleIds = $state<string[]>([]);
  let editSubmitting = $state(false);

  // Delete confirmation
  let showDeleteModal = $state(false);
  let deleteUser = $state<User | null>(null);
  let deleteSubmitting = $state(false);

  async function loadUsers() {
    if (!selectedTenantId) return;
    usersLoading = true;
    try {
      const res = await adminApi.listUsers(selectedTenantId);
      users = (res.data ?? []) as User[];
    } catch (e) {
      notifyError(`Failed to load users: ${(e as Error).message}`);
      users = [];
    } finally {
      usersLoading = false;
    }
  }

  async function loadRoles() {
    if (!selectedTenantId) return;
    rolesLoading = true;
    try {
      const res = await adminApi.listRoles(selectedTenantId);
      roles = (res.data ?? []) as Role[];
    } catch (e) {
      roles = [];
    } finally {
      rolesLoading = false;
    }
  }

  function onTenantChange() {
    users = [];
    roles = [];
    loadUsers();
    loadRoles();
  }

  function toggleCreateRole(roleId: string) {
    if (createRoleIds.includes(roleId)) {
      createRoleIds = createRoleIds.filter((id) => id !== roleId);
    } else {
      createRoleIds = [...createRoleIds, roleId];
    }
  }

  function toggleEditRole(roleId: string) {
    if (editRoleIds.includes(roleId)) {
      editRoleIds = editRoleIds.filter((id) => id !== roleId);
    } else {
      editRoleIds = [...editRoleIds, roleId];
    }
  }

  async function handleCreateUser() {
    if (!createUsername.trim()) {
      notifyError('Username is required.');
      return;
    }
    createSubmitting = true;
    try {
      await adminApi.createUser(selectedTenantId, {
        username: createUsername.trim(),
        roleIDs: createRoleIds,
      });
      showCreateModal = false;
      createUsername = '';
      createEmail = '';
      createRoleIds = [];
      notifySuccess('User created successfully.');
      await loadUsers();
    } catch (e) {
      notifyError(`Failed to create user: ${(e as Error).message}`);
    } finally {
      createSubmitting = false;
    }
  }

  function openEditModal(user: User) {
    editUser = user;
    editUsername = user.username;
    editRoleIds = [...(user.role_ids ?? [])];
    showEditModal = true;
  }

  async function handleEditUser() {
    if (!editUser || !editUsername.trim()) {
      notifyError('Username is required.');
      return;
    }
    editSubmitting = true;
    try {
      await adminApi.updateUser(selectedTenantId, editUser.id, {
        username: editUsername.trim(),
        roleIDs: editRoleIds,
      });
      showEditModal = false;
      editUser = null;
      notifySuccess('User updated successfully.');
      await loadUsers();
    } catch (e) {
      notifyError(`Failed to update user: ${(e as Error).message}`);
    } finally {
      editSubmitting = false;
    }
  }

  function openDeleteModal(user: User) {
    deleteUser = user;
    showDeleteModal = true;
  }

  async function handleDeleteUser() {
    if (!deleteUser) return;
    deleteSubmitting = true;
    try {
      await adminApi.deleteUser(selectedTenantId, deleteUser.id);
      showDeleteModal = false;
      deleteUser = null;
      notifySuccess('User deleted.');
      await loadUsers();
    } catch (e) {
      notifyError(`Failed to delete user: ${(e as Error).message}`);
    } finally {
      deleteSubmitting = false;
    }
  }

  function roleNamesFor(roleIds: string[] | undefined): string {
    if (!roleIds || roleIds.length === 0) return '—';
    return roleIds
      .map((id) => roles.find((r) => r.id === id)?.name ?? id)
      .join(', ');
  }

  onMount(async () => {
    await fetchTenants({ per_page: 100 });
    if ($tenants.length > 0) {
      selectedTenantId = $tenants[0].id;
      loadUsers();
      loadRoles();
    }
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">User Manager</h1>

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
        + Create User
      </button>
    </div>
  </div>

  <Card>
    {#if !selectedTenantId}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        Select a tenant to manage its users.
      </div>
    {:else if usersLoading}
      <div class="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    {:else if users.length === 0}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        No users found for this tenant.
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="table w-full">
          <thead>
            <tr>
              <th>Username</th>
              <th>Status</th>
              <th>Roles</th>
              <th>Created</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each users as user (user.id)}
              <tr class="hover">
                <td class="font-medium">{user.username}</td>
                <td>
                  {#if user.status}
                    <StatusBadge status={user.status} />
                  {:else}
                    <span class="text-sm text-slate-400 dark:text-slate-500">—</span>
                  {/if}
                </td>
                <td class="text-sm text-slate-600 dark:text-slate-300">
                  {roleNamesFor(user.role_ids)}
                </td>
                <td class="text-sm text-slate-500 dark:text-slate-400">
                  {user.created_at ? formatDateTime(user.created_at) : '—'}
                </td>
                <td>
                  <div class="flex justify-end gap-2">
                    <button
                      class="btn btn-ghost btn-xs"
                      onclick={() => openEditModal(user)}
                    >
                      Edit
                    </button>
                    <button
                      class="btn btn-ghost btn-xs text-error"
                      onclick={() => openDeleteModal(user)}
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

<!-- Create User Modal -->
<dialog class="modal" class:modal-open={showCreateModal}>
  <div class="modal-box max-w-lg">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Create User</h3>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="user-username">
          <span class="label-text">Username <span class="text-error">*</span></span>
        </label>
        <input
          id="user-username"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. jane.doe"
          bind:value={createUsername}
        />
      </div>

      <div class="form-control w-full">
        <label class="label" for="user-email">
          <span class="label-text">Email</span>
          <span class="label-text-alt text-slate-400">Optional</span>
        </label>
        <input
          id="user-email"
          class="input input-bordered w-full"
          type="email"
          placeholder="e.g. jane@example.com"
          bind:value={createEmail}
        />
      </div>

      <div class="form-control w-full">
        <label class="label">
          <span class="label-text">Assign Roles</span>
        </label>
        {#if rolesLoading}
          <div class="flex justify-center py-4">
            <LoadingSpinner size="sm" />
          </div>
        {:else if roles.length === 0}
          <p class="text-sm text-slate-400 dark:text-slate-500">No roles available for this tenant.</p>
        {:else}
          <div class="rounded-lg border border-base-300 p-3 max-h-40 overflow-y-auto">
            {#each roles as role (role.id)}
              <label class="flex cursor-pointer items-center gap-2 rounded p-1.5 hover:bg-base-200">
                <input
                  class="checkbox checkbox-primary checkbox-sm"
                  type="checkbox"
                  checked={createRoleIds.includes(role.id)}
                  onchange={() => toggleCreateRole(role.id)}
                />
                <span class="text-sm">{role.name}</span>
              </label>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showCreateModal = false; createUsername = ''; createEmail = ''; createRoleIds = []; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={createSubmitting}
        disabled={createSubmitting}
        onclick={handleCreateUser}
      >
        Create
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showCreateModal = false; }}>close</button>
  </form>
</dialog>

<!-- Edit User Modal -->
<dialog class="modal" class:modal-open={showEditModal}>
  <div class="modal-box max-w-lg">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Edit User</h3>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="edit-username">
          <span class="label-text">Username <span class="text-error">*</span></span>
        </label>
        <input
          id="edit-username"
          class="input input-bordered w-full"
          type="text"
          bind:value={editUsername}
        />
      </div>

      <div class="form-control w-full">
        <label class="label">
          <span class="label-text">Assign Roles</span>
        </label>
        {#if roles.length === 0}
          <p class="text-sm text-slate-400 dark:text-slate-500">No roles available for this tenant.</p>
        {:else}
          <div class="rounded-lg border border-base-300 p-3 max-h-40 overflow-y-auto">
            {#each roles as role (role.id)}
              <label class="flex cursor-pointer items-center gap-2 rounded p-1.5 hover:bg-base-200">
                <input
                  class="checkbox checkbox-primary checkbox-sm"
                  type="checkbox"
                  checked={editRoleIds.includes(role.id)}
                  onchange={() => toggleEditRole(role.id)}
                />
                <span class="text-sm">{role.name}</span>
              </label>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showEditModal = false; editUser = null; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={editSubmitting}
        disabled={editSubmitting}
        onclick={handleEditUser}
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
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Delete User</h3>
    <p class="py-4 text-sm text-slate-600 dark:text-slate-300">
      Are you sure you want to delete user <strong>{deleteUser?.username}</strong>?
      This action cannot be undone.
    </p>
    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showDeleteModal = false; deleteUser = null; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-error"
        class:loading={deleteSubmitting}
        disabled={deleteSubmitting}
        onclick={handleDeleteUser}
      >
        Delete
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showDeleteModal = false; }}>close</button>
  </form>
</dialog>
