<script lang="ts">
  import { createEventDispatcher, tick } from 'svelte';
  import Icon from './Icon.svelte';
  import FolderTreeNode from './FolderTreeNode.svelte';
  import {
    mdiFolderPlus,
    mdiFormatListBulleted,
    mdiPencil,
    mdiDelete,
  } from '$lib/utils/icons';

  export let folders: string[] = [];
  export let selectedFolder: string | null = null;
  export let passwordCounts: Record<string, number> = {};

  const dispatch = createEventDispatcher<{
    select: string | null;
    createFolder: void;
    createSubfolder: string;
    renameFolder: string;
    deleteFolder: string;
  }>();

  interface FolderNode {
    name: string;
    path: string;
    children: FolderNode[];
  }

  let expandedPaths = new Set<string>();
  let contextMenuPath: string | null = null;
  let contextMenuPosition = { x: 0, y: 0 };

  $: totalCount = Object.values(passwordCounts).reduce((sum, c) => sum + c, 0);

  $: folderTree = buildTree(folders);

  function buildTree(paths: string[]): FolderNode[] {
    const root: FolderNode[] = [];
    const sorted = [...paths].sort();

    for (const path of sorted) {
      const parts = path.split('/');
      let current = root;
      let accumulated = '';

      for (let i = 0; i < parts.length; i++) {
        accumulated = i === 0 ? parts[i] : `${accumulated}/${parts[i]}`;
        let existing = current.find(n => n.name === parts[i]);
        if (!existing) {
          existing = { name: parts[i], path: accumulated, children: [] };
          current.push(existing);
        }
        current = existing.children;
      }
    }

    return root;
  }

  function getSubtreeCount(path: string): number {
    let count = passwordCounts[path] || 0;
    for (const key of Object.keys(passwordCounts)) {
      if (key.startsWith(path + '/')) {
        count += passwordCounts[key];
      }
    }
    return count;
  }

  function toggleExpand(path: string): void {
    if (expandedPaths.has(path)) {
      expandedPaths.delete(path);
    } else {
      expandedPaths.add(path);
    }
    expandedPaths = expandedPaths;
  }

  function selectFolder(path: string | null): void {
    dispatch('select', path);
  }

  function openContextMenu(e: MouseEvent, path: string): void {
    e.preventDefault();
    e.stopPropagation();
    const target = e.currentTarget as HTMLElement;
    const rect = target.getBoundingClientRect();
    const nav = target.closest('.folder-tree');
    const navRect = nav?.getBoundingClientRect();
    contextMenuPosition = {
      x: rect.right - (navRect?.left ?? 0) - 4,
      y: rect.bottom - (navRect?.top ?? 0) + 2,
    };
    contextMenuPath = path;
    void tick();
  }

  function closeContextMenu(): void {
    contextMenuPath = null;
  }

  function handleMenuAction(action: 'createSubfolder' | 'rename' | 'delete', path: string): void {
    contextMenuPath = null;
    if (action === 'createSubfolder') {
      dispatch('createSubfolder', path);
    } else if (action === 'rename') {
      dispatch('renameFolder', path);
    } else {
      dispatch('deleteFolder', path);
    }
  }

  function handleKeyDown(e: KeyboardEvent, path: string | null): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      selectFolder(path);
    }
  }

  // Handle events from recursive FolderTreeNode
  function handleNodeSelect(e: CustomEvent<string>): void {
    selectFolder(e.detail);
  }

  function handleNodeToggleExpand(e: CustomEvent<string>): void {
    toggleExpand(e.detail);
  }

  function handleNodeContextMenu(e: CustomEvent<{ event: MouseEvent; path: string }>): void {
    openContextMenu(e.detail.event, e.detail.path);
  }
</script>

<svelte:window on:click={closeContextMenu} />

<div class="folder-tree" role="tree" aria-label="Password folders">
  <!-- All Items root -->
  <div
    class="tree-item"
    class:selected={selectedFolder === null}
    on:click={() => selectFolder(null)}
    on:keydown={(e) => handleKeyDown(e, null)}
    role="treeitem"
    tabindex="0"
    aria-selected={selectedFolder === null}
  >
    <span class="indent-guide" style="width: 4px;"></span>
    <span class="item-icon all-icon">
      <Icon path={mdiFormatListBulleted} size={18} />
    </span>
    <span class="item-label">All Passwords</span>
    {#if totalCount > 0}
      <span class="item-count">{totalCount}</span>
    {/if}
  </div>

  <div class="tree-divider"></div>

  <!-- Recursive folder tree -->
  <div class="tree-nodes" role="group">
    {#each folderTree as node (node.path)}
      <FolderTreeNode
        {node}
        depth={0}
        {selectedFolder}
        {expandedPaths}
        {getSubtreeCount}
        on:select={handleNodeSelect}
        on:toggleExpand={handleNodeToggleExpand}
        on:openContextMenu={handleNodeContextMenu}
      />
    {/each}
  </div>

  <!-- New Folder button -->
  <div class="tree-divider"></div>
  <button
    class="tree-item new-folder-btn"
    on:click={() => dispatch('createFolder')}
  >
    <span class="indent-guide" style="width: 4px;"></span>
    <span class="chevron-spacer"></span>
    <span class="item-icon new-folder-icon">
      <Icon path={mdiFolderPlus} size={18} />
    </span>
    <span class="item-label">New Folder</span>
  </button>

  <!-- Context menu popover -->
  {#if contextMenuPath}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      class="context-menu"
      style="right: 8px; top: {contextMenuPosition.y}px;"
      role="menu"
      tabindex="-1"
      on:click|stopPropagation
      on:keydown={(e) => e.key === 'Escape' && closeContextMenu()}
    >
      <button
        class="context-menu-item"
        role="menuitem"
        on:click={() => contextMenuPath && handleMenuAction('createSubfolder', contextMenuPath)}
      >
        <Icon path={mdiFolderPlus} size={16} />
        <span>Create Subfolder</span>
      </button>
      <button
        class="context-menu-item"
        role="menuitem"
        on:click={() => contextMenuPath && handleMenuAction('rename', contextMenuPath)}
      >
        <Icon path={mdiPencil} size={16} />
        <span>Rename</span>
      </button>
      <div class="context-menu-divider"></div>
      <button
        class="context-menu-item context-menu-item--danger"
        role="menuitem"
        on:click={() => contextMenuPath && handleMenuAction('delete', contextMenuPath)}
      >
        <Icon path={mdiDelete} size={16} />
        <span>Delete</span>
      </button>
    </div>
  {/if}
</div>

<style>
  /* ---- Tree container ---- */
  .folder-tree {
    display: flex;
    flex-direction: column;
    padding: 8px 0;
    overflow-y: auto;
    overflow-x: hidden;
    height: 100%;
    position: relative;
    user-select: none;
  }

  /* ---- Tree item (row) ---- */
  .tree-item {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 8px 6px 0;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1;
    width: 100%;
    text-align: left;
    border-radius: var(--radius-sm);
    margin: 0 4px;
    box-sizing: border-box;
    transition: background-color 120ms ease, color 120ms ease;
    position: relative;
    min-height: 32px;
  }

  .tree-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .tree-item.selected {
    background-color: var(--color-primary-container, var(--color-surface-variant));
    color: var(--color-on-primary-container, var(--color-primary));
    font-weight: 500;
  }

  .tree-item:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: -2px;
  }

  /* ---- Indentation guide ---- */
  .indent-guide {
    flex-shrink: 0;
    display: inline-block;
  }

  .chevron-spacer {
    width: 18px;
    flex-shrink: 0;
    display: inline-block;
  }

  /* ---- Folder icon ---- */
  .item-icon {
    display: flex;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .selected .item-icon {
    color: var(--color-on-primary-container, var(--color-primary));
  }

  .all-icon {
    display: flex;
    flex-shrink: 0;
    color: var(--color-primary);
  }

  /* ---- Label ---- */
  .item-label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  /* ---- Count badge ---- */
  .item-count {
    font-size: 11px;
    font-weight: 500;
    padding: 0 5px;
    min-width: 18px;
    height: 18px;
    line-height: 18px;
    text-align: center;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .selected .item-count {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
  }

  /* ---- Divider ---- */
  .tree-divider {
    height: 1px;
    background-color: var(--color-outline-variant);
    margin: 6px 12px;
    opacity: 0.4;
  }

  /* ---- New Folder button ---- */
  .new-folder-btn {
    color: var(--color-primary);
    opacity: 0.85;
    border: none;
  }

  .new-folder-btn:hover {
    opacity: 1;
    background-color: var(--color-surface-container);
  }

  .new-folder-icon {
    color: var(--color-primary);
  }

  /* ---- Context menu ---- */
  .context-menu {
    position: absolute;
    z-index: 100;
    background-color: var(--color-surface-container-high);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    min-width: 148px;
    padding: 4px 0;
    overflow: hidden;
  }

  .context-menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 14px;
    border: none;
    background: transparent;
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
    transition: background-color 120ms ease;
  }

  .context-menu-item:hover {
    background-color: var(--color-surface-container);
  }

  .context-menu-item--danger {
    color: var(--color-error);
  }

  .context-menu-item--danger:hover {
    background-color: var(--color-error-container);
  }

  .context-menu-divider {
    height: 1px;
    background-color: var(--color-outline-variant);
    margin: 4px 0;
    opacity: 0.4;
  }
</style>
