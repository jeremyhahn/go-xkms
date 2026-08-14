<script lang="ts">
  import {
    LayoutDashboard,
    Server,
    Key,
    ShieldCheck,
    FileBadge,
    Landmark,
    Lock,
    KeyRound,
    CreditCard,
    TerminalSquare,
    Vault,
    FolderLock,
    Sparkles,
    Users,
    Building2,
    UsersRound,
    Split,
    Network,
    Settings,
    Fingerprint,
    Snowflake,
    ScrollText,
  } from "lucide-svelte";
  import { navSections, type NavItem } from "$lib/nav.ts";
  import { routerStore, navigateTo } from "$stores/router.svelte.ts";
  import { can, hasCapability } from "$stores/session.svelte.ts";

  // Icon lookup keyed by the string names in nav.ts.
  const icons: Record<string, typeof LayoutDashboard> = {
    LayoutDashboard, Server, Key, ShieldCheck, FileBadge, Landmark, Lock,
    KeyRound, CreditCard, TerminalSquare, Vault, FolderLock, Sparkles,
    Users, Building2, UsersRound, Split, Network, Settings,
    Fingerprint, Snowflake, ScrollText,
  };

  // An item is visible when its RBAC gate (if any) and capability gate (if
  // any) both pass. Unmet items are hidden, not disabled; the route guard and
  // the server still reject direct access.
  function visible(item: NavItem): boolean {
    if (item.requires && !can(item.requires.resource, item.requires.action)) {
      return false;
    }
    if (item.capability && !hasCapability(item.capability)) {
      return false;
    }
    return true;
  }

  function go(path: string): void {
    navigateTo(path);
  }
</script>

<aside class="w-60 shrink-0 bg-base-200 h-full overflow-y-auto border-r border-base-300">
  <div class="p-4 text-lg font-semibold tracking-tight">xKMS Console</div>
  <nav class="px-2 pb-6" aria-label="Primary">
    {#each navSections as section (section.heading)}
      {@const items = section.items.filter(visible)}
      {@const groupId = `nav-group-${section.heading.toLowerCase().replace(/\s+/g, "-")}`}
      {#if items.length > 0}
        <div id={groupId} class="mt-4 mb-1 px-2 text-xs uppercase tracking-wide text-base-content/50">
          {section.heading}
        </div>
        <ul class="menu menu-sm gap-0.5" aria-labelledby={groupId}>
          {#each items as item (item.route)}
            {@const Icon = icons[item.icon] ?? Server}
            <li>
              <button
                class="flex items-center gap-2"
                class:menu-active={routerStore.name === item.route}
                onclick={() => go(item.path)}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    {/each}
  </nav>
</aside>
