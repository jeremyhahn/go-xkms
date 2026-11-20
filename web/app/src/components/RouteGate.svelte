<!--
  Copyright (c) 2026 Jeremy Hahn
  Copyright (c) 2026 Automate The Things, LLC

  This file is part of go-xkms.

  go-xkms is dual-licensed:

  1. GNU Affero General Public License v3.0 (AGPL-3.0)
     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

  2. Commercial License
     Contact licensing@automatethethings.com for commercial licensing options.
-->

<!--
  RouteGate mounts a view only when the server serves its routes (ruling
  972 (1)), per the session's /auth/me capabilities (App.svelte loads the
  session once signed in). A view gated on a subsystem reported off renders the
  disabled state naming the setting to turn on; it never mounts, so it never
  calls a route that would answer 501. Ungated views render at once.
-->
<script lang="ts">
  import type { Snippet } from "svelte";
  import { SUBSYSTEM_OFF, routeOffFlag, routePending } from "$stores/capabilities.svelte.ts";

  let { route, children }: { route: string; children: Snippet } = $props();

  const off = $derived(routeOffFlag(route));
  const pending = $derived(routePending(route));
</script>

{#if off}
  <div class="alert alert-warning max-w-2xl" role="status" data-testid="subsystem-off" data-capability={off}>
    <div>
      <div class="font-semibold">{SUBSYSTEM_OFF[off].title}</div>
      <div class="text-sm">{SUBSYSTEM_OFF[off].setting}</div>
    </div>
  </div>
{:else if pending}
  <span class="loading loading-spinner loading-md" aria-label="Loading"></span>
{:else}
  {@render children()}
{/if}
