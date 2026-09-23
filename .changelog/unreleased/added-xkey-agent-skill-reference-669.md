- **The xkey-agent skill covers every xkey capability and is checked against
  the real command tree.** `xkey/skills/xkey-agent/SKILL.md` is organized by
  purpose, and permissions are left to the server, so it labels no command
  human-only. `xkey/tools/skillgen` generates
  `skills/xkey-agent/reference/cli.md` (every command, flag, type and
  default) from the cobra tree. `make -C xkey check-skill-reference` fails
  when that reference is stale or when SKILL.md cites a command or flag xkey
  does not have, and the CI Lint job runs it (#669).
