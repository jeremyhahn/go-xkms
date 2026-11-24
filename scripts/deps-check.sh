#!/usr/bin/env bash
# Fail when a direct dependency of a shipped module is behind a release out for 7 days or more.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
modules=(. sdk/go xkey)
format='{{if and (not .Main) (not .Indirect) (not .Replace) .Update}}{{.Path}} {{.Version}} {{.Update.Version}} {{if .Update.Time}}{{.Update.Time.Unix}}{{else}}0{{end}}{{end}}'
attempts=3
retry_pause=5
grace_days=7

errlog=$(mktemp)
trap 'rm -f "$errlog"' EXIT

# list_behind prints "path version update published-unix-time" for every
# direct requirement of module $1 that is behind its newest release, trying
# a failing go list up to $attempts times.
list_behind() {
  local mod=$1 attempt out err
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if out=$(cd "$root/$mod" && go list -m -u -f "$format" all 2>"$errlog"); then
      printf '%s\n' "$out"
      return 0
    fi
    err=$(<"$errlog")
    echo "deps-check: $mod: go list attempt $attempt/$attempts failed: ${err//$'\n'/; }" >&2
    if ((attempt < attempts)); then
      sleep "$retry_pause"
    fi
  done
  return 1
}

# held_reason prints the reason of the `// held: <reason>` comment on the
# require line for module path $2 in go.mod $1, and fails when there is none.
held_reason() {
  local gomod=$1 path=$2 line reason
  local -a fields
  while IFS= read -r line; do
    [[ $line == *"// held:"* ]] || continue
    read -r -a fields <<<"${line%%//*}"
    if [[ ${fields[0]:-} == require ]]; then
      fields=("${fields[@]:1}")
    fi
    if [[ ${fields[0]:-} == "$path" ]]; then
      read -r reason <<<"${line#*// held:}"
      printf '%s\n' "$reason"
      return 0
    fi
  done <"$gomod"
  return 1
}

now=$(date +%s)
status=0
for mod in "${modules[@]}"; do
  if ! behind=$(list_behind "$mod"); then
    echo "deps-check: $mod: go list failed" >&2
    status=1
    continue
  fi
  failing=()
  noted=()
  while read -r path version update published; do
    [ -n "$path" ] || continue
    entry="$path $version -> $update"
    age_days=$(((now - published) / 86400))
    if reason=$(held_reason "$root/$mod/go.mod" "$path"); then
      noted+=("$entry (held: $reason)")
    elif ((age_days < grace_days)); then
      noted+=("$entry (behind a release $age_days days old)")
    else
      failing+=("$entry")
    fi
  done <<<"$behind"

  if ((${#noted[@]} > 0)); then
    echo "deps-check: $mod has direct dependencies behind their newest release, not failing:"
    printf '  %s\n' "${noted[@]}"
  fi
  if ((${#failing[@]} > 0)); then
    echo "deps-check: $mod has direct dependencies behind a release $grace_days days old or older:"
    printf '  %s\n' "${failing[@]}"
    status=1
  elif ((${#noted[@]} == 0)); then
    echo "deps-check: $mod is current"
  fi
done
exit "$status"
