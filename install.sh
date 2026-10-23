#!/bin/sh
# install.sh: check the settings, create the slots dir, write the unit.
# Never starts, enables or stops a unit; never runs systemctl.
#
# Validate first: check, render-unit and the unit-path test run before
# anything is created, written or printed; a refusal exits non-zero
# with exactly one line.
set -eu

usage() {
  echo "usage: install.sh --settings FILE [--dry-run]" >&2
}

settings=""
dry_run=0
while [ $# -gt 0 ]; do
  case "$1" in
    --settings)
      if [ $# -lt 2 ] || [ "${2#-}" != "$2" ]; then
        usage
        exit 64
      fi
      settings="$2"
      shift 2
      ;;
    --settings=?*)
      settings="${1#--settings=}"
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      echo "usage: install.sh --settings FILE [--dry-run]"
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done
if [ -z "$settings" ]; then
  usage
  exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script="$script_dir/secret_drop.py"

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "install.sh: python3 3.11 or later is required" >&2
  exit 1
fi

# A failing check stops the script with the check's own line and status.
check_out=$(python3 "$script" --settings "$settings" check) || exit $?
unit=$(printf '%s\n' "$check_out" | sed -n 's/^unit=//p')
slots_dir=$(printf '%s\n' "$check_out" | sed -n 's/^slots_dir=//p')
python=$(printf '%s\n' "$check_out" | sed -n 's/^python=//p')

# The unit runs the settings python, so that interpreter is checked too.
# The probe's own stderr is discarded: a missing interpreter must not
# add the shell's error line to the one-line refusal.
if ! "$python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
  echo "install.sh: the settings python must be 3.11 or later" >&2
  exit 1
fi

# The server could not see an interpreter under a home directory, so such
# a python is refused with the same line the check command prints.
real_python=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$python" 2>/dev/null || printf '%s' "$python")
case "$real_python" in
  /home|/home/*|/root|/root/*)
    echo "secret-drop: python_under_home" >&2
    exit 1
    ;;
esac
if [ -n "${HOME:-}" ]; then
  home_real=$(python3 -c 'import os; print(os.path.realpath(os.environ.get("HOME", "/nonexistent")))' 2>/dev/null || printf '%s' "$HOME")
  case "$real_python" in
    "$home_real"|"$home_real"/*)
      echo "secret-drop: python_under_home" >&2
      exit 1
      ;;
  esac
fi

unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit_path="$unit_dir/$unit"

# Phase 1: validate only. Nothing is created, written or printed here
# except a refusal, which exits non-zero with exactly one stderr line.
# render-unit also refuses an unsafe slots dir.
python3 "$script" --settings "$settings" render-unit > /dev/null || exit $?
if [ -L "$unit_path" ]; then
  echo "secret-drop: unit_path_unsafe" >&2
  exit 1
fi
if [ -e "$unit_path" ] && [ ! -f "$unit_path" ]; then
  echo "secret-drop: unit_path_unsafe" >&2
  exit 1
fi

# Phase 2.
if [ "$dry_run" = 1 ]; then
  if [ ! -d "$slots_dir" ]; then
    echo "would create $slots_dir (mode 700)"
  fi
  echo "would write $unit_path"
else
  mkdir -p "$unit_dir"
  tmp=$(mktemp "$unit_dir/.secret-drop.XXXXXX")
  trap 'rm -f "$tmp"' EXIT
  python3 "$script" --settings "$settings" render-unit > "$tmp" || exit $?
  if [ ! -d "$slots_dir" ]; then
    mkdir -p -m 700 "$slots_dir"
    echo "created $slots_dir"
  fi
  chmod 644 "$tmp"
  mv -f "$tmp" "$unit_path"
  trap - EXIT
  echo "wrote $unit_path"
fi
echo "next: systemctl --user daemon-reload (the unit is started by open, never enabled)"
