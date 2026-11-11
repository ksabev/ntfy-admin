#!/bin/sh
# Print the CHANGELOG.md section of one version: scripts/release-notes.sh 0.2.2
# Fails if the version has no section, so a tag without a changelog entry is noticed.
set -eu
v="${1:?usage: $0 VERSION}"
notes=$(awk -v v="$v" '
  /^## / { if (found) exit; if (index($0, "## " v " ") == 1 || $0 == "## " v) { found = 1; next } }
  found { print }
  END { if (!found) exit 1 }
' "$(dirname "$0")/../CHANGELOG.md") || { echo "no CHANGELOG.md section for $v" >&2; exit 1; }
printf '%s\n' "$notes" | sed -e '/./,$!d'
