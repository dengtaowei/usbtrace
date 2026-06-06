#!/usr/bin/env bash
#
# Validate that commit subjects in a range follow Conventional Commits.
#
# Usage:
#   scripts/check-commits.sh [base_ref] [head_ref]
#   e.g.  scripts/check-commits.sh origin/main HEAD
#
# CI passes the PR base/head SHAs. Merge and revert auto-subjects are skipped.
set -euo pipefail

BASE="${1:-origin/main}"
HEAD_REF="${2:-HEAD}"

# Allowed commit types (Conventional Commits + a couple of project-specific).
TYPES='feat|fix|perf|refactor|docs|build|ci|test|chore|style|revert'

# <type>(<scope>)!: <description>
#   - scope optional, lowercase, comma-separated (module names: urb, power, ...)
#   - optional "!" marks a breaking change
SUBJECT_RE="^(${TYPES})(\([a-z0-9._-]+(,[a-z0-9._-]+)*\))?!?: .+"
MAX_LEN=72

range="${BASE}..${HEAD_REF}"
commits="$(git rev-list --no-merges "$range" 2>/dev/null || true)"

if [ -z "$commits" ]; then
	echo "No non-merge commits in range ${range}; nothing to check."
	exit 0
fi

fail=0
while IFS= read -r sha; do
	[ -n "$sha" ] || continue
	subject="$(git log -1 --format=%s "$sha")"
	short="$(git rev-parse --short "$sha")"

	# Tolerate auto-generated merge/revert subjects.
	case "$subject" in
	"Merge "*|"Revert "*)
		echo "skip ${short}: ${subject}"
		continue
		;;
	esac

	if ! printf '%s' "$subject" | grep -Eq "$SUBJECT_RE"; then
		echo "FAIL ${short}: bad format: ${subject}"
		fail=1
		continue
	fi
	if [ "${#subject}" -gt "$MAX_LEN" ]; then
		echo "FAIL ${short}: subject too long (${#subject} > ${MAX_LEN}): ${subject}"
		fail=1
		continue
	fi
	echo "PASS ${short}: ${subject}"
done <<EOF
${commits}
EOF

if [ "$fail" -ne 0 ]; then
	cat >&2 <<'EOF'

Commit messages must follow Conventional Commits:

  <type>(<scope>)!: <description>

Allowed types:  feat fix perf refactor docs build ci test chore style revert
Scope (optional, usually a module): urb enum lifecycle power uvc uac hid storage diag class cli core build ci docs deps
Subject length: <= 72 characters.

Examples:
  feat(power): trace autosuspend/autoresume
  fix(urb): correct giveback status read
  docs(modules): document --json output
  ci: add native build gate
  refactor(cli)!: rename usbtrace_filter fields
EOF
	exit 1
fi

echo "All commit messages OK."
