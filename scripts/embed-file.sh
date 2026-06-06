#!/usr/bin/env bash
# Emit a C source fragment embedding a file's bytes as a NUL-terminated array.
#
# Usage: embed-file.sh <input-file> <symbol-name>  > out.h
#
# Used by the build to bake the default diag rules.yaml into the binary so it
# works standalone, while --rules can still override at runtime.
set -euo pipefail

src=$1
sym=$2

printf 'static const char %s[] = {\n' "$sym"
od -An -v -tu1 "$src" | awk '{ for (i = 1; i <= NF; i++) printf "%s,", $i }'
printf '0\n};\n'
