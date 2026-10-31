#!/bin/sh
# Concatenate the license files of every third-party Go module linked into an
# f2b binary into third_party/THIRD_PARTY_LICENSES.txt, which the release
# attaches next to the binaries: Apache-2.0 §4(a) and BSD-3-Clause clause 2
# require the notices to accompany them. One file, because release assets are a
# flat list and several modules name theirs plain LICENSE.
#
# The module set differs per GOOS (cobra links mousetrap only on Windows), so
# the union over every GOOS the toolchain supports is collected; that is a
# superset of what goreleaser builds and needs no second copy of its platform
# list. CGO_ENABLED=1 only lets `go list` evaluate cgo-only targets (android,
# ios); nothing is compiled. go-licenses is not used because it cannot load
# packages for a foreign GOOS.
set -eu

out=third_party/THIRD_PARTY_LICENSES.txt
mkdir -p third_party
: >"$out"

mods=
for goos in $(go tool dist list | cut -d/ -f1 | sort -u); do
  list=$(CGO_ENABLED=1 GOOS=$goos go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}}={{.Dir}}{{end}}{{end}}' .)
  mods="$mods
$list"
done

mods=$(printf '%s\n' "$mods" | sed '/^$/d' | sort -u)
if [ -z "$mods" ]; then
  echo "collect-licenses: no third-party modules found" >&2
  exit 1
fi

printf '%s\n' "$mods" | while IFS='=' read -r mod dir; do
  found=
  for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
    if [ -f "$f" ]; then
      printf '==> %s/%s <==\n\n' "$mod" "${f##*/}" >>"$out"
      cat "$f" >>"$out"
      printf '\n' >>"$out"
      found=1
    fi
  done
  if [ -z "$found" ]; then
    echo "collect-licenses: no license file for $mod in $dir" >&2
    exit 1
  fi
done
