#!/usr/bin/env bats
# vim: ft=bats

version() { grep -o '^[0-9]\+\.[0-9]\+\.[0-9]\+$'; }
export -f version

@test "version" {
  run "$PWD/f2b" version
  [ "$status" -eq 0 ]
  run version <<<"$output"
  echo "OUTPUT: $output"
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "timestamp" {
  run "$PWD/f2b" _test timestamp 1
  echo "OUTPUT: $output"
  [ "$status" -eq 0 ]
  [ "$output" -gt 0 ]
}
