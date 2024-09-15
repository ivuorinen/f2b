#!/usr/bin/env bats
# vim: ft=bats

version() { grep -o '[0-9.]+'; }
export -f version

@test "version" {
  run -1 bash -c "$PWD/f2b version | version"
  # [ "$status" -eq 0 ]
  echo "OUTPUT: $output"
  [ "$output" = "1.1.0" ]
}

@test "timestamp" {
  run "$PWD/f2b" test timestamp 1
  echo "OUTPUT: $output"
  [ "$status" -eq 0 ]
  [ "$output" -gt 0 ]
}
