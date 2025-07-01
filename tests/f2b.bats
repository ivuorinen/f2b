#!/usr/bin/env bats

setup() {
  export PATH="$BATS_TEST_DIRNAME/bin:$PATH"
  mkdir -p "$BATS_TEST_DIRNAME/bin"
  cat > "$BATS_TEST_DIRNAME/bin/fail2ban-client" <<'MOCK'
#!/usr/bin/env bash
cmd=$1
shift
case "$cmd" in
  ping)
    echo "pong"
    ;;
  status)
    if [ -z "$1" ]; then
      echo "Status"
      echo "|- Number of jail:      2"
      echo "\`- Jail list:   sshd, testjail"
    else
      echo "Status for the jail: $1"
    fi
    ;;
  -V)
    echo "0.11.2"
    ;;
  *)
    echo "Mocked fail2ban-client: $cmd $*"
    ;;
esac
MOCK
  chmod +x "$BATS_TEST_DIRNAME/bin/fail2ban-client"
}

@test "status invalid jail" {
  run "$BATS_TEST_DIRNAME/../f2b" status invalid
  [ "$status" -eq 1 ]
  [[ "$output" == *"Error: Jail 'invalid' does not exist."* ]]
}

@test "logs invalid jail" {
  run "$BATS_TEST_DIRNAME/../f2b" logs invalid
  [ "$status" -eq 1 ]
  [[ "$output" == *"Error: Jail 'invalid' does not exist."* ]]
}

@test "logs valid jail" {
  run "$BATS_TEST_DIRNAME/../f2b" logs sshd
  [ "$status" -eq 0 ]
}

@test "format seconds into DD:HH:MM:SS" {
  run bash -c "source <(awk '/^f2b_secs_to_hours_minutes_seconds()/,/^}/' '$BATS_TEST_DIRNAME/../f2b'); f2b_secs_to_hours_minutes_seconds 90061"
  [ "$status" -eq 0 ]
  [ "$output" = "01:01:01:01" ]
}

@test "negative seconds returns error" {
  run bash -c "source <(awk '/^f2b_secs_to_hours_minutes_seconds()/,/^}/' '$BATS_TEST_DIRNAME/../f2b'); f2b_secs_to_hours_minutes_seconds -1"
  [ "$status" -eq 1 ]
  [[ "$output" == *"positive integer"* ]]
}
