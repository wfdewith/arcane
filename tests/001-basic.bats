ARTIFACTS="$BATS_TEST_DIRNAME/artifacts"

setup() {
    cd "$BATS_TEST_TMPDIR"
}

send_password() {
    local password="$1"
    shift
    expect <<EOF
        log_user 1
        spawn $*
        expect "Password:"
        send "$password\n"
        expect eof
        lassign [wait] _ _ _ code
        exit \$code
EOF
}

@test "pack and unpack an ELF binary" {
    "$ARCANE" pack -p secret -o packed /usr/bin/ls
    "$ARCANE" unpack -p secret -o unpacked packed
    cmp /usr/bin/ls unpacked
}

@test "pack and unpack a script" {
    cat > script.sh <<EOF
#!/bin/sh
echo hello
EOF
    chmod +x script.sh
    "$ARCANE" pack -p secret -o packed script.sh
    "$ARCANE" unpack -p secret -o unpacked packed
    cmp script.sh unpacked
}

@test "env vars round-trip" {
    "$ARCANE" pack -p secret -e FOO=bar -e BAZ=qux -o packed /usr/bin/ls
    "$ARCANE" unpack -p secret --env-file env.txt -o unpacked packed
    grep -q '^FOO=bar$' env.txt
    grep -q '^BAZ=qux$' env.txt
}

@test "unpack a non-packed file" {
    run "$ARCANE" unpack -p secret -o unpacked /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"not a packed executable"* ]]
}

@test "wrong password" {
    "$ARCANE" pack -p right -o packed /usr/bin/ls
    run "$ARCANE" unpack -p wrong -o unpacked packed
    [ "$status" -ne 0 ]
}

@test "run a packed ELF binary" {
    "$ARCANE" pack -p secret -o packed /usr/bin/echo
    result=$(send_password secret ./packed hello world)
    [[ "$result" == *"hello world"* ]]
}

@test "run a packed script" {
    cat > script.sh <<'SCRIPT'
#!/bin/sh
echo "packed script output"
SCRIPT
    chmod +x script.sh
    "$ARCANE" pack -p secret -o packed script.sh
    result=$(send_password secret ./packed)
    [[ "$result" == *"packed script output"* ]]
}

@test "packed env vars are available at runtime" {
    cat > printenv.sh <<'SCRIPT'
#!/bin/sh
echo "FOO=$FOO"
echo "BAZ=$BAZ"
SCRIPT
    chmod +x printenv.sh
    "$ARCANE" pack -p secret -e FOO=bar -e BAZ=qux -o packed printenv.sh
    result=$(send_password secret ./packed)
    [[ "$result" == *"FOO=bar"* ]]
    [[ "$result" == *"BAZ=qux"* ]]
}

@test "unsupported format version" {
    run "$ARCANE" unpack -p secret -o unpacked "$ARTIFACTS/wrong-version"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unsupported format version"* ]]
}

@test "custom compression level round-trips" {
    "$ARCANE" pack -p secret -l 5 -o packed /usr/bin/ls
    "$ARCANE" unpack -p secret -o unpacked packed
    cmp /usr/bin/ls unpacked
}

@test "custom kdf params round-trip" {
    "$ARCANE" pack -p secret --kdf-memory 65536 --kdf-time 2 --kdf-parallelism 4 -o packed /usr/bin/ls
    "$ARCANE" unpack -p secret -o unpacked packed
    cmp /usr/bin/ls unpacked
}

@test "run a packed executable with custom kdf params" {
    "$ARCANE" pack -p secret --kdf-memory 65536 --kdf-time 2 --kdf-parallelism 4 -o packed /usr/bin/echo
    result=$(send_password secret ./packed hello world)
    [[ "$result" == *"hello world"* ]]
}

@test "reject compression level 0" {
    run "$ARCANE" pack -p secret -l 0 -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"Compression level must be between 1 and 22"* ]]
}

@test "reject compression level 23" {
    run "$ARCANE" pack -p secret -l 23 -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"Compression level must be between 1 and 22"* ]]
}

@test "reject kdf time 0" {
    run "$ARCANE" pack -p secret --kdf-time 0 -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"KDF time must be greater than 0"* ]]
}

@test "reject kdf parallelism 0" {
    run "$ARCANE" pack -p secret --kdf-parallelism 0 -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"KDF parallelism must be greater than 0"* ]]
}

@test "reject kdf memory less than 8 times parallelism" {
    run "$ARCANE" pack -p secret --kdf-memory 1 --kdf-parallelism 4 -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"KDF memory must be at least 8 * parallelism"* ]]
}

@test "reject env var name exceeding u16 max length" {
    long_name=$(printf '%0.sA' $(seq 1 65536))
    run "$ARCANE" pack -p secret -e "${long_name}=value" -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
}

@test "reject password exceeding max length" {
    long_pw=$(printf '%0.sA' $(seq 1 1025))
    run send_password "$long_pw" "$ARCANE" pack -o packed /usr/bin/ls
    [ "$status" -ne 0 ]
    [[ "$output" == *"Password is too long"* ]]
}

@test "reject password exceeding max length when running packed" {
    "$ARCANE" pack -p secret -o packed /usr/bin/echo
    long_pw=$(printf '%0.sA' $(seq 1 1025))
    run send_password "$long_pw" ./packed
    [ "$status" -ne 0 ]
    [[ "$output" == *"Password is too long"* ]]
}

@test "run packed with wrong password fails" {
    "$ARCANE" pack -p right -o packed /usr/bin/echo
    run send_password wrong ./packed
    [ "$status" -ne 0 ]
}
