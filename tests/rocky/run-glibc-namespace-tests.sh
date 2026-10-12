#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Run inside Mock's nspawn context. A namespace denial is a failure of this
# acceptance check, not successful coverage of the emulator.
set -euo pipefail
[[ $(id -u) = 0 ]]
root=${1:?preserved glibc Mock root}
out=${2:?new results directory}
mkdir "$out"
exec 9>/run/lock/rvvm-glibc-dev-validation.lock
flock -n 9
sha256sum /usr/local/bin/rvvm-riscv64-static > "$out/emulator.sha256"
targets=(dirent/tst-readdir-long dirent/tst-readdir-zero-inode dirent/tst-rewinddir
         elf/tst-pldd io/tst-getcwd-smallbuff stdio-common/tst-fwrite-pos)
if [[ ${3:-} ]]; then mapfile -t targets < "$3"; fi
((${#targets[@]}))
for test in "${targets[@]}"; do [[ $test =~ ^[a-z0-9_-]+/[a-zA-Z0-9_.-]+$ ]]; done
printf '%s\n' "${targets[@]}" > "$out/targets.txt"
modes=(39:jit 39:interpreter 48:jit 48:interpreter)
if [[ ${4:-} ]]; then
    [[ $4 =~ ^(39|48):(jit|interpreter)$ ]]
    modes=("$4")
fi
cat > "$out/guest-check.sh" <<'GUEST'
#!/bin/bash
set -euo pipefail
ulimit -c 0
export TIMEOUTFACTOR=16
export RVVM_USER_PREFIX= RVVM_USER_BINFMT=1
export RVVM_USER_VA_BITS=$1
unset RVVM_NOJIT
[[ $2 != interpreter ]] || export RVVM_NOJIT=1
src=/builddir/build/BUILD/glibc-2.39
build=$src/build-riscv64-redhat-linux
declare -a groups=()
declare -A tests=()
while IFS= read -r test; do
    group=${test%/*}
    [[ -v tests[$group] ]] || groups+=("$group")
    tests[$group]+=" ${test#*/}"
done < "$3"
for group in "${groups[@]}"; do
    outputs=()
    for test in ${tests[$group]}; do outputs+=("$build/$group/$test.out"); done
    # Use the original recipes, including test-container and per-test settings.
    # A partial rerun must not rescan transient testroot DSOs as library targets.
    /usr/bin/make -C "$src/$group" -O -j48 V=1 VERBOSE=1 \
        objdir="$build" "${outputs[@]}"
    for test in ${tests[$group]}; do
        grep -qx "PASS: $group/$test" "$build/$group/$test.test-result"
        echo "VERIFIED PASS $group/$test"
    done
done
GUEST
install -m755 "$out/guest-check.sh" "$root/var/tmp/rvvm-glibc-namespace-guest-check.sh"
install -m644 "$out/targets.txt" "$root/var/tmp/rvvm-glibc-namespace-targets.txt"
build=$root/builddir/build/BUILD/glibc-2.39/build-riscv64-redhat-linux
for pair in "${modes[@]}"; do
    bits=${pair%:*}
    mode=${pair#*:}
    result=$out/sv$bits-$mode
    mkdir -p "$result/previous" "$result/current"
    for test in "${targets[@]}"; do
        mkdir -p "$result/previous/${test%/*}" "$result/current/${test%/*}"
        for suffix in out test-result; do
            [[ ! -e $build/$test.$suffix ]] || mv "$build/$test.$suffix" "$result/previous/$test.$suffix"
        done
    done
    date -u +%FT%TZ > "$result/started.txt"
    set +e
    SYSTEMD_SECCOMP=0 SYSTEMD_NSPAWN_TMPFS_TMP=0 systemd-nspawn -q \
        --register=no -D "$root" -a -u mockbuild --capability=cap_ipc_lock \
        --bind=/dev/fuse --console=pipe /bin/bash \
        /var/tmp/rvvm-glibc-namespace-guest-check.sh "$bits" "$mode" \
        /var/tmp/rvvm-glibc-namespace-targets.txt \
        > "$result/check.log" 2>&1
    status=$?
    set -e
    printf '%s\n' "$status" > "$result/exit-status.txt"
    date -u +%FT%TZ > "$result/finished.txt"
    for test in "${targets[@]}"; do
        for suffix in out test-result; do
            [[ ! -e $build/$test.$suffix ]] || cp "$build/$test.$suffix" "$result/current/$test.$suffix"
        done
    done
    if ((status)); then tail -60 "$result/check.log"; exit "$status"; fi
    grep '^VERIFIED PASS ' "$result/check.log"
done
sha256sum /usr/local/bin/rvvm-riscv64-static > "$out/emulator-after.sha256"
cmp "$out/emulator.sha256" "$out/emulator-after.sha256"
