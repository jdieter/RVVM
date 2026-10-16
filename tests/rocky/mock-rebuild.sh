#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# mock-rebuild.sh <rvvm_user> <srpm> [mock-config] [resultdir]
#
# Rebuild a source RPM with mock as koji does, %check included, but with
# <rvvm_user> as the RISC-V interpreter instead of the installed one. Run it
# with sudo on a builder whose /etc/binfmt.d/rvvm-riscv64.conf registers the
# installed interpreter; mock drops to the invoking user (SUDO_UID).
#
# The candidate is registered in the private binfmt_misc instance of a new
# user namespace with an identity mapping (Linux 6.7+), so the host's
# registration and installed interpreter are never touched. The mock root
# gets its own --uniqueext, so other roots on the host are left alone.
#
# Signals: a build started from a shell's background job inherits SIGINT and
# SIGQUIT as ignored, and every test of KeyboardInterrupt or SIGINT handling
# then fails. This script resets HUP, INT, QUIT and PIPE to their defaults
# itself. To keep a long build independent of the login session, start it
# with systemd-run in the login session's SELinux domain: in the default
# service domain, mock's userdel/groupadd --root fail on the root (status 3).
#   sudo systemd-run --unit=rebuild-foo -p SELinuxContext=unconfined_u:unconfined_r:unconfined_t:s0 \
#       -E SUDO_UID=$(id -u) -E SUDO_GID=$(id -g) -E SUDO_USER=$(id -un) \
#       /bin/bash tests/rocky/mock-rebuild.sh ./rvvm_user foo.src.rpm
#
# Exit status is mock's. The result directory holds mock's logs and RPMs;
# "interpreter.sha256" records the candidate used.
set -euo pipefail

if [[ ${1:-} != --inner ]]; then
    if (($# < 2)); then
        sed -n '3,26s/^# \{0,1\}//p' "$0" >&2
        exit 2
    fi
    [[ $(id -u) == 0 && -n ${SUDO_UID:-} ]] || { echo "mock-rebuild.sh: run with sudo" >&2; exit 2; }
    rvvm=$(readlink -f "$1") srpm=$(readlink -f "$2")
    config=${3:-rocky-10-riscv64-rvvm}
    result=$(readlink -m "${4:-./result-$(basename "$srpm" .src.rpm)}")
    [[ -x $rvvm && -f $srpm ]] || { echo "mock-rebuild.sh: missing $rvvm or $srpm" >&2; exit 2; }
    install -d -m 0775 -o "$SUDO_UID" -g "${SUDO_GID:-$SUDO_UID}" "$result"
    sha256sum "$rvvm" > "$result/interpreter.sha256"
    exec env --default-signal=HUP,INT,QUIT,PIPE \
        unshare --map-users=0:0:65536 --map-groups=0:0:65536 --mount --mount-binfmt \
        --pid --fork bash "$0" --inner "$rvvm" "$srpm" "$config" "$result"
fi
shift
rvvm=$1 srpm=$2 config=$3 result=$4
mount --make-rprivate /
binfmt=/proc/sys/fs/binfmt_misc
extra=$(ls "$binfmt" | grep -v -x -e register -e status || true)
if [[ -n $extra ]] || ! findmnt -n "$binfmt" >/dev/null; then
    echo "mock-rebuild.sh: refusing to register outside a private binfmt instance" >&2
    exit 99
fi
line=$(grep -m1 '^:rvvm-riscv64:' /etc/binfmt.d/rvvm-riscv64.conf)
installed=$(echo "$line" | awk -F: '{print $(NF-1)}')
printf '%s\n' "${line//$installed/$rvvm}" > "$binfmt/register"
grep -E '^(interpreter|flags)' "$binfmt/rvvm-riscv64"
# Name the root after the package and candidate, with no dots.
name=$(rpm -qp --qf '%{NAME}' "$srpm" 2>/dev/null || basename "$srpm" .src.rpm)
unique=$(printf '%s' "$name" | tr -c 'A-Za-z0-9_' '-')-$(sha256sum "$rvvm" | cut -c1-8)
# mock stays a child of this shell, not the PID namespace's init.
/usr/libexec/mock/mock -r "$config" --uniqueext="$unique" --resultdir="$result" --rebuild "$srpm"
