#!/bin/sh
set -eu

if [ "$#" -lt 20 ] || [ "$(/usr/bin/id -u)" -ne 0 ] || [ "$$" -ne 1 ]; then
    echo "sealed Linux command requires root and exact boundary arguments" >&2
    exit 1
fi
build_uid=$1
original_home=$2
hidden_home=$3
build_home=$4
build_tmp=$5
cargo_home=$6
target_dir=$7
trusted_bin=$8
rustc=$9
rustdoc=${10}
rustfmt=${11}
rustdocflags=${12}
rustc_bootstrap=${13}
sealed_dependency_target=${14}
sealed_workspace_target=${15}
original_cargo_home=${16}
host_write_target=${17}
var_tmp_target=${18}
delayed_write_target=${19}
shift 19
if [ "$#" -lt 1 ]; then
    echo "sealed Linux command requires one command after 19 fixed arguments" >&2
    exit 1
fi
case "$target_dir" in
    */ordinary-wallet-plan-public-proof-target) inactive_target_dir=${target_dir%/*}/workspace-target ;;
    */workspace-target) inactive_target_dir=${target_dir%/*}/ordinary-wallet-plan-public-proof-target ;;
    *) exit 1 ;;
esac

case "$build_uid" in *[!0-9]*|'') exit 1 ;; esac
for path in "$original_home" "$hidden_home" "$build_home" "$build_tmp" "$cargo_home" "$target_dir" "$trusted_bin" "$original_cargo_home" "$host_write_target" "$var_tmp_target" "$delayed_write_target"; do
    case "$path" in /*) ;; *) exit 1 ;; esac
done
if [ "$(/usr/bin/readlink /proc/1/ns/pid)" != "$(/usr/bin/readlink /proc/self/ns/pid)" ] ||
    [ "$(/usr/bin/findmnt --noheadings --output FSTYPE --target /proc | /usr/bin/tr -d ' ')" != proc ] ||
    ! /usr/bin/awk '$1 == "NSpid:" && $NF == "1" { accepted = 1 } END { exit !accepted }' /proc/self/status; then
    echo "sealed Linux command lacks a private PID namespace and procfs" >&2
    exit 1
fi
/usr/bin/mount --bind "$hidden_home" "$original_home"

# Every inherited host mount is read-only in this private namespace. Only the
# exact per-command build roots are rebound writable below.
mountpoints="$(/usr/bin/findmnt --kernel --list --noheadings --output TARGET | /usr/bin/sort -r)"
old_ifs=$IFS
IFS='
'
for mountpoint in $mountpoints; do
    /usr/bin/mount --remount --bind --read-only "$mountpoint"
done
IFS=$old_ifs
for writable in "$build_home" "$build_tmp" "$target_dir"; do
    /usr/bin/mount --bind "$writable" "$writable"
    /usr/bin/mount --remount --bind --rw "$writable"
done

sealed_workspace_root=${sealed_workspace_target%/*}
exec /usr/bin/python3 "$sealed_workspace_root/ci/run-sealed-command-supervisor.py" \
    /usr/bin/setpriv --reuid="$build_uid" --regid="$build_uid" --clear-groups \
    /usr/bin/env -i HOME="$build_home" TMPDIR="$build_tmp" PATH="$trusted_bin:/usr/bin:/bin" \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
    RUSTC="$rustc" RUSTDOC="$rustdoc" RUSTFMT="$rustfmt" \
    RUSTDOCFLAGS="$rustdocflags" RUSTC_BOOTSTRAP="$rustc_bootstrap" \
    SEALED_DEPENDENCY_TARGET="$sealed_dependency_target" \
    SEALED_WORKSPACE_TARGET="$sealed_workspace_target" \
    SEALED_ORIGINAL_CARGO_HOME="$original_cargo_home" \
    SEALED_BUILD_HOME="$build_home" SEALED_BUILD_TMP="$build_tmp" SEALED_BUILD_TARGET="$target_dir" \
    SEALED_HOST_WRITE_TARGET="$host_write_target" SEALED_VAR_TMP_TARGET="$var_tmp_target" \
    SEALED_DELAYED_WRITE_TARGET="$delayed_write_target" \
    SEALED_INACTIVE_BUILD_TARGET="$inactive_target_dir" \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
    "$@"
