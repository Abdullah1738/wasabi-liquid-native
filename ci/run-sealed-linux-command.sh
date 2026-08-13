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
expected_workspace_target="${target_dir%/*}/sealed-workspace/Cargo.toml"
if [ "$sealed_workspace_target" != "$expected_workspace_target" ]; then
    echo "sealed Linux workspace target differs from its exact sibling" >&2
    exit 1
fi
sealed_workspace_root=${sealed_workspace_target%/Cargo.toml}

case "$build_uid" in *[!0-9]*|'') exit 1 ;; esac
for path in "$original_home" "$hidden_home" "$build_home" "$build_tmp" "$cargo_home" "$target_dir" "$trusted_bin" "$original_cargo_home" "$host_write_target" "$var_tmp_target" "$delayed_write_target"; do
    case "$path" in /*) ;; *) exit 1 ;; esac
done
if ! pid_one_namespace="$(/usr/bin/readlink /proc/1/ns/pid)"; then
    echo "sealed Linux PID-one namespace handle is unavailable" >&2
    exit 1
fi
if ! active_pid_namespace="$(/usr/bin/readlink /proc/self/ns/pid)"; then
    echo "sealed Linux active PID namespace handle is unavailable" >&2
    exit 1
fi
if [ "$pid_one_namespace" != "$active_pid_namespace" ]; then
    echo "sealed Linux procfs PID namespace differs from the active namespace" >&2
    exit 1
fi
if ! proc_filesystem_type="$(/usr/bin/findmnt --first-only --noheadings --raw --output FSTYPE --target /proc)"; then
    echo "sealed Linux proc filesystem type lookup failed" >&2
    exit 1
fi
if [ "$proc_filesystem_type" != proc ]; then
    echo "sealed Linux proc filesystem type is not proc" >&2
    exit 1
fi
if [ ! -r /proc/1/status ]; then
    echo "sealed Linux PID-one status is unavailable" >&2
    exit 1
fi
if ! /usr/bin/awk '$1 == "NSpid:" && $NF == "1" { accepted = 1 } END { exit !accepted }' /proc/1/status; then
    echo "sealed Linux PID-one namespace PID is not one" >&2
    exit 1
fi
/usr/bin/mount --bind "$hidden_home" "$original_home"
preexisting_mount_ids="$(/usr/bin/awk 'NF < 6 { exit 1 } { print $1 }' /proc/self/mountinfo | /usr/bin/sort -n)"
if [ -z "$preexisting_mount_ids" ]; then
    echo "sealed Linux pre-transition mount inventory is empty" >&2
    exit 1
fi

# Apply the read-only VFS attribute directly to the complete inherited mount
# tree. Kernel mountinfo is then the authority that every record transitioned.
/usr/bin/python3 -I "$sealed_workspace_root/ci/set-recursive-mount-readonly.py"
post_transition_mount_ids="$(/usr/bin/awk 'NF < 6 { exit 1 } { print $1 }' /proc/self/mountinfo | /usr/bin/sort -n)"
if [ "$post_transition_mount_ids" != "$preexisting_mount_ids" ]; then
    echo "sealed Linux mount inventory changed during read-only transition" >&2
    exit 1
fi
if ! /usr/bin/awk '
function has_option(options, wanted, count, position, fields) {
    count = split(options, fields, ",")
    for (position = 1; position <= count; position++) {
        if (fields[position] == wanted) return 1
    }
    return 0
}
NF < 6 { invalid = 1; next }
{
    read_only = has_option($6, "ro")
    read_write = has_option($6, "rw")
    if (!read_only || read_write) {
        invalid = 1
        if (reported < 20) {
            print "sealed Linux unexpected writable mount record: " $5 " " $6 > "/dev/stderr"
        }
        reported++
    }
    if ($5 == "/" && read_only && !read_write) root_read_only = 1
}
END {
    if (reported > 20) {
        print "sealed Linux additional writable mount records: " reported - 20 > "/dev/stderr"
    }
    exit !(NR > 0 && root_read_only && !invalid)
}
' /proc/self/mountinfo; then
    echo "sealed Linux recursive read-only mount transition is incomplete" >&2
    exit 1
fi

# Only the exact per-command build roots are rebound writable.
for writable in "$build_home" "$build_tmp" "$target_dir"; do
    /usr/bin/mount --bind "$writable" "$writable"
    /usr/bin/mount -o remount,bind,rw "$writable"
done
if ! /usr/bin/awk -v build_home="$build_home" -v build_tmp="$build_tmp" -v target_dir="$target_dir" '
function has_option(options, wanted, count, position, fields) {
    count = split(options, fields, ",")
    for (position = 1; position <= count; position++) {
        if (fields[position] == wanted) return 1
    }
    return 0
}
NF < 6 { invalid = 1; next }
{
    read_only = has_option($6, "ro")
    read_write = has_option($6, "rw")
    if (read_only == read_write) invalid = 1
    if ($5 == "/" && read_only && !read_write) root_read_only = 1
    if (read_write) {
        if ($5 == build_home) build_home_count++
        else if ($5 == build_tmp) build_tmp_count++
        else if ($5 == target_dir) target_dir_count++
        else invalid = 1
    }
}
END {
    exit !(NR > 0 && root_read_only && !invalid &&
        build_home_count == 1 && build_tmp_count == 1 && target_dir_count == 1)
}
' /proc/self/mountinfo; then
    echo "sealed Linux writable mount inventory differs from the exact build roots" >&2
    exit 1
fi

cd -P "$sealed_workspace_root"
if [ "$(/bin/pwd -P)" != "$sealed_workspace_root" ]; then
    echo "sealed Linux workspace root is nonphysical or noncanonical" >&2
    exit 1
fi
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
