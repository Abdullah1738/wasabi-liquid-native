#!/bin/sh
set -eu

if [ "$#" -lt 20 ] || [ "$(/usr/bin/id -u)" -ne 0 ]; then
    echo "sealed Darwin command requires root and exact boundary arguments" >&2
    exit 1
fi
build_user=$1
build_uid=$2
sandbox_profile=$3
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
    echo "sealed Darwin command requires one command after 19 fixed arguments" >&2
    exit 1
fi
case "$target_dir" in
    */ordinary-wallet-plan-public-proof-target) inactive_target_dir=${target_dir%/*}/workspace-target ;;
    */workspace-target) inactive_target_dir=${target_dir%/*}/ordinary-wallet-plan-public-proof-target ;;
    *) exit 1 ;;
esac

case "$build_user" in *[!a-z0-9]*|'') exit 1 ;; esac
case "$build_uid" in *[!0-9]*|'') exit 1 ;; esac
for path in "$sandbox_profile" "$build_home" "$build_tmp" "$cargo_home" "$target_dir" "$trusted_bin" "$rustc" "$rustdoc" "$rustfmt" "$original_cargo_home" "$host_write_target" "$var_tmp_target" "$delayed_write_target"; do
    case "$path" in /*) ;; *) exit 1 ;; esac
done

set +e
/usr/bin/sudo -n -u "$build_user" /usr/bin/sandbox-exec -f "$sandbox_profile" \
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
status=$?

# This account is unique to this gate, so clearing its process ownership does
# not affect another job. TERM is followed by KILL and an exact zero-process
# assertion before control returns.
/usr/bin/pkill -TERM -u "$build_uid" 2>/dev/null || :
/bin/sleep 1
/usr/bin/pkill -KILL -u "$build_uid" 2>/dev/null || :
if /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; then
    echo "sealed Darwin command left an unreaped descendant" >&2
    exit 1
fi
exit "$status"
