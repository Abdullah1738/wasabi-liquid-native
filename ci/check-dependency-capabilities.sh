#!/bin/sh
set -eu

# The CI workflow supplies loader isolation by launching this gate through a
# minimal environment. Direct local invocation is not loader-isolated; its
# already-loaded shell remains part of the ambient trust base. The gate still
# rejects common loader overrides before launching further child tools.
PATH=/usr/bin:/bin
export PATH

repository_root="$(/bin/pwd -P)"
if [ ! -f ci/check-dependency-capabilities.sh ]; then
    echo "dependency capability gate must run from the repository root" >&2
    exit 1
fi
if env | grep -Eiq '^(CARGO(=|_)|RUSTC(=|_)|RUSTDOC(=|_)|RUSTFMT(=|_)|RUSTFLAGS=|RUSTDOCFLAGS=|RUSTUP_(HOME|TOOLCHAIN)=|PYTHON(=|_)|VIRTUAL_ENV=|PERL5(OPT|LIB)=|BASH_ENV=|ENV=|CDPATH=|SHELLOPTS=|BASHOPTS=|MAKEFLAGS=|MFLAGS=|MAKELEVEL=|GIT_(CONFIG|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|WORK_TREE|DIR|CEILING_DIRECTORIES)(=|_)|GIT_ASKPASS=|SSH_(ASKPASS|AUTH_SOCK|AGENT_PID)=|(HTTP|HTTPS|ALL|NO)_PROXY=|[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY)[A-Z0-9_]*=|AWS_[A-Z0-9_]+=|HOST=|TARGET=|((HOST|TARGET)_)?(CC|CXX|AR|ARFLAGS|RANLIB|RANLIBFLAGS|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)(=|_)|[A-Z0-9_]+_(CC|CXX|AR|ARFLAGS|RANLIB|RANLIBFLAGS|LINKER|RUSTFLAGS|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS)=|COMPILER_PATH=|GCC_EXEC_PREFIX=|CPATH=|C_INCLUDE_PATH=|CPLUS_INCLUDE_PATH=|OBJC_INCLUDE_PATH=|LIBRARY_PATH=|LD_RUN_PATH=|LD_(LIBRARY_PATH|PRELOAD|AUDIT|DEBUG|PROFILE|USE_LOAD_BIAS|BIND_NOW|ORIGIN_PATH)=|DYLD_[A-Z0-9_]+=|DEPENDENCIES_OUTPUT=|SUNPRO_DEPENDENCIES=|CCC_OVERRIDE_OPTIONS=|CCC_PRINT_OPTIONS=|CCC_PRINT_BINDINGS=|CLANG_CONFIG_FILE_(SYSTEM|USER)_DIR=|CLANG_NO_DEFAULT_CONFIG=|MACOSX_DEPLOYMENT_TARGET=|DEVELOPER_DIR=|SDKROOT=|CRATE_CC_NO_DEFAULTS=|CC_SHELL_ESCAPED_FLAGS=)'; then
    echo "compiler or Cargo execution environment contains an unreviewed override" >&2
    exit 1
fi
host_system="$(/usr/bin/uname -s)"
case "$host_system" in
    Darwin) python_bin=/opt/homebrew/bin/python3; chown_bin=/usr/sbin/chown ;;
    Linux) python_bin=/usr/bin/python3; chown_bin=/usr/bin/chown ;;
    *) echo "unsupported compiler host" >&2; exit 1 ;;
esac
darwin_developer_dir=
darwin_sdkroot=
darwin_toolchain_bin=
darwin_cc_bin=
darwin_cxx_bin=
darwin_ar_bin=
darwin_as_bin=
darwin_ld_bin=
darwin_nm_bin=
darwin_ranlib_bin=
darwin_strip_bin=
darwin_cc_sha256=
darwin_cxx_sha256=
darwin_ar_sha256=
darwin_as_sha256=
darwin_ld_sha256=
darwin_nm_sha256=
darwin_ranlib_sha256=
darwin_strip_sha256=
prepare_darwin_toolchain() {
    if [ "$host_system" != Darwin ]; then
        return
    fi
    expected_darwin_developer_dir=/Applications/Xcode_15.4.app/Contents/Developer
    expected_darwin_sdkroot="$expected_darwin_developer_dir/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
    expected_darwin_xcode_version='Xcode 15.4
Build version 15F31d'
    darwin_host_uid="$(/usr/bin/id -u)"
    case "$darwin_host_uid" in *[!0-9]*|'') echo "Darwin host UID is unavailable" >&2; exit 1 ;; esac
    darwin_require_host_authority_path() {
        authority_path=$1
        authority_type=$2
        authority_state="$(/usr/bin/sudo -n /usr/bin/stat -f '%u:%OLp:%HT' "$authority_path")"
        authority_uid=${authority_state%%:*}
        authority_remainder=${authority_state#*:}
        authority_mode=${authority_remainder%%:*}
        authority_actual_type=${authority_remainder#*:}
        case "$authority_mode" in
            [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
            *) echo "selected Darwin path has a noncanonical mode: $authority_path" >&2; exit 1 ;;
        esac
        if { [ "$authority_uid" != 0 ] && [ "$authority_uid" != "$darwin_host_uid" ]; } || [ "$authority_actual_type" != "$authority_type" ]; then
            echo "selected Darwin path has an unreviewed owner or type: $authority_path" >&2
            exit 1
        fi
        case "$authority_mode" in
            *[2367][0-7]|*[0-7][2367])
                echo "selected Darwin path is writable outside its host owner: $authority_path" >&2
                exit 1
                ;;
        esac
    }
    darwin_resolve_tool() {
        tool_path="$darwin_toolchain_bin/$1"
        link_depth=0
        while [ -L "$tool_path" ]; do
            link_name="$(/usr/bin/readlink "$tool_path")"
            case "$link_name" in ''|.|..|*/*) echo "selected Darwin tool symlink escapes its reviewed directory" >&2; exit 1 ;; esac
            tool_path="$darwin_toolchain_bin/$link_name"
            link_depth=$((link_depth + 1))
            if [ "$link_depth" -gt 8 ]; then
                echo "selected Darwin tool symlink chain is noncanonical" >&2
                exit 1
            fi
        done
        tool_parent="$(cd -P "${tool_path%/*}" && /bin/pwd -P)"
        tool_path="$tool_parent/${tool_path##*/}"
        case "$tool_path" in "$darwin_toolchain_bin"/*) ;; *) echo "selected Darwin tool escapes its reviewed directory" >&2; exit 1 ;; esac
        if [ ! -f "$tool_path" ] || [ ! -x "$tool_path" ]; then
            echo "selected Darwin tool is unavailable: $1" >&2
            exit 1
        fi
        darwin_require_host_authority_path "$tool_path" 'Regular File'
        /usr/bin/printf '%s\n' "$tool_path"
    }
    darwin_developer_dir="$(/usr/bin/xcode-select --print-path)"
    darwin_developer_dir="$(cd -P "$darwin_developer_dir" && /bin/pwd -P)"
    if [ "$darwin_developer_dir" != "$expected_darwin_developer_dir" ]; then
        echo "selected Darwin developer directory differs from Xcode 15.4" >&2
        exit 1
    fi
    darwin_require_host_authority_path "$darwin_developer_dir" 'Directory'
    darwin_xcodebuild="$darwin_developer_dir/usr/bin/xcodebuild"
    darwin_require_host_authority_path "$darwin_xcodebuild" 'Regular File'
    if [ "$("$darwin_xcodebuild" -version)" != "$expected_darwin_xcode_version" ]; then
        echo "selected Darwin Xcode build identity differs from 15F31d" >&2
        exit 1
    fi
    darwin_sdkroot="$(DEVELOPER_DIR="$darwin_developer_dir" /usr/bin/xcrun --sdk macosx --show-sdk-path)"
    darwin_sdkroot="$(cd -P "$darwin_sdkroot" && /bin/pwd -P)"
    if [ "$darwin_sdkroot" != "$expected_darwin_sdkroot" ]; then
        echo "selected Darwin SDK differs from the Xcode 15.4 default" >&2
        exit 1
    fi
    darwin_require_host_authority_path "$darwin_sdkroot" 'Directory'
    darwin_toolchain_bin="$darwin_developer_dir/Toolchains/XcodeDefault.xctoolchain/usr/bin"
    darwin_toolchain_bin="$(cd -P "$darwin_toolchain_bin" && /bin/pwd -P)"
    darwin_require_host_authority_path "$darwin_toolchain_bin" 'Directory'
    if [ "$(DEVELOPER_DIR="$darwin_developer_dir" /usr/bin/xcrun --sdk macosx --find clang)" != "$darwin_toolchain_bin/clang" ]; then
        echo "selected Darwin clang differs from the reviewed default toolchain" >&2
        exit 1
    fi
    darwin_cc_bin="$(darwin_resolve_tool clang)"
    darwin_cxx_bin="$(darwin_resolve_tool clang++)"
    darwin_ar_bin="$(darwin_resolve_tool ar)"
    darwin_as_bin="$(darwin_resolve_tool as)"
    darwin_ld_bin="$(darwin_resolve_tool ld)"
    darwin_nm_bin="$(darwin_resolve_tool nm)"
    darwin_ranlib_bin="$(darwin_resolve_tool ranlib)"
    darwin_strip_bin="$(darwin_resolve_tool strip)"
    darwin_cc_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_cc_bin")"
    darwin_cxx_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_cxx_bin")"
    darwin_ar_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ar_bin")"
    darwin_as_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_as_bin")"
    darwin_ld_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ld_bin")"
    darwin_nm_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_nm_bin")"
    darwin_ranlib_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_ranlib_bin")"
    darwin_strip_sha256="$("$python_bin" -I ci/check-sealed-rust-command-bin.py --digest "$darwin_strip_bin")"
    for darwin_system_exec in \
        /usr/bin/env /bin/sh /bin/bash /bin/pwd /bin/sleep /bin/zsh /usr/bin/dirname /bin/realpath; do
        darwin_require_host_authority_path "$darwin_system_exec" 'Regular File'
    done
}
if [ ! -x "$python_bin" ]; then
    echo "reviewed Python interpreter path is unavailable" >&2
    exit 1
fi
"$python_bin" -I ci/check-ordinary-wallet-plan-public-proof-surface.py "$repository_root"
"$python_bin" -I ci/check-wlpq-ffi-surface.py "$repository_root"
"$python_bin" -I ci/test-wlpq-ffi-surface.py
"$python_bin" -I ci/check-cargo-fetch-preflight.py "$repository_root"
if ! compiler_toolchain_root="$("$python_bin" -I ci/check-pinned-rust-toolchain.py "${HOME:?}")"; then
    echo "dependency compiler and artifact gates require Cargo 1.96.0" >&2
    exit 1
fi
compiler_cargo_bin="$compiler_toolchain_root/bin/cargo"
compiler_rustc_bin="$compiler_toolchain_root/bin/rustc"
compiler_rustdoc_bin="$compiler_toolchain_root/bin/rustdoc"
compiler_rustfmt_bin="$compiler_toolchain_root/bin/rustfmt"
cargo_bin="$compiler_cargo_bin"
if ! /usr/bin/sudo -n true; then
    echo "distinct-owner build boundary requires noninteractive sudo" >&2
    exit 1
fi
prepare_darwin_toolchain
original_home="${HOME:?}"
scratch="$(/usr/bin/mktemp -d "/tmp/wasabi-liquid-dependency-gate.XXXXXX")"
scratch="$(cd "$scratch" && pwd -P)"
proof_snapshot="$scratch/ordinary-wallet-plan-public-proof-snapshot"
build_user=
build_uid=
var_tmp_target=
var_tmp_physical_target=
darwin_account_lock=/var/tmp/wasabi-liquid-wlpq-account.lock
darwin_account_marker=
darwin_account_marker_value=
TMPDIR=/tmp
export TMPDIR
darwin_account_matches() {
    [ -n "$build_user" ] && [ -n "$build_uid" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" RecordName 2>/dev/null)" = "RecordName: $build_user" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" UniqueID 2>/dev/null)" = "UniqueID: $build_uid" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" PrimaryGroupID 2>/dev/null)" = "PrimaryGroupID: 20" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" NFSHomeDirectory 2>/dev/null)" = "NFSHomeDirectory: $scratch/build-home" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" UserShell 2>/dev/null)" = "UserShell: /usr/bin/false" ]
}
darwin_marker_matches() {
    [ -n "$darwin_account_marker" ] &&
        [ -n "$darwin_account_marker_value" ] &&
        [ "$(/usr/bin/sudo -n /usr/bin/stat -f '%u:%Lp' "$darwin_account_marker" 2>/dev/null)" = "0:400" ] &&
        [ "$(/usr/bin/sudo -n /bin/cat "$darwin_account_marker" 2>/dev/null)" = "$darwin_account_marker_value" ]
}
cleanup() {
    if [ "$host_system" = Darwin ] && [ -n "$darwin_account_marker" ]; then
        if darwin_marker_matches; then
            if /usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" >/dev/null 2>&1; then
                if darwin_account_matches; then
                    /usr/bin/sudo -n /usr/bin/pkill -TERM -u "$build_uid" 2>/dev/null || :
                    /bin/sleep 1
                    /usr/bin/sudo -n /usr/bin/pkill -KILL -u "$build_uid" 2>/dev/null || :
                    if /usr/bin/sudo -n /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; then
                        echo "refusing Darwin account cleanup while exact UID still owns a process" >&2
                    else
                        /usr/bin/sudo -n /usr/bin/dscl . -delete "/Users/$build_user"
                    fi
                else
                    echo "refusing Darwin account cleanup after account attributes changed" >&2
                fi
            fi
            if ! /usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" >/dev/null 2>&1; then
                /usr/bin/sudo -n /bin/rm "$darwin_account_marker"
                /usr/bin/sudo -n /bin/rmdir "$darwin_account_lock"
            fi
        else
            echo "refusing Darwin account cleanup after lock marker changed" >&2
        fi
    fi
    if [ -n "$var_tmp_target" ]; then
        /usr/bin/sudo -n /bin/rm -f "$var_tmp_target" 2>/dev/null || :
    fi
    if [ -d "$scratch" ]; then
        /usr/bin/sudo -n "$chown_bin" -R "$(/usr/bin/id -u)" "$scratch" 2>/dev/null || :
        chmod -R u+w "$scratch" 2>/dev/null || :
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT HUP INT TERM
trusted_bin="$scratch/trusted-bin"
/bin/mkdir "$trusted_bin"
link_trusted_tool() {
    trusted_name=$1
    trusted_target=$2
    if [ ! -x "$trusted_target" ]; then
        echo "required trusted tool is unavailable: $trusted_target" >&2
        exit 1
    fi
    /bin/ln -s "$trusted_target" "$trusted_bin/$trusted_name"
}
link_system_tool() {
    system_name=$1
    if [ -x "/usr/bin/$system_name" ]; then
        link_trusted_tool "$system_name" "/usr/bin/$system_name"
    elif [ -x "/bin/$system_name" ]; then
        link_trusted_tool "$system_name" "/bin/$system_name"
    else
        echo "required system tool is unavailable: $system_name" >&2
        exit 1
    fi
}
link_trusted_tool python3 "$python_bin"
link_trusted_tool cargo "$compiler_cargo_bin"
link_trusted_tool rustc "$compiler_rustc_bin"
link_trusted_tool rustdoc "$compiler_rustdoc_bin"
link_trusted_tool rustfmt "$compiler_rustfmt_bin"
link_trusted_tool cargo-fmt "$compiler_toolchain_root/bin/cargo-fmt"
link_trusted_tool cargo-clippy "$compiler_toolchain_root/bin/cargo-clippy"
link_trusted_tool clippy-driver "$compiler_toolchain_root/bin/clippy-driver"
for system_name in awk bash cat chmod diff env find git grep head id make mkdir mktemp perl rm sed sh sort tr uname wc; do
    link_system_tool "$system_name"
done
if [ "$host_system" = Darwin ]; then
    link_trusted_tool cc "$darwin_cc_bin"
    link_trusted_tool c++ "$darwin_cxx_bin"
    link_trusted_tool ar "$darwin_ar_bin"
    link_trusted_tool as "$darwin_as_bin"
    link_trusted_tool ld "$darwin_ld_bin"
    link_trusted_tool nm "$darwin_nm_bin"
    link_trusted_tool ranlib "$darwin_ranlib_bin"
    link_trusted_tool strip "$darwin_strip_bin"
else
    for system_name in ar as cc c++ ld nm ranlib strip; do
        link_system_tool "$system_name"
    done
fi
PATH="$trusted_bin"
export PATH
python3 -I ci/test-ordinary-wallet-plan-public-proof-surface.py
python3 -I ci/test-pinned-rust-toolchain.py
python3 -I ci/test-cargo-fetch-preflight.py
python3 -I ci/test-sealed-rust-command-bin.py
python3 -I ci/test-bounded-command-diagnostics.py
python3 -I ci/test-compiler-source-closure.py
python3 -I ci/test-sealed-tree-readable.py
python3 -I ci/test-cargo-credential-provider.py
source_cargo_home="$scratch/source-cargo-home"
proof_authority_cargo_home="$scratch/proof-authority-cargo-home"
workspace_authority_cargo_home="$scratch/workspace-authority-cargo-home"
proof_materialized_cargo_home="$scratch/proof-materialized-cargo-home"
workspace_materialized_cargo_home="$scratch/workspace-materialized-cargo-home"
proof_cargo_home="$scratch/proof-final-cargo-home"
workspace_cargo_home="$scratch/workspace-final-cargo-home"
proof_cache_authority="$scratch/proof-cache-authority.jsonl"
workspace_cache_authority="$scratch/workspace-cache-authority.jsonl"
proof_lock_sha256=4ca45ca0dd27b2a545b0d93174e02487cc756b26a34d946de5dcb349ceea7aab
workspace_lock_sha256=9058d12bbe79b4655ccdccb4315e8c041ec326d114ad4de674c4375c6e8a7318
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --snapshot-only \
    "$repository_root" \
    "$proof_snapshot"
proof_snapshot_authority="$scratch/proof-snapshot-authority.jsonl"
proof_snapshot_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --seal-tree \
        "$proof_snapshot" \
        "$proof_snapshot_authority"
)"
repository_head="$(/usr/bin/git rev-parse HEAD)"
sealed_workspace="$scratch/sealed-workspace"
sealed_workspace_authority="$scratch/sealed-workspace-authority.jsonl"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --workspace-snapshot \
    "$repository_root" \
    "$sealed_workspace" \
    /usr/bin/git \
    "$repository_head"
sealed_workspace_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --seal-tree \
        "$sealed_workspace" \
        "$sealed_workspace_authority"
)"

# Fetch only after all tracked, proof-surface, and toolchain preflights have
# passed. Both closures use an empty Cargo home, a non-checkout HOME, null Git
# configuration, and absolute snapshot manifests from the filesystem root.
for root_cargo_config in /.cargo/config /.cargo/config.toml; do
    if [ -e "$root_cargo_config" ] || [ -L "$root_cargo_config" ]; then
        echo "Cargo configuration exists above snapshot fetch manifest: $root_cargo_config" >&2
        exit 1
    fi
done
fetch_home="$scratch/fetch-home"
fetch_tmp="$scratch/fetch-tmp"
credential_sentinel="$scratch/external-credential-provider-ran"
credential_provider="$scratch/external-credential-provider"
credential_home="$scratch/credential-positive-home"
credential_cargo_home="$scratch/credential-positive-cargo-home"
credential_registry="$scratch/credential-positive-registry"
/bin/mkdir "$source_cargo_home" "$fetch_home" "$fetch_tmp" "$credential_home" "$credential_cargo_home" "$credential_registry"
python3 -I ci/prepare-cargo-credential-provider.py "$credential_provider" "$credential_sentinel"
printf '%s\n' '{"dl":"https://example.invalid/{crate}/{version}/download","api":"https://example.invalid"}' >"$credential_registry/config.json"
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git -C "$credential_registry" init --quiet
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git -C "$credential_registry" -c user.name=wlpq -c user.email=wlpq@invalid add config.json
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git -C "$credential_registry" -c user.name=wlpq -c user.email=wlpq@invalid commit --quiet -m initial
printf '%s\n' \
    '[credential-alias]' \
    "external = [\"$credential_provider\"]" \
    '[registries.wlpq-positive]' \
    "index = \"file://$credential_registry\"" \
    'credential-provider = ["external"]' >"$credential_cargo_home/config.toml"
printf %s wlpq-positive-control | /usr/bin/env -i \
    HOME="$credential_home" TMPDIR="$fetch_tmp" PATH="$trusted_bin" \
    CARGO_HOME="$credential_cargo_home" \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    "$compiler_cargo_bin" login --registry wlpq-positive
if [ "$(cat "$credential_sentinel")" != provider-ran ]; then
    echo "external credential provider positive control did not activate" >&2
    exit 1
fi
/bin/rm "$credential_sentinel"
(
    cd /
    /usr/bin/env -i HOME="$fetch_home" TMPDIR="$fetch_tmp" PATH="$trusted_bin" \
            CARGO_HOME="$source_cargo_home" CARGO_NET_GIT_FETCH_WITH_CLI=true \
            GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
            GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=pack.writeReverseIndex GIT_CONFIG_VALUE_0=false \
            GIT_CONFIG_KEY_1=maintenance.auto GIT_CONFIG_VALUE_1=false \
            GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false SSH_ASKPASS=/usr/bin/false \
            "$compiler_cargo_bin" fetch \
                --manifest-path "$sealed_workspace/Cargo.toml" \
                --locked
    /usr/bin/env -i HOME="$fetch_home" TMPDIR="$fetch_tmp" PATH="$trusted_bin" \
            CARGO_HOME="$source_cargo_home" CARGO_NET_GIT_FETCH_WITH_CLI=true \
            GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1 \
            GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=pack.writeReverseIndex GIT_CONFIG_VALUE_0=false \
            GIT_CONFIG_KEY_1=maintenance.auto GIT_CONFIG_VALUE_1=false \
            GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false SSH_ASKPASS=/usr/bin/false \
            "$compiler_cargo_bin" fetch \
                --manifest-path "$proof_snapshot/Cargo.toml" \
                --locked
)
if [ -e "$credential_sentinel" ]; then
    echo "external credential provider escaped isolated Cargo fetch" >&2
    exit 1
fi
WLPQ_TEST_DARWIN_SDKROOT="$darwin_sdkroot" \
    python3 -I ci/test-ordinary-wallet-plan-proof-snapshot.py "$source_cargo_home"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --copy-cache \
    "$source_cargo_home" \
    "$proof_authority_cargo_home" \
    "$proof_snapshot/Cargo.lock" \
    "$proof_lock_sha256"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --workspace-cache \
    "$sealed_workspace" \
    "$source_cargo_home" \
    "$workspace_authority_cargo_home"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --copy-cache \
    "$proof_authority_cargo_home" \
    "$proof_materialized_cargo_home" \
    "$proof_snapshot/Cargo.lock" \
    "$proof_lock_sha256"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --copy-cache \
    "$workspace_authority_cargo_home" \
    "$workspace_materialized_cargo_home" \
    "$sealed_workspace/Cargo.lock" \
    "$workspace_lock_sha256"
CARGO_HOME="$proof_materialized_cargo_home" CARGO_TARGET_DIR="$scratch/proof-materialize-target" \
    "$compiler_cargo_bin" metadata \
        --manifest-path "$proof_snapshot/Cargo.toml" \
        --locked \
        --offline \
        --format-version 1 >/dev/null
CARGO_HOME="$workspace_materialized_cargo_home" CARGO_TARGET_DIR="$scratch/workspace-materialize-target" \
    "$compiler_cargo_bin" metadata \
        --manifest-path "$sealed_workspace/Cargo.toml" \
        --locked \
        --offline \
        --format-version 1 >/dev/null
proof_cache_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --finalize-cache \
        "$proof_authority_cargo_home" \
        "$proof_materialized_cargo_home" \
        "$proof_cargo_home" \
        "$proof_cache_authority" \
        "$proof_snapshot/Cargo.lock" \
        /usr/bin/git \
        "$proof_lock_sha256"
)"
workspace_cache_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --finalize-cache \
        "$workspace_authority_cargo_home" \
        "$workspace_materialized_cargo_home" \
        "$workspace_cargo_home" \
        "$workspace_cache_authority" \
        "$sealed_workspace/Cargo.lock" \
        /usr/bin/git \
        "$workspace_lock_sha256"
)"
sealed_toolchain="$scratch/sealed-toolchain"
python3 -I ci/check-pinned-rust-toolchain.py \
    --construct-toolchain \
    "$compiler_toolchain_root" \
    "$sealed_toolchain" >/dev/null
python3 -I ci/check-pinned-rust-toolchain.py --toolchain-root "$sealed_toolchain" >/dev/null
case "$("$sealed_toolchain/bin/cargo" --version --verbose)" in
    cargo\ 1.96.0\ *30a34c6821b57de0aaec83a901aca39f88f6778c*) ;;
    *) echo "copied Cargo version or commit mismatch" >&2; exit 1 ;;
esac
case "$("$sealed_toolchain/bin/rustc" --version --verbose)" in
    *commit-hash:\ ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96*release:\ 1.96.0*) ;;
    *) echo "copied Rust compiler version or commit mismatch" >&2; exit 1 ;;
esac
case "$("$sealed_toolchain/bin/rustdoc" --version)" in rustdoc\ 1.96.0\ *) ;; *) exit 1 ;; esac
case "$("$sealed_toolchain/bin/rustfmt" --version)" in rustfmt\ 1.9.0-stable\ *) ;; *) exit 1 ;; esac
sealed_command_bin="$scratch/sealed-rust-command-bin"
/bin/mkdir "$sealed_command_bin"
for command in cargo-fmt cargo-clippy clippy-driver; do
    /bin/ln -s "$sealed_toolchain/bin/$command" "$sealed_command_bin/$command"
done
if [ "$host_system" = Darwin ]; then
    /bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/cc"
    /bin/ln -s "$darwin_cxx_bin" "$sealed_command_bin/c++"
    /bin/ln -s "$darwin_cc_bin" "$sealed_command_bin/clang"
    /bin/ln -s "$darwin_cxx_bin" "$sealed_command_bin/clang++"
    /bin/ln -s "$darwin_ar_bin" "$sealed_command_bin/ar"
    /bin/ln -s "$darwin_as_bin" "$sealed_command_bin/as"
    /bin/ln -s "$darwin_ld_bin" "$sealed_command_bin/ld"
    /bin/ln -s "$darwin_nm_bin" "$sealed_command_bin/nm"
    /bin/ln -s "$darwin_ranlib_bin" "$sealed_command_bin/ranlib"
    /bin/ln -s "$darwin_strip_bin" "$sealed_command_bin/strip"
fi
/bin/chmod 0555 "$sealed_command_bin"
check_sealed_command_bin() {
    if [ "$host_system" = Darwin ]; then
        for darwin_command_target in \
            "$darwin_cc_bin" "$darwin_cxx_bin" "$darwin_ar_bin" "$darwin_as_bin" \
            "$darwin_ld_bin" "$darwin_nm_bin" "$darwin_ranlib_bin" "$darwin_strip_bin"; do
            darwin_require_host_authority_path "$darwin_command_target" 'Regular File'
        done
        python3 -I ci/check-sealed-rust-command-bin.py \
            "$sealed_command_bin" "$sealed_toolchain" \
            "$darwin_cc_bin" "$darwin_cxx_bin" "$darwin_cc_bin" "$darwin_cxx_bin" \
            "$darwin_ar_bin" "$darwin_as_bin" "$darwin_ld_bin" "$darwin_nm_bin" \
            "$darwin_ranlib_bin" "$darwin_strip_bin" \
            "$darwin_cc_sha256" "$darwin_cxx_sha256" "$darwin_cc_sha256" "$darwin_cxx_sha256" \
            "$darwin_ar_sha256" "$darwin_as_sha256" "$darwin_ld_sha256" "$darwin_nm_sha256" \
            "$darwin_ranlib_sha256" "$darwin_strip_sha256"
    else
        python3 -I ci/check-sealed-rust-command-bin.py "$sealed_command_bin" "$sealed_toolchain"
    fi
}
sealed_toolchain_authority="$scratch/sealed-toolchain-authority.jsonl"
sealed_toolchain_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --seal-tree \
        "$sealed_toolchain" \
        "$sealed_toolchain_authority"
)"
sealed_probe="$scratch/sealed-build-boundary-probe"
sealed_probe_authority="$scratch/sealed-build-boundary-probe-authority.jsonl"
python3 -I ci/prepare-sealed-build-boundary-probe.py "$sealed_probe"
sealed_probe_authority_sha256="$(
    python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
        --seal-tree \
        "$sealed_probe" \
        "$sealed_probe_authority"
)"
case "$host_system" in
    Darwin)
        if ! /usr/bin/sudo -n /bin/mkdir "$darwin_account_lock"; then
            echo "Darwin account lifecycle lock already exists; stale and concurrent locks fail closed" >&2
            exit 1
        fi
        /usr/bin/sudo -n "$chown_bin" 0 "$darwin_account_lock"
        /usr/bin/sudo -n /bin/chmod 0700 "$darwin_account_lock"
        if [ "$(/usr/bin/sudo -n /usr/bin/stat -f '%u:%Lp' "$darwin_account_lock")" != "0:700" ]; then
            echo "Darwin account lifecycle lock attributes differ" >&2
            exit 1
        fi
        build_nonce="$(printf '%s' "$scratch:$$" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:20])')"
        build_user="wlpq$build_nonce"
        case "$build_user" in *[!a-z0-9]*|'') echo "Darwin build account name is noncanonical" >&2; exit 1 ;; esac
        if /usr/bin/sudo -n /usr/bin/dscl . -read "/Users/$build_user" >/dev/null 2>&1; then
            echo "collision-resistant Darwin build account name already exists" >&2
            exit 1
        fi
        build_uid=550
        while /usr/bin/sudo -n /usr/bin/dscl . -search /Users UniqueID "$build_uid" 2>/dev/null | /usr/bin/grep -q . ||
            /usr/bin/sudo -n /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; do
            build_uid=$((build_uid + 1))
            [ "$build_uid" -le 649 ] || { echo "ephemeral build UID range is exhausted" >&2; exit 1; }
        done
        if /usr/bin/sudo -n /usr/bin/dscl . -search /Users UniqueID "$build_uid" 2>/dev/null | /usr/bin/grep -q . ||
            /usr/bin/sudo -n /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; then
            echo "Darwin build UID is not exactly absent and process-free" >&2
            exit 1
        fi
        darwin_account_marker="$darwin_account_lock/owner"
        darwin_account_marker_value="$build_user:$build_uid:$scratch/build-home:/usr/bin/false:20:$build_nonce"
        printf '%s\n' "$darwin_account_marker_value" | /usr/bin/sudo -n /usr/bin/tee "$darwin_account_marker" >/dev/null
        /usr/bin/sudo -n "$chown_bin" 0 "$darwin_account_marker"
        /usr/bin/sudo -n /bin/chmod 0400 "$darwin_account_marker"
        darwin_marker_matches || { echo "Darwin account lifecycle marker differs" >&2; exit 1; }
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user"
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user" UniqueID "$build_uid"
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user" PrimaryGroupID 20
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user" NFSHomeDirectory "$scratch/build-home"
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user" UserShell /usr/bin/false
        /usr/bin/sudo -n /usr/bin/dscl . -create "/Users/$build_user" Password '*'
        darwin_account_matches || { echo "Darwin build account attributes differ after creation" >&2; exit 1; }
        if /usr/bin/sudo -n /usr/bin/pgrep -u "$build_uid" >/dev/null 2>&1; then
            echo "Darwin build UID gained a process before command execution" >&2
            exit 1
        fi
        ;;
    Linux)
        build_user=nobody
        build_uid="$(/usr/bin/id -u "$build_user")"
        ;;
esac
case "$build_uid" in *[!0-9]*|'') echo "dedicated unprivileged build UID is unavailable" >&2; exit 1 ;; esac
if /usr/bin/sudo -n -u "$build_user" /usr/bin/sudo -n true >/dev/null 2>&1; then
    echo "unprivileged build identity unexpectedly has sudo authority" >&2
    exit 1
fi
for sealed in \
    "$proof_snapshot" "$proof_snapshot_authority" \
    "$proof_cargo_home" "$proof_cache_authority" \
    "$workspace_cargo_home" "$workspace_cache_authority" \
    "$sealed_workspace" "$sealed_workspace_authority" \
    "$sealed_toolchain" "$sealed_toolchain_authority" \
    "$sealed_command_bin" \
    "$sealed_probe" "$sealed_probe_authority"; do
    /usr/bin/sudo -n "$chown_bin" -R 0 "$sealed"
done
python3 -I ci/check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain" >/dev/null
check_sealed_command_bin >/dev/null
for authority in "$proof_snapshot_authority" "$proof_cache_authority" "$workspace_cache_authority" "$sealed_workspace_authority" "$sealed_toolchain_authority" "$sealed_probe_authority"; do
    /usr/bin/sudo -n /bin/chmod 0444 "$authority"
done
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify \
    "$proof_snapshot" \
    "$proof_cargo_home" \
    "$proof_cache_authority" \
    "$proof_cache_authority_sha256" \
    "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$proof_snapshot" "$proof_snapshot_authority" "$proof_snapshot_authority_sha256" "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify-cache \
    "$workspace_cargo_home" \
    "$workspace_cache_authority" \
    "$workspace_cache_authority_sha256" \
    "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_workspace" "$sealed_workspace_authority" "$sealed_workspace_authority_sha256" "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_toolchain" "$sealed_toolchain_authority" "$sealed_toolchain_authority_sha256" "$build_uid"
python3 -I ci/check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain" >/dev/null
check_sealed_command_bin >/dev/null
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_probe" "$sealed_probe_authority" "$sealed_probe_authority_sha256" "$build_uid"
build_home="$scratch/build-home"
proof_target="$scratch/ordinary-wallet-plan-public-proof-target"
workspace_target="$scratch/workspace-target"
sealed_proof_binary="$scratch/ordinary-wallet-plan-public-proof-verifier"
build_tmp="$scratch/build-tmp"
gate_output="$scratch/gate-output"
/bin/mkdir "$build_home" "$proof_target" "$workspace_target" "$build_tmp" "$gate_output" "$scratch/hidden-home"
/bin/chmod 0755 "$gate_output"
for writable in "$build_home" "$proof_target" "$workspace_target" "$build_tmp"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$writable"
    /usr/bin/sudo -n /bin/chmod 0700 "$writable"
done
/usr/bin/sudo -n /bin/chmod 0755 "$proof_target" "$workspace_target"
host_write_target="$scratch/host-write-probe"
var_tmp_target="/var/tmp/wasabi-liquid-build-write-probe.$$"
delayed_write_target="$build_home/delayed-descendant-write"
/usr/bin/touch "$host_write_target"
/usr/bin/sudo -n /usr/bin/touch "$var_tmp_target"
if [ "$host_system" = Darwin ]; then
    var_tmp_physical_target="$(/bin/realpath "$var_tmp_target")"
    if [ "$var_tmp_physical_target" != "/private$var_tmp_target" ]; then
        echo "Darwin var-tmp probe physical path differs from its exact alias" >&2
        exit 1
    fi
fi
for denied_write in "$host_write_target" "$var_tmp_target"; do
    /usr/bin/sudo -n "$chown_bin" "$build_uid" "$denied_write"
    /usr/bin/sudo -n /bin/chmod 0600 "$denied_write"
done
/bin/chmod 0711 "$scratch"
compiler_toolchain_root="$sealed_toolchain"
compiler_cargo_bin="$sealed_toolchain/bin/cargo"
compiler_rustc_bin="$sealed_toolchain/bin/rustc"
compiler_rustdoc_bin="$sealed_toolchain/bin/rustdoc"
compiler_rustfmt_bin="$sealed_toolchain/bin/rustfmt"
cargo_bin="$compiler_cargo_bin"
repository_root="$sealed_workspace"
case "$host_system" in
    Darwin)
        proof_sandbox_profile="$scratch/build-proof.sb"
        workspace_sandbox_profile="$scratch/build-workspace.sb"
        for profile_target in "$proof_target" "$workspace_target"; do
            case "$profile_target" in
                "$proof_target") sandbox_profile="$proof_sandbox_profile" ;;
                "$workspace_target") sandbox_profile="$workspace_sandbox_profile" ;;
                *) exit 1 ;;
            esac
            printf '%s\n' \
                '(version 1)' \
                '(deny default)' \
                '(allow process-fork)' \
                '(allow process-info* (target self))' \
                '(allow process-exec* (literal "/usr/bin/env") (literal "/bin/sh") (literal "/bin/bash") (literal "/bin/pwd") (literal "/bin/sleep") (literal "/bin/zsh") (literal "/usr/bin/dirname") (literal "/bin/realpath"))' \
                "(allow process-exec* (literal \"$darwin_cc_bin\") (literal \"$darwin_cxx_bin\") (literal \"$darwin_ar_bin\") (literal \"$darwin_as_bin\") (literal \"$darwin_ld_bin\") (literal \"$darwin_nm_bin\") (literal \"$darwin_ranlib_bin\") (literal \"$darwin_strip_bin\"))" \
                "(allow process-exec* (subpath \"$sealed_toolchain\") (subpath \"$sealed_command_bin\") (subpath \"$profile_target\") (literal \"$sealed_proof_binary\"))" \
                '(allow signal (target self))' \
                '(allow sysctl-read)' \
                '(allow mach-lookup)' \
                '(allow file-read* (literal "/"))' \
                '(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/Applications") (subpath "/Library/Developer") (subpath "/private/etc") (subpath "/private/var/db"))' \
                '(allow file-read-metadata (literal "/var") (literal "/var/tmp") (literal "/private/var/select/developer_dir") (literal "/private/var/select/sh"))' \
                '(allow file-read-metadata (literal "/private") (literal "/private/tmp") (literal "/private/var") (literal "/private/var/tmp"))' \
                "(allow file-read* (subpath \"$scratch\"))" \
                "(allow file-read-metadata (literal \"$var_tmp_target\") (literal \"$var_tmp_physical_target\"))" \
                '(allow file-map-executable (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/Applications") (subpath "/Library/Developer"))' \
                "(allow file-map-executable (subpath \"$sealed_toolchain\") (subpath \"$sealed_command_bin\") (subpath \"$profile_target\") (literal \"$sealed_proof_binary\"))" \
                "(allow file-write* (subpath \"$build_home\") (subpath \"$build_tmp\") (subpath \"$profile_target\"))" \
                '(allow file-read-data (literal "/dev/null"))' \
                '(allow file-write-data (literal "/dev/null"))' \
                '(deny network*)' >"$sandbox_profile"
            /usr/bin/sudo -n "$chown_bin" 0 "$sandbox_profile"
            /usr/bin/sudo -n /bin/chmod 0444 "$sandbox_profile"
        done
        run_sealed() {
            case "$CARGO_TARGET_DIR" in
                "$proof_target") sandbox_profile="$proof_sandbox_profile" ;;
                "$workspace_target") sandbox_profile="$workspace_sandbox_profile" ;;
                *) echo "sealed Darwin command target has no exact sandbox profile" >&2; return 1 ;;
            esac
            /usr/bin/sudo -n "$sealed_workspace/ci/run-sealed-darwin-command.sh" \
                "$build_user" "$build_uid" "$sandbox_profile" "$build_home" "$build_tmp" \
                "$CARGO_HOME" "$CARGO_TARGET_DIR" "$sealed_command_bin" \
                "$compiler_rustc_bin" "$compiler_rustdoc_bin" "$compiler_rustfmt_bin" \
                "${RUSTDOCFLAGS-}" "${RUSTC_BOOTSTRAP-}" \
                "${SEALED_DEPENDENCY_TARGET-}" "${SEALED_WORKSPACE_TARGET-}" \
                "$original_home/.cargo" "$host_write_target" "$var_tmp_target" "$delayed_write_target" \
                "$darwin_sdkroot" \
                "${@}"
        }
        ;;
    Linux)
        run_sealed() {
            /usr/bin/sudo -n /usr/bin/unshare --net --mount --pid --fork --kill-child --mount-proc --propagation private -- \
                "$sealed_workspace/ci/run-sealed-linux-command.sh" \
                "$build_uid" "$original_home" "$scratch/hidden-home" "$build_home" "$build_tmp" \
                "$CARGO_HOME" "$CARGO_TARGET_DIR" "$sealed_command_bin" \
                "$compiler_rustc_bin" "$compiler_rustdoc_bin" "$compiler_rustfmt_bin" \
                "${RUSTDOCFLAGS-}" "${RUSTC_BOOTSTRAP-}" \
                "${SEALED_DEPENDENCY_TARGET-}" "${SEALED_WORKSPACE_TARGET-}" \
                "$original_home/.cargo" "$host_write_target" "$var_tmp_target" "$delayed_write_target" \
                "${@}"
        }
        ;;
esac
CARGO_HOME="$workspace_cargo_home"
CARGO_TARGET_DIR="$workspace_target"
export CARGO_HOME CARGO_TARGET_DIR
sealed_dependency_target="$(find "$workspace_cargo_home/registry/src" -type f ! -name .cargo-ok -print -quit)"
if [ -z "$sealed_dependency_target" ]; then
    echo "sealed dependency mutation probe target is unavailable" >&2
    exit 1
fi
SEALED_DEPENDENCY_TARGET="$sealed_dependency_target"
SEALED_WORKSPACE_TARGET="$sealed_workspace/Cargo.toml"
export SEALED_DEPENDENCY_TARGET SEALED_WORKSPACE_TARGET
/usr/bin/sudo -n -u "$build_user" /usr/bin/env -i PATH=/usr/bin:/bin \
    "$python_bin" -I "$sealed_workspace/ci/check-sealed-tree-readable.py" \
        "$proof_snapshot" "$proof_cargo_home" "$workspace_cargo_home" \
        "$sealed_workspace" "$sealed_toolchain" "$sealed_probe"
if [ "$(run_sealed /bin/pwd -P)" != "$sealed_workspace" ]; then
    echo "sealed command current directory differs from the workspace authority" >&2
    exit 1
fi
if [ "$host_system" = Darwin ]; then
    for denied_darwin_tool in /usr/bin/cc /usr/bin/make /usr/bin/xcrun; do
        if [ ! -x "$denied_darwin_tool" ] || ! run_sealed /bin/sh -c \
            '"$1" --version >/dev/null 2>&1; [ "$?" -eq 126 ]' \
            wlpq-denied-darwin-tool "$denied_darwin_tool"; then
            echo "sealed Darwin system compiler shim remained executable" >&2
            exit 1
        fi
    done
    if ! run_sealed "$sealed_command_bin/as" --version >/dev/null; then
        echo "sealed Darwin assembler wrapper could not reach its exact interpreter and helpers" >&2
        exit 1
    fi
    expected_darwin_rustc_version='rustc 1.96.0 (ac68faa20 2026-05-25)
binary: rustc
commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96
commit-date: 2026-05-25
host: aarch64-apple-darwin
release: 1.96.0
LLVM version: 22.1.2'
    if [ "$(run_sealed /bin/sh -c 'exec "$1" -vV </dev/null' wlpq-rustc "$compiler_rustc_bin")" != "$expected_darwin_rustc_version" ]; then
        echo "isolated Darwin null-stdin child-exec Rust compiler identity mismatch" >&2
        exit 1
    fi
fi
case "$(run_sealed "$compiler_cargo_bin" --version --verbose)" in
    cargo\ 1.96.0\ *30a34c6821b57de0aaec83a901aca39f88f6778c*) ;;
    *) echo "isolated Cargo version or commit mismatch" >&2; exit 1 ;;
esac
case "$(run_sealed "$compiler_rustc_bin" --version --verbose)" in
    *commit-hash:\ ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96*release:\ 1.96.0*) ;;
    *) echo "isolated Rust compiler version or commit mismatch" >&2; exit 1 ;;
esac
case "$(run_sealed "$compiler_rustdoc_bin" --version)" in rustdoc\ 1.96.0\ *) ;; *) exit 1 ;; esac
case "$(run_sealed "$compiler_rustfmt_bin" --version)" in rustfmt\ 1.9.0-stable\ *) ;; *) exit 1 ;; esac
case "$(run_sealed "$sealed_command_bin/cargo-fmt" --version)" in rustfmt\ 1.9.0-stable\ *) ;; *) exit 1 ;; esac
case "$(run_sealed "$sealed_command_bin/cargo-clippy" --version)" in clippy\ 0.1.96\ *) ;; *) exit 1 ;; esac
case "$(run_sealed "$sealed_command_bin/clippy-driver" --version)" in clippy\ 0.1.96\ *) ;; *) exit 1 ;; esac
for boundary_target in "$proof_target" "$workspace_target"; do
    case "$boundary_target" in
        "$proof_target") boundary_cargo_home="$proof_cargo_home" ;;
        "$workspace_target") boundary_cargo_home="$workspace_cargo_home" ;;
        *) exit 1 ;;
    esac
    CARGO_HOME="$boundary_cargo_home" CARGO_TARGET_DIR="$boundary_target" \
        run_sealed "$compiler_cargo_bin" build \
            --manifest-path "$sealed_probe/Cargo.toml" \
            --target-dir "$boundary_target/sealed-boundary-probe" \
            --locked \
            --offline
    /bin/sleep 6
    if [ -e "$delayed_write_target" ]; then
        echo "daemonized build descendant survived sealed command supervision" >&2
        exit 1
    fi
done
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify \
    "$proof_snapshot" \
    "$proof_cargo_home" \
    "$proof_cache_authority" \
    "$proof_cache_authority_sha256" \
    "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$proof_snapshot" "$proof_snapshot_authority" "$proof_snapshot_authority_sha256" "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify-cache \
    "$workspace_cargo_home" \
    "$workspace_cache_authority" \
    "$workspace_cache_authority_sha256" \
    "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_workspace" "$sealed_workspace_authority" "$sealed_workspace_authority_sha256" "$build_uid"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_toolchain" "$sealed_toolchain_authority" "$sealed_toolchain_authority_sha256" "$build_uid"
python3 -I ci/check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain" >/dev/null
check_sealed_command_bin >/dev/null
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
    "$sealed_probe" "$sealed_probe_authority" "$sealed_probe_authority_sha256" "$build_uid"
cd "$sealed_workspace"
export CARGO_HOME="$workspace_cargo_home"
export CARGO_TARGET_DIR="$workspace_target"
export RUSTC="$compiler_rustc_bin"
export RUSTDOC="$compiler_rustdoc_bin"
export RUSTFMT="$compiler_rustfmt_bin"
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0

tree_raw="$(
    run_sealed "$cargo_bin" tree \
    --workspace \
    --locked \
    --target all \
    -e normal,build \
    --no-dedupe \
    --prefix depth \
    --format '{p}|{f}'
)"
tree="$(
    printf '%s\n' "$tree_raw" |
        sed -E 's#^[0-9]+##; s# \(/[^)]*\)# (workspace)#' |
        sed '/^$/d' |
        sort -u
)"

metadata_raw="$(run_sealed "$cargo_bin" metadata --locked --format-version 1)"
printf '%s\n' "$tree_raw" >"$gate_output/tree.txt"
printf '%s' "$metadata_raw" >"$gate_output/metadata.json"
edges="$(
    python3 -I ci/canonicalize-dependency-edges.py \
        "$gate_output/tree.txt" \
        "$gate_output/metadata.json"
)"

printf '%s\n' "$tree" | awk -F '|' '
function has_feature(features, expected, count, position, item) {
    count = split(features, item, ",")
    for (position = 1; position <= count; position++) {
        if (item[position] == expected) {
            return 1
        }
    }
    return 0
}

function reject(message) {
    print message > "/dev/stderr"
    failed = 1
}

BEGIN {
    failed = 0
    bitcoin = 0
    digest = 0
    elements = 0
    miniscript = 0
    rand_count = 0
    plan = 0
    plan_ffi = 0
    plan_proof = 0
    secp = 0
    sha2 = 0
    zkp = 0
    zkp_sys = 0
    wire = 0

    digest_prefix = "digest v0.11.3 (https://github.com/liquid-wasabi/traits.git?rev=113c5ba12876e332335e49d1462a2c96c9928006#"
    elements_prefix = "elements v0.27.0 (https://github.com/Abdullah1738/rust-elements.git?rev=5b8865f8061459f82dcb8a1cf476b7ba17b14193#"
    zkp_prefix = "secp256k1-zkp v0.11.1 (https://github.com/Abdullah1738/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
    zkp_sys_prefix = "secp256k1-zkp-sys v0.10.0 (https://github.com/Abdullah1738/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
}

$1 ~ /^elements-miniscript v/ ||
$1 ~ /^elements v0\.25\./ ||
$1 ~ /^secp256k1-zkp v0\.11\.0([ (]|$)/ ||
$1 ~ /^serde_json v/ ||
$1 ~ /^simplicity-lang v/ ||
$1 ~ /^getrandom v/ {
    reject("denied dependency: " $0)
}

has_feature($2, "compiler") ||
has_feature($2, "getrandom") ||
has_feature($2, "global-context") ||
has_feature($2, "json-contract") ||
has_feature($2, "rand-std") ||
has_feature($2, "serde") {
    reject("denied dependency feature: " $0)
}

$1 ~ /^bitcoin v/ {
    bitcoin++
    if ($1 != "bitcoin v0.32.102" || $2 != "encoding,std") {
        reject("unexpected bitcoin capability: " $0)
    }
}

$1 ~ /^digest v/ {
    digest++
    if (index($1, digest_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "block-api,default,zeroize") {
        reject("unexpected digest capability: " $0)
    }
}

$1 ~ /^elements v/ {
    elements++
    if (index($1, elements_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "") {
        reject("unexpected Elements capability: " $0)
    }
}

$1 ~ /^miniscript v/ {
    miniscript++
    if ($1 != "miniscript v12.3.7" || $2 != "no-std") {
        reject("unexpected Miniscript capability: " $0)
    }
}

$1 ~ /^rand v/ {
    rand_count++
    if ($1 != "rand v0.8.7" || $2 != "") {
        reject("unexpected caller-randomness capability: " $0)
    }
}

$1 ~ /^secp256k1 v/ {
    secp++
    if ($1 != "secp256k1 v0.29.1" || $2 != "alloc,default,hashes,rand,std") {
        reject("unexpected secp256k1 capability: " $0)
    }
}

$1 ~ /^secp256k1-zkp v/ {
    zkp++
    if (index($1, zkp_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "actual-rand,hashes,rand,std") {
        reject("unexpected secp256k1-zkp capability: " $0)
    }
}

$1 ~ /^secp256k1-zkp-sys v/ {
    zkp_sys++
    if (index($1, zkp_sys_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "std") {
        reject("unexpected secp256k1-zkp-sys capability: " $0)
    }
}

$1 ~ /^sha2 v/ {
    sha2++
    if ($1 != "sha2 v0.11.0" || $2 != "zeroize") {
        reject("unexpected SHA-256 capability: " $0)
    }
}

$1 ~ /^wasabi-liquid-native-wallet-facts-wire v/ {
    wire++
    if ($1 != "wasabi-liquid-native-wallet-facts-wire v0.1.0 (workspace)" || $2 != "") {
        reject("unexpected wallet-facts wire capability: " $0)
    }
}

$1 ~ /^wasabi-liquid-native-ordinary-wallet-plan v/ {
    plan++
    if ($1 != "wasabi-liquid-native-ordinary-wallet-plan v0.1.0 (workspace)" || $2 != "") {
        reject("unexpected ordinary-wallet plan capability: " $0)
    }
}

$1 ~ /^wasabi-liquid-native-ordinary-wallet-plan-ffi v/ {
    plan_ffi++
    if ($1 != "wasabi-liquid-native-ordinary-wallet-plan-ffi v0.1.0 (workspace)" || $2 != "") {
        reject("unexpected WLPQ FFI capability: " $0)
    }
}

END {
    if (bitcoin != 1 || digest != 1 || elements != 1 || miniscript != 1 ||
        plan != 1 || plan_ffi != 1 || rand_count != 1 || secp != 1 || sha2 != 1 || zkp != 1 || zkp_sys != 1 || wire != 1) {
        reject("required dependency capability count mismatch")
    }
    exit failed
}'

printf '%s\n' "$tree" | diff -u ci/expected-dependency-capabilities.txt -
printf '%s\n' "$edges" | diff -u ci/expected-dependency-edges.txt -

python3 -I ci/check-wallet-facts-conformance.py "$repository_root"
conformance_inventory_hash="$(
    python3 -I -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/wallet-facts/v1/nonlinkable-reference/vectors/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$conformance_inventory_hash" != "9bcdcf31ffe90e7a23ada162c61c71cfc84343ba1c190865e0ed34af8c7da933" ]; then
    echo "wallet-facts conformance inventory root mismatch" >&2
    exit 1
fi
conformance_parent_hash="$(
    python3 -I -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/wallet-facts/v1/nonlinkable-reference/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$conformance_parent_hash" != "9a3d11662670d13e23ed248f2ae145c87a52739e2e3bb03f7628e4d12e147c63" ]; then
    echo "wallet-facts conformance parent root mismatch" >&2
    exit 1
fi

python3 -I ci/check-ordinary-wallet-plan-conformance.py "$repository_root"
plan_conformance_inventory_hash="$(
    python3 -I -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference/vectors/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$plan_conformance_inventory_hash" != "a4aaa0e0b13b5544fd8e53f703a685fc56f4ec95f1e1c052f19bf50365ce2f6c" ]; then
    echo "ordinary-wallet plan conformance inventory root mismatch" >&2
    exit 1
fi
plan_conformance_parent_hash="$(
    python3 -I -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/ordinary-wallet-plan/v1/nonlinkable-reference/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$plan_conformance_parent_hash" != "a1e1db8cba234d5154e947a32539c0ac461ddbaa812a0dd4e7c4e007a9541600" ]; then
    echo "ordinary-wallet plan conformance parent root mismatch" >&2
    exit 1
fi
if [ "$(cat contracts/ordinary-wallet-plan/v1/nonlinkable-reference/CORPUS_ROOT_SHA256)" != "$plan_conformance_parent_hash" ]; then
    echo "ordinary-wallet plan declared conformance root mismatch" >&2
    exit 1
fi
python3 -I ci/test-ordinary-wallet-plan-conformance.py
(
    cd /
    CARGO_HOME="$proof_cargo_home" CARGO_TARGET_DIR="$proof_target" \
        run_sealed "$compiler_cargo_bin" build \
            --manifest-path "$proof_snapshot/Cargo.toml" \
            --quiet \
            --locked \
            --offline \
            -p wasabi-liquid-native-ordinary-wallet-plan-public-proof-verifier \
            --bin ordinary-wallet-plan-public-proof-verifier
)
proof_dep_info="$(find "$proof_target/debug/deps" -maxdepth 1 -type f -name 'ordinary_wallet_plan_public_proof_verifier-*.d' -print)"
if [ -z "$proof_dep_info" ] || [ "$(printf '%s\n' "$proof_dep_info" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "ordinary-wallet plan public proof compiler source closure is not singular" >&2
    exit 1
fi
python3 -I ci/check-ordinary-wallet-plan-public-proof-surface.py \
    --snapshot "$proof_snapshot" \
    "$proof_dep_info"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify \
    "$proof_snapshot" \
    "$proof_cargo_home" \
    "$proof_cache_authority" \
    "$proof_cache_authority_sha256" \
    "$build_uid"
proof_binary="$sealed_proof_binary"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --seal-binary \
    "$proof_target" \
    "$proof_dep_info" \
    "$proof_binary" \
    "$build_uid"
/usr/bin/sudo -n "$chown_bin" 0 "$proof_binary"
/usr/bin/sudo -n /bin/chmod 0555 "$proof_binary"
proof_binary_sha256="$(python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --binary-digest "$proof_binary")"
run_sealed "$proof_binary" "$proof_snapshot"
if [ "$(python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --binary-digest "$proof_binary")" != "$proof_binary_sha256" ]; then
    echo "ordinary-wallet plan public proof binary changed during execution" >&2
    exit 1
fi
python3 -I ci/check-ordinary-wallet-plan-public-proof-surface.py \
    --snapshot "$proof_snapshot" \
    "$proof_dep_info"
python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
    --verify \
    "$proof_snapshot" \
    "$proof_cargo_home" \
    "$proof_cache_authority" \
    "$proof_cache_authority_sha256" \
    "$build_uid"

if [ "$(grep -Fxc 'sha2 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }' crates/wallet-facts-wire/Cargo.toml)" -ne 1 ]; then
    echo "wallet-facts conformance test dependency mismatch" >&2
    exit 1
fi
python3 -I - "$repository_root" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
lock_path = root / "Cargo.lock"
baseline_path = root / "ci/expected-wallet-facts-conformance-lock-baseline.txt"
lock_bytes = lock_path.read_bytes()
baseline_text = baseline_path.read_text()
baseline_hash = "544ad20b54fe2e279a3074a5cfdeec49bd13752f358ffd0d67c0573546af326c"
wire_post_hash = "f30d4a8bfc6b43f61fb7eefdd0d86f866ebef815d5aa57cc2b5b3319023fcf25"
provider_post_hash = "5d105ea8138170cac5501f42d148855b9b9141d38b3c2b9532a246a4d5dc9ade"
plan_base_hash = "3287e329ab3d1b9868cb5eb3c39b1713a0d660b0dcd35100688bfb7c7a867178"
ffi_base_hash = "5a6a3fa2fbf890844009d1ff1ad40841977a0ffa32c0faba795fa211262f8678"
equality_base_hash = "67f5fa8be8d5f932f4a5ea55c43b32cf4961357a17986533f6fbb82432b7d263"
transcript_base_hash = "705ef6c3c0abfedf3af2028bc4d20912f0d92365188d1deb462b7f8d32f54e10"
facts_ffi_base_hash = "c12c61b0848647ad550dd5d63e9283559809f12e56d86646328bd99566cf7064"
current_hash = "9058d12bbe79b4655ccdccb4315e8c041ec326d114ad4de674c4375c6e8a7318"
if baseline_text != baseline_hash + "\n":
    raise SystemExit("wallet-facts conformance lock baseline pin mismatch")
if hashlib.sha256(lock_bytes).hexdigest() != current_hash:
    raise SystemExit("wallet-facts conformance post-slice lock pin mismatch")

text = lock_bytes.decode("utf-8")
blocks = text.split("[[package]]\n")
collab_blinding_marker = 'name = "wasabi-liquid-native-coinjoin-collab-blinding"\n'
collab_blinding_indexes = [index for index, block in enumerate(blocks) if collab_blinding_marker in block]
collab_blinding_block = """name = "wasabi-liquid-native-coinjoin-collab-blinding"
version = "0.1.0"
dependencies = [
 "elements",
 "rand",
 "wasabi-liquid-native-coinjoin-pset-state",
]

"""
if len(collab_blinding_indexes) != 1 or blocks[collab_blinding_indexes[0]] != collab_blinding_block:
    raise SystemExit("CoinJoin collab blinding lock package mismatch")
del blocks[collab_blinding_indexes[0]]
collab_blinding_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(collab_blinding_base_bytes).hexdigest() != "708113d44c50f948d20d231b1c425d9060b88360ef9b4312bb6181d50f673049":
    raise SystemExit("CoinJoin collab blinding lock reverse transform mismatch")

pset_state_marker = 'name = "wasabi-liquid-native-coinjoin-pset-state"\n'
pset_state_indexes = [index for index, block in enumerate(blocks) if pset_state_marker in block]
pset_state_block = """name = "wasabi-liquid-native-coinjoin-pset-state"
version = "0.1.0"
dependencies = [
 "elements",
 "rand",
 "wasabi-liquid-native-coinjoin-state-transcript",
]

"""
if len(pset_state_indexes) != 1 or blocks[pset_state_indexes[0]] != pset_state_block:
    raise SystemExit("CoinJoin PSET state lock package mismatch")
del blocks[pset_state_indexes[0]]
pset_state_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(pset_state_base_bytes).hexdigest() != "d6efc0056683780da23d8c06017d6618f8a2ae0d1164ab40e41176ab17c088ca":
    raise SystemExit("CoinJoin PSET state lock reverse transform mismatch")

transcript_marker = 'name = "wasabi-liquid-native-coinjoin-state-transcript"\n'
transcript_indexes = [index for index, block in enumerate(blocks) if transcript_marker in block]
transcript_block = """name = "wasabi-liquid-native-coinjoin-state-transcript"
version = "0.1.0"
dependencies = [
 "sha2",
]

"""
if len(transcript_indexes) != 1 or blocks[transcript_indexes[0]] != transcript_block:
    raise SystemExit("CoinJoin state transcript lock package mismatch")
del blocks[transcript_indexes[0]]
transcript_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(transcript_base_bytes).hexdigest() != transcript_base_hash:
    raise SystemExit("CoinJoin state transcript lock reverse transform mismatch")

equality_marker = 'name = "wasabi-liquid-native-credential-commitment-equality"\n'
equality_indexes = [index for index, block in enumerate(blocks) if equality_marker in block]
equality_block = """name = "wasabi-liquid-native-credential-commitment-equality"
version = "0.1.0"
dependencies = [
 "elements",
 "rand",
 "sha2",
 "zeroize",
]

"""
if len(equality_indexes) != 1 or blocks[equality_indexes[0]] != equality_block:
    raise SystemExit("credential-commitment equality lock package mismatch")
del blocks[equality_indexes[0]]
equality_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(equality_base_bytes).hexdigest() != equality_base_hash:
    raise SystemExit("credential-commitment equality lock reverse transform mismatch")

facts_ffi_marker = 'name = "wasabi-liquid-native-wallet-facts-ffi"\n'
facts_ffi_indexes = [index for index, block in enumerate(blocks) if facts_ffi_marker in block]
facts_ffi_block = """name = "wasabi-liquid-native-wallet-facts-ffi"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "wasabi-liquid-native-wallet-facts",
 "wasabi-liquid-native-wallet-facts-wire",
 "zeroize",
]

"""
if len(facts_ffi_indexes) != 1 or blocks[facts_ffi_indexes[0]] != facts_ffi_block:
    raise SystemExit("wallet-facts FFI lock package mismatch")
del blocks[facts_ffi_indexes[0]]
facts_ffi_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(facts_ffi_base_bytes).hexdigest() != facts_ffi_base_hash:
    raise SystemExit("wallet-facts FFI lock reverse transform mismatch")

ffi_marker = 'name = "wasabi-liquid-native-ordinary-wallet-plan-ffi"\n'
ffi_indexes = [index for index, block in enumerate(blocks) if ffi_marker in block]
ffi_block = """name = "wasabi-liquid-native-ordinary-wallet-plan-ffi"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "wasabi-liquid-native-ordinary-pset",
 "wasabi-liquid-native-ordinary-wallet-plan",
 "wasabi-liquid-native-ordinary-wallet-pset",
 "wasabi-liquid-native-wallet-facts",
 "zeroize",
]

"""
if len(ffi_indexes) != 1 or blocks[ffi_indexes[0]] != ffi_block:
    raise SystemExit("WLPQ FFI lock package mismatch")
del blocks[ffi_indexes[0]]
ffi_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(ffi_base_bytes).hexdigest() != ffi_base_hash:
    raise SystemExit("WLPQ FFI lock reverse transform mismatch")

plan_marker = 'name = "wasabi-liquid-native-ordinary-wallet-plan"\n'
plan_indexes = [index for index, block in enumerate(blocks) if plan_marker in block]
plan_block = """name = "wasabi-liquid-native-ordinary-wallet-plan"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "static_assertions",
 "wasabi-liquid-native-address",
 "wasabi-liquid-native-ordinary-pset",
 "wasabi-liquid-native-ordinary-wallet-pset",
 "wasabi-liquid-native-output-opening",
 "wasabi-liquid-native-wallet-facts",
 "zeroize",
]

"""
if len(plan_indexes) != 1 or blocks[plan_indexes[0]] != plan_block:
    raise SystemExit("ordinary-wallet plan lock package mismatch")
del blocks[plan_indexes[0]]
plan_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(plan_base_bytes).hexdigest() != plan_base_hash:
    raise SystemExit("ordinary-wallet plan lock reverse transform mismatch")

ordinary_marker = 'name = "wasabi-liquid-native-ordinary-pset"\n'
composer_marker = 'name = "wasabi-liquid-native-ordinary-wallet-pset"\n'
facts_marker = 'name = "wasabi-liquid-native-wallet-facts"\n'
wire_marker = 'name = "wasabi-liquid-native-wallet-facts-wire"\n'
sha_marker = 'name = "sha2"\nversion = "0.11.0"\n'
ordinary_indexes = [index for index, block in enumerate(blocks) if ordinary_marker in block]
composer_indexes = [index for index, block in enumerate(blocks) if composer_marker in block]
facts_indexes = [index for index, block in enumerate(blocks) if facts_marker in block]
wire_indexes = [index for index, block in enumerate(blocks) if wire_marker in block]
sha_blocks = [block for block in blocks if sha_marker in block]
if (
    len(ordinary_indexes) != 1
    or len(composer_indexes) != 1
    or len(facts_indexes) != 1
    or len(wire_indexes) != 1
    or len(sha_blocks) != 1
):
    raise SystemExit("wallet-facts conformance lock package multiplicity mismatch")

composer_block = """name = "wasabi-liquid-native-ordinary-wallet-pset"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "static_assertions",
 "wasabi-liquid-native-address",
 "wasabi-liquid-native-ordinary-pset",
 "wasabi-liquid-native-wallet-facts",
]

"""
for marker in (composer_marker, facts_marker):
    indexes = [index for index, block in enumerate(blocks) if marker in block]
    entry = ' "wasabi-liquid-native-output-opening",\n'
    if len(indexes) != 1 or blocks[indexes[0]].count(entry) != 1:
        raise SystemExit("selected opening-provider lock edge multiplicity mismatch")
    blocks[indexes[0]] = blocks[indexes[0]].replace(entry, "", 1)

provider_post_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(provider_post_bytes).hexdigest() != provider_post_hash:
    raise SystemExit("selected opening-provider lock reverse transform mismatch")

if blocks[composer_indexes[0]] != composer_block:
    raise SystemExit("ordinary-wallet PSET lock package mismatch")
del blocks[composer_indexes[0]]

for marker, entry in (
    (ordinary_marker, ' "rand",\n'),
    (facts_marker, ' "wasabi-liquid-native-ordinary-pset",\n'),
):
    indexes = [index for index, block in enumerate(blocks) if marker in block]
    if len(indexes) != 1 or blocks[indexes[0]].count(entry) != 1:
        raise SystemExit("ordinary-wallet PSET lock edge multiplicity mismatch")
    blocks[indexes[0]] = blocks[indexes[0]].replace(entry, "", 1)

wire_post_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(wire_post_bytes).hexdigest() != wire_post_hash:
    raise SystemExit("ordinary-wallet PSET lock reverse transform mismatch")

wire_indexes = [index for index, block in enumerate(blocks) if wire_marker in block]
if len(wire_indexes) != 1:
    raise SystemExit("wallet-facts conformance lock package multiplicity mismatch")
wire_block = blocks[wire_indexes[0]]
entry = ' "sha2",\n'
if wire_block.count(entry) != 1:
    raise SystemExit("wallet-facts conformance lock edge multiplicity mismatch")
blocks[wire_indexes[0]] = wire_block.replace(entry, "", 1)
reconstructed = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(reconstructed).hexdigest() != baseline_hash:
    raise SystemExit("wallet-facts conformance lock reverse transform mismatch")
PY

wire_sources="crates/wallet-facts-wire/src/lib.rs crates/wallet-facts-wire/src/request.rs crates/wallet-facts-wire/src/response.rs crates/wallet-facts-wire/src/reader.rs crates/wallet-facts-wire/src/writer.rs"
if grep -En 'use (elements|secp256k1|sha2|bitcoin_hashes)(::|[[:space:]])|SecretKey|HashMap|HashSet|\.sort\(|\.sort_by\(|rand::|getrandom|no_mangle|export_name|extern[[:space:]]+"C"' $wire_sources; then
    echo "wallet-facts wire source capability escaped its reviewed boundary" >&2
    exit 1
fi
if [ "$(grep -h -c 'sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes))' $wire_sources | awk '{ total += $1 } END { print total + 0 }')" -ne 1 ]; then
    echo "wallet-facts wire uniqueness call manifest mismatch" >&2
    exit 1
fi
if [ "$(grep -h -c 'validates_observed_public_output(' $wire_sources | awk '{ total += $1 } END { print total + 0 }')" -ne 2 ]; then
    echo "wallet-facts wire public-output validation call manifest mismatch" >&2
    exit 1
fi
if ! grep -Fq 'crate-type = ["rlib"]' crates/wallet-facts-wire/Cargo.toml ||
    grep -Fq 'cdylib' crates/wallet-facts-wire/Cargo.toml; then
    echo "wallet-facts wire crate type mismatch" >&2
    exit 1
fi

python3 -I -c 'import importlib.util, pathlib; p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); s = importlib.util.spec_from_file_location("plan_surface", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); m.validate_manifest_targets(); m.validate_dependency_authority_surface(m.production_text())'
WLPQ_TEST_DARWIN_SDKROOT="$darwin_sdkroot" \
    python3 -I ci/test-ordinary-wallet-plan-surface.py
plan_sources='crates/ordinary-wallet-plan/src/lib.rs
crates/ordinary-wallet-plan/src/reader.rs
crates/ordinary-wallet-plan/src/writer.rs'
plan_lexical_source="$(
    python3 -I -c 'import importlib.util, pathlib; p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); s = importlib.util.spec_from_file_location("plan_surface", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.strip_rust_comments(m.production_text()), end="")'
)"
if grep -En '^[[:space:]]*(test|doctest|doc)[[:space:]]*=[[:space:]]*false([[:space:]]|$)|^[[:space:]]*harness[[:space:]]*=|required-features[[:space:]]*=|\[\[test\]\]' crates/ordinary-wallet-plan/Cargo.toml; then
    echo "ordinary-wallet plan Cargo test or documentation target was disabled" >&2
    exit 1
fi
plan_crate_attributes="$(grep -h -E '^[[:space:]]*#!\[' $plan_sources)"
expected_plan_crate_attributes='#![forbid(unsafe_code)]
#![deny(missing_docs)]'
if [ "$plan_crate_attributes" != "$expected_plan_crate_attributes" ]; then
    echo "ordinary-wallet plan exact crate-level safety attributes changed" >&2
    exit 1
fi
if printf '%s\n' "$plan_lexical_source" | grep -En '#[[:space:]]*\[[[:space:]]*path([[:space:]=\]])|(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)'; then
    echo "ordinary-wallet plan path attribute or unsafe syntax escaped its boundary" >&2
    exit 1
fi
plan_module_count="$(
    grep -h -E -c '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[[:alpha:]_][[:alnum:]_]*[[:space:]]*(;|\{)' $plan_sources |
        awk '{ total += $1 } END { print total + 0 }'
)"
plan_module_hash="$(
    sed -n '/^mod reader;/,/^mod tests;/p' crates/ordinary-wallet-plan/src/lib.rs |
        python3 -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_module_count" -ne 3 ] || [ "$plan_module_hash" != "9bf302755ec28c38c79a36f3f7945a47fe8d736d267b8373981852afa6949272" ]; then
    echo "ordinary-wallet plan exact module declarations or attributes changed" >&2
    exit 1
fi
plan_outer_attribute_hash="$(
    grep -h -E '^[[:space:]]*#\[' $plan_sources |
        python3 -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_outer_attribute_hash" != "ca090cdae5ab9fd46a9f1e89ec0f9d51e6f99657ca44c7d1c9832f9f6a02ad2e" ]; then
    echo "ordinary-wallet plan allowed outer attribute inventory changed" >&2
    exit 1
fi
plan_trait_impl_count="$(
    grep -h -E -c '^[[:space:]]*(unsafe[[:space:]]+)?impl.*[[:space:]]for[[:space:]]' $plan_sources |
        awk '{ total += $1 } END { print total + 0 }'
)"
if [ "$plan_trait_impl_count" -ne 42 ] || grep -En '^[[:space:]]+impl[[:space:]<]' $plan_sources; then
    echo "ordinary-wallet plan exact trait implementation syntax changed" >&2
    exit 1
fi
plan_diagnostic_output="$gate_output/ordinary-wallet-plan.stderr"
plan_diagnostic_status="$gate_output/ordinary-wallet-plan.status"
plan_dep_info="$workspace_target/ordinary-wallet-plan-source-closure.d"
if [ -e "$plan_dep_info" ] || [ -L "$plan_dep_info" ]; then
    echo "ordinary-wallet plan compiler source closure already exists" >&2
    exit 1
fi
if ! (
    umask 022
    if run_sealed "$compiler_cargo_bin" rustc \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --lib \
            --locked \
            --offline \
            -- \
            --emit=dep-info="$plan_dep_info"
    then
        plan_pipeline_status=0
    else
        plan_pipeline_status=$?
    fi
    /usr/bin/printf '%s\n' "$plan_pipeline_status" >"$plan_diagnostic_status"
) 2>&1 | python3 -I ci/capture-bounded-command-diagnostics.py \
    --capture-stdin "$plan_diagnostic_output"
then
    echo "ordinary-wallet plan bounded compiler diagnostic capture failed" >&2
    exit 1
fi
if [ ! -f "$plan_diagnostic_status" ]; then
    echo "ordinary-wallet plan compiler status handoff is missing" >&2
    exit 1
fi
plan_compile_status="$(cat "$plan_diagnostic_status")"
case "$plan_compile_status" in *[!0-9]*|'') echo "ordinary-wallet plan compiler status handoff is invalid" >&2; exit 1 ;; esac
if [ "$plan_compile_status" -gt 255 ]; then
    echo "ordinary-wallet plan compiler status handoff is out of range" >&2
    exit 1
fi
if [ "$plan_compile_status" -ne 0 ]; then
    if ! python3 -I ci/capture-bounded-command-diagnostics.py \
        --emit "$plan_diagnostic_output"; then
        echo "ordinary-wallet plan bounded compiler diagnostic emission failed" >&2
        exit 1
    fi
    if [ -e "$plan_dep_info" ] || [ -L "$plan_dep_info" ]; then
        plan_dep_info_state=present
    else
        plan_dep_info_state=absent
    fi
    echo "ordinary-wallet plan compiler source closure derivation failed: status=$plan_compile_status dep-info=$plan_dep_info_state" >&2
    exit 1
fi
plan_compiled_sources="$(
    python3 -I ci/read-compiler-source-closure.py \
        "$sealed_workspace" "$workspace_target" "$plan_dep_info" 0 "$build_uid"
)"
expected_plan_compiled_sources='crates/ordinary-wallet-plan/src/lib.rs
crates/ordinary-wallet-plan/src/reader.rs
crates/ordinary-wallet-plan/src/writer.rs'
if [ "$plan_compiled_sources" != "$expected_plan_compiled_sources" ]; then
    echo "ordinary-wallet plan compiler source closure changed" >&2
    exit 1
fi
python3 -I -c 'import importlib.util, pathlib, sys; p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); s = importlib.util.spec_from_file_location("plan_surface", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); m.validate_with_compiled_source_files(tuple(path.removeprefix("crates/ordinary-wallet-plan/") for path in sys.argv[1].splitlines()))' "$plan_compiled_sources"
if printf '%s\n' "$plan_lexical_source" | grep -En 'wasabi_liquid_native_output_opening|open_prepared_selected_owned_inputs|SecretKey|getrandom|std[[:space:]]*::[[:space:]]*(process|env|thread|fs|net|time)|no_mangle|export_name|extern[[:space:]]*"C"|include(_str|_bytes)?[[:space:]]*!|AddressParams::ELEMENTS|LiquidAddressProfile::ElementsDefault'; then
    echo "ordinary-wallet plan source capability escaped its reviewed boundary" >&2
    exit 1
fi
plan_function_macro_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -Eo '(^|[^[:alnum:]_])[[:alpha:]_][[:alnum:]_]*[[:space:]]*![[:space:]]*(\(|\{|\[)' |
        awk 'END { print NR + 0 }'
)"
plan_test_panic_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -F -c 'panic!("test-only ordinary-wallet plan staging unwind");'
)"
plan_test_thread_local_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -F -c 'thread_local! {'
)"
if [ "$plan_function_macro_count" -ne 9 ] || [ "$plan_test_thread_local_count" -ne 1 ] || [ "$plan_test_panic_count" -ne 1 ]; then
    echo "ordinary-wallet plan function-like macro surface is not the exact test-only hook" >&2
    exit 1
fi
plan_ordinary_pset_import="$(
    sed -n '/^use wasabi_liquid_native_ordinary_pset::{/,/^};/p' crates/ordinary-wallet-plan/src/lib.rs
)"
expected_plan_ordinary_pset_import='use wasabi_liquid_native_ordinary_pset::{
    BlindedOrdinaryPset, ConfidentialOutput, ExplicitFee, FinalizedOrdinaryTransaction,
    OrdinaryP2wpkhSigner,
};'
plan_wallet_pset_import="$(
    sed -n '/^use wasabi_liquid_native_ordinary_wallet_pset::{/,/^};/p' crates/ordinary-wallet-plan/src/lib.rs
)"
expected_plan_wallet_pset_import='use wasabi_liquid_native_ordinary_wallet_pset::{
    OrdinaryWalletPsetError, OrdinaryWalletTransactionFailure, build_blinded_ordinary_wallet_pset,
    build_sign_and_finalize_ordinary_wallet_transaction,
};'
if [ "$plan_ordinary_pset_import" != "$expected_plan_ordinary_pset_import" ] ||
    [ "$plan_wallet_pset_import" != "$expected_plan_wallet_pset_import" ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'wasabi_liquid_native_ordinary_pset' | awk 'END { print NR + 0 }')" -ne 1 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'BlindedOrdinaryPset' | awk 'END { print NR + 0 }')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'ConfidentialOutput' | awk 'END { print NR + 0 }')" -ne 6 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'ExplicitFee' | awk 'END { print NR + 0 }')" -ne 9 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'FinalizedOrdinaryTransaction' | awk 'END { print NR + 0 }')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'OrdinaryP2wpkhSigner' | awk 'END { print NR + 0 }')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'OrdinaryWalletTransactionFailure' | awk 'END { print NR + 0 }')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'build_sign_and_finalize_ordinary_wallet_transaction' | awk 'END { print NR + 0 }')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -F -c 'ConfidentialOutput::from_address')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -F -c 'ExplicitFee::new')" -ne 2 ]; then
    echo "ordinary-wallet plan ordinary-pset exact API inventory changed" >&2
    exit 1
fi
if printf '%s\n' "$plan_lexical_source" | grep -En '(^|[^[:alnum:]_])(prepare_ordinary_pset|SpendableInput|PreparedOrdinaryPset|PsetConstructionError|OrdinaryPsetBlindingError|SignedOrdinaryPset|OrdinarySigningFailure|PartiallySignedTransaction|sign_and_finalize|serialize_for_broadcast|serialize_sensitive|as_pset|blind)([^[:alnum:]_]|$)'; then
    echo "ordinary-wallet plan ordinary-pset capability escaped its boundary" >&2
    exit 1
fi
for required_call in \
    'build_blinded_ordinary_wallet_pset(' \
    'build_sign_and_finalize_ordinary_wallet_transaction(' \
    'prepare_selected_owned_inputs(' \
    'SelectedOutputBatch::new(' \
    'ConfidentialOutput::from_address(' \
    'ExplicitFee::new(' \
    'ConfidentialLiquidAddress::parse(' \
    'preflight_frame(frame, expected_source_epoch)'
do
    expected_count=1
    case "$required_call" in
        'ConfidentialOutput::from_address('|\
        'ExplicitFee::new('|\
        'ConfidentialLiquidAddress::parse('|\
        'preflight_frame(frame, expected_source_epoch)') expected_count=2 ;;
    esac
    if [ "$(grep -h -F -c "$required_call" $plan_sources | awk '{ total += $1 } END { print total + 0 }')" -ne "$expected_count" ]; then
        echo "ordinary-wallet plan source call manifest mismatch" >&2
        exit 1
    fi
done
plan_preflight_source="$(
    awk '
        /^fn preflight_frame/ { capture = 1 }
        /^fn parse_owned/ { capture = 0 }
        capture { print }
    ' crates/ordinary-wallet-plan/src/lib.rs
)"
if printf '%s\n' "$plan_preflight_source" | grep -En 'Vec|String|Address|AssetId|SelectedOutputBatch|prepare_selected_owned_inputs|deserialize|to_vec|with_capacity|\.reserve\(|\.reserve_exact\(|collect'; then
    echo "ordinary-wallet plan structural preflight allocated or invoked semantics" >&2
    exit 1
fi
plan_preflight_hash="$(
    printf '%s\n' "$plan_preflight_source" |
        python3 -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_preflight_hash" != "483952c5fa1f9aea89585f317551c728513241c8800aeaf1fca4d0e534d6ea28" ]; then
    echo "ordinary-wallet plan structural preflight source hash mismatch" >&2
    exit 1
fi
if ! grep -Fq 'crate-type = ["rlib"]' crates/ordinary-wallet-plan/Cargo.toml ||
    grep -Fq 'cdylib' crates/ordinary-wallet-plan/Cargo.toml; then
    echo "ordinary-wallet plan crate type mismatch" >&2
    exit 1
fi

helper_source="$(
    awk '
        /^pub fn validates_observed_public_output/ { capture = 1 }
        /^\/\/\/ The public derivation branch/ { capture = 0 }
        capture { print }
    ' crates/wallet-facts/src/lib.rs
)"
if printf '%s\n' "$helper_source" | grep -En 'Vec|Box|format!|SecretKey|Transaction|Pset|rand|std::|unwrap|expect|panic!'; then
    echo "wallet-facts public-output helper call manifest escaped its reviewed boundary" >&2
    exit 1
fi
helper_source_hash="$(
    printf '%s\n' "$helper_source" |
        python3 -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$helper_source_hash" != "c9154cfc0437b6563964de67e68ed5157f33570e3ea3c6b8618bd253ceba0ed9" ]; then
    echo "wallet-facts public-output helper source hash mismatch" >&2
    exit 1
fi
for required_call in \
    'PublicKey::from_slice(spend_public_key)' \
    'PublicKey::from_slice(blinding_public_key)' \
    'hash160::Hash::hash(spend_public_key)'
do
    if ! printf '%s\n' "$helper_source" | grep -Fq "$required_call"; then
        echo "wallet-facts public-output helper call manifest mismatch" >&2
        exit 1
    fi
done

uniqueness_source="$(
    awk '
        /^fn validate_source_uniqueness/ { capture = 1 }
        /^fn validate_output/ { capture = 0 }
        /^fn validate_response_uniqueness/ { capture = 1 }
        /^fn construct_response/ { capture = 0 }
        capture { print }
    ' crates/wallet-facts-wire/src/response.rs
)"
for required_line in \
    'Vec::with_capacity(inputs.len())' \
    'Vec::with_capacity(input_count)' \
    'for input in inputs' \
    'scratch.0.push(ScopedWireOutPoint::new(input))' \
    'scratch.0.push(ScopedWireOutPoint::new_parts(' \
    '.sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes))' \
    '.windows(2)' \
    '.any(|pair| pair[0].bytes == pair[1].bytes)'
do
    if [ "$(printf '%s\n' "$uniqueness_source" | grep -F -c "$required_line")" -ne 1 ]; then
        echo "wallet-facts wire uniqueness source manifest mismatch" >&2
        exit 1
    fi
done
uniqueness_source_hash="$(
    printf '%s\n' "$uniqueness_source" |
        python3 -I -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$uniqueness_source_hash" != "953e88c1fa78a5b83b85874b9c1e6a1706324595ec05a0167987ca69fe47f2ff" ]; then
    echo "wallet-facts wire uniqueness source hash mismatch" >&2
    exit 1
fi
if printf '%s\n' "$uniqueness_source" | grep -En 'HashMap|HashSet|Vec::new|vec!|Vec::from|VecDeque|LinkedList|BTree|Box|String|collect|to_vec|reserve|resize|\.sort\(|\.sort_by\(|sort_by_key|sort_unstable_by_key|slice::sort|while[[:space:]]|loop[[:space:]]*\{|enumerate|position|binary_search|dedup|\.find\(|\.filter\(|\.fold\(|\.all\(|\.chunks\('; then
    echo "wallet-facts wire uniqueness source manifest escaped its reviewed path" >&2
    exit 1
fi

cargo_version="$(run_sealed "$compiler_cargo_bin" --version 2>/dev/null)"
case "$cargo_version" in
    cargo\ *)
        case "$cargo_version" in
            cargo\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts compiler call manifests require Cargo 1.96.0" >&2
                exit 1
                ;;
        esac
        rustc_version="$(
            run_sealed "$compiler_cargo_bin" rustc \
                --quiet \
                -p wasabi-liquid-native-wallet-facts-wire \
                --lib \
                --locked \
                --offline \
                -- \
                --version 2>/dev/null
        )"
        case "$rustc_version" in
            rustc\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts compiler call manifests require Rust 1.96.0" >&2
                exit 1
                ;;
        esac
        run_sealed "$compiler_cargo_bin" rustc \
            --quiet \
            -p wasabi-liquid-native-wallet-facts \
            --lib \
            --release \
            --locked \
            --offline \
            -- \
            --emit=mir \
            -o "$workspace_target/wallet-facts.mir"
        helper_mir_file="$(find "$workspace_target" -maxdepth 1 -name 'wallet-facts-*.mir' -print | head -1)"
        if [ -z "$helper_mir_file" ]; then
            echo "wallet-facts helper MIR was not produced" >&2
            exit 1
        fi
        helper_mir="$(
            awk '
                /^fn validates_observed_public_output/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$helper_mir_file"
        )"
        if printf '%s\n' "$helper_mir" | grep -En 'alloc::alloc|exchange_malloc|RawVec|Vec<|Box<|String|begin_panic|panic_|assert\('; then
            echo "wallet-facts public-output helper MIR escaped its nonallocating call manifest" >&2
            exit 1
        fi
        if [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'secp256k1_ec_pubkey_parse')" -ne 2 ] ||
            [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'Hash160::hash')" -ne 1 ] ||
            [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'raw_eq::<[u8; 20]>')" -ne 1 ] ||
            [ "$(printf '%s\n' "$helper_mir" | awk '/ -> \[return:/ { count++ } END { print count + 0 }')" -ne 4 ]; then
            echo "wallet-facts public-output helper compiler call manifest mismatch" >&2
            exit 1
        fi

        run_sealed "$compiler_cargo_bin" rustc \
            --quiet \
            -p wasabi-liquid-native-wallet-facts-wire \
            --lib \
            --locked \
            --offline \
            -- \
            -C opt-level=0 \
            --emit=mir="$workspace_target/wallet-facts-wire.mir"
        if [ ! -f "$workspace_target/wallet-facts-wire.mir" ]; then
            echo "wallet-facts wire MIR was not produced" >&2
            exit 1
        fi
        input_uniqueness_mir="$(
            awk '
                /^fn validate_inputs_unique/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$workspace_target/wallet-facts-wire.mir"
        )"
        scratch_uniqueness_mir="$(
            awk '
                /^fn scratch_is_unique/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$workspace_target/wallet-facts-wire.mir"
        )"
        decoder_uniqueness_mir="$(
            awk '
                /^fn validate_response_uniqueness/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$workspace_target/wallet-facts-wire.mir"
        )"
        for required_call in \
            'Vec::<ScopedWireOutPoint>::with_capacity' \
            'Vec::<ScopedWireOutPoint>::push' \
            'ScopedWireOutPoint::new::<T>' \
            'scratch_is_unique'
        do
            if [ "$(printf '%s\n' "$input_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts input uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        for required_call in \
            'sort_unstable_by::<' \
            '>::windows' \
            ' as Iterator>::any::<'
        do
            if [ "$(printf '%s\n' "$scratch_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts scratch uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        for required_call in \
            'Vec::<ScopedWireOutPoint>::with_capacity' \
            'Vec::<ScopedWireOutPoint>::push' \
            'ScopedWireOutPoint::new_parts' \
            'scratch_is_unique' \
            'checked_multiply'
        do
            if [ "$(printf '%s\n' "$decoder_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts decoder uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        uniqueness_mir="$input_uniqueness_mir
$scratch_uniqueness_mir
$decoder_uniqueness_mir"
        if printf '%s\n' "$uniqueness_mir" | grep -En 'RawVec|alloc::alloc|exchange_malloc|VecDeque|LinkedList|BTree|HashMap|HashSet|Vec::<ScopedWireOutPoint>::(reserve|resize|extend|from)|sort_by_key|sort_unstable_by_key|slice::<.*>::sort::<|binary_search|dedup|\.chunks\('; then
            echo "wallet-facts uniqueness compiler call manifest escaped its reviewed path" >&2
            exit 1
        fi

        run_sealed "$compiler_cargo_bin" build \
            --quiet \
            -p wasabi-liquid-native-wallet-facts-wire \
            --lib \
            --release \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" build \
            --quiet \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --lib \
            --release \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" build \
            --quiet \
            -p wasabi-liquid-native-ordinary-wallet-plan-ffi \
            --lib \
            --release \
            --locked \
            --offline
        target_directory="$(
            python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["target_directory"])' \
                "$gate_output/metadata.json"
        )"
        wire_archive="$target_directory/release/libwasabi_liquid_native_wallet_facts_wire.rlib"
        plan_archive="$target_directory/release/libwasabi_liquid_native_ordinary_wallet_plan.rlib"
        ffi_archive="$target_directory/release/libwasabi_liquid_native_ordinary_wallet_plan_ffi.a"
        if [ ! -f "$wire_archive" ]; then
            echo "wallet-facts wire release archive is missing" >&2
            exit 1
        fi
        if [ ! -f "$plan_archive" ]; then
            echo "ordinary-wallet plan release archive is missing" >&2
            exit 1
        fi
        if [ ! -f "$ffi_archive" ]; then
            echo "WLPQ FFI release archive is missing" >&2
            exit 1
        fi
        if ! command -v ar >/dev/null 2>&1 || ! command -v nm >/dev/null 2>&1; then
            echo "archive or symbol inspection tool is unavailable" >&2
            exit 1
        fi
        rustc_bin="$compiler_rustc_bin"
        case "$("$rustc_bin" --version 2>/dev/null)" in
            rustc\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts symbol inspection requires Rust 1.96.0" >&2
                exit 1
                ;;
        esac
        symbol_checker="$workspace_target/check-rust-rlib-symbols"
        RUSTC_BOOTSTRAP=wasabi_liquid_symbol_gate run_sealed "$rustc_bin" \
            --crate-name wasabi_liquid_symbol_gate \
            --edition=2024 \
            ci/check-rust-rlib-symbols.rs \
            -o "$symbol_checker"
        run_sealed "$symbol_checker" --self-test
        ar t "$wire_archive" >"$gate_output/wallet-facts-wire.archive"
        if ! grep -Eq '\.o$' "$gate_output/wallet-facts-wire.archive"; then
            echo "wallet-facts wire release archive has no object members" >&2
            exit 1
        fi
        nm -g "$wire_archive" >"$gate_output/wallet-facts-wire.symbols" 2>"$gate_output/wallet-facts-wire.nm-stderr"
        if ! run_sealed "$symbol_checker" "$gate_output/wallet-facts-wire.symbols"; then
            echo "wallet-facts wire release archive exposes an unmangled global symbol" >&2
            exit 1
        fi
        ar t "$plan_archive" >"$gate_output/ordinary-wallet-plan.archive"
        if ! grep -Eq '\.o$' "$gate_output/ordinary-wallet-plan.archive"; then
            echo "ordinary-wallet plan release archive has no object members" >&2
            exit 1
        fi
        nm -g "$plan_archive" >"$gate_output/ordinary-wallet-plan.symbols" 2>"$gate_output/ordinary-wallet-plan.nm-stderr"
        if ! run_sealed "$symbol_checker" "$gate_output/ordinary-wallet-plan.symbols"; then
            echo "ordinary-wallet plan release archive exposes an unmangled global symbol" >&2
            exit 1
        fi
        c++ -x c++ -std=c++17 -fsyntax-only -Wall -Wextra -Werror \
            crates/ordinary-wallet-plan-ffi/src/shim.c
        ffi_output="$gate_output/wlpq-ffi-library"
        mkdir "$ffi_output"
        ffi_library="$(
            SDKROOT="$darwin_sdkroot" \
            ci/build-wlpq-ffi-library.sh \
                "$repository_root" \
                "$target_directory" \
                "$ffi_output"
        )"
        case "$host_system" in
            Darwin)
                if [ "$ffi_library" != "$ffi_output/libwasabi_liquid_wlpq_v1.dylib" ]; then
                    echo "WLPQ FFI macOS artifact path changed" >&2
                    exit 1
                fi
                nm -gjU "$ffi_library" >"$gate_output/wlpq-ffi.symbols"
                ;;
            Linux)
                if [ "$ffi_library" != "$ffi_output/libwasabi_liquid_wlpq_v1.so" ]; then
                    echo "WLPQ FFI Linux artifact path changed" >&2
                    exit 1
                fi
                nm -D --defined-only "$ffi_library" | awk '{ print $3 }' \
                    >"$gate_output/wlpq-ffi.symbols"
                ;;
        esac
        python3 -I ci/check-wlpq-ffi-surface.py \
            "$repository_root" \
            --symbols \
            "$host_system" \
            "$gate_output/wlpq-ffi.symbols"
        python3 -I ci/test-wlpq-ffi-dynamic.py "$repository_root" "$ffi_library"
        if ! dynamic_artifacts="$(
            find "$target_directory/release" "$target_directory/debug" -type f \
                \( -name 'libwasabi_liquid_native_wallet_facts_wire*.dylib' \
                -o -name 'libwasabi_liquid_native_wallet_facts_wire*.so' \
                -o -name 'wasabi_liquid_native_wallet_facts_wire*.dll' \
                -o -name 'libwasabi_liquid_native_ordinary_wallet_plan*.dylib' \
                -o -name 'libwasabi_liquid_native_ordinary_wallet_plan*.so' \
                -o -name 'wasabi_liquid_native_ordinary_wallet_plan*.dll' \) \
                -print
        )"; then
            echo "wallet-facts wire dynamic-library artifact inspection failed" >&2
            exit 1
        fi
        if [ -n "$dynamic_artifacts" ]; then
            printf '%s\n' "$dynamic_artifacts" >&2
            echo "wallet-facts wire dynamic-library artifact is forbidden" >&2
            exit 1
        fi
        run_sealed "$compiler_cargo_bin" check \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" check \
            --workspace \
            --all-targets \
            --all-features \
            --release \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" test \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" test \
            --workspace \
            --all-targets \
            --all-features \
            --release \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --release \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" fmt --all -- --check
        run_sealed "$compiler_cargo_bin" clippy \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline \
            -- \
            -D warnings
        RUSTDOCFLAGS='-D warnings' run_sealed "$compiler_cargo_bin" doc \
            --workspace \
            --no-deps \
            --all-features \
            --locked \
            --offline
        run_sealed "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-wallet-facts-wire \
            --locked \
            --offline \
            conformance
        python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py \
            --verify-cache \
            "$workspace_cargo_home" \
            "$workspace_cache_authority" \
            "$workspace_cache_authority_sha256" \
            "$build_uid"
        python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
            "$sealed_workspace" "$sealed_workspace_authority" "$sealed_workspace_authority_sha256" "$build_uid"
        python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
            "$sealed_toolchain" "$sealed_toolchain_authority" "$sealed_toolchain_authority_sha256" "$build_uid"
        python3 -I ci/check-pinned-rust-toolchain.py --root-owned-toolchain "$sealed_toolchain" >/dev/null
        check_sealed_command_bin >/dev/null
        python3 -I ci/prepare-ordinary-wallet-plan-proof-snapshot.py --verify-tree \
            "$sealed_probe" "$sealed_probe_authority" "$sealed_probe_authority_sha256" "$build_uid"
        ;;
    *)
        echo "wallet-facts compiler and artifact gates require Cargo 1.96.0" >&2
        exit 1
        ;;
esac
