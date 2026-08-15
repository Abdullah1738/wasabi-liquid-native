#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: build-wlpq-ffi-library.sh REPOSITORY_ROOT TARGET_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 1
fi

repository_root=$1
target_directory=$2
output_directory=$3
crate="$repository_root/crates/ordinary-wallet-plan-ffi"
archive="$target_directory/release/libwasabi_liquid_native_ordinary_wallet_plan_ffi.a"

if [ ! -f "$archive" ] || [ ! -d "$output_directory" ]; then
    echo "WLPQ FFI archive or output directory is unavailable" >&2
    exit 1
fi

object="$output_directory/wlpq-v1-shim.o"
host_system="$(uname -s)"

cc -std=c11 -fPIC -fvisibility=hidden -Wall -Wextra -Werror \
    -c "$crate/src/shim.c" \
    -o "$object"

case "$host_system" in
    Darwin)
        output="$output_directory/libwasabi_liquid_wlpq_v1.dylib"
        cc -dynamiclib -Wl,-dead_strip \
            -Wl,-install_name,@rpath/libwasabi_liquid_wlpq_v1.dylib \
            -Wl,-compatibility_version,1.0.0 \
            -Wl,-current_version,1.0.0 \
            -o "$output" \
            "$object" \
            -Wl,-force_load,"$archive" \
            -Wl,-exported_symbols_list,"$crate/exports/macos.txt" \
            -liconv
        ;;
    Linux)
        output="$output_directory/libwasabi_liquid_wlpq_v1.so"
        cc -shared -Wl,--no-undefined -Wl,--gc-sections \
            -Wl,-soname,libwasabi_liquid_wlpq_v1.so \
            -o "$output" \
            "$object" \
            -Wl,--whole-archive "$archive" -Wl,--no-whole-archive \
            -Wl,--version-script="$crate/exports/linux.map" \
            -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc
        ;;
    *)
        echo "WLPQ FFI dynamic library target is not qualified" >&2
        exit 1
        ;;
esac

printf '%s\n' "$output"
