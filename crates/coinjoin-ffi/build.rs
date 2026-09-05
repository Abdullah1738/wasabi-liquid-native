use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=include/wasabi_liquid_coinjoin_v1.h");
    println!("cargo:rerun-if-changed=exports/linux.map");
    println!("cargo:rerun-if-changed=exports/macos.txt");
    println!("cargo:rerun-if-changed=exports/windows.def");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let target = env::var("TARGET").expect("Cargo provides TARGET");
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let object = out_dir.join(if target.contains("windows-msvc") {
        "coinjoin-v1-shim.obj"
    } else {
        "coinjoin-v1-shim.o"
    });

    let mut compile = Command::new(compiler);
    if target.contains("windows-msvc") {
        compile.args(["/nologo", "/c", "src/shim.c"]);
        compile.arg(format!("/Fo{}", object.display()));
    } else {
        compile.args([
            "-std=c11",
            "-fPIC",
            "-fvisibility=hidden",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            "src/shim.c",
            "-o",
        ]);
        compile.arg(&object);
    }
    let status = compile.status().expect("run the configured C compiler");
    assert!(status.success(), "CoinJoin C shim compilation failed");

    // The shim object is linked into the dynamic artifact by the CI build
    // script (ci/build-coinjoin-ffi-library.sh), which is the ONLY path that
    // enforces the export allowlist; Cargo's own cdylib link would re-export
    // the toolchain's own symbol set regardless of -exported_symbols_list.
    let _ = object;
}
