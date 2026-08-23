use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=include/wasabi_liquid_wallet_facts_v1.h");
    println!("cargo:rerun-if-changed=exports/linux.map");
    println!("cargo:rerun-if-changed=exports/macos.txt");
    println!("cargo:rerun-if-changed=exports/windows.def");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let target = env::var("TARGET").expect("Cargo provides TARGET");
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let object = out_dir.join(if target.contains("windows-msvc") {
        "wallet-facts-v1-shim.obj"
    } else {
        "wallet-facts-v1-shim.o"
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
    assert!(status.success(), "wallet-facts C shim compilation failed");

    println!("cargo:rustc-cdylib-link-arg={}", object.display());
    if target.contains("apple-darwin") {
        let exports =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("exports/macos.txt");
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-exported_symbols_list,{}",
            exports.display()
        );
    } else if target.contains("linux") {
        let exports =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("exports/linux.map");
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
            exports.display()
        );
    } else if target.contains("windows-msvc") {
        let exports =
            PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("exports/windows.def");
        println!("cargo:rustc-cdylib-link-arg=/DEF:{}", exports.display());
    }
}
