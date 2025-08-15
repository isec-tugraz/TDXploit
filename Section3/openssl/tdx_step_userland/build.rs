extern crate bindgen;

use anyhow::{Context, Result};
use dotenv;
use std::env::{self};
use std::path::PathBuf;

fn main() -> Result<()> {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=environment.sh");

    const ENV_KERNEL_HEADERS: &'static str = "KERNEL_HEADERS";

    /*besides making usage more convenient, this is also crucial for the rust language
    server to pick up the env var, allowing more in-depth analysis*/
    dotenv::from_path("./build.env").context("failed to load env file")?;

    let header_path = env::var(ENV_KERNEL_HEADERS)
        .with_context(|| format!("Failed to get {} env var", ENV_KERNEL_HEADERS))?;

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", header_path))
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustified_enum("attack_type_t")
        .derive_default(true)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .with_context(|| {
            format!(
                "Failed to build bindings to C API definitions. Include path is {}",
                header_path
            )
        })?;

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .with_context(|| format!("Failed to create bindings.rs file at {:?}", out_path))?;

    cc::Build::new()
        .file("src/bin/vm_copy_cat_victim/copy_cat_victim_fn.S")
        .compile("copy_cat_victim_fn");

    Ok(())
}
