#![feature(exit_status_error)]

use std::env;
use std::fs;
use std::io::Result;
use std::path::Path;
use std::process::Command;
use std::string::String;

fn main() -> Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let linux_dir = env::var("LINUX").unwrap();

    let output = Command::new("python3")
        .arg("build.py")
        .arg(&linux_dir)
        .arg(&out_dir)
        .output()?;

    output
        .status
        .exit_ok()
        .map(|_| print!("{}", String::from_utf8_lossy(&output.stdout)))
        .map_err(|_| panic!("\n{}", String::from_utf8_lossy(&output.stderr)))
        .unwrap();

    let mut iustub_outdir = Path::new(&out_dir).join("libiustub");
    if !iustub_outdir.exists() {
        fs::create_dir(&iustub_outdir)?;
    }

    let iustub_so = iustub_outdir.join("libiustub.so");
    Command::new("gcc")
        .arg("-fPIC")
        .arg("-nostartfiles")
        .arg("-nodefaultlibs")
        .arg("--shared")
        .arg("-o")
        .arg(iustub_so.to_string_lossy().to_mut())
        .arg("./libiustub/lib.c")
        .output()?;

    iustub_outdir = iustub_outdir.canonicalize()?;

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=./src/*");
    println!("cargo:rerun-if-changed=./libiustub/*");
    println!("cargo:rustc-link-lib=dylib=iustub");
    println!(
        "cargo:rustc-link-search=native={}",
        iustub_outdir.to_string_lossy()
    );

    Ok(())
}
