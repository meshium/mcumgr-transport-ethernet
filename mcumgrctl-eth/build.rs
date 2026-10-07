use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        env::var("CARGO_MANIFEST_DIR")
            .map(|dir| format!("{dir}/Cargo.lock"))
            .unwrap_or_else(|_| "Cargo.lock".into())
    );

    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("Cargo.toml")
        .exec()
        .expect("cargo metadata failed");
    let version = metadata
        .packages
        .iter()
        .find(|package| package.name == "mcumgrctl")
        .expect("mcumgrctl is a dependency")
        .version
        .clone();
    println!("cargo:rustc-env=MCUMGRCTL_VERSION={version}");
}
