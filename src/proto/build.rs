fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap()); }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let proto_dir = std::path::Path::new(&manifest_dir);
    let proto_file = proto_dir.join("cerberus.proto");
    
    // Ensure the output directory exists
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(&out_dir)
        .compile_protos(&[proto_file.to_str().unwrap()], &[proto_dir.to_str().unwrap()])?;
    
    // Tell cargo to rerun if proto file changes
    println!("cargo:rerun-if-changed={}", proto_file.display());
    
    Ok(())
}