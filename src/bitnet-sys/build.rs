fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rustc-check-cfg=cfg(bitnet_unavailable)");
    // Check if bitnet.cpp is available as a submodule
    let bitnet_dir = std::path::Path::new("third_party/bitnet.cpp");
    
    if !bitnet_dir.exists() {
        println!("cargo:warning=bitnet.cpp not found at third_party/bitnet.cpp");
        println!("cargo:warning=Run: git submodule update --init --recursive");
        println!("cargo:rustc-cfg=bitnet_unavailable");
        return Ok(());
    }
    
    // Build bitnet.cpp with CMake
    let dst = cmake::Config::new(bitnet_dir)
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("BITNET_QUANTIZE", "1")
        .define("BUILD_SHARED_LIBS", "ON")
        .build();
    
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=bitnet");
    println!("cargo:rustc-link-lib=ggml");
    println!("cargo:rustc-link-lib=ggml-base");
    println!("cargo:rustc-link-lib=ggml-cpu");
    
    // Link system libraries
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=winmm");
    }
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=Accelerate");
        println!("cargo:rustc-link-lib=framework=Metal");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
    
    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("third_party/bitnet.cpp/bitnet.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("bitnet_.*")
        .allowlist_type("bitnet_.*")
        .allowlist_var("BITNET_.*")
        .generate_comments(false)
        .layout_tests(false)
        .generate()
        .expect("Unable to generate bindings");
    
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    
    Ok(())
}