fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "macos" {
        cc::Build::new()
            .file("src/credstore.m")
            .flag("-fobjc-arc")
            .compile("arca_credstore");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=AuthenticationServices");
        println!("cargo:rerun-if-changed=src/credstore.m");
    }
}
