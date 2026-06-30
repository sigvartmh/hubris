// Link the prebuilt nRF Oberon (ocrypto) static library. We use the Cortex-M33
// **hard-float** build (matches the EFR32MG24 M33 FPU and the hubris
// `thumbv8m.main-none-eabihf` target), which is the fastest variant.

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_dir = format!(
        "{manifest}/../../ref/sdk-nrfxlib/crypto/nrf_oberon/lib/cortex-m33/hard-float"
    );
    println!("cargo:rustc-link-search=native={lib_dir}");
    // liboberon_3.0.19.a  ->  link name "oberon_3.0.19"
    println!("cargo:rustc-link-lib=static=oberon_3.0.19");
    println!("cargo:rerun-if-changed=build.rs");
}
