fn main() {
    // The scanner runs elevated, often from a folder the normal user can write (target\release).
    // Windows searches the exe's own folder first for imported DLLs, so a planted iphlpapi.dll
    // would run as admin. LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800) makes the loader resolve static
    // imports from System32 only. Needs Windows 10 1607 or later.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
