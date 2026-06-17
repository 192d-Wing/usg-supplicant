// Compile the Slint UI into the generated module consumed by `slint::include_modules!()`.
// Only on Windows: the GUI stack (and `slint-build`) is a Windows-only dependency, and
// a build script's `cfg(windows)` reflects the host, which matches the target for the
// native Windows build the tray actually launches.
fn main() {
    #[cfg(windows)]
    slint_build::compile("ui/main.slint").expect("compile Slint UI");
}
