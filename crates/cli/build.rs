fn main() {
    println!("cargo:rerun-if-changed=../../.git");
    built::write_built_file().expect("failed to acquire build-time information");
}
