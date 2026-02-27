use std::path::PathBuf;

fn main() {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let ebpf_target = if profile == "release" {
        "release"
    } else {
        "debug"
    };

    let ebpf_binary: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "cgnat-ebpf",
        "target",
        "bpfel-unknown-none",
        ebpf_target,
        "cgnat-ebpf",
    ]
    .iter()
    .collect();

    println!("cargo::rerun-if-changed={}", ebpf_binary.display());

    if !ebpf_binary.exists() {
        panic!(
            "\n\
            ======================================================\n\
            ERROR: eBPF binary not found at:\n\
              {}\n\
            \n\
            Build the eBPF program first:\n\
              make build-ebpf       (release)\n\
              make debug-ebpf       (debug)\n\
            ======================================================\n",
            ebpf_binary.display()
        );
    }
}
