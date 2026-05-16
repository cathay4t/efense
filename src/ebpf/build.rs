// SPDX-License-Identifier: GPL-2.0-only

use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary.
/// This would be better expressed by [artifact-dependencies][bindeps] but
/// issues such as https://github.com/rust-lang/cargo/issues/12385 make their
/// use impractical for the time being.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
