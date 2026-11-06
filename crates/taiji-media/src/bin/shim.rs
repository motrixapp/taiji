//! Exec-shim host binary (dev/embedder face of `taiji_media::exec_shim`).
//!
//! Production hosts do not need this binary: the `taiji` executable
//! itself calls [`taiji_media::exec_shim::maybe_run_shim`] at the top
//! of its `main`, and `MediaCommand` defaults its shim program to
//! `current_exe()`. Test drivers (whose `current_exe` is a libtest
//! harness that cannot host the hook) and embedders with the same
//! constraint point `MediaCommand::shim_program` at this binary — the
//! embedding contract is exactly the two lines of `main` below.

fn main() {
    let code = taiji_media::exec_shim::maybe_run_shim().unwrap_or(0);
    std::process::exit(code);
}
