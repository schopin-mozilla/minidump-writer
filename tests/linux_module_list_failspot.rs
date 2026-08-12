#![cfg(any(target_os = "linux", target_os = "android"))]

//! Lives in its own test binary because failspots are process-global: enabling
//! one here would otherwise leak into the tests running concurrently in
//! `linux_module_list.rs`.

use {
    common::*,
    minidump::*,
    minidump_writer::{
        FailSpotName,
        minidump_writer::{MinidumpWriterConfig, ModuleListSource},
    },
};

mod common;

/// The point of preferring the rendez-vous is that it doesn't go through
/// `/proc/<pid>/maps` at all, so it should still produce a module list when
/// reading that file fails.
#[test]
fn module_list_from_debugger_rendezvous_without_proc_maps() {
    let mut failspot_client = FailSpotName::testing_client();
    failspot_client.set_enabled(FailSpotName::EnumerateMappingsFromProc, true);

    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("module_list_without_proc_maps")
        .tempfile()
        .unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(ModuleListSource::DebuggerRendezvous);
    writer
        .write(&mut tmpfile)
        .expect("could not write minidump");

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("no module list");
    let names = modules
        .iter()
        .map(|module| module.name.clone())
        .collect::<Vec<_>>();

    assert!(!names.is_empty(), "empty module list");
    assert!(
        names.iter().any(|name| name.contains("libc")),
        "no libc in the module list: {names:?}"
    );
}

/// A crash taken while the linker is mutating the link map must not be walked.
/// Falling back to `/proc/<pid>/maps` costs us the extent fixes, but the kernel
/// keeps that file consistent whatever the linker is in the middle of.
#[test]
fn inconsistent_debugger_rendezvous_falls_back_to_proc_maps() {
    let mut failspot_client = FailSpotName::testing_client();
    failspot_client.set_enabled(FailSpotName::DebuggerRendezvousNotConsistent, true);

    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new()
        .prefix("inconsistent_debugger_rendezvous")
        .tempfile()
        .unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(ModuleListSource::DebuggerRendezvous);
    writer
        .write(&mut tmpfile)
        .expect("could not write minidump");

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("no module list");
    let names = modules
        .iter()
        .map(|module| module.name.clone())
        .collect::<Vec<_>>();

    // The fallback produced a list, rather than the walk producing a bad one.
    assert!(!names.is_empty(), "empty module list");
    assert!(
        names.iter().any(|name| name.contains("libc")),
        "no libc in the module list: {names:?}"
    );

    // And the reason we fell back is on the record.
    let soft_errors = read_minidump_soft_errors_or_panic(&dump);
    assert!(
        soft_errors
            .to_string()
            .contains("DebuggerRendezvousNotConsistent"),
        "no record of the inconsistent rendez-vous: {soft_errors:#?}"
    );
}
