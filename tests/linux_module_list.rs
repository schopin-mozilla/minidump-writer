#![cfg(any(target_os = "linux", target_os = "android"))]

use {
    common::*,
    minidump::*,
    minidump_writer::minidump_writer::{MinidumpWriterConfig, ModuleListSource},
    std::path::Path,
};

mod common;

/// Dumps a freshly spawned child and returns the names in its `ModuleListStream`,
/// in the order they were written.
fn module_names(prefix: &str, source: ModuleListSource) -> Vec<String> {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new().prefix(prefix).tempfile().unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(source);
    writer
        .write(&mut tmpfile)
        .expect("could not write minidump");

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    let modules: MinidumpModuleList = dump.get_stream().expect("no module list");
    modules
        .iter()
        .map(|module| module.name.clone())
        .collect::<Vec<_>>()
}

/// Dumps a freshly spawned child and returns its whole `ModuleListStream`, so a
/// test can look entries up by address rather than by name.
fn module_list(prefix: &str, source: ModuleListSource) -> MinidumpModuleList {
    let mut child = start_child_and_wait_for_threads(1);
    let pid = child.id() as i32;

    let mut tmpfile = tempfile::Builder::new().prefix(prefix).tempfile().unwrap();

    let mut writer = MinidumpWriterConfig::new(pid, pid);
    writer.set_module_list_source(source);
    writer
        .write(&mut tmpfile)
        .expect("could not write minidump");

    child.kill().expect("Failed to kill process");
    child.wait().expect("Failed to wait on killed process");

    let dump = Minidump::read_path(tmpfile.path()).expect("failed to read minidump");
    dump.get_stream().expect("no module list")
}

/// The stackwalker takes the first module to be the main executable, so getting
/// that one right matters more than any other entry in the list.
fn assert_module_list_is_sane(modules: &[String]) {
    assert!(!modules.is_empty(), "empty module list");
    assert!(
        modules[0].contains("test"),
        "first module should be the test helper executable, got {:?}",
        modules[0]
    );
    assert!(
        modules.iter().any(|name| name.contains("libc")),
        "no libc in the module list: {modules:?}"
    );
}

#[test]
fn module_list_from_debugger_rendezvous() {
    let modules = module_names(
        "module_list_from_debugger_rendezvous",
        ModuleListSource::DebuggerRendezvous,
    );
    assert_module_list_is_sane(&modules);
}

#[test]
fn module_list_from_proc_maps() {
    let modules = module_names("module_list_from_proc_maps", ModuleListSource::ProcMaps);
    assert_module_list_is_sane(&modules);
}

/// Both sources should agree on which files are loaded.
///
/// They don't agree on the paths -- on Android the linker records the pre-apex
/// path it was handed (`/system/bin/linker64`) while the memory map reports the
/// resolved one (`/apex/com.android.runtime/bin/linker64`) -- so this compares
/// file names, which is what symbolication keys off of alongside the build ID.
#[test]
fn both_module_list_sources_agree_on_files() {
    // Bionic's dynamic linker names its own `soinfo` `ld-android.so`, so the
    // rendez-vous never mentions `linker64` even though the object is there.
    const LINKER_ALIASES: &[&str] = &["ld-android.so", "linker64", "linker"];

    let file_names = |modules: Vec<String>| {
        let mut names = modules
            .into_iter()
            .filter(|name| name.starts_with('/'))
            .map(|name| {
                Path::new(&name)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    };

    let from_rendezvous = file_names(module_names(
        "module_list_agree_rendezvous",
        ModuleListSource::DebuggerRendezvous,
    ));
    let from_proc_maps = file_names(module_names(
        "module_list_agree_proc_maps",
        ModuleListSource::ProcMaps,
    ));

    for name in &from_proc_maps {
        let found = from_rendezvous.contains(name)
            || (LINKER_ALIASES.contains(&name.as_str())
                && from_rendezvous
                    .iter()
                    .any(|other| LINKER_ALIASES.contains(&other.as_str())));
        assert!(
            found,
            "{name} is in the /proc/<pid>/maps module list but not in the rendez-vous one\n\
             rendez-vous: {from_rendezvous:?}\n\
             proc maps:   {from_proc_maps:?}"
        );
    }
}

/// Each ELF object should appear exactly once. It's easy to accidentally emit
/// one entry per `PT_LOAD` segment, which gives the stackwalker several modules
/// with the same name and only one usable base address.
///
/// Only checked for the rendez-vous: the memory map genuinely can't tell one
/// object from two adjacent ones, and does report the main executable twice
/// here. Getting that right is the reason to prefer the rendez-vous.
#[test]
fn module_list_has_no_duplicates() {
    let modules = module_names(
        "module_list_no_duplicates",
        ModuleListSource::DebuggerRendezvous,
    );
    let mut seen = modules.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        modules.len(),
        "duplicate modules in the rendez-vous list: {modules:?}"
    );
}

/// The vDSO is mapped by the kernel rather than the linker, so it takes an
/// extra step to get it into the rendez-vous-derived list.
#[test]
fn module_list_includes_the_vdso() {
    let modules = module_names("module_list_vdso", ModuleListSource::DebuggerRendezvous);
    assert!(
        modules
            .iter()
            .any(|name| name.contains("vdso") || name.contains("linux-gate")),
        "no vDSO in the module list: {modules:?}"
    );
}

/// Being in the stream isn't enough: a reader indexes modules by address and
/// drops any whose range overlaps one it has already seen, so a module that
/// another one reaches over is written but unreachable. The vDSO is the case
/// that bites -- it routinely sits in a hole between the dynamic linker's
/// segments -- but nothing in the list may shadow anything else.
#[test]
fn every_module_is_reachable_by_address() {
    let modules = module_list(
        "every_module_is_reachable_by_address",
        ModuleListSource::DebuggerRendezvous,
    );

    for module in modules.iter() {
        let found = modules.module_at_address(module.raw.base_of_image);
        assert_eq!(
            found.map(|found| found.raw.base_of_image),
            Some(module.raw.base_of_image),
            "`{}` at {:#x} is in the module list but resolves to {:?}",
            module.name,
            module.raw.base_of_image,
            found.map(|found| &found.name),
        );
    }
}
