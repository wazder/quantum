//! `quantum` — entry point.
//!
//! Subcommands:
//!   quantum dump <file>    — parse PE and print headers / sections
//!   quantum run  <file>    — load PE, JIT-translate, execute, exit with
//!                            whatever the guest passes to ExitProcess

mod process;

use std::env;
use std::fs;
use std::process::ExitCode;

use quantum_loader::{PeFile, PeKind};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => match args.get(2) {
            Some(path) => cmd_run(path),
            None => {
                eprintln!("usage: quantum run <path-to.exe>");
                ExitCode::from(2)
            }
        },
        Some("dump") => match args.get(2) {
            Some(path) => cmd_dump(path),
            None => {
                eprintln!("usage: quantum dump <path-to.exe>");
                ExitCode::from(2)
            }
        },
        // Back-compat: bare path = dump.
        Some(path) if !path.starts_with('-') => cmd_dump(path),
        _ => {
            eprintln!("usage: quantum {{run|dump}} <path-to.exe>");
            ExitCode::from(2)
        }
    }
}

fn cmd_run(path: &str) -> ExitCode {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("quantum: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    match process::run_pe(&bytes) {
        Ok(code) => ExitCode::from((code & 0xFF) as u8),
        Err(e) => {
            eprintln!("quantum: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_dump(path: &str) -> ExitCode {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let pe = match PeFile::parse(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let kind = match pe.opt.kind {
        PeKind::Pe32 => "PE32",
        PeKind::Pe32Plus => "PE32+",
    };
    println!("{path}: {kind}, machine={:#06x}", pe.coff.machine);
    println!(
        "  image_base={:#x}  entry={:#x}  size_of_image={:#x}",
        pe.opt.image_base, pe.opt.address_of_entry_point, pe.opt.size_of_image
    );
    println!("  sections ({}):", pe.coff.number_of_sections);
    for s in pe.sections() {
        println!(
            "    {:<8}  va={:#010x}  vsize={:#x}  rawptr={:#x}  rawsize={:#x}  ch={:#010x}",
            s.name_str(),
            s.virtual_address,
            s.virtual_size,
            s.pointer_to_raw_data,
            s.size_of_raw_data,
            s.characteristics
        );
    }

    ExitCode::SUCCESS
}
