//! Import resolver. Given a DLL name + function name, return the
//! host-side function pointer the JIT should install into the IAT slot.

/// Resolve an imported function to a host address suitable for IAT
/// installation. Names are case-insensitive on the DLL side (Windows
/// behaviour) but exact on the function side (also Windows behaviour).
pub fn resolve(dll: &str, function: &str) -> Option<u64> {
    if dll.eq_ignore_ascii_case("kernel32.dll") || dll.eq_ignore_ascii_case("kernelbase.dll") {
        return resolve_kernel32(function);
    }
    None
}

fn resolve_kernel32(function: &str) -> Option<u64> {
    let ptr: *const () = match function {
        "ExitProcess" => crate::process::ExitProcess as *const (),
        "GetStdHandle" => crate::io::GetStdHandle as *const (),
        "WriteFile" => crate::io::WriteFile as *const (),
        _ => return None,
    };
    Some(ptr as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_exit_process() {
        let addr = resolve("KERNEL32.DLL", "ExitProcess").expect("resolve");
        assert_eq!(addr as *const (), crate::process::ExitProcess as *const ());
    }

    #[test]
    fn resolves_case_insensitive_dll() {
        assert!(resolve("kernel32.dll", "ExitProcess").is_some());
        assert!(resolve("Kernel32.Dll", "ExitProcess").is_some());
    }

    #[test]
    fn unknown_function_returns_none() {
        assert!(resolve("KERNEL32.DLL", "DefinitelyNotARealFunction").is_none());
    }

    #[test]
    fn unknown_dll_returns_none() {
        assert!(resolve("user32.dll", "ExitProcess").is_none());
    }
}
