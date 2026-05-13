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
        "GetProcessHeap" => crate::heap::GetProcessHeap as *const (),
        "HeapAlloc" => crate::heap::HeapAlloc as *const (),
        "HeapFree" => crate::heap::HeapFree as *const (),
        "Sleep" => crate::time::Sleep as *const (),
        "GetTickCount" => crate::time::GetTickCount as *const (),
        "GetTickCount64" => crate::time::GetTickCount64 as *const (),
        "QueryPerformanceCounter" => crate::time::QueryPerformanceCounter as *const (),
        "QueryPerformanceFrequency" => crate::time::QueryPerformanceFrequency as *const (),
        "GetSystemTimeAsFileTime" => crate::time::GetSystemTimeAsFileTime as *const (),
        "GetCurrentThreadId" => crate::time::GetCurrentThreadId as *const (),
        "GetCurrentProcessId" => crate::time::GetCurrentProcessId as *const (),
        "VirtualAlloc" => crate::vm::VirtualAlloc as *const (),
        "VirtualFree" => crate::vm::VirtualFree as *const (),
        "VirtualProtect" => crate::vm::VirtualProtect as *const (),
        "InitializeCriticalSection" => crate::sync::InitializeCriticalSection as *const (),
        "InitializeCriticalSectionAndSpinCount" => {
            crate::sync::InitializeCriticalSectionAndSpinCount as *const ()
        }
        "EnterCriticalSection" => crate::sync::EnterCriticalSection as *const (),
        "LeaveCriticalSection" => crate::sync::LeaveCriticalSection as *const (),
        "DeleteCriticalSection" => crate::sync::DeleteCriticalSection as *const (),
        "TryEnterCriticalSection" => crate::sync::TryEnterCriticalSection as *const (),
        "SetLastError" => crate::sync::SetLastError as *const (),
        "GetLastError" => crate::sync::GetLastError as *const (),
        "LoadLibraryA" => crate::modules::LoadLibraryA as *const (),
        "LoadLibraryW" => crate::modules::LoadLibraryW as *const (),
        "LoadLibraryExA" => crate::modules::LoadLibraryExA as *const (),
        "LoadLibraryExW" => crate::modules::LoadLibraryExW as *const (),
        "FreeLibrary" => crate::modules::FreeLibrary as *const (),
        "GetModuleHandleA" => crate::modules::GetModuleHandleA as *const (),
        "GetModuleHandleW" => crate::modules::GetModuleHandleW as *const (),
        "GetProcAddress" => crate::modules::GetProcAddress as *const (),
        "CreateEventA" => crate::threads::CreateEventA as *const (),
        "CreateEventW" => crate::threads::CreateEventW as *const (),
        "SetEvent" => crate::threads::SetEvent as *const (),
        "ResetEvent" => crate::threads::ResetEvent as *const (),
        "CreateMutexA" => crate::threads::CreateMutexA as *const (),
        "CreateMutexW" => crate::threads::CreateMutexW as *const (),
        "ReleaseMutex" => crate::threads::ReleaseMutex as *const (),
        "CreateSemaphoreA" => crate::threads::CreateSemaphoreA as *const (),
        "CreateSemaphoreW" => crate::threads::CreateSemaphoreW as *const (),
        "ReleaseSemaphore" => crate::threads::ReleaseSemaphore as *const (),
        "WaitForSingleObject" => crate::threads::WaitForSingleObject as *const (),
        "WaitForSingleObjectEx" => crate::threads::WaitForSingleObjectEx as *const (),
        "WaitForMultipleObjects" => crate::threads::WaitForMultipleObjects as *const (),
        "CloseHandle" => crate::threads::CloseHandle as *const (),
        "DuplicateHandle" => crate::threads::DuplicateHandle as *const (),
        "CreateThread" => crate::threads::CreateThread as *const (),
        "GetCurrentThread" => crate::threads::GetCurrentThread as *const (),
        "GetCurrentProcess" => crate::threads::GetCurrentProcess as *const (),
        "ExitThread" => crate::threads::ExitThread as *const (),

        // SEH stubs
        "RtlLookupFunctionEntry" => crate::stubs::RtlLookupFunctionEntry as *const (),
        "RtlCaptureContext" => crate::stubs::RtlCaptureContext as *const (),
        "RtlPcToFileHeader" => crate::stubs::RtlPcToFileHeader as *const (),
        "RtlUnwindEx" => crate::stubs::RtlUnwindEx as *const (),
        "RtlVirtualUnwind" => crate::stubs::RtlVirtualUnwind as *const (),
        "RtlAddFunctionTable" => crate::stubs::RtlAddFunctionTable as *const (),
        "UnhandledExceptionFilter" => crate::stubs::UnhandledExceptionFilter as *const (),
        "SetUnhandledExceptionFilter" => crate::stubs::SetUnhandledExceptionFilter as *const (),

        // CRT init
        "GetCommandLineA" => crate::stubs::GetCommandLineA as *const (),
        "GetCommandLineW" => crate::stubs::GetCommandLineW as *const (),
        "GetStartupInfoA" => crate::stubs::GetStartupInfoA as *const (),
        "GetStartupInfoW" => crate::stubs::GetStartupInfoW as *const (),

        // Environment
        "GetEnvironmentStrings" => crate::stubs::GetEnvironmentStrings as *const (),
        "GetEnvironmentStringsW" => crate::stubs::GetEnvironmentStringsW as *const (),
        "FreeEnvironmentStringsA" => crate::stubs::FreeEnvironmentStringsA as *const (),
        "FreeEnvironmentStringsW" => crate::stubs::FreeEnvironmentStringsW as *const (),
        "GetEnvironmentVariableA" => crate::stubs::GetEnvironmentVariableA as *const (),
        "GetEnvironmentVariableW" => crate::stubs::GetEnvironmentVariableW as *const (),
        "SetEnvironmentVariableA" => crate::stubs::SetEnvironmentVariableA as *const (),
        "SetEnvironmentVariableW" => crate::stubs::SetEnvironmentVariableW as *const (),

        // Locale
        "GetACP" => crate::stubs::GetACP as *const (),
        "GetOEMCP" => crate::stubs::GetOEMCP as *const (),
        "GetUserDefaultLCID" => crate::stubs::GetUserDefaultLCID as *const (),
        "GetSystemDefaultLCID" => crate::stubs::GetSystemDefaultLCID as *const (),
        "GetCPInfo" => crate::stubs::GetCPInfo as *const (),
        "GetLocaleInfoA" => crate::stubs::GetLocaleInfoA as *const (),
        "GetLocaleInfoW" => crate::stubs::GetLocaleInfoW as *const (),
        "LCMapStringW" => crate::stubs::LCMapStringW as *const (),
        "CompareStringW" => crate::stubs::CompareStringW as *const (),
        "GetStringTypeW" => crate::stubs::GetStringTypeW as *const (),
        "GetTimeZoneInformation" => crate::stubs::GetTimeZoneInformation as *const (),
        "GetTimeFormatW" => crate::stubs::GetTimeFormatW as *const (),

        // Misc process / feature
        "IsDebuggerPresent" => crate::stubs::IsDebuggerPresent as *const (),
        "IsProcessorFeaturePresent" => crate::stubs::IsProcessorFeaturePresent as *const (),
        "GetSystemDirectoryA" => crate::stubs::GetSystemDirectoryA as *const (),
        "GetSystemDirectoryW" => crate::stubs::GetSystemDirectoryW as *const (),
        "GetVersionExW" => crate::stubs::GetVersionExW as *const (),
        "GetVersion" => crate::stubs::GetVersion as *const (),
        "TerminateProcess" => crate::stubs::TerminateProcess as *const (),
        "FreeLibraryAndExitThread" => crate::stubs::FreeLibraryAndExitThread as *const (),
        "EncodePointer" => crate::stubs::EncodePointer as *const (),
        "DecodePointer" => crate::stubs::DecodePointer as *const (),

        // SList
        "InitializeSListHead" => crate::stubs::InitializeSListHead as *const (),
        "InterlockedPopEntrySList" => crate::stubs::InterlockedPopEntrySList as *const (),
        "InterlockedPushEntrySList" => crate::stubs::InterlockedPushEntrySList as *const (),
        "QueryDepthSList" => crate::stubs::QueryDepthSList as *const (),
        "InterlockedFlushSList" => crate::stubs::InterlockedFlushSList as *const (),

        // Thread misc
        "SwitchToThread" => crate::stubs::SwitchToThread as *const (),
        "GetThreadPriority" => crate::stubs::GetThreadPriority as *const (),
        "SetThreadPriority" => crate::stubs::SetThreadPriority as *const (),
        "GetThreadTimes" => crate::stubs::GetThreadTimes as *const (),
        "GetLogicalProcessorInformation" => {
            crate::stubs::GetLogicalProcessorInformation as *const ()
        }
        "GetNumaHighestNodeNumber" => crate::stubs::GetNumaHighestNodeNumber as *const (),
        "RegisterWaitForSingleObject" => crate::stubs::RegisterWaitForSingleObject as *const (),
        "UnregisterWait" => crate::stubs::UnregisterWait as *const (),
        "UnregisterWaitEx" => crate::stubs::UnregisterWaitEx as *const (),
        "SignalObjectAndWait" => crate::stubs::SignalObjectAndWait as *const (),

        // Timer queue
        "CreateTimerQueue" => crate::stubs::CreateTimerQueue as *const (),
        "CreateTimerQueueTimer" => crate::stubs::CreateTimerQueueTimer as *const (),
        "ChangeTimerQueueTimer" => crate::stubs::ChangeTimerQueueTimer as *const (),
        "DeleteTimerQueueTimer" => crate::stubs::DeleteTimerQueueTimer as *const (),

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
