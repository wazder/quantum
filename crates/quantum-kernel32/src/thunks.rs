//! Import resolver. Given a DLL name + function name, return the
//! host-side function pointer the JIT should install into the IAT slot.

/// Resolve an imported function to a host address suitable for IAT
/// installation. Names are case-insensitive on the DLL side (Windows
/// behaviour) but exact on the function side (also Windows behaviour).
pub fn resolve(dll: &str, function: &str) -> Option<u64> {
    if dll.eq_ignore_ascii_case("kernel32.dll") || dll.eq_ignore_ascii_case("kernelbase.dll") {
        return resolve_kernel32(function);
    }
    if dll.eq_ignore_ascii_case("steam_api64.dll") {
        return crate::steam::resolve(function);
    }
    if dll.eq_ignore_ascii_case("d3d11.dll") {
        return crate::d3d11::resolve(function);
    }
    if dll.eq_ignore_ascii_case("d3d9.dll") {
        return crate::d3d11::resolve_d3d9(function);
    }
    if dll.eq_ignore_ascii_case("d3dx11_43.dll") {
        return crate::d3d11::resolve_d3dx11(function);
    }
    if dll.eq_ignore_ascii_case("d3dcompiler_43.dll") {
        return crate::d3d11::resolve_d3dcompiler(function);
    }
    if dll.eq_ignore_ascii_case("dxgi.dll") {
        return crate::d3d11::resolve_dxgi(function);
    }
    if dll.eq_ignore_ascii_case("user32.dll") {
        return crate::user32::resolve(function);
    }
    if dll.eq_ignore_ascii_case("gdi32.dll") {
        return crate::gdi32::resolve(function);
    }
    if dll.eq_ignore_ascii_case("advapi32.dll") {
        return crate::advapi32::resolve(function);
    }
    if dll.eq_ignore_ascii_case("winmm.dll") {
        return crate::winmm::resolve(function);
    }
    if dll.eq_ignore_ascii_case("shell32.dll") {
        return crate::misc_win::resolve_shell32(function);
    }
    if dll.eq_ignore_ascii_case("ole32.dll") {
        return crate::misc_win::resolve_ole32(function);
    }
    if dll.eq_ignore_ascii_case("imm32.dll") {
        return crate::misc_win::resolve_imm32(function);
    }
    if dll.eq_ignore_ascii_case("crypt32.dll") {
        return crate::misc_win::resolve_crypt32(function);
    }
    if dll.eq_ignore_ascii_case("dinput8.dll") {
        return crate::misc_win::resolve_dinput8(function);
    }
    if dll.eq_ignore_ascii_case("oleaut32.dll") {
        return crate::misc_win::resolve_oleaut32(function);
    }
    if dll.eq_ignore_ascii_case("xinput1_3.dll") {
        return crate::misc_win::resolve_xinput1_3(function);
    }
    if dll.eq_ignore_ascii_case("wldap32.dll") {
        return crate::misc_win::resolve_wldap32(function);
    }
    if dll.eq_ignore_ascii_case("ws2_32.dll") {
        return crate::ws2_32::resolve(function);
    }
    if dll.eq_ignore_ascii_case("wsock32.dll") {
        return crate::misc_win::resolve_wsock32(function);
    }
    if dll.eq_ignore_ascii_case("msacm32.dll") {
        return crate::misc_win::resolve_msacm32(function);
    }
    None
}

fn resolve_kernel32(function: &str) -> Option<u64> {
    let ptr: *const () = match function {
        "ExitProcess" => crate::process::ExitProcess as *const (),
        "GetStdHandle" => crate::io::GetStdHandle as *const (),
        "WriteFile" => crate::file_io::WriteFile as *const (),
        "GetProcessHeap" => crate::heap::GetProcessHeap as *const (),
        "HeapAlloc" => crate::heap::HeapAlloc as *const (),
        "HeapFree" => crate::heap::HeapFree as *const (),
        "HeapCreate" => crate::heap::HeapCreate as *const (),
        "HeapDestroy" => crate::heap::HeapDestroy as *const (),
        "HeapReAlloc" => crate::heap::HeapReAlloc as *const (),
        "HeapSize" => crate::heap::HeapSize as *const (),
        "HeapValidate" => crate::heap::HeapValidate as *const (),
        "HeapSetInformation" => crate::heap::HeapSetInformation as *const (),
        "LCMapStringA" => crate::stubs::LCMapStringA as *const (),
        "GetStringTypeA" => crate::stubs::GetStringTypeA as *const (),
        "GetStringTypeExA" => crate::stubs::GetStringTypeExA as *const (),
        "GetStringTypeExW" => crate::stubs::GetStringTypeExW as *const (),
        "FindFirstFileExA" => crate::stubs::FindFirstFileExA as *const (),
        "FindNextFileA" => crate::stubs::FindNextFileA as *const (),
        "GetFullPathNameA" => crate::stubs::GetFullPathNameA as *const (),
        "GetTempPathA" => crate::stubs::GetTempPathA as *const (),
        "GetDriveTypeA" => crate::stubs::GetDriveTypeA as *const (),
        "GetWindowsDirectoryA" => crate::stubs::GetWindowsDirectoryA as *const (),
        "DeviceIoControl" => crate::stubs::DeviceIoControl as *const (),
        "OpenEventA" => crate::stubs::OpenEventA as *const (),
        "OpenEventW" => crate::stubs::OpenEventW as *const (),
        "FlsAlloc" => crate::stubs::FlsAlloc as *const (),
        "FlsFree" => crate::stubs::FlsFree as *const (),
        "FlsGetValue" => crate::stubs::FlsGetValue as *const (),
        "FlsSetValue" => crate::stubs::FlsSetValue as *const (),
        "SetHandleCount" => crate::stubs::SetHandleCount as *const (),
        "CreateWaitableTimerA" => crate::stubs::CreateWaitableTimerA as *const (),
        "CreateWaitableTimerW" => crate::stubs::CreateWaitableTimerW as *const (),
        "SetWaitableTimer" => crate::stubs::SetWaitableTimer as *const (),
        "GetVersionExA" => crate::stubs::GetVersionExA as *const (),
        "OpenFile" => crate::stubs::OpenFile as *const (),
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
        "PulseEvent" => crate::threads::PulseEvent as *const (),
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
        "AddVectoredExceptionHandler" => crate::seh::AddVectoredExceptionHandler as *const (),
        "RemoveVectoredExceptionHandler" => crate::seh::RemoveVectoredExceptionHandler as *const (),
        "AddVectoredContinueHandler" => crate::seh::AddVectoredContinueHandler as *const (),
        "RemoveVectoredContinueHandler" => crate::seh::RemoveVectoredContinueHandler as *const (),

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

        // File I/O
        "CreateFileA" => crate::file_io::CreateFileA as *const (),
        "CreateFileW" => crate::file_io::CreateFileW as *const (),
        "ReadFile" => crate::file_io::ReadFile as *const (),
        "FlushFileBuffers" => crate::stubs::FlushFileBuffers as *const (),
        "SetFilePointer" => crate::file_io::SetFilePointer as *const (),
        "SetFilePointerEx" => crate::file_io::SetFilePointerEx as *const (),
        "GetFileSizeEx" => crate::file_io::GetFileSizeEx as *const (),
        "SetEndOfFile" => crate::stubs::SetEndOfFile as *const (),
        "GetFileSize" => crate::file_io::GetFileSize as *const (),
        "GetFileType" => crate::stubs::GetFileType as *const (),
        "GetFileAttributesA" => crate::stubs::GetFileAttributesA as *const (),
        "GetFileAttributesW" => crate::stubs::GetFileAttributesW as *const (),
        "GetFileAttributesExW" => crate::stubs::GetFileAttributesExW as *const (),
        "SetFileAttributesW" => crate::stubs::SetFileAttributesW as *const (),
        "GetFileInformationByHandle" => crate::stubs::GetFileInformationByHandle as *const (),
        "FindFirstFileW" => crate::stubs::FindFirstFileW as *const (),
        "FindFirstFileExW" => crate::stubs::FindFirstFileExW as *const (),
        "FindNextFileW" => crate::stubs::FindNextFileW as *const (),
        "FindClose" => crate::stubs::FindClose as *const (),
        "CreateDirectoryW" => crate::stubs::CreateDirectoryW as *const (),
        "RemoveDirectoryW" => crate::stubs::RemoveDirectoryW as *const (),
        "DeleteFileW" => crate::stubs::DeleteFileW as *const (),
        "MoveFileW" => crate::stubs::MoveFileW as *const (),
        "MoveFileExW" => crate::stubs::MoveFileExW as *const (),
        "CopyFileW" => crate::stubs::CopyFileW as *const (),
        "GetCurrentDirectoryW" => crate::stubs::GetCurrentDirectoryW as *const (),
        "GetFullPathNameW" => crate::stubs::GetFullPathNameW as *const (),
        "GetTempPathW" => crate::stubs::GetTempPathW as *const (),
        "GetTempFileNameW" => crate::stubs::GetTempFileNameW as *const (),
        "GetDriveTypeW" => crate::stubs::GetDriveTypeW as *const (),
        "GetDiskFreeSpaceW" => crate::stubs::GetDiskFreeSpaceW as *const (),
        "GetDiskFreeSpaceExW" => crate::stubs::GetDiskFreeSpaceExW as *const (),
        "ReadDirectoryChangesW" => crate::stubs::ReadDirectoryChangesW as *const (),

        // Console
        "ReadConsoleA" => crate::stubs::ReadConsoleA as *const (),
        "ReadConsoleW" => crate::stubs::ReadConsoleW as *const (),
        "WriteConsoleW" => crate::stubs::WriteConsoleW as *const (),
        "GetConsoleMode" => crate::stubs::GetConsoleMode as *const (),
        "SetConsoleMode" => crate::stubs::SetConsoleMode as *const (),
        "GetConsoleCP" => crate::stubs::GetConsoleCP as *const (),
        "SetConsoleCtrlHandler" => crate::stubs::SetConsoleCtrlHandler as *const (),
        "OutputDebugStringA" => crate::stubs::OutputDebugStringA as *const (),
        "OutputDebugStringW" => crate::stubs::OutputDebugStringW as *const (),

        // Pipes / I/O misc
        "CreatePipe" => crate::stubs::CreatePipe as *const (),
        "PeekNamedPipe" => crate::stubs::PeekNamedPipe as *const (),
        "GetOverlappedResult" => crate::stubs::GetOverlappedResult as *const (),
        "CancelIo" => crate::stubs::CancelIo as *const (),
        "SetHandleInformation" => crate::stubs::SetHandleInformation as *const (),
        "SetStdHandle" => crate::stubs::SetStdHandle as *const (),
        "SetErrorMode" => crate::stubs::SetErrorMode as *const (),

        // TLS
        "TlsAlloc" => crate::stubs::TlsAlloc as *const (),
        "TlsFree" => crate::stubs::TlsFree as *const (),
        "TlsGetValue" => crate::stubs::TlsGetValue as *const (),
        "TlsSetValue" => crate::stubs::TlsSetValue as *const (),

        // Local/Global alloc
        "LocalAlloc" => crate::stubs::LocalAlloc as *const (),
        "LocalFree" => crate::stubs::LocalFree as *const (),
        "GlobalAlloc" => crate::stubs::GlobalAlloc as *const (),
        "GlobalFree" => crate::stubs::GlobalFree as *const (),
        "GlobalLock" => crate::stubs::GlobalLock as *const (),
        "GlobalUnlock" => crate::stubs::GlobalUnlock as *const (),
        "GlobalMemoryStatus" => crate::stubs::GlobalMemoryStatus as *const (),
        "HeapQueryInformation" => crate::stubs::HeapQueryInformation as *const (),

        // String conversion
        "MultiByteToWideChar" => crate::stubs::MultiByteToWideChar as *const (),
        "WideCharToMultiByte" => crate::stubs::WideCharToMultiByte as *const (),
        "IsValidCodePage" => crate::stubs::IsValidCodePage as *const (),
        "IsValidLocale" => crate::stubs::IsValidLocale as *const (),
        "FormatMessageA" => crate::stubs::FormatMessageA as *const (),
        "FormatMessageW" => crate::stubs::FormatMessageW as *const (),
        "ExpandEnvironmentStringsA" => crate::stubs::ExpandEnvironmentStringsA as *const (),
        "EnumSystemLocalesW" => crate::stubs::EnumSystemLocalesW as *const (),
        "GetSystemDefaultLangID" => crate::stubs::GetSystemDefaultLangID as *const (),
        "GetUserDefaultLangID" => crate::stubs::GetUserDefaultLangID as *const (),
        "GetSystemDefaultLocaleName" => crate::stubs::GetSystemDefaultLocaleName as *const (),
        "GetDateFormatW" => crate::stubs::GetDateFormatW as *const (),

        // Process / Thread misc
        "CreateProcessA" => crate::stubs::CreateProcessA as *const (),
        "GetExitCodeProcess" => crate::stubs::GetExitCodeProcess as *const (),
        "GetExitCodeThread" => crate::stubs::GetExitCodeThread as *const (),
        "OpenThread" => crate::stubs::OpenThread as *const (),
        "ResumeThread" => crate::stubs::ResumeThread as *const (),
        "SuspendThread" => crate::stubs::SuspendThread as *const (),
        "TerminateThread" => crate::stubs::TerminateThread as *const (),
        "SetThreadAffinityMask" => crate::stubs::SetThreadAffinityMask as *const (),
        "SetThreadIdealProcessor" => crate::stubs::SetThreadIdealProcessor as *const (),
        "SetProcessAffinityMask" => crate::stubs::SetProcessAffinityMask as *const (),
        "GetProcessAffinityMask" => crate::stubs::GetProcessAffinityMask as *const (),
        "SleepEx" => crate::stubs::SleepEx as *const (),
        "QueueUserAPC" => crate::stubs::QueueUserAPC as *const (),
        "RaiseException" => crate::stubs::RaiseException as *const (),
        "ConvertFiberToThread" => crate::stubs::ConvertFiberToThread as *const (),
        "DeleteFiber" => crate::stubs::DeleteFiber as *const (),

        // Module info
        "GetModuleFileNameA" => crate::stubs::GetModuleFileNameA as *const (),
        "GetModuleFileNameW" => crate::stubs::GetModuleFileNameW as *const (),
        "GetModuleHandleExW" => crate::stubs::GetModuleHandleExW as *const (),

        // System info / time
        "GetSystemInfo" => crate::stubs::GetSystemInfo as *const (),
        "GetLocalTime" => crate::stubs::GetLocalTime as *const (),
        "FileTimeToLocalFileTime" => crate::stubs::FileTimeToLocalFileTime as *const (),
        "LocalFileTimeToFileTime" => crate::stubs::LocalFileTimeToFileTime as *const (),
        "FileTimeToSystemTime" => crate::stubs::FileTimeToSystemTime as *const (),
        "SystemTimeToFileTime" => crate::stubs::SystemTimeToFileTime as *const (),
        "SystemTimeToTzSpecificLocalTime" => {
            crate::stubs::SystemTimeToTzSpecificLocalTime as *const ()
        }
        "VerSetConditionMask" => crate::stubs::VerSetConditionMask as *const (),
        "VerifyVersionInfoW" => crate::stubs::VerifyVersionInfoW as *const (),
        "VirtualQuery" => crate::stubs::VirtualQuery as *const (),

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
