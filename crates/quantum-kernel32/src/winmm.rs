//! `winmm.dll` — Windows multimedia / timing.
//! Sekiro only needs the three timing functions.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

/// `MMRESULT timeBeginPeriod(UINT uPeriod)` — request finer timer
/// resolution. We ignore the request (macOS gives us 1ms by default
/// on the timer side via mach absolute time).
#[unsafe(no_mangle)]
pub extern "C" fn timeBeginPeriod(_period: u32) -> u32 {
    0 // TIMERR_NOERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn timeEndPeriod(_period: u32) -> u32 {
    0
}

/// `DWORD timeGetTime()` — returns ms since system boot.
#[unsafe(no_mangle)]
pub extern "C" fn timeGetTime() -> u32 {
    // Reuse the kernel32 tick-count source.
    crate::time::GetTickCount()
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "timeBeginPeriod" => timeBeginPeriod as *const (),
        "timeEndPeriod" => timeEndPeriod as *const (),
        "timeGetTime" => timeGetTime as *const (),
        _ => return None,
    };
    Some(p as u64)
}
