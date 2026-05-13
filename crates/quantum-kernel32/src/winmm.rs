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

// ---------- waveOut / waveIn (audio I/O) ----------
//
// Game audio engines call these to enumerate devices and stream PCM.
// We stub them so init paths proceed; real audio routes through
// macOS CoreAudio in a future iteration.

use core::ffi::c_void;

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_NODRIVER: u32 = 6;
const FAKE_AUDIO_HANDLE: usize = 0x4000_0000_0005_0000;

#[unsafe(no_mangle)]
pub extern "C" fn waveOutGetNumDevs() -> u32 {
    // Report 1 device so callers don't bail; they'll open it and
    // either fail later or accept silence.
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutGetDevCapsA(_dev_id: usize, caps: *mut c_void, size: u32) -> u32 {
    if !caps.is_null() && size > 0 {
        unsafe {
            core::ptr::write_bytes(caps as *mut u8, 0, size as usize);
        }
    }
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutGetDevCapsW(_dev_id: usize, caps: *mut c_void, size: u32) -> u32 {
    waveOutGetDevCapsA(_dev_id, caps, size)
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutOpen(
    h_out: *mut usize,
    _dev_id: u32,
    _fmt: *const c_void,
    _callback: usize,
    _instance: usize,
    _flags: u32,
) -> u32 {
    if !h_out.is_null() {
        unsafe {
            *h_out = FAKE_AUDIO_HANDLE;
        }
    }
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutClose(_h: usize) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutPrepareHeader(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutUnprepareHeader(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutWrite(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutReset(_h: usize) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveOutGetPosition(_h: usize, _info: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn waveInGetNumDevs() -> u32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInGetDevCapsA(_dev_id: usize, _caps: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NODRIVER
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInGetDevCapsW(_dev_id: usize, _caps: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NODRIVER
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInOpen(
    _h_in: *mut usize,
    _dev_id: u32,
    _fmt: *const c_void,
    _callback: usize,
    _instance: usize,
    _flags: u32,
) -> u32 {
    MMSYSERR_NODRIVER
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInClose(_h: usize) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInPrepareHeader(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInUnprepareHeader(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInAddBuffer(_h: usize, _hdr: *mut c_void, _size: u32) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInStart(_h: usize) -> u32 {
    MMSYSERR_NOERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn waveInReset(_h: usize) -> u32 {
    MMSYSERR_NOERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn mciSendCommandA(_id: u32, _msg: u32, _flags: usize, _params: usize) -> u32 {
    0
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "timeBeginPeriod" => timeBeginPeriod as *const (),
        "timeEndPeriod" => timeEndPeriod as *const (),
        "timeGetTime" => timeGetTime as *const (),
        "waveOutGetNumDevs" => waveOutGetNumDevs as *const (),
        "waveOutGetDevCapsA" => waveOutGetDevCapsA as *const (),
        "waveOutGetDevCapsW" => waveOutGetDevCapsW as *const (),
        "waveOutOpen" => waveOutOpen as *const (),
        "waveOutClose" => waveOutClose as *const (),
        "waveOutPrepareHeader" => waveOutPrepareHeader as *const (),
        "waveOutUnprepareHeader" => waveOutUnprepareHeader as *const (),
        "waveOutWrite" => waveOutWrite as *const (),
        "waveOutReset" => waveOutReset as *const (),
        "waveOutGetPosition" => waveOutGetPosition as *const (),
        "waveInGetNumDevs" => waveInGetNumDevs as *const (),
        "waveInGetDevCapsA" => waveInGetDevCapsA as *const (),
        "waveInGetDevCapsW" => waveInGetDevCapsW as *const (),
        "waveInOpen" => waveInOpen as *const (),
        "waveInClose" => waveInClose as *const (),
        "waveInPrepareHeader" => waveInPrepareHeader as *const (),
        "waveInUnprepareHeader" => waveInUnprepareHeader as *const (),
        "waveInAddBuffer" => waveInAddBuffer as *const (),
        "waveInStart" => waveInStart as *const (),
        "waveInReset" => waveInReset as *const (),
        "mciSendCommandA" => mciSendCommandA as *const (),
        _ => return None,
    };
    Some(p as u64)
}
