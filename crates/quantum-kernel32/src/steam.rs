//! Minimal Steamworks API stubs needed to satisfy Sekiro's Steam DRM
//! wrapper. The .bind entry point calls SteamAPI_Init early; if it
//! returns false, the wrapper exits. SteamAPI_RestartAppIfNecessary
//! is the OTHER early check — it returns true if the game wasn't
//! launched through Steam, which would normally cause the game to
//! relaunch itself through Steam. We return false (no restart needed)
//! since quantum IS the launcher.
//!
//! Interface getters (SteamUser, SteamUtils, etc.) return non-null
//! fake interface pointers. The wrapper's check is usually just
//! "non-null", not "calls a method on it". If a method call happens,
//! we crash with a clear error — we'll grow the stub then.

#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::fn_to_numeric_cast)]

use core::ffi::c_void;

/// Static "interface" pointer we hand back from each accessor. The
/// real interfaces contain vtables; ours has a fake one filled with
/// a noop function so any vtable lookup returns the same noop.
/// We initialise lazily via OnceLock since `extern fn as usize` is
/// not a const expression.
fn fake_interface() -> *mut c_void {
    use std::sync::OnceLock;
    static VTABLE: OnceLock<Box<[usize; 128]>> = OnceLock::new();
    let vtable = VTABLE.get_or_init(|| Box::new([steam_noop as *const () as usize; 128]));
    vtable.as_ref() as *const _ as *mut c_void
}

extern "C" fn steam_noop() -> usize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_Init() -> i32 {
    1 // true = init succeeded
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_Shutdown() {}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_RestartAppIfNecessary(_appid: u32) -> i32 {
    0 // false = no restart needed (we ARE the launcher)
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_RunCallbacks() {}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_RegisterCallback(_callback: *mut c_void, _id: i32) {}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_UnregisterCallback(_callback: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_RegisterCallResult(_call: *mut c_void, _api_call: u64) {}

#[unsafe(no_mangle)]
pub extern "C" fn SteamAPI_UnregisterCallResult(_call: *mut c_void, _api_call: u64) {}

// Interface accessors. Each returns a non-null fake pointer.

#[unsafe(no_mangle)]
pub extern "C" fn SteamUser() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamUtils() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamApps() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamClient() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamFriends() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamMatchmaking() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamNetworking() -> *mut c_void {
    fake_interface()
}

#[unsafe(no_mangle)]
pub extern "C" fn SteamUserStats() -> *mut c_void {
    fake_interface()
}

/// Resolver for the `steam_api64.dll` module entry in `modules.rs`.
pub fn resolve(function: &str) -> Option<u64> {
    let ptr: *const () = match function {
        "SteamAPI_Init" => SteamAPI_Init as *const (),
        "SteamAPI_Shutdown" => SteamAPI_Shutdown as *const (),
        "SteamAPI_RestartAppIfNecessary" => SteamAPI_RestartAppIfNecessary as *const (),
        "SteamAPI_RunCallbacks" => SteamAPI_RunCallbacks as *const (),
        "SteamAPI_RegisterCallback" => SteamAPI_RegisterCallback as *const (),
        "SteamAPI_UnregisterCallback" => SteamAPI_UnregisterCallback as *const (),
        "SteamAPI_RegisterCallResult" => SteamAPI_RegisterCallResult as *const (),
        "SteamAPI_UnregisterCallResult" => SteamAPI_UnregisterCallResult as *const (),
        "SteamUser" => SteamUser as *const (),
        "SteamUtils" => SteamUtils as *const (),
        "SteamApps" => SteamApps as *const (),
        "SteamClient" => SteamClient as *const (),
        "SteamFriends" => SteamFriends as *const (),
        "SteamMatchmaking" => SteamMatchmaking as *const (),
        "SteamNetworking" => SteamNetworking as *const (),
        "SteamUserStats" => SteamUserStats as *const (),
        _ => return None,
    };
    Some(ptr as u64)
}
