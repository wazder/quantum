//! `ws2_32.dll` — Winsock 2.
//!
//! Sekiro imports 46 entries, mostly by ordinal. We stub all of them
//! so the IAT resolves; calls do nothing useful but don't crash. The
//! byte-order helpers (htonl/htons/ntohl/ntohs) DO produce correct
//! values since they're pure compute.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

const SOCKET_ERROR: i32 = -1;
const INVALID_SOCKET: usize = usize::MAX;

// ---------- Byte-order helpers (real impls) ----------

#[unsafe(no_mangle)]
pub extern "C" fn htonl(host: u32) -> u32 {
    host.to_be()
}
#[unsafe(no_mangle)]
pub extern "C" fn htons(host: u16) -> u16 {
    host.to_be()
}
#[unsafe(no_mangle)]
pub extern "C" fn ntohl(net: u32) -> u32 {
    u32::from_be(net)
}
#[unsafe(no_mangle)]
pub extern "C" fn ntohs(net: u16) -> u16 {
    u16::from_be(net)
}

// ---------- Lifecycle / state ----------

#[unsafe(no_mangle)]
pub extern "C" fn WSAStartup(_version: u16, data: *mut c_void) -> i32 {
    // WSADATA is 408 bytes on Win64. Zero-fill — caller mostly reads
    // wVersion + wHighVersion which are 0 here. Most games proceed if
    // WSAStartup returns 0.
    if !data.is_null() {
        unsafe {
            core::ptr::write_bytes(data as *mut u8, 0, 408);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn WSACleanup() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn WSAGetLastError() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn WSASetLastError(_err: i32) {}

// ---------- Sockets (stubs returning failure) ----------

#[unsafe(no_mangle)]
pub extern "C" fn socket(_af: i32, _ty: i32, _proto: i32) -> usize {
    INVALID_SOCKET
}
#[unsafe(no_mangle)]
pub extern "C" fn closesocket(_s: usize) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn bind(_s: usize, _addr: *const c_void, _len: i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn connect(_s: usize, _addr: *const c_void, _len: i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn listen(_s: usize, _backlog: i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn accept(_s: usize, _addr: *mut c_void, _len: *mut i32) -> usize {
    INVALID_SOCKET
}
#[unsafe(no_mangle)]
pub extern "C" fn shutdown(_s: usize, _how: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn getsockname(_s: usize, _addr: *mut c_void, _len: *mut i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn getpeername(_s: usize, _addr: *mut c_void, _len: *mut i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn getsockopt(
    _s: usize,
    _level: i32,
    _name: i32,
    _val: *mut u8,
    _len: *mut i32,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn setsockopt(_s: usize, _l: i32, _n: i32, _v: *const u8, _len: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn ioctlsocket(_s: usize, _cmd: i32, _arg: *mut u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn select(
    _nfds: i32,
    _r: *mut c_void,
    _w: *mut c_void,
    _e: *mut c_void,
    _timeout: *const c_void,
) -> i32 {
    0
}

// I/O — pretend the socket immediately reports closed.
#[unsafe(no_mangle)]
pub extern "C" fn recv(_s: usize, _buf: *mut u8, _len: i32, _flags: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn recvfrom(
    _s: usize,
    _buf: *mut u8,
    _len: i32,
    _flags: i32,
    _from: *mut c_void,
    _fromlen: *mut i32,
) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn send(_s: usize, _buf: *const u8, len: i32, _flags: i32) -> i32 {
    len
}
#[unsafe(no_mangle)]
pub extern "C" fn sendto(
    _s: usize,
    _buf: *const u8,
    len: i32,
    _flags: i32,
    _to: *const c_void,
    _tolen: i32,
) -> i32 {
    len
}

// Address conversions.
#[unsafe(no_mangle)]
pub extern "C" fn inet_pton(_af: i32, _src: *const i8, _dst: *mut c_void) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn inet_ntop(
    _af: i32,
    _src: *const c_void,
    dst: *mut i8,
    _size: usize,
) -> *const i8 {
    if !dst.is_null() {
        unsafe {
            *dst = 0;
        }
    }
    dst
}
#[unsafe(no_mangle)]
pub extern "C" fn inet_addr(_cp: *const i8) -> u32 {
    0xFFFF_FFFF
}
#[unsafe(no_mangle)]
pub extern "C" fn inet_ntoa(_addr: u32) -> *const i8 {
    // Static "0.0.0.0\0" placeholder.
    static ZERO: [u8; 8] = *b"0.0.0.0\0";
    ZERO.as_ptr() as *const i8
}
#[unsafe(no_mangle)]
pub extern "C" fn getaddrinfo(
    _node: *const i8,
    _service: *const i8,
    _hints: *const c_void,
    res: *mut *mut c_void,
) -> i32 {
    if !res.is_null() {
        unsafe {
            *res = core::ptr::null_mut();
        }
    }
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn freeaddrinfo(_info: *mut c_void) {}
#[unsafe(no_mangle)]
pub extern "C" fn getnameinfo(
    _addr: *const c_void,
    _addr_len: i32,
    _host: *mut i8,
    _host_len: u32,
    _serv: *mut i8,
    _serv_len: u32,
    _flags: i32,
) -> i32 {
    SOCKET_ERROR
}

// WSA event / overlapped I/O.
#[unsafe(no_mangle)]
pub extern "C" fn WSASocketW(
    _af: i32,
    _ty: i32,
    _proto: i32,
    _proto_info: *const c_void,
    _g: u32,
    _flags: u32,
) -> usize {
    INVALID_SOCKET
}
#[unsafe(no_mangle)]
pub extern "C" fn WSACreateEvent() -> usize {
    0 // WSA_INVALID_EVENT
}
#[unsafe(no_mangle)]
pub extern "C" fn WSACloseEvent(_event: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASetEvent(_event: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn WSAResetEvent(_event: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn WSAWaitForMultipleEvents(
    _count: u32,
    _events: *const usize,
    _wait_all: i32,
    _timeout: u32,
    _alertable: i32,
) -> u32 {
    // WSA_WAIT_FAILED
    0xFFFF_FFFF
}
#[unsafe(no_mangle)]
pub extern "C" fn WSAEventSelect(_s: usize, _event: usize, _net_events: i32) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSAEnumNetworkEvents(_s: usize, _event: usize, _out: *mut c_void) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn __WSAFDIsSet(_s: usize, _fdset: *const c_void) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn WSAStringToAddressW(
    _str: *const u16,
    _af: i32,
    _proto: *const c_void,
    _addr: *mut c_void,
    _len: *mut i32,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSARecv(
    _s: usize,
    _buffers: *mut c_void,
    _buffer_count: u32,
    _bytes: *mut u32,
    _flags: *mut u32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASend(
    _s: usize,
    _buffers: *mut c_void,
    _buffer_count: u32,
    _bytes: *mut u32,
    _flags: u32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSARecvFrom(
    _s: usize,
    _buffers: *mut c_void,
    _buffer_count: u32,
    _bytes: *mut u32,
    _flags: *mut u32,
    _from: *mut c_void,
    _fromlen: *mut i32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASendTo(
    _s: usize,
    _buffers: *mut c_void,
    _buffer_count: u32,
    _bytes: *mut u32,
    _flags: u32,
    _to: *const c_void,
    _tolen: i32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    SOCKET_ERROR
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASocketA(
    _af: i32,
    _ty: i32,
    _proto: i32,
    _proto_info: *const c_void,
    _g: u32,
    _flags: u32,
) -> usize {
    INVALID_SOCKET
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        // Named imports first.
        "WSAStartup" | "#57" => WSAStartup as *const (),
        "WSACleanup" | "#52" => WSACleanup as *const (),
        "WSAGetLastError" | "#55" => WSAGetLastError as *const (),
        "WSASetLastError" | "#56" => WSASetLastError as *const (),
        "WSASocketW" => WSASocketW as *const (),
        "WSASocketA" | "#115" => WSASocketA as *const (),
        "WSACreateEvent" => WSACreateEvent as *const (),
        "WSACloseEvent" => WSACloseEvent as *const (),
        "WSASetEvent" => WSASetEvent as *const (),
        "WSAResetEvent" => WSAResetEvent as *const (),
        "WSAWaitForMultipleEvents" => WSAWaitForMultipleEvents as *const (),
        "WSAEventSelect" => WSAEventSelect as *const (),
        "WSAEnumNetworkEvents" => WSAEnumNetworkEvents as *const (),
        "WSAStringToAddressW" | "#116" => WSAStringToAddressW as *const (),
        "WSARecv" | "#111" => WSARecv as *const (),
        "WSASend" | "#113" => WSASend as *const (),
        "WSARecvFrom" | "#112" => WSARecvFrom as *const (),
        "WSASendTo" | "#114" => WSASendTo as *const (),
        "__WSAFDIsSet" | "#151" | "#51" => __WSAFDIsSet as *const (),
        // BSD socket ordinals.
        "accept" | "#1" => accept as *const (),
        "bind" | "#2" => bind as *const (),
        "closesocket" | "#3" => closesocket as *const (),
        "connect" | "#4" => connect as *const (),
        "getpeername" | "#5" => getpeername as *const (),
        "getsockname" | "#6" => getsockname as *const (),
        "getsockopt" | "#7" => getsockopt as *const (),
        "htonl" | "#8" => htonl as *const (),
        "htons" | "#9" => htons as *const (),
        "inet_addr" | "#10" => inet_addr as *const (),
        "inet_ntoa" | "#11" => inet_ntoa as *const (),
        "ioctlsocket" | "#12" => ioctlsocket as *const (),
        "listen" | "#13" => listen as *const (),
        "ntohl" | "#14" => ntohl as *const (),
        "ntohs" | "#15" => ntohs as *const (),
        "recv" | "#16" => recv as *const (),
        "recvfrom" | "#17" => recvfrom as *const (),
        "select" | "#18" => select as *const (),
        "send" | "#19" => send as *const (),
        "sendto" | "#20" => sendto as *const (),
        "setsockopt" | "#21" => setsockopt as *const (),
        "shutdown" | "#22" => shutdown as *const (),
        "socket" | "#23" => socket as *const (),
        // Address resolution.
        "getaddrinfo" => getaddrinfo as *const (),
        "freeaddrinfo" => freeaddrinfo as *const (),
        "getnameinfo" => getnameinfo as *const (),
        "inet_pton" => inet_pton as *const (),
        "inet_ntop" => inet_ntop as *const (),
        _ => return None,
    };
    Some(p as u64)
}
