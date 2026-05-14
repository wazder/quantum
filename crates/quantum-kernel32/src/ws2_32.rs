//! `ws2_32.dll` — Winsock 2 bridged to Darwin BSD sockets.
//!
//! Windows socket handles map 1:1 to POSIX file descriptors. The
//! Winsock and BSD calling conventions are compatible enough that
//! most calls forward directly via `libc`.
//!
//! Areas needing translation:
//!   * `sockaddr_in` layout: Windows packs `sin_family` as `u16` at
//!     offset 0; Darwin BSD splits that byte into `sin_len:u8` (offset
//!     0) + `sin_family:u8` (offset 1). We patch the caller's buffer
//!     before each kernel call.
//!   * Error codes: BSD `errno` → WSA `WSAGetLastError` (Win-side
//!     codes are `10000 + errno` for the common subset).
//!
//! Functions we don't implement yet (overlapped I/O, named events,
//! IOCP) still return Win-style failure — same as before. Synchronous
//! path is the realistic Steam minimum.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

const SOCKET_ERROR: i32 = -1;
const INVALID_SOCKET: usize = usize::MAX;

// ---------- Byte-order helpers (pure compute) ----------

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

// ---------- libc FFI ----------

#[link(name = "System", kind = "framework")]
unsafe extern "C" {
    #[link_name = "socket"]
    fn libc_socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn close(fd: i32) -> i32;
    #[link_name = "bind"]
    fn libc_bind(fd: i32, addr: *const c_void, len: u32) -> i32;
    #[link_name = "connect"]
    fn libc_connect(fd: i32, addr: *const c_void, len: u32) -> i32;
    #[link_name = "listen"]
    fn libc_listen(fd: i32, backlog: i32) -> i32;
    #[link_name = "accept"]
    fn libc_accept(fd: i32, addr: *mut c_void, len: *mut u32) -> i32;
    #[link_name = "send"]
    fn libc_send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    #[link_name = "recv"]
    fn libc_recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    #[link_name = "sendto"]
    fn libc_sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const c_void,
        addr_len: u32,
    ) -> isize;
    #[link_name = "recvfrom"]
    fn libc_recvfrom(
        fd: i32,
        buf: *mut u8,
        len: usize,
        flags: i32,
        addr: *mut c_void,
        addr_len: *mut u32,
    ) -> isize;
    #[link_name = "getsockname"]
    fn libc_getsockname(fd: i32, addr: *mut c_void, len: *mut u32) -> i32;
    #[link_name = "getpeername"]
    fn libc_getpeername(fd: i32, addr: *mut c_void, len: *mut u32) -> i32;
    #[link_name = "getsockopt"]
    fn libc_getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32;
    #[link_name = "setsockopt"]
    fn libc_setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
    #[link_name = "shutdown"]
    fn libc_shutdown(fd: i32, how: i32) -> i32;
    fn __error() -> *mut i32; // Darwin: errno is per-thread via __error()
}

fn errno() -> i32 {
    unsafe { *__error() }
}

/// Map a Darwin errno to a Winsock `WSAGetLastError` value. The
/// classic Winsock convention is `WSA_<name> == 10000 + <name>` for
/// the common subset.
fn wsa_from_errno(e: i32) -> i32 {
    match e {
        0 => 0,
        // Common subset — Darwin errno on the left, WSA on the right.
        9 => 10038,    // EBADF -> WSAENOTSOCK
        13 => 10013,   // EACCES -> WSAEACCES
        22 => 10022,   // EINVAL -> WSAEINVAL
        35 => 10035,   // EAGAIN/EWOULDBLOCK -> WSAEWOULDBLOCK
        36 => 10036,   // EINPROGRESS -> WSAEINPROGRESS
        47 => 10047,   // EAFNOSUPPORT -> WSAEAFNOSUPPORT
        48 => 10048,   // EADDRINUSE -> WSAEADDRINUSE
        49 => 10049,   // EADDRNOTAVAIL -> WSAEADDRNOTAVAIL
        50 => 10050,   // ENETDOWN -> WSAENETDOWN
        51 => 10051,   // ENETUNREACH -> WSAENETUNREACH
        52 => 10052,   // ENETRESET -> WSAENETRESET
        53 => 10053,   // ECONNABORTED -> WSAECONNABORTED
        54 => 10054,   // ECONNRESET -> WSAECONNRESET
        55 => 10055,   // ENOBUFS -> WSAENOBUFS
        56 => 10056,   // EISCONN -> WSAEISCONN
        57 => 10057,   // ENOTCONN -> WSAENOTCONN
        60 => 10060,   // ETIMEDOUT -> WSAETIMEDOUT
        61 => 10061,   // ECONNREFUSED -> WSAECONNREFUSED
        64 => 10064,   // EHOSTDOWN -> WSAEHOSTDOWN
        65 => 10065,   // EHOSTUNREACH -> WSAEHOSTUNREACH
        other => 10000 + other,
    }
}

thread_local! {
    static LAST_WSA_ERROR: core::cell::Cell<i32> = const { core::cell::Cell::new(0) };
}

fn set_last_error_from_errno() {
    let e = errno();
    LAST_WSA_ERROR.with(|c| c.set(wsa_from_errno(e)));
}

// ---------- Sockaddr translation ----------
//
// We translate sockaddr_in only — IPv6 / Unix-domain are out of scope
// for the initial bring-up. AF_INET = 2 on both Windows and BSD; the
// caller-supplied buffer is rewritten in place if writable, otherwise
// we copy into a stack buffer and pass that.

/// Re-shape a Windows-side `sockaddr_in` buffer to Darwin's layout:
/// set byte 0 to `sin_len = 16`, leave byte 1 as `sin_family` (the low
/// byte of the Windows `u16` family — same as the BSD `u8` family
/// when family is AF_INET=2). Rest of the buffer is preserved.
unsafe fn rewrite_win_sa_for_bsd(buf: *mut u8, len: u32) {
    if buf.is_null() || len < 2 {
        return;
    }
    // Read low byte of Windows family from offset 0.
    let fam = unsafe { *buf };
    // BSD layout: [sin_len, sin_family, ...]
    unsafe {
        *buf = (len.min(255)) as u8;
        *buf.add(1) = fam;
    }
}

/// Inverse: Darwin → Windows. The Win caller expects `sin_family` as
/// `u16` at offset 0. Move the BSD `sin_family` byte from offset 1 to
/// offset 0 and zero out offset 1's high half.
unsafe fn rewrite_bsd_sa_for_win(buf: *mut u8, len: u32) {
    if buf.is_null() || len < 2 {
        return;
    }
    let fam = unsafe { *buf.add(1) };
    unsafe {
        *buf = fam;
        *buf.add(1) = 0;
    }
}

// ---------- Lifecycle / state ----------

#[unsafe(no_mangle)]
pub extern "C" fn WSAStartup(_version: u16, data: *mut c_void) -> i32 {
    if !data.is_null() {
        unsafe { core::ptr::write_bytes(data as *mut u8, 0, 408) };
        // Write a non-zero version into the first 4 bytes so callers
        // that check `WSADATA.wVersion` are happy.
        unsafe {
            (data as *mut u16).write(0x0202); // Winsock 2.2
            (data as *mut u16).add(1).write(0x0202);
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
    LAST_WSA_ERROR.with(|c| c.get())
}

#[unsafe(no_mangle)]
pub extern "C" fn WSASetLastError(err: i32) {
    LAST_WSA_ERROR.with(|c| c.set(err));
}

// ---------- Sockets (real implementations) ----------

pub extern "C" fn socket(af: i32, ty: i32, proto: i32) -> usize {
    let fd = unsafe { libc_socket(af, ty, proto) };
    if fd < 0 {
        set_last_error_from_errno();
        INVALID_SOCKET
    } else {
        fd as usize
    }
}

pub extern "C" fn closesocket(s: usize) -> i32 {
    let r = unsafe { close(s as i32) };
    if r != 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn bind(s: usize, addr: *const c_void, len: i32) -> i32 {
    if !addr.is_null() {
        unsafe { rewrite_win_sa_for_bsd(addr as *mut u8, len as u32) };
    }
    let r = unsafe { libc_bind(s as i32, addr, len as u32) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn connect(s: usize, addr: *const c_void, len: i32) -> i32 {
    if !addr.is_null() {
        unsafe { rewrite_win_sa_for_bsd(addr as *mut u8, len as u32) };
    }
    let r = unsafe { libc_connect(s as i32, addr, len as u32) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn listen(s: usize, backlog: i32) -> i32 {
    let r = unsafe { libc_listen(s as i32, backlog) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn accept(s: usize, addr: *mut c_void, len: *mut i32) -> usize {
    let mut native_len: u32 = if !len.is_null() {
        unsafe { *len as u32 }
    } else {
        0
    };
    let len_ptr: *mut u32 = if len.is_null() {
        core::ptr::null_mut()
    } else {
        &mut native_len
    };
    let r = unsafe { libc_accept(s as i32, addr, len_ptr) };
    if r < 0 {
        set_last_error_from_errno();
        INVALID_SOCKET
    } else {
        if !addr.is_null() {
            unsafe { rewrite_bsd_sa_for_win(addr as *mut u8, native_len) };
        }
        if !len.is_null() {
            unsafe { *len = native_len as i32 };
        }
        r as usize
    }
}

pub extern "C" fn shutdown(s: usize, how: i32) -> i32 {
    let r = unsafe { libc_shutdown(s as i32, how) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn getsockname(s: usize, addr: *mut c_void, len: *mut i32) -> i32 {
    let mut native_len: u32 = if !len.is_null() {
        unsafe { *len as u32 }
    } else {
        0
    };
    let len_ptr: *mut u32 = if len.is_null() {
        core::ptr::null_mut()
    } else {
        &mut native_len
    };
    let r = unsafe { libc_getsockname(s as i32, addr, len_ptr) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        if !addr.is_null() {
            unsafe { rewrite_bsd_sa_for_win(addr as *mut u8, native_len) };
        }
        if !len.is_null() {
            unsafe { *len = native_len as i32 };
        }
        0
    }
}

pub extern "C" fn getpeername(s: usize, addr: *mut c_void, len: *mut i32) -> i32 {
    let mut native_len: u32 = if !len.is_null() {
        unsafe { *len as u32 }
    } else {
        0
    };
    let len_ptr: *mut u32 = if len.is_null() {
        core::ptr::null_mut()
    } else {
        &mut native_len
    };
    let r = unsafe { libc_getpeername(s as i32, addr, len_ptr) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        if !addr.is_null() {
            unsafe { rewrite_bsd_sa_for_win(addr as *mut u8, native_len) };
        }
        if !len.is_null() {
            unsafe { *len = native_len as i32 };
        }
        0
    }
}

pub extern "C" fn getsockopt(
    s: usize,
    level: i32,
    name: i32,
    val: *mut u8,
    len: *mut i32,
) -> i32 {
    let mut native_len: u32 = if !len.is_null() {
        unsafe { *len as u32 }
    } else {
        0
    };
    let len_ptr: *mut u32 = if len.is_null() {
        core::ptr::null_mut()
    } else {
        &mut native_len
    };
    let r = unsafe { libc_getsockopt(s as i32, level, name, val, len_ptr) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        if !len.is_null() {
            unsafe { *len = native_len as i32 };
        }
        0
    }
}

pub extern "C" fn setsockopt(s: usize, l: i32, n: i32, v: *const u8, len: i32) -> i32 {
    let r = unsafe { libc_setsockopt(s as i32, l, n, v, len as u32) };
    if r < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        0
    }
}

pub extern "C" fn ioctlsocket(s: usize, cmd: i32, arg: *mut u32) -> i32 {
    // FIONBIO = 0x8004667E (Win) ≈ Darwin's O_NONBLOCK via fcntl. Map
    // the common case ourselves; everything else is best-effort.
    const FIONBIO: i32 = 0x8004_667E_u32 as i32;
    if cmd == FIONBIO && !arg.is_null() {
        let nonblock = unsafe { *arg } != 0;
        unsafe extern "C" {
            fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
        }
        const F_GETFL: i32 = 3;
        const F_SETFL: i32 = 4;
        const O_NONBLOCK: i32 = 0x0004;
        let flags = unsafe { fcntl(s as i32, F_GETFL, 0) };
        if flags < 0 {
            set_last_error_from_errno();
            return SOCKET_ERROR;
        }
        let new_flags = if nonblock {
            flags | O_NONBLOCK
        } else {
            flags & !O_NONBLOCK
        };
        let r = unsafe { fcntl(s as i32, F_SETFL, new_flags) };
        if r < 0 {
            set_last_error_from_errno();
            return SOCKET_ERROR;
        }
        return 0;
    }
    0
}

pub extern "C" fn select(
    nfds: i32,
    r: *mut c_void,
    w: *mut c_void,
    e: *mut c_void,
    timeout: *const c_void,
) -> i32 {
    unsafe extern "C" {
        fn select(
            nfds: i32,
            r: *mut c_void,
            w: *mut c_void,
            e: *mut c_void,
            timeout: *const c_void,
        ) -> i32;
    }
    let rv = unsafe { select(nfds, r, w, e, timeout) };
    if rv < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        rv
    }
}

// ---------- I/O ----------

pub extern "C" fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let n = unsafe { libc_recv(s as i32, buf, len as usize, flags) };
    if n < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        n as i32
    }
}

pub extern "C" fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32 {
    let n = unsafe { libc_send(s as i32, buf, len as usize, flags) };
    if n < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        n as i32
    }
}

pub extern "C" fn recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut c_void,
    fromlen: *mut i32,
) -> i32 {
    let mut native_len: u32 = if !fromlen.is_null() {
        unsafe { *fromlen as u32 }
    } else {
        0
    };
    let len_ptr: *mut u32 = if fromlen.is_null() {
        core::ptr::null_mut()
    } else {
        &mut native_len
    };
    let n = unsafe { libc_recvfrom(s as i32, buf, len as usize, flags, from, len_ptr) };
    if n < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        if !from.is_null() {
            unsafe { rewrite_bsd_sa_for_win(from as *mut u8, native_len) };
        }
        if !fromlen.is_null() {
            unsafe { *fromlen = native_len as i32 };
        }
        n as i32
    }
}

pub extern "C" fn sendto(
    s: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const c_void,
    tolen: i32,
) -> i32 {
    if !to.is_null() {
        unsafe { rewrite_win_sa_for_bsd(to as *mut u8, tolen as u32) };
    }
    let n = unsafe { libc_sendto(s as i32, buf, len as usize, flags, to, tolen as u32) };
    if n < 0 {
        set_last_error_from_errno();
        SOCKET_ERROR
    } else {
        n as i32
    }
}

// ---------- Address conversions ----------

pub extern "C" fn inet_pton(af: i32, src: *const i8, dst: *mut c_void) -> i32 {
    unsafe extern "C" {
        fn inet_pton(af: i32, src: *const i8, dst: *mut c_void) -> i32;
    }
    unsafe { inet_pton(af, src, dst) }
}

pub extern "C" fn inet_ntop(
    af: i32,
    src: *const c_void,
    dst: *mut i8,
    size: usize,
) -> *const i8 {
    unsafe extern "C" {
        fn inet_ntop(af: i32, src: *const c_void, dst: *mut i8, size: u32) -> *const i8;
    }
    unsafe { inet_ntop(af, src, dst, size as u32) }
}

pub extern "C" fn inet_addr(cp: *const i8) -> u32 {
    unsafe extern "C" {
        fn inet_addr(cp: *const i8) -> u32;
    }
    unsafe { inet_addr(cp) }
}

pub extern "C" fn inet_ntoa(addr: u32) -> *const i8 {
    // Darwin inet_ntoa returns a pointer to a static buffer; same on
    // Win. Tolerate.
    unsafe extern "C" {
        fn inet_ntoa(addr: u32) -> *const i8;
    }
    unsafe { inet_ntoa(addr) }
}

pub extern "C" fn getaddrinfo(
    node: *const i8,
    service: *const i8,
    hints: *const c_void,
    res: *mut *mut c_void,
) -> i32 {
    unsafe extern "C" {
        fn getaddrinfo(
            node: *const i8,
            service: *const i8,
            hints: *const c_void,
            res: *mut *mut c_void,
        ) -> i32;
    }
    let r = unsafe { getaddrinfo(node, service, hints, res) };
    if r != 0 {
        set_last_error_from_errno();
    }
    r
}

pub extern "C" fn freeaddrinfo(info: *mut c_void) {
    unsafe extern "C" {
        fn freeaddrinfo(info: *mut c_void);
    }
    unsafe { freeaddrinfo(info) };
}

pub extern "C" fn getnameinfo(
    addr: *const c_void,
    addr_len: i32,
    host: *mut i8,
    host_len: u32,
    serv: *mut i8,
    serv_len: u32,
    flags: i32,
) -> i32 {
    unsafe extern "C" {
        fn getnameinfo(
            addr: *const c_void,
            addr_len: u32,
            host: *mut i8,
            host_len: u32,
            serv: *mut i8,
            serv_len: u32,
            flags: i32,
        ) -> i32;
    }
    let r =
        unsafe { getnameinfo(addr, addr_len as u32, host, host_len, serv, serv_len, flags) };
    if r != 0 {
        set_last_error_from_errno();
    }
    r
}

// ---------- WSA event / overlapped — stubs (not yet wired) ----------

#[unsafe(no_mangle)]
pub extern "C" fn WSASocketW(
    af: i32,
    ty: i32,
    proto: i32,
    _proto_info: *const c_void,
    _g: u32,
    _flags: u32,
) -> usize {
    socket(af, ty, proto)
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASocketA(
    af: i32,
    ty: i32,
    proto: i32,
    _proto_info: *const c_void,
    _g: u32,
    _flags: u32,
) -> usize {
    socket(af, ty, proto)
}

#[unsafe(no_mangle)]
pub extern "C" fn WSACreateEvent() -> usize {
    0
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
    s: usize,
    buffers: *mut c_void,
    buffer_count: u32,
    bytes: *mut u32,
    _flags: *mut u32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    // Single-buffer best effort: synchronously recv into buffers[0].
    if buffers.is_null() || buffer_count == 0 {
        return SOCKET_ERROR;
    }
    // WSABUF layout: { ULONG len; CHAR* buf; }
    let len = unsafe { *(buffers as *const u32) };
    let buf_ptr = unsafe { *(buffers.add(8) as *const *mut u8) };
    let n = recv(s, buf_ptr, len as i32, 0);
    if n < 0 {
        return SOCKET_ERROR;
    }
    if !bytes.is_null() {
        unsafe { *bytes = n as u32 };
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASend(
    s: usize,
    buffers: *mut c_void,
    buffer_count: u32,
    bytes: *mut u32,
    _flags: u32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    if buffers.is_null() || buffer_count == 0 {
        return SOCKET_ERROR;
    }
    let len = unsafe { *(buffers as *const u32) };
    let buf_ptr = unsafe { *(buffers.add(8) as *const *const u8) };
    let n = send(s, buf_ptr, len as i32, 0);
    if n < 0 {
        return SOCKET_ERROR;
    }
    if !bytes.is_null() {
        unsafe { *bytes = n as u32 };
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn WSARecvFrom(
    s: usize,
    buffers: *mut c_void,
    buffer_count: u32,
    bytes: *mut u32,
    _flags: *mut u32,
    from: *mut c_void,
    fromlen: *mut i32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    if buffers.is_null() || buffer_count == 0 {
        return SOCKET_ERROR;
    }
    let len = unsafe { *(buffers as *const u32) };
    let buf_ptr = unsafe { *(buffers.add(8) as *const *mut u8) };
    let n = recvfrom(s, buf_ptr, len as i32, 0, from, fromlen);
    if n < 0 {
        return SOCKET_ERROR;
    }
    if !bytes.is_null() {
        unsafe { *bytes = n as u32 };
    }
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn WSASendTo(
    s: usize,
    buffers: *mut c_void,
    buffer_count: u32,
    bytes: *mut u32,
    _flags: u32,
    to: *const c_void,
    tolen: i32,
    _ov: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    if buffers.is_null() || buffer_count == 0 {
        return SOCKET_ERROR;
    }
    let len = unsafe { *(buffers as *const u32) };
    let buf_ptr = unsafe { *(buffers.add(8) as *const *const u8) };
    let n = sendto(s, buf_ptr, len as i32, 0, to, tolen);
    if n < 0 {
        return SOCKET_ERROR;
    }
    if !bytes.is_null() {
        unsafe { *bytes = n as u32 };
    }
    0
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
        // gethostbyname / gethostbyaddr ordinals (#52 conflicts above).
        "inet_pton" => inet_pton as *const (),
        "inet_ntop" => inet_ntop as *const (),
        "getaddrinfo" => getaddrinfo as *const (),
        "freeaddrinfo" => freeaddrinfo as *const (),
        "getnameinfo" => getnameinfo as *const (),
        _ => return None,
    };
    Some(p as u64)
}
