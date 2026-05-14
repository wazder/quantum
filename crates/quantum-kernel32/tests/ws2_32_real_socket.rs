//! Smoke test for the real ws2_32 → Darwin BSD socket bridge.
//! Opens a TCP listener on a random port, connects to it, sends 4
//! bytes, reads them back. Exercises socket / bind / listen / accept
//! / connect / send / recv / closesocket all in one shot.

use core::ffi::c_void;
use quantum_kernel32::ws2_32::{
    WSAGetLastError, accept, bind, closesocket, connect, getsockname, htons, listen, recv, send,
    socket,
};

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const INVALID_SOCKET: usize = usize::MAX;

#[repr(C, packed)]
struct WinSockAddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[test]
fn tcp_loopback_roundtrip() {
    // Listener
    let listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert!(
        listener != INVALID_SOCKET,
        "socket() returned INVALID_SOCKET (WSAErr={})",
        WSAGetLastError()
    );

    let mut sa = WinSockAddrIn {
        family: AF_INET as u16,
        port: 0, // let kernel pick a port
        addr: 0, // INADDR_ANY = 0
        zero: [0; 8],
    };
    let bind_r = bind(
        listener,
        &mut sa as *mut _ as *const c_void,
        core::mem::size_of::<WinSockAddrIn>() as i32,
    );
    assert_eq!(bind_r, 0, "bind failed err={}", WSAGetLastError());

    let listen_r = listen(listener, 1);
    assert_eq!(listen_r, 0, "listen failed err={}", WSAGetLastError());

    // Find which port the kernel chose.
    let mut bound_sa = WinSockAddrIn {
        family: 0,
        port: 0,
        addr: 0,
        zero: [0; 8],
    };
    let mut bound_len: i32 = core::mem::size_of::<WinSockAddrIn>() as i32;
    let gn = getsockname(
        listener,
        &mut bound_sa as *mut _ as *mut c_void,
        &mut bound_len,
    );
    assert_eq!(gn, 0, "getsockname failed err={}", WSAGetLastError());
    let port = bound_sa.port;
    assert!(port != 0, "kernel did not assign a port");

    // Spawn a connect-and-recv on another thread.
    let client_handle = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert!(client != INVALID_SOCKET);
        let _ = htons(0); // keep htons in scope; compute addr directly.
        let mut dest = WinSockAddrIn {
            family: AF_INET as u16,
            port,
            // 127.0.0.1 in network-byte order: bytes 127,0,0,1 → little-endian
            // 0x0100007F. We construct as u32 already in big-endian on wire.
            addr: 0x0100007F,
            zero: [0; 8],
        };
        let c = connect(
            client,
            &mut dest as *mut _ as *const c_void,
            core::mem::size_of::<WinSockAddrIn>() as i32,
        );
        assert_eq!(c, 0, "connect failed err={}", WSAGetLastError());
        let payload = b"PING";
        let s = send(client, payload.as_ptr(), payload.len() as i32, 0);
        assert_eq!(s, 4);
        let mut buf = [0u8; 8];
        let r = recv(client, buf.as_mut_ptr(), buf.len() as i32, 0);
        assert_eq!(r, 4);
        assert_eq!(&buf[..4], b"PONG");
        closesocket(client);
    });

    let mut peer = WinSockAddrIn {
        family: 0,
        port: 0,
        addr: 0,
        zero: [0; 8],
    };
    let mut peer_len: i32 = core::mem::size_of::<WinSockAddrIn>() as i32;
    let conn = accept(listener, &mut peer as *mut _ as *mut c_void, &mut peer_len);
    assert!(
        conn != INVALID_SOCKET,
        "accept failed err={}",
        WSAGetLastError()
    );

    let mut buf = [0u8; 8];
    let n = recv(conn, buf.as_mut_ptr(), buf.len() as i32, 0);
    assert_eq!(n, 4, "recv n={} err={}", n, WSAGetLastError());
    assert_eq!(&buf[..4], b"PING");

    let payload = b"PONG";
    let s = send(conn, payload.as_ptr(), payload.len() as i32, 0);
    assert_eq!(s, 4);

    client_handle.join().unwrap();
    closesocket(conn);
    closesocket(listener);
}
