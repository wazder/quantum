//! IDXGIFactory::CreateSwapChain + IDXGISwapChain::Present
//!
//! Build a factory, call CreateSwapChain with an HWND we registered
//! ourselves, then call Present through the returned vtable. Headless
//! mode is fine — the cocoa layer no-ops when the HWND has no real
//! NSWindow attached.

use core::ffi::c_void;

const S_OK: i32 = 0;
const CREATE_SWAP_CHAIN_SLOT: usize = 10;
const PRESENT_SLOT: usize = 8;

unsafe fn vtbl_slot(obj: *mut c_void, slot: usize) -> usize {
    let vtbl: *const *const usize = obj as *const *const usize;
    let table = unsafe { *vtbl };
    unsafe { *table.add(slot) }
}

#[repr(C)]
struct DxgiModeDesc {
    width: u32,
    height: u32,
    refresh_numerator: u32,
    refresh_denominator: u32,
    format: u32,
    scanline_ordering: u32,
    scaling: u32,
}

#[repr(C)]
struct DxgiSwapChainDesc {
    buffer_desc: DxgiModeDesc,
    sample_count: u32,
    sample_quality: u32,
    buffer_usage: u32,
    buffer_count: u32,
    output_window: usize,
    windowed: i32,
    swap_effect: u32,
    flags: u32,
}

#[test]
fn create_swap_chain_and_present_returns_s_ok() {
    // Register a class + create a headless window so the swap chain
    // has a real HWND to bind. The NSWindow won't be allocated here
    // (QUANTUM_REAL_COCOA not set) — that's fine, the swap chain
    // tolerates a null layer.
    let class = "SwapChainTest\0".encode_utf16().collect::<Vec<u16>>();
    let title = "swap-chain-test\0".encode_utf16().collect::<Vec<u16>>();
    let wc = quantum_kernel32::user32::WndClassExW {
        cb_size: core::mem::size_of::<quantum_kernel32::user32::WndClassExW>() as u32,
        style: 0,
        lpfn_wnd_proc: 0,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: core::ptr::null_mut(),
        h_icon: 0,
        h_cursor: 0,
        hbr_background: 0,
        lpsz_menu_name: core::ptr::null(),
        lpsz_class_name: class.as_ptr(),
        h_icon_sm: 0,
    };
    let atom = quantum_kernel32::user32::RegisterClassExW(&wc as *const _ as *const c_void);
    assert_ne!(atom, 0);
    let hwnd = quantum_kernel32::user32::CreateWindowExW(
        0,
        class.as_ptr(),
        title.as_ptr(),
        0,
        0,
        0,
        800,
        600,
        0,
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    assert_ne!(hwnd, 0);

    // Acquire the factory.
    let mut factory: *mut c_void = core::ptr::null_mut();
    let hr = quantum_kernel32::d3d11::CreateDXGIFactory(core::ptr::null(), &mut factory);
    assert_eq!(hr, S_OK);
    assert!(!factory.is_null());

    // Build the swap-chain desc.
    let desc = DxgiSwapChainDesc {
        buffer_desc: DxgiModeDesc {
            width: 800,
            height: 600,
            refresh_numerator: 60,
            refresh_denominator: 1,
            format: 87, // DXGI_FORMAT_B8G8R8A8_UNORM
            scanline_ordering: 0,
            scaling: 0,
        },
        sample_count: 1,
        sample_quality: 0,
        buffer_usage: 0x20, // DXGI_USAGE_RENDER_TARGET_OUTPUT
        buffer_count: 2,
        output_window: hwnd,
        windowed: 1,
        swap_effect: 4, // DXGI_SWAP_EFFECT_FLIP_DISCARD
        flags: 0,
    };

    // CreateSwapChain via factory vtbl[10].
    let create_addr = unsafe { vtbl_slot(factory, CREATE_SWAP_CHAIN_SLOT) };
    type CreateSC = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create: CreateSC = unsafe { core::mem::transmute(create_addr) };
    let mut swap_chain: *mut c_void = core::ptr::null_mut();
    let hr_sc = unsafe {
        create(
            factory,
            core::ptr::null_mut(),
            &desc as *const _ as *const c_void,
            &mut swap_chain,
        )
    };
    assert_eq!(hr_sc, S_OK);
    assert!(!swap_chain.is_null());

    // Call Present via swap chain vtbl[8].
    let present_addr = unsafe { vtbl_slot(swap_chain, PRESENT_SLOT) };
    type Present = unsafe extern "C" fn(*mut c_void, u32, u32) -> i32;
    let present: Present = unsafe { core::mem::transmute(present_addr) };
    let hr_p = unsafe { present(swap_chain, 1, 0) };
    assert_eq!(hr_p, S_OK);

    let _ = quantum_kernel32::user32::DestroyWindow(hwnd);
}

const GET_BUFFER_SLOT: usize = 9;
const CREATE_RTV_SLOT: usize = 9;

#[test]
fn swap_chain_get_buffer_returns_back_buffer_texture() {
    if !quantum_kernel32::cocoa::metal_available() {
        return;
    }

    let class = "GetBufferTestClass\0".encode_utf16().collect::<Vec<u16>>();
    let wc = quantum_kernel32::user32::WndClassExW {
        cb_size: core::mem::size_of::<quantum_kernel32::user32::WndClassExW>() as u32,
        style: 0,
        lpfn_wnd_proc: 0,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: core::ptr::null_mut(),
        h_icon: 0,
        h_cursor: 0,
        hbr_background: 0,
        lpsz_menu_name: core::ptr::null(),
        lpsz_class_name: class.as_ptr(),
        h_icon_sm: 0,
    };
    let _atom = quantum_kernel32::user32::RegisterClassExW(&wc as *const _ as *const c_void);
    let hwnd = quantum_kernel32::user32::CreateWindowExW(
        0,
        class.as_ptr(),
        core::ptr::null(),
        0,
        0,
        0,
        640,
        480,
        0,
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    let mut factory: *mut c_void = core::ptr::null_mut();
    let _ = quantum_kernel32::d3d11::CreateDXGIFactory(core::ptr::null(), &mut factory);

    let desc = DxgiSwapChainDesc {
        buffer_desc: DxgiModeDesc {
            width: 640,
            height: 480,
            refresh_numerator: 60,
            refresh_denominator: 1,
            format: 87, // BGRA8Unorm
            scanline_ordering: 0,
            scaling: 0,
        },
        sample_count: 1,
        sample_quality: 0,
        buffer_usage: 0x20,
        buffer_count: 2,
        output_window: hwnd,
        windowed: 1,
        swap_effect: 4,
        flags: 0,
    };
    let create_addr = unsafe { vtbl_slot(factory, CREATE_SWAP_CHAIN_SLOT) };
    type CreateSC = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create: CreateSC = unsafe { core::mem::transmute(create_addr) };
    let mut swap_chain: *mut c_void = core::ptr::null_mut();
    let _ = unsafe {
        create(
            factory,
            core::ptr::null_mut(),
            &desc as *const _ as *const c_void,
            &mut swap_chain,
        )
    };

    // GetBuffer at slot 9.
    let gb_addr = unsafe { vtbl_slot(swap_chain, GET_BUFFER_SLOT) };
    type GetBuf = unsafe extern "C" fn(
        *mut c_void,
        u32,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let gb: GetBuf = unsafe { core::mem::transmute(gb_addr) };
    let mut back_buf: *mut c_void = core::ptr::null_mut();
    let hr_gb = unsafe { gb(swap_chain, 0, core::ptr::null(), &mut back_buf) };
    assert_eq!(hr_gb, S_OK);
    assert!(!back_buf.is_null(), "GetBuffer should return a non-null texture");

    // Calling again returns the same pointer (cached).
    let mut back_buf2: *mut c_void = core::ptr::null_mut();
    let _ = unsafe { gb(swap_chain, 0, core::ptr::null(), &mut back_buf2) };
    assert_eq!(back_buf, back_buf2);

    // Now use the texture as a CreateRenderTargetView resource through
    // the device-level RTV slot (slot 9 of the *device* vtable, which
    // is *different* from slot 9 of the *swap-chain* vtable above —
    // both happen to share the index 9 in their respective tables).
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut fl: u32 = 0;
    let mut ctx: *mut c_void = core::ptr::null_mut();
    let _ = quantum_kernel32::d3d11::D3D11CreateDevice(
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
        core::ptr::null(),
        0,
        0,
        &mut device,
        &mut fl,
        &mut ctx,
    );
    let rtv_addr = unsafe { vtbl_slot(device, CREATE_RTV_SLOT) };
    type CreateRtv = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_rtv: CreateRtv = unsafe { core::mem::transmute(rtv_addr) };
    let mut rtv: *mut c_void = core::ptr::null_mut();
    let hr_rtv =
        unsafe { create_rtv(device, back_buf, core::ptr::null(), &mut rtv) };
    assert_eq!(hr_rtv, S_OK);
    assert!(!rtv.is_null());
}

