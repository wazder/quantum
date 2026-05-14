//! Minimal `d3d11.dll` surface. Today this only stubs
//! `D3D11CreateDevice` and the small set of `ID3D11Device` /
//! `ID3D11DeviceContext` vtable entries the guest dereferences right
//! after creation. Real Metal-backed implementation comes in Phase 4.
//!
//! Architectural note: COM interfaces in Windows are layouts of the
//! form
//!
//! ```c
//! struct ID3D11Device {
//!     const ID3D11DeviceVtbl *lpVtbl;
//!     // implementation-defined data follows
//! };
//! struct ID3D11DeviceVtbl {
//!     HRESULT (*QueryInterface)(self, REFIID, void**);
//!     ULONG   (*AddRef)(self);
//!     ULONG   (*Release)(self);
//!     // ... ~40 more methods
//! };
//! ```
//!
//! Guest code reads `obj->lpVtbl->Method(obj, args...)`. We hand the
//! guest a pointer to a static "fake object" whose first qword is the
//! pointer to a static vtable filled with our stub functions. The
//! stubs are plain Rust functions with `extern "C"` calling
//! convention; the JIT calls them through the IAT thunk mechanism as
//! usual (via BLR).

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

/// Standard Win32 success.
const S_OK: i32 = 0;
/// "Method not implemented".
const E_NOTIMPL: i32 = 0x8000_4001u32 as i32;
/// "No such interface".
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;

// ---------- IUnknown / device ref-count plumbing ----------
//
// All COM objects start with these three methods. We keep an atomic
// refcount per object — necessary only so the guest doesn't trip its
// own AddRef/Release sanity checks.

static DEVICE_REFCOUNT: AtomicU32 = AtomicU32::new(1);

#[unsafe(no_mangle)]
extern "C" fn d3d11_qi(_this: *mut c_void, _iid: *const c_void, out: *mut *mut c_void) -> i32 {
    if !out.is_null() {
        // SAFETY: caller pointer.
        unsafe {
            *out = core::ptr::null_mut();
        }
    }
    E_NOINTERFACE
}

#[unsafe(no_mangle)]
extern "C" fn d3d11_addref(_this: *mut c_void) -> u32 {
    DEVICE_REFCOUNT.fetch_add(1, Ordering::SeqCst) + 1
}

#[unsafe(no_mangle)]
extern "C" fn d3d11_release(_this: *mut c_void) -> u32 {
    DEVICE_REFCOUNT
        .fetch_sub(1, Ordering::SeqCst)
        .saturating_sub(1)
}

/// Generic noop returning E_NOTIMPL — installed at every slot we
/// haven't real-stubbed yet so the guest at least gets a defined
/// HRESULT instead of jumping to a null pointer.
#[unsafe(no_mangle)]
extern "C" fn d3d11_method_notimpl() -> i32 {
    E_NOTIMPL
}

/// Number of method slots in the `ID3D11Device` vtable. Real Windows
/// header has 43 entries (indices 0..=42). We oversize to 128 to give
/// headroom for the future device-context vtable that's even bigger,
/// and to be friendly to any guest that miscalculates the offset.
const VTABLE_SLOTS: usize = 128;

/// Static vtable for `ID3D11Device`. Layout:
///   [0]: QueryInterface
///   [1]: AddRef
///   [2]: Release
///   [3..]: device methods (all stubbed to E_NOTIMPL today)
#[repr(C)]
struct DeviceVtbl {
    slots: [usize; VTABLE_SLOTS],
}

unsafe impl Sync for DeviceVtbl {}

/// ID3D11Device::CreateBuffer vtable slot — per `<d3d11.h>`.
const D3D11_DEVICE_CREATE_BUFFER_SLOT: usize = 3;
/// ID3D11Device::CreateVertexShader vtable slot.
const D3D11_DEVICE_CREATE_VERTEX_SHADER_SLOT: usize = 12;
/// ID3D11Device::CreatePixelShader vtable slot.
const D3D11_DEVICE_CREATE_PIXEL_SHADER_SLOT: usize = 15;

/// D3D11_BUFFER_DESC layout — exactly 6 × u32 = 24 bytes.
#[repr(C)]
struct BufferDesc {
    byte_width: u32,
    usage: u32,
    bind_flags: u32,
    cpu_access_flags: u32,
    misc_flags: u32,
    structure_byte_stride: u32,
}

/// D3D11_SUBRESOURCE_DATA layout — 24 bytes on x64.
#[repr(C)]
struct SubresourceData {
    p_sys_mem: *const c_void,
    sys_mem_pitch: u32,
    sys_mem_slice_pitch: u32,
}

/// `HRESULT ID3D11Device::CreateBuffer(const D3D11_BUFFER_DESC*,
///                                      const D3D11_SUBRESOURCE_DATA*,
///                                      ID3D11Buffer**)`
///
/// Allocates a real `MTLBuffer` of the requested size in unified
/// memory and (optionally) copies initial data into it. The returned
/// `ppBuffer` slot gets a `BufferObject` whose first qword is a vtable
/// pointer compatible with `ID3D11Resource`-shaped queries from the
/// guest. Returns S_OK on success, E_NOTIMPL on bad inputs.
extern "C" fn d3d11_create_buffer(
    _this: *mut c_void,
    p_desc: *const c_void,
    p_initial_data: *const c_void,
    pp_buffer: *mut *mut c_void,
) -> i32 {
    if p_desc.is_null() {
        return E_NOTIMPL;
    }
    // SAFETY: the caller (a DX11 guest) is contractually required to
    // pass a properly aligned, fully populated `D3D11_BUFFER_DESC`.
    let desc = unsafe { &*(p_desc as *const BufferDesc) };
    if desc.byte_width == 0 {
        return E_NOTIMPL;
    }
    let init_ptr: *const c_void = if p_initial_data.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: same contract — caller guarantees a valid
        // `D3D11_SUBRESOURCE_DATA` pointer when non-null.
        let init = unsafe { &*(p_initial_data as *const SubresourceData) };
        init.p_sys_mem
    };
    let mtl = crate::cocoa::metal_new_buffer(desc.byte_width as usize, init_ptr);
    if mtl.is_null() {
        return E_NOTIMPL;
    }
    if !pp_buffer.is_null() {
        // For now we hand back the raw MTLBuffer pointer. The guest
        // treats it as opaque (its only handle on the buffer); real
        // ID3D11Buffer vtable indirection lands when the draw path
        // starts using IASetVertexBuffers et al.
        unsafe {
            *pp_buffer = mtl;
        }
    } else {
        // Caller threw away the handle; we can't track it, so
        // immediately release to avoid a leak. Apps that pass NULL
        // here are non-conformant anyway.
        crate::cocoa::release(mtl);
    }
    S_OK
}

/// `HRESULT ID3D11Device::CreateVertexShader(LPCVOID pShaderBytecode,
///                                            SIZE_T BytecodeLength,
///                                            ID3D11ClassLinkage *pClassLinkage,
///                                            ID3D11VertexShader **ppVertexShader)`
///
/// We validate the DXBC blob via `quantum_kernel32::dxbc::parse` and
/// (optionally) transpile its SHEX chunk to MSL with `emit_msl`. The
/// MSL string is dropped today — Metal pipeline creation lands in a
/// follow-up. Returns S_OK if the blob is a well-formed DXBC container
/// even when transpilation fails, so games can proceed past the shader
/// load.
///
/// `ppVertexShader` may be NULL in our JIT pipeline because the lifter
/// doesn't yet marshal the 5th Win64 arg; we tolerate that.
extern "C" fn d3d11_create_vertex_shader(
    _this: *mut c_void,
    p_bytecode: *const c_void,
    bytecode_len: usize,
    _class_linkage: *mut c_void,
    pp_vs: *mut *mut c_void,
) -> i32 {
    process_shader_blob(p_bytecode, bytecode_len, pp_vs)
}

/// `ID3D11Device::CreatePixelShader` — same layout as the VS variant.
extern "C" fn d3d11_create_pixel_shader(
    _this: *mut c_void,
    p_bytecode: *const c_void,
    bytecode_len: usize,
    _class_linkage: *mut c_void,
    pp_ps: *mut *mut c_void,
) -> i32 {
    process_shader_blob(p_bytecode, bytecode_len, pp_ps)
}

/// Shared bytecode handler: parse the DXBC container, attempt MSL
/// transpilation of the instruction chunk for diagnostics, and write a
/// fake shader pointer into `pp_out` if it's non-null.
fn process_shader_blob(
    p_bytecode: *const c_void,
    bytecode_len: usize,
    pp_out: *mut *mut c_void,
) -> i32 {
    if p_bytecode.is_null() || bytecode_len == 0 {
        return E_NOTIMPL;
    }
    // SAFETY: caller is a Win32 guest contract obligated to provide a
    // valid pointer + length. We make a slice and inspect it read-only.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(p_bytecode as *const u8, bytecode_len)
    };
    let container = match crate::dxbc::parse(bytes) {
        Ok(c) => c,
        Err(_) => return E_NOTIMPL,
    };
    // Transpile is best-effort; failure doesn't fail the call.
    if let Some(chunk) = container.instructions_chunk() {
        let payload = chunk.payload(bytes);
        if let Some(tokens) = crate::dxbc::InstructionIter::from_payload_bytes(payload)
        {
            let _msl = crate::dxbc::emit_msl(&tokens);
            // TODO: hand the MSL string to a Metal pipeline factory
            // and stash the resulting pipeline pointer in the
            // returned shader object. For now we just drop it.
        }
    }
    if !pp_out.is_null() {
        // Reuse the device's static object so the guest has a
        // non-null shader handle to stash; vtable methods on the
        // shader object aren't exercised yet, so the static stub
        // suffices.
        unsafe {
            *pp_out = device_instance() as *const Device as *mut c_void;
        }
    }
    S_OK
}

/// Build the vtable at init time so the addresses of the stubs are
/// stable. We expose it via a `&'static DeviceVtbl` so the device
/// object's `lpVtbl` can point at it.
fn device_vtbl() -> &'static DeviceVtbl {
    use std::sync::OnceLock;
    static VTBL: OnceLock<DeviceVtbl> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut slots = [d3d11_method_notimpl as *const () as usize; VTABLE_SLOTS];
        slots[0] = d3d11_qi as *const () as usize;
        slots[1] = d3d11_addref as *const () as usize;
        slots[2] = d3d11_release as *const () as usize;
        slots[D3D11_DEVICE_CREATE_BUFFER_SLOT] =
            d3d11_create_buffer as *const () as usize;
        slots[D3D11_DEVICE_CREATE_VERTEX_SHADER_SLOT] =
            d3d11_create_vertex_shader as *const () as usize;
        slots[D3D11_DEVICE_CREATE_PIXEL_SHADER_SLOT] =
            d3d11_create_pixel_shader as *const () as usize;
        DeviceVtbl { slots }
    })
}

/// A pseudo `ID3D11Device` instance — single static object shared
/// across the whole guest. First qword points to the vtable. The
/// guest dereferences obj->vtbl->method, so as long as the first qword
/// is valid we're fine.
#[repr(C, align(16))]
struct Device {
    vtbl: *const DeviceVtbl,
    _pad: [u8; 248],
}

// SAFETY: Device is only read by guest code through its vtbl pointer;
// the `_pad` bytes are inert. The raw pointer field doesn't actually
// alias mutable state.
unsafe impl Sync for Device {}
unsafe impl Send for Device {}

fn device_instance() -> &'static Device {
    use std::sync::OnceLock;
    static DEV: OnceLock<Device> = OnceLock::new();
    DEV.get_or_init(|| Device {
        vtbl: device_vtbl() as *const DeviceVtbl,
        _pad: [0; 248],
    })
}

/// `HRESULT D3D11CreateDevice(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE,
///                             HMODULE Software, UINT Flags,
///                             const D3D_FEATURE_LEVEL *FeatureLevels,
///                             UINT FeatureLevelsCount, UINT SDKVersion,
///                             ID3D11Device **ppDevice,
///                             D3D_FEATURE_LEVEL *pFeatureLevel,
///                             ID3D11DeviceContext **ppImmediateContext)`
///
/// Win64 ABI passes the first four args in RCX/RDX/R8/R9; the rest go
/// on the guest stack. Our JIT marshals the first four into AAPCS64
/// X0..X3, and pushes the rest. We don't currently shuffle stack-resident
/// args, so we read them via the saved guest RSP if needed.
///
/// Today we always succeed and hand back the shared static
/// `ID3D11Device` instance. Future versions wire this through Metal.
#[unsafe(no_mangle)]
pub extern "C" fn D3D11CreateDevice(
    _adapter: *mut c_void,
    _driver_type: u32,
    _software: *mut c_void,
    _flags: u32,
    _feature_levels: *const u32,
    _feature_levels_count: u32,
    _sdk_version: u32,
    // The remaining three args arrive via stack on Win64; the JIT
    // doesn't yet marshal those into AAPCS64 stack arguments cleanly,
    // so callers from guest code may pass garbage in the upper slots.
    // We treat NULL pointers as "caller doesn't need this".
    pp_device: *mut *mut c_void,
    p_feature_level: *mut u32,
    pp_immediate_context: *mut *mut c_void,
) -> i32 {
    if !pp_device.is_null() {
        unsafe {
            *pp_device = device_instance() as *const Device as *mut c_void;
        }
    }
    if !p_feature_level.is_null() {
        // 0xB000 = D3D_FEATURE_LEVEL_11_0 in d3dcommon.h. Game code
        // typically checks this is at least 10_0 (0xA000) before
        // proceeding.
        unsafe {
            *p_feature_level = 0xB000;
        }
    }
    if !pp_immediate_context.is_null() {
        // Reuse the same shared object for the immediate context —
        // its vtable has different methods but our stubs return
        // E_NOTIMPL across the board, so a single static is fine until
        // real implementations land.
        unsafe {
            *pp_immediate_context = device_instance() as *const Device as *mut c_void;
        }
    }
    S_OK
}

/// Resolver for d3d11.dll. Returns the host function address of an
/// exported symbol, or None if the name isn't covered yet.
pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "D3D11CreateDevice" => D3D11CreateDevice as *const (),
        _ => return None,
    };
    Some(p as u64)
}

// ---------- Adjacent DX-family stubs ----------
//
// Sekiro imports one function each from d3d9.dll (a debug-perf probe),
// d3dx11_43.dll (a screenshot helper), and d3dcompiler_43.dll (a shader
// reflection accessor). Stubbing them keeps the IAT-resolution phase
// happy; real implementations come later.

/// `int D3DPERF_GetStatus()` — when no debugger is attached this just
/// returns 0. Almost no game depends on the real value.
#[unsafe(no_mangle)]
pub extern "C" fn D3DPERF_GetStatus() -> u32 {
    0
}

/// `HRESULT D3DX11SaveTextureToFileW(...)` — screenshot helper.
/// Returning S_OK without doing anything lets game code that calls
/// this for periodic debug screenshots proceed.
#[unsafe(no_mangle)]
pub extern "C" fn D3DX11SaveTextureToFileW(
    _ctx: *mut c_void,
    _resource: *mut c_void,
    _format: u32,
    _filename: *const u16,
) -> i32 {
    S_OK
}

/// `HRESULT D3DGetBlobPart(LPCVOID pSrcData, SIZE_T SrcDataSize, D3D_BLOB_PART Part,
///                          UINT Flags, ID3DBlob **ppPart)`.
/// We don't have shader blob parsing yet, so return E_NOTIMPL — most
/// callers handle that by skipping shader-reflection paths.
#[unsafe(no_mangle)]
pub extern "C" fn D3DGetBlobPart(
    _src_data: *const c_void,
    _src_data_size: usize,
    _part: u32,
    _flags: u32,
    pp_part: *mut *mut c_void,
) -> i32 {
    if !pp_part.is_null() {
        unsafe {
            *pp_part = core::ptr::null_mut();
        }
    }
    E_NOTIMPL
}

pub fn resolve_d3d9(function: &str) -> Option<u64> {
    match function {
        "D3DPERF_GetStatus" => Some(D3DPERF_GetStatus as *const () as u64),
        _ => None,
    }
}

pub fn resolve_d3dx11(function: &str) -> Option<u64> {
    match function {
        "D3DX11SaveTextureToFileW" => Some(D3DX11SaveTextureToFileW as *const () as u64),
        _ => None,
    }
}

pub fn resolve_d3dcompiler(function: &str) -> Option<u64> {
    match function {
        "D3DGetBlobPart" => Some(D3DGetBlobPart as *const () as u64),
        _ => None,
    }
}

// ---------- DXGI ----------
//
// DXGI sits between D3D11 and the OS — creates the factory that hands
// out adapters, outputs, and (most importantly) swap chains. Sekiro
// imports just CreateDXGIFactory; engine wraps the returned interface
// to enumerate adapters and create a swap chain over a window.

/// Static IDXGIFactory vtable — same layout philosophy as the
/// ID3D11Device one above. Slots 0..2 are IUnknown.
fn dxgi_factory_vtbl() -> &'static DeviceVtbl {
    use std::sync::OnceLock;
    static VTBL: OnceLock<DeviceVtbl> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut slots = [d3d11_method_notimpl as *const () as usize; VTABLE_SLOTS];
        slots[0] = d3d11_qi as *const () as usize;
        slots[1] = d3d11_addref as *const () as usize;
        slots[2] = d3d11_release as *const () as usize;
        DeviceVtbl { slots }
    })
}

fn dxgi_factory_instance() -> &'static Device {
    use std::sync::OnceLock;
    static INST: OnceLock<Device> = OnceLock::new();
    INST.get_or_init(|| Device {
        vtbl: dxgi_factory_vtbl() as *const DeviceVtbl,
        _pad: [0; 248],
    })
}

/// `HRESULT CreateDXGIFactory(REFIID riid, void **ppFactory)`.
/// We hand back a shared static factory regardless of the requested
/// IID. Most games ask for IDXGIFactory or IDXGIFactory1 — both have
/// compatible vtable headers for the IUnknown methods we implement.
#[unsafe(no_mangle)]
pub extern "C" fn CreateDXGIFactory(_riid: *const c_void, pp_factory: *mut *mut c_void) -> i32 {
    if !pp_factory.is_null() {
        unsafe {
            *pp_factory = dxgi_factory_instance() as *const Device as *mut c_void;
        }
    }
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateDXGIFactory1(_riid: *const c_void, pp_factory: *mut *mut c_void) -> i32 {
    CreateDXGIFactory(_riid, pp_factory)
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateDXGIFactory2(
    _flags: u32,
    _riid: *const c_void,
    pp_factory: *mut *mut c_void,
) -> i32 {
    CreateDXGIFactory(_riid, pp_factory)
}

pub fn resolve_dxgi(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CreateDXGIFactory" => CreateDXGIFactory as *const (),
        "CreateDXGIFactory1" => CreateDXGIFactory1 as *const (),
        "CreateDXGIFactory2" => CreateDXGIFactory2 as *const (),
        _ => return None,
    };
    Some(p as u64)
}
