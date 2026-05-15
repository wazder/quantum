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
/// ID3D11Device::CreateTexture2D vtable slot.
const D3D11_DEVICE_CREATE_TEXTURE_2D_SLOT: usize = 5;
/// ID3D11Device::CreateShaderResourceView vtable slot.
const D3D11_DEVICE_CREATE_SRV_SLOT: usize = 7;
/// ID3D11Device::CreateRenderTargetView vtable slot.
const D3D11_DEVICE_CREATE_RTV_SLOT: usize = 9;
/// ID3D11Device::CreateInputLayout vtable slot.
const D3D11_DEVICE_CREATE_INPUT_LAYOUT_SLOT: usize = 11;
/// ID3D11Device::CreateVertexShader vtable slot.
const D3D11_DEVICE_CREATE_VERTEX_SHADER_SLOT: usize = 12;
/// ID3D11Device::CreatePixelShader vtable slot.
const D3D11_DEVICE_CREATE_PIXEL_SHADER_SLOT: usize = 15;

/// ID3D11RenderTargetView / ShaderResourceView vtable — just IUnknown.
/// The resource these views wrap is stored after the vtable pointer.
#[repr(C, align(16))]
struct ResourceView {
    vtbl: *const DeviceVtbl,
    resource: *mut c_void,
    _pad: [u8; 240],
}

unsafe impl Sync for ResourceView {}
unsafe impl Send for ResourceView {}

fn view_vtbl() -> &'static DeviceVtbl {
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

fn make_view(resource: *mut c_void) -> *mut c_void {
    let v = Box::new(ResourceView {
        vtbl: view_vtbl() as *const DeviceVtbl,
        resource,
        _pad: [0; 240],
    });
    Box::into_raw(v) as *mut c_void
}

extern "C" fn d3d11_create_rtv(
    _this: *mut c_void,
    p_resource: *mut c_void,
    _p_desc: *const c_void,
    pp_rtv: *mut *mut c_void,
) -> i32 {
    if p_resource.is_null() {
        return E_NOTIMPL;
    }
    let view = make_view(p_resource);
    if !pp_rtv.is_null() {
        unsafe {
            *pp_rtv = view;
        }
    } else {
        // Free immediately rather than leak.
        unsafe {
            let _ = Box::from_raw(view as *mut ResourceView);
        }
        return E_NOTIMPL;
    }
    S_OK
}

extern "C" fn d3d11_create_srv(
    _this: *mut c_void,
    p_resource: *mut c_void,
    _p_desc: *const c_void,
    pp_srv: *mut *mut c_void,
) -> i32 {
    if p_resource.is_null() {
        return E_NOTIMPL;
    }
    let view = make_view(p_resource);
    if !pp_srv.is_null() {
        unsafe {
            *pp_srv = view;
        }
    } else {
        unsafe {
            let _ = Box::from_raw(view as *mut ResourceView);
        }
        return E_NOTIMPL;
    }
    S_OK
}

/// `HRESULT ID3D11Device::CreateInputLayout(...)` — needs an opaque
/// handle the guest can hand back to `IASetInputLayout` later. We
/// allocate a tiny owned object; vtable just has IUnknown.
extern "C" fn d3d11_create_input_layout(
    _this: *mut c_void,
    _p_elements: *const c_void,
    _num_elements: u32,
    _p_shader_bytecode: *const c_void,
    _bytecode_len: usize,
    pp_input_layout: *mut *mut c_void,
) -> i32 {
    let view = make_view(core::ptr::null_mut());
    if !pp_input_layout.is_null() {
        unsafe {
            *pp_input_layout = view;
        }
    } else {
        unsafe {
            let _ = Box::from_raw(view as *mut ResourceView);
        }
        return E_NOTIMPL;
    }
    S_OK
}

/// D3D11_TEXTURE2D_DESC layout — 44 bytes. Several fields here are
/// 32-bit unsigned; we only consume the ones we map.
#[repr(C)]
struct Texture2DDesc {
    width: u32,
    height: u32,
    mip_levels: u32,
    array_size: u32,
    format: u32,
    sample_count: u32,   // packed DXGI_SAMPLE_DESC.Count
    sample_quality: u32, // packed DXGI_SAMPLE_DESC.Quality
    usage: u32,
    bind_flags: u32,
    cpu_access_flags: u32,
    misc_flags: u32,
}

/// Map a `DXGI_FORMAT` value to an `MTLPixelFormat`. Returns the Metal
/// enum value the cocoa layer expects. The handful of formats covered
/// here are the ones the SDK samples + most indie games use; the rest
/// fall through to BGRA8Unorm as a safe-ish default.
fn dxgi_to_metal_format(dxgi: u32) -> u64 {
    match dxgi {
        // DXGI_FORMAT_R8G8B8A8_UNORM → MTLPixelFormatRGBA8Unorm
        28 => 70,
        // DXGI_FORMAT_R8G8B8A8_UNORM_SRGB → MTLPixelFormatRGBA8Unorm_sRGB
        29 => 71,
        // DXGI_FORMAT_B8G8R8A8_UNORM → MTLPixelFormatBGRA8Unorm
        87 => 80,
        // DXGI_FORMAT_B8G8R8A8_UNORM_SRGB → MTLPixelFormatBGRA8Unorm_sRGB
        91 => 81,
        // DXGI_FORMAT_R32_FLOAT → MTLPixelFormatR32Float
        41 => 53,
        // DXGI_FORMAT_R16G16B16A16_FLOAT → MTLPixelFormatRGBA16Float
        10 => 115,
        // DXGI_FORMAT_D24_UNORM_S8_UINT → MTLPixelFormatDepth24Unorm_Stencil8 (255)
        45 => 255,
        // DXGI_FORMAT_D32_FLOAT → MTLPixelFormatDepth32Float
        40 => 252,
        _ => 80, // BGRA8Unorm safe default
    }
}

/// Translate `D3D11_BIND_FLAG` to `MTLTextureUsage`. DX11 bind flags
/// are a bitmask; we OR the equivalents.
///   D3D11_BIND_SHADER_RESOURCE = 0x08 → MTLTextureUsageShaderRead = 0x01
///   D3D11_BIND_RENDER_TARGET   = 0x20 → MTLTextureUsageRenderTarget = 0x04
///   D3D11_BIND_UNORDERED_ACCESS= 0x80 → MTLTextureUsageShaderWrite = 0x02
///   D3D11_BIND_DEPTH_STENCIL   = 0x40 → MTLTextureUsageRenderTarget = 0x04
fn bind_flags_to_metal_usage(bind_flags: u32) -> u64 {
    let mut u = 0u64;
    if bind_flags & 0x08 != 0 {
        u |= 0x01;
    }
    if bind_flags & 0x80 != 0 {
        u |= 0x02;
    }
    if bind_flags & 0x20 != 0 {
        u |= 0x04;
    }
    if bind_flags & 0x40 != 0 {
        u |= 0x04;
    }
    if u == 0 {
        u = 0x01; // default to shader-read so the texture is still usable
    }
    u
}

/// `HRESULT ID3D11Device::CreateTexture2D(const D3D11_TEXTURE2D_DESC*,
///                                         const D3D11_SUBRESOURCE_DATA*,
///                                         ID3D11Texture2D**)`
extern "C" fn d3d11_create_texture_2d(
    _this: *mut c_void,
    p_desc: *const c_void,
    _p_initial_data: *const c_void,
    pp_tex: *mut *mut c_void,
) -> i32 {
    if p_desc.is_null() {
        return E_NOTIMPL;
    }
    // SAFETY: caller (DX11 guest) is contractually required to pass a
    // populated, properly-aligned descriptor.
    let desc = unsafe { &*(p_desc as *const Texture2DDesc) };
    if desc.width == 0 || desc.height == 0 {
        return E_NOTIMPL;
    }
    let format = dxgi_to_metal_format(desc.format);
    let usage = bind_flags_to_metal_usage(desc.bind_flags);
    let tex = crate::cocoa::metal_new_texture_2d_with_usage(
        desc.width,
        desc.height,
        format,
        usage,
    );
    if tex.is_null() {
        return E_NOTIMPL;
    }
    if !pp_tex.is_null() {
        unsafe {
            *pp_tex = tex;
        }
    } else {
        crate::cocoa::release(tex);
    }
    S_OK
}

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
    // Hash the whole DXBC blob so repeated CreateVertexShader /
    // CreatePixelShader calls with the same bytecode reuse the
    // compiled MTLLibrary instead of recompiling (games create the
    // same shaders every level load).
    let hash = fnv1a64(bytes);
    let library = shader_library_for(hash, &container, bytes);

    if !pp_out.is_null() {
        // Hand back a ShaderObject wrapping the (possibly null)
        // MTLLibrary + its hash. The guest stashes this pointer and
        // later passes it to VS/PSSetShader; the draw path resolves
        // the library from it.
        let so = Box::new(ShaderObject {
            vtbl: view_vtbl() as *const DeviceVtbl,
            library,
            dxbc_hash: hash,
            _pad: [0; 232],
        });
        unsafe {
            *pp_out = Box::into_raw(so) as *mut c_void;
        }
    }
    S_OK
}

/// Wrapper handed to the guest as ID3D11VertexShader* /
/// ID3D11PixelShader*. First qword is an IUnknown-shaped vtable so a
/// guest QI/AddRef/Release doesn't fault; the rest carries the
/// compiled `MTLLibrary` (null if MSL didn't compile yet) + the DXBC
/// hash for cache lookups.
#[repr(C, align(16))]
struct ShaderObject {
    vtbl: *const DeviceVtbl,
    library: *mut c_void,
    dxbc_hash: u64,
    _pad: [u8; 232],
}

unsafe impl Sync for ShaderObject {}
unsafe impl Send for ShaderObject {}

/// FNV-1a 64-bit. Tiny, dependency-free, good enough for keying the
/// shader-library cache (collision risk is negligible for the few
/// hundred distinct shaders a game ships).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Compile (or fetch a cached) MTLLibrary for the given DXBC blob.
/// Returns null when Metal is unreachable or the emitted MSL doesn't
/// compile yet (the emitter is still partial — callers tolerate a
/// null library; the shader object is still handed back so game init
/// proceeds).
fn shader_library_for(
    hash: u64,
    container: &crate::dxbc::Container,
    bytes: &[u8],
) -> *mut c_void {
    use std::sync::OnceLock;
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<u64, usize>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(&lib) = cache.lock().unwrap().get(&hash) {
        return lib as *mut c_void;
    }
    let mut library: *mut c_void = core::ptr::null_mut();
    if let Some(chunk) = container.instructions_chunk() {
        let payload = chunk.payload(bytes);
        if let Some(tokens) = crate::dxbc::InstructionIter::from_payload_bytes(payload)
            && let Ok(msl) = crate::dxbc::emit_msl(&tokens)
        {
            // Best-effort: emit_msl is still partial so most real
            // shaders won't compile yet — that's expected and
            // non-fatal. A null library just means the draw path
            // falls back until the transpiler matures.
            library = crate::cocoa::metal_new_library(&msl);
        }
    }
    cache.lock().unwrap().insert(hash, library as usize);
    library
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
        slots[D3D11_DEVICE_CREATE_TEXTURE_2D_SLOT] =
            d3d11_create_texture_2d as *const () as usize;
        slots[D3D11_DEVICE_CREATE_SRV_SLOT] = d3d11_create_srv as *const () as usize;
        slots[D3D11_DEVICE_CREATE_RTV_SLOT] = d3d11_create_rtv as *const () as usize;
        slots[D3D11_DEVICE_CREATE_INPUT_LAYOUT_SLOT] =
            d3d11_create_input_layout as *const () as usize;
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
        unsafe {
            *pp_immediate_context =
                context_instance() as *const DeviceContext as *mut c_void;
        }
    }
    S_OK
}

// ---------- ID3D11DeviceContext ----------
//
// Layout: 144 vtable slots. We share the DeviceVtbl size constant
// (128) so a misaligned guest can't walk off the end; the methods we
// actually populate fit comfortably.

const D3D11_CTX_VS_SET_CONSTANT_BUFFERS_SLOT: usize = 7;
const D3D11_CTX_PS_SET_SHADER_RESOURCES_SLOT: usize = 8;
const D3D11_CTX_PS_SET_SHADER_SLOT: usize = 9;
const D3D11_CTX_PS_SET_SAMPLERS_SLOT: usize = 10;
const D3D11_CTX_VS_SET_SHADER_SLOT: usize = 11;
const D3D11_CTX_DRAW_INDEXED_SLOT: usize = 12;
const D3D11_CTX_DRAW_SLOT: usize = 13;
const D3D11_CTX_IA_SET_INPUT_LAYOUT_SLOT: usize = 17;
const D3D11_CTX_IA_SET_VERTEX_BUFFERS_SLOT: usize = 18;
const D3D11_CTX_IA_SET_INDEX_BUFFER_SLOT: usize = 19;
const D3D11_CTX_IA_SET_PRIMITIVE_TOPOLOGY_SLOT: usize = 24;
const D3D11_CTX_OM_SET_RENDER_TARGETS_SLOT: usize = 33;
const D3D11_CTX_RS_SET_VIEWPORTS_SLOT: usize = 44;
const D3D11_CTX_CLEAR_RENDER_TARGET_VIEW_SLOT: usize = 50;

/// Accept-and-ignore void state setter. Win64 ABI: AAPCS64 trims any
/// args we don't read.
extern "C" fn ctx_noop_void() {}

// ---------- DrawState tracking ----------
//
// Real games make ~thousands of state-setter calls per frame
// (IASetVertexBuffers, VSSetShader, …) interleaved with Draw /
// DrawIndexed. The setters used to be silent no-ops, which meant a
// guest's render path silently dropped every binding before reaching
// the (also no-op) Draw — there was no signal at all that the API
// path was being exercised. This commit records the most-recent set
// of each binding in a mutex-guarded DrawState, plus an atomic Draw
// counter, so tests can verify the path executed end to end.

#[derive(Debug, Clone, Copy, Default)]
pub struct DrawState {
    pub vs_shader: usize,
    pub ps_shader: usize,
    pub vertex_buffer: usize,
    pub vertex_stride: u32,
    pub vertex_offset: u32,
    pub index_buffer: usize,
    pub index_format: u32,
    pub input_layout: usize,
    pub primitive_topology: u32,
    pub render_target: usize,
    pub viewport_w: f32,
    pub viewport_h: f32,
}

fn draw_state() -> &'static std::sync::Mutex<DrawState> {
    use std::sync::OnceLock;
    static S: OnceLock<std::sync::Mutex<DrawState>> = OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(DrawState::default()))
}

/// Read a snapshot of the current draw state. Useful for tests and
/// runtime diagnostics. The returned value is a clone — concurrent
/// updates won't be observed.
pub fn snapshot_draw_state() -> DrawState {
    *draw_state().lock().unwrap()
}

/// Number of `Draw` / `DrawIndexed` invocations seen since process
/// start. Atomic so multiple guest threads can increment concurrently
/// without locking.
pub fn draw_count() -> u32 {
    use core::sync::atomic::Ordering;
    DRAW_COUNTER.load(Ordering::SeqCst)
}

static DRAW_COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

extern "C" fn ctx_vs_set_shader(
    _this: *mut c_void,
    p_shader: usize,
    _p_class_instances: *mut c_void,
    _num_class_instances: u32,
) {
    draw_state().lock().unwrap().vs_shader = p_shader;
}

extern "C" fn ctx_ps_set_shader(
    _this: *mut c_void,
    p_shader: usize,
    _p_class_instances: *mut c_void,
    _num_class_instances: u32,
) {
    draw_state().lock().unwrap().ps_shader = p_shader;
}

extern "C" fn ctx_ia_set_input_layout(_this: *mut c_void, p_input_layout: usize) {
    draw_state().lock().unwrap().input_layout = p_input_layout;
}

extern "C" fn ctx_ia_set_primitive_topology(_this: *mut c_void, topology: u32) {
    draw_state().lock().unwrap().primitive_topology = topology;
}

extern "C" fn ctx_ia_set_vertex_buffers(
    _this: *mut c_void,
    _start_slot: u32,
    num_buffers: u32,
    pp_buffers: *const *mut c_void,
    p_strides: *const u32,
    p_offsets: *const u32,
) {
    if num_buffers == 0 || pp_buffers.is_null() {
        return;
    }
    // SAFETY: caller guarantees pp_buffers points at an array of
    // `num_buffers` ID3D11Buffer pointers; same for strides/offsets.
    let buf = unsafe { *pp_buffers };
    let stride = if !p_strides.is_null() { unsafe { *p_strides } } else { 0 };
    let offset = if !p_offsets.is_null() { unsafe { *p_offsets } } else { 0 };
    let mut s = draw_state().lock().unwrap();
    s.vertex_buffer = buf as usize;
    s.vertex_stride = stride;
    s.vertex_offset = offset;
}

extern "C" fn ctx_ia_set_index_buffer(
    _this: *mut c_void,
    p_index_buffer: usize,
    format: u32,
    _offset: u32,
) {
    let mut s = draw_state().lock().unwrap();
    s.index_buffer = p_index_buffer;
    s.index_format = format;
}

extern "C" fn ctx_om_set_render_targets(
    _this: *mut c_void,
    num_views: u32,
    pp_rtvs: *const *mut c_void,
    _p_dsv: *mut c_void,
) {
    if num_views == 0 || pp_rtvs.is_null() {
        draw_state().lock().unwrap().render_target = 0;
        return;
    }
    let rtv = unsafe { *pp_rtvs };
    if rtv.is_null() {
        return;
    }
    // SAFETY: rtv is a ResourceView we ourselves allocated.
    let view = unsafe { &*(rtv as *const ResourceView) };
    draw_state().lock().unwrap().render_target = view.resource as usize;
}

#[repr(C)]
struct D3D11Viewport {
    top_left_x: f32,
    top_left_y: f32,
    width: f32,
    height: f32,
    min_depth: f32,
    max_depth: f32,
}

extern "C" fn ctx_rs_set_viewports(
    _this: *mut c_void,
    num: u32,
    p_viewports: *const c_void,
) {
    if num == 0 || p_viewports.is_null() {
        return;
    }
    // SAFETY: caller's guest passes an array of D3D11_VIEWPORT.
    let vp = unsafe { &*(p_viewports as *const D3D11Viewport) };
    let mut s = draw_state().lock().unwrap();
    s.viewport_w = vp.width;
    s.viewport_h = vp.height;
}

extern "C" fn ctx_draw(_this: *mut c_void, _vertex_count: u32, _start_vertex_location: u32) {
    use core::sync::atomic::Ordering;
    DRAW_COUNTER.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn ctx_draw_indexed(
    _this: *mut c_void,
    _index_count: u32,
    _start_index_location: u32,
    _base_vertex_location: i32,
) {
    use core::sync::atomic::Ordering;
    DRAW_COUNTER.fetch_add(1, Ordering::SeqCst);
}

/// `void ID3D11DeviceContext::ClearRenderTargetView(
///        ID3D11RenderTargetView *pRenderTargetView,
///        const FLOAT ColorRGBA[4])`
///
/// Reads the resource pointer out of our ResourceView wrapper, then
/// drives a CPU-side BGRA fill via cocoa::metal_texture_fill_bgra. Slow
/// but functional — every game's clear pass now actually mutates the
/// back buffer's bytes. A future commit will replace this with a real
/// MTLRenderPassDescriptor + MTLRenderCommandEncoder pass that runs
/// on the GPU.
extern "C" fn ctx_clear_render_target_view(
    _this: *mut c_void,
    p_rtv: *mut c_void,
    p_color: *const f32,
) {
    if p_rtv.is_null() || p_color.is_null() {
        return;
    }
    // SAFETY: caller passed us a real ResourceView we allocated.
    let view = unsafe { &*(p_rtv as *const ResourceView) };
    if view.resource.is_null() {
        return;
    }
    // Read RGBA floats and pack into BGRA8 byte order (matches Metal's
    // RGBA8Unorm / BGRA8Unorm pixel layouts for the common swap-chain
    // formats).
    let rgba = unsafe { [
        *p_color.add(0),
        *p_color.add(1),
        *p_color.add(2),
        *p_color.add(3),
    ] };
    let to_byte = |f: f32| (f.clamp(0.0, 1.0) * 255.0).round() as u8;
    let bgra = [to_byte(rgba[2]), to_byte(rgba[1]), to_byte(rgba[0]), to_byte(rgba[3])];
    // Query the texture's real dimensions so the clear actually fills
    // the whole surface. Falls back to 1×1 if the property accessors
    // return 0 (e.g. detached or freed).
    //
    // SAFETY: view.resource is a live MTLTexture we created via our
    // allocator; metal_texture_{width,height} only call objc_msgSend
    // with the matching selector.
    let (w, h) = unsafe {
        (
            crate::cocoa::metal_texture_width(view.resource) as u32,
            crate::cocoa::metal_texture_height(view.resource) as u32,
        )
    };
    if w == 0 || h == 0 {
        return;
    }
    // SAFETY: as above; format-compatibility is upheld by the resource
    // tracker (RTVs are always wrapped around BGRA/RGBA family).
    unsafe {
        crate::cocoa::metal_texture_fill_bgra(view.resource, w, h, bgra);
    }
}

/// Some context methods are documented to return `HRESULT`; for those
/// we hand back S_OK so the guest believes the state was accepted.
extern "C" fn ctx_noop_hresult() -> i32 {
    S_OK
}

#[repr(C, align(16))]
struct DeviceContext {
    vtbl: *const DeviceVtbl,
    _pad: [u8; 248],
}

unsafe impl Sync for DeviceContext {}
unsafe impl Send for DeviceContext {}

fn context_vtbl() -> &'static DeviceVtbl {
    use std::sync::OnceLock;
    static VTBL: OnceLock<DeviceVtbl> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut slots = [d3d11_method_notimpl as *const () as usize; VTABLE_SLOTS];
        slots[0] = d3d11_qi as *const () as usize;
        slots[1] = d3d11_addref as *const () as usize;
        slots[2] = d3d11_release as *const () as usize;
        // State setters that aren't yet stateful (constant buffers,
        // shader resources, samplers) keep the bare no-op binding.
        for slot in [
            D3D11_CTX_VS_SET_CONSTANT_BUFFERS_SLOT,
            D3D11_CTX_PS_SET_SHADER_RESOURCES_SLOT,
            D3D11_CTX_PS_SET_SAMPLERS_SLOT,
        ] {
            slots[slot] = ctx_noop_void as *const () as usize;
        }
        // Real state-tracking setters / Draw counters.
        slots[D3D11_CTX_VS_SET_SHADER_SLOT] = ctx_vs_set_shader as *const () as usize;
        slots[D3D11_CTX_PS_SET_SHADER_SLOT] = ctx_ps_set_shader as *const () as usize;
        slots[D3D11_CTX_IA_SET_INPUT_LAYOUT_SLOT] =
            ctx_ia_set_input_layout as *const () as usize;
        slots[D3D11_CTX_IA_SET_VERTEX_BUFFERS_SLOT] =
            ctx_ia_set_vertex_buffers as *const () as usize;
        slots[D3D11_CTX_IA_SET_INDEX_BUFFER_SLOT] =
            ctx_ia_set_index_buffer as *const () as usize;
        slots[D3D11_CTX_IA_SET_PRIMITIVE_TOPOLOGY_SLOT] =
            ctx_ia_set_primitive_topology as *const () as usize;
        slots[D3D11_CTX_OM_SET_RENDER_TARGETS_SLOT] =
            ctx_om_set_render_targets as *const () as usize;
        slots[D3D11_CTX_RS_SET_VIEWPORTS_SLOT] = ctx_rs_set_viewports as *const () as usize;
        slots[D3D11_CTX_DRAW_SLOT] = ctx_draw as *const () as usize;
        slots[D3D11_CTX_DRAW_INDEXED_SLOT] = ctx_draw_indexed as *const () as usize;
        // Override Clear with the real implementation that actually
        // touches the texture bytes.
        slots[D3D11_CTX_CLEAR_RENDER_TARGET_VIEW_SLOT] =
            ctx_clear_render_target_view as *const () as usize;
        // A small number of context methods do return HRESULT; we don't
        // have those wired today, but leave the slot template for them.
        let _ = ctx_noop_hresult; // keep the symbol live for the future.
        DeviceVtbl { slots }
    })
}

fn context_instance() -> &'static DeviceContext {
    use std::sync::OnceLock;
    static CTX: OnceLock<DeviceContext> = OnceLock::new();
    CTX.get_or_init(|| DeviceContext {
        vtbl: context_vtbl() as *const DeviceVtbl,
        _pad: [0; 248],
    })
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

/// IDXGIFactory::CreateSwapChain vtable slot — per `<dxgi.h>`.
const DXGI_FACTORY_CREATE_SWAP_CHAIN_SLOT: usize = 10;

/// Static IDXGIFactory vtable — same layout philosophy as the
/// ID3D11Device one above. Slots 0..2 are IUnknown. We populate
/// CreateSwapChain so games can ask for a swap chain over their
/// HWND and get a real CAMetalLayer-backed object.
fn dxgi_factory_vtbl() -> &'static DeviceVtbl {
    use std::sync::OnceLock;
    static VTBL: OnceLock<DeviceVtbl> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut slots = [d3d11_method_notimpl as *const () as usize; VTABLE_SLOTS];
        slots[0] = d3d11_qi as *const () as usize;
        slots[1] = d3d11_addref as *const () as usize;
        slots[2] = d3d11_release as *const () as usize;
        slots[DXGI_FACTORY_CREATE_SWAP_CHAIN_SLOT] =
            dxgi_create_swap_chain as *const () as usize;
        DeviceVtbl { slots }
    })
}

/// DXGI_MODE_DESC layout — 28 bytes.
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

/// DXGI_SWAP_CHAIN_DESC layout — 64 bytes on x64. We only consume the
/// fields we currently care about (BufferDesc + OutputWindow).
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

/// SwapChain object handed back to the guest. First qword is the
/// vtable; the rest holds the CAMetalLayer + MTLCommandQueue + cached
/// back-buffer texture we need for Present + GetBuffer.
#[repr(C, align(16))]
struct SwapChain {
    vtbl: *const DeviceVtbl,
    layer: *mut c_void,
    cmd_queue: *mut c_void,
    back_buffer: *mut c_void,
    width: u32,
    height: u32,
    format: u32,
    _pad: [u8; 208],
}

unsafe impl Sync for SwapChain {}
unsafe impl Send for SwapChain {}

/// IDXGISwapChain::Present vtable slot — per `<dxgi.h>`.
const DXGI_SWAP_CHAIN_PRESENT_SLOT: usize = 8;
/// IDXGISwapChain::GetBuffer vtable slot.
const DXGI_SWAP_CHAIN_GET_BUFFER_SLOT: usize = 9;

/// IDXGISwapChain vtable. Slots 0..2 are IUnknown; slot 8 is Present;
/// slot 9 is GetBuffer.
fn dxgi_swap_chain_vtbl() -> &'static DeviceVtbl {
    use std::sync::OnceLock;
    static VTBL: OnceLock<DeviceVtbl> = OnceLock::new();
    VTBL.get_or_init(|| {
        let mut slots = [d3d11_method_notimpl as *const () as usize; VTABLE_SLOTS];
        slots[0] = d3d11_qi as *const () as usize;
        slots[1] = d3d11_addref as *const () as usize;
        slots[2] = d3d11_release as *const () as usize;
        slots[DXGI_SWAP_CHAIN_PRESENT_SLOT] = dxgi_swap_chain_present as *const () as usize;
        slots[DXGI_SWAP_CHAIN_GET_BUFFER_SLOT] =
            dxgi_swap_chain_get_buffer as *const () as usize;
        DeviceVtbl { slots }
    })
}

/// `HRESULT IDXGISwapChain::GetBuffer(UINT Buffer, REFIID, void **ppSurface)`.
/// Returns the swap chain's back buffer as an `ID3D11Texture2D`. We
/// allocate a real MTLTexture at the swap chain's width/height/format
/// the first time GetBuffer is called and cache it on the SwapChain
/// object; subsequent calls hand back the same pointer (matching the
/// guest's lifetime expectations).
extern "C" fn dxgi_swap_chain_get_buffer(
    this: *mut c_void,
    _buffer: u32,
    _riid: *const c_void,
    pp_surface: *mut *mut c_void,
) -> i32 {
    if this.is_null() || pp_surface.is_null() {
        return E_NOTIMPL;
    }
    // SAFETY: `this` is our SwapChain. We need a mutable view to set
    // the cached back buffer on first call.
    let sc = unsafe { &mut *(this as *mut SwapChain) };
    if sc.back_buffer.is_null() {
        let usage = bind_flags_to_metal_usage(0x20); // RENDER_TARGET
        let format = dxgi_to_metal_format(sc.format);
        let tex =
            crate::cocoa::metal_new_texture_2d_with_usage(sc.width, sc.height, format, usage);
        if tex.is_null() {
            return E_NOTIMPL;
        }
        sc.back_buffer = tex;
    }
    unsafe {
        *pp_surface = sc.back_buffer;
    }
    S_OK
}

/// `HRESULT IDXGISwapChain::Present(UINT SyncInterval, UINT Flags)`.
/// Grabs the next CAMetalDrawable, queues a present command on the
/// MTLCommandQueue stashed in the SwapChain struct, commits.
extern "C" fn dxgi_swap_chain_present(this: *mut c_void, _sync: u32, _flags: u32) -> i32 {
    if this.is_null() {
        return E_NOTIMPL;
    }
    // SAFETY: `this` is a `SwapChain` we ourselves allocated and
    // handed to the guest; it kept the pointer opaque so we can
    // reborrow it here.
    let sc = unsafe { &*(this as *const SwapChain) };
    let drawable = crate::cocoa::next_drawable(sc.layer);
    let cmd_buf = crate::cocoa::metal_command_buffer(sc.cmd_queue);
    crate::cocoa::metal_present(cmd_buf, drawable);
    S_OK
}

/// `HRESULT IDXGIFactory::CreateSwapChain(IUnknown*, DXGI_SWAP_CHAIN_DESC*,
///                                         IDXGISwapChain**)`.
extern "C" fn dxgi_create_swap_chain(
    _this: *mut c_void,
    _p_device: *mut c_void,
    p_desc: *const c_void,
    pp_swap_chain: *mut *mut c_void,
) -> i32 {
    if p_desc.is_null() {
        return E_NOTIMPL;
    }
    // SAFETY: caller's DX11 guest contract guarantees a populated
    // DXGI_SWAP_CHAIN_DESC.
    let desc = unsafe { &*(p_desc as *const DxgiSwapChainDesc) };

    // Find the NSWindow backing the HWND, if any. When QUANTUM_REAL_COCOA
    // was off the guest's window was a registry-only token and we'll get
    // 0 back; the swap chain still works in headless mode (Present is a
    // no-op when layer is null).
    let ns_window = crate::windows_state::ns_window_of(desc.output_window);
    let layer = if ns_window != 0 {
        let l = crate::cocoa::create_metal_layer();
        if !l.is_null() {
            crate::cocoa::attach_metal_layer(ns_window as *mut c_void, l);
        }
        l
    } else {
        core::ptr::null_mut()
    };
    let cmd_queue = crate::cocoa::metal_new_command_queue();

    // Allocate the SwapChain on the heap so its address stays stable
    // for the life of the program. Leaking is fine — swap chains are
    // long-lived game-process singletons.
    let sc = Box::new(SwapChain {
        vtbl: dxgi_swap_chain_vtbl() as *const DeviceVtbl,
        layer,
        cmd_queue,
        back_buffer: core::ptr::null_mut(),
        width: desc.buffer_desc.width,
        height: desc.buffer_desc.height,
        format: desc.buffer_desc.format,
        _pad: [0; 208],
    });
    let raw = Box::into_raw(sc) as *mut c_void;
    if !pp_swap_chain.is_null() {
        unsafe {
            *pp_swap_chain = raw;
        }
    } else {
        // If the guest asked us to allocate but threw away the
        // pointer we're going to leak the SwapChain + layer + queue.
        // Returning the failure code makes that visible.
        return E_NOTIMPL;
    }
    S_OK
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
