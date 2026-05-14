//! ID3D11Device::CreateVertexShader / CreatePixelShader must accept a
//! well-formed DXBC blob, drive it through `quantum_kernel32::dxbc::parse`
//! + `emit_msl`, and return S_OK with a non-null shader pointer.
//!
//! No guest involvement: we extract the vtable function pointer
//! directly and call it like the JIT would after a vtable indirection.

use core::ffi::c_void;
use quantum_kernel32::dxbc;

const S_OK: i32 = 0;

/// Vtable slot offsets per `<d3d11.h>` (and matching d3d11.rs constants).
const VS_SLOT: usize = 12;
const PS_SLOT: usize = 15;
const CREATE_BUFFER_SLOT: usize = 3;
const CREATE_TEXTURE_2D_SLOT: usize = 5;

/// Layout of our Device + Vtbl (must mirror d3d11.rs). We don't import
/// the private structs — we read the first qword of the Device pointer
/// (the vtbl) and treat the rest as a slot array.
unsafe fn vtbl_slot(device: *mut c_void, slot: usize) -> usize {
    let vtbl: *const *const usize = device as *const *const usize;
    let table = unsafe { *vtbl };
    unsafe { *table.add(slot) }
}

fn build_minimal_dxbc() -> Vec<u8> {
    // 1-chunk container: just an SHEX with 4 tokens (program header +
    // RET-only body).
    let prog_type_vs: u32 = 1;
    let major: u32 = 4;
    let version_token = (major << 4) | (prog_type_vs << 16);
    let total: u32 = 4;
    let ret = 0x3E_u32 | (2u32 << 24); // opcode::RET (0x3E), length 2

    let mut shex_payload = Vec::new();
    shex_payload.extend_from_slice(&version_token.to_le_bytes());
    shex_payload.extend_from_slice(&total.to_le_bytes());
    shex_payload.extend_from_slice(&ret.to_le_bytes());
    shex_payload.extend_from_slice(&0u32.to_le_bytes()); // pad to total=4

    // Build the container: 0x20-byte header + 1 offset entry + chunk
    // (8-byte header + payload).
    let mut blob = Vec::new();
    blob.extend_from_slice(b"DXBC");
    blob.extend_from_slice(&[0u8; 16]); // hash
    blob.extend_from_slice(&1u32.to_le_bytes()); // one
    let total_size_off = blob.len();
    blob.extend_from_slice(&0u32.to_le_bytes()); // total_size placeholder
    blob.extend_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
    let chunk_off = 0x20u32 + 4;
    blob.extend_from_slice(&chunk_off.to_le_bytes());

    // Chunk: "SHEX" + size + payload
    blob.extend_from_slice(b"SHEX");
    blob.extend_from_slice(&(shex_payload.len() as u32).to_le_bytes());
    blob.extend_from_slice(&shex_payload);

    let total_size = blob.len() as u32;
    blob[total_size_off..total_size_off + 4].copy_from_slice(&total_size.to_le_bytes());

    blob
}

#[test]
fn create_vertex_shader_accepts_minimal_dxbc_blob() {
    // Acquire the device + vtbl by calling D3D11CreateDevice with
    // mostly-null args (our implementation returns the static device).
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
    let mut ctx: *mut c_void = core::ptr::null_mut();
    let hr = quantum_kernel32::d3d11::D3D11CreateDevice(
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
        core::ptr::null(),
        0,
        0,
        &mut device,
        &mut feature_level,
        &mut ctx,
    );
    assert_eq!(hr, S_OK);
    assert!(!device.is_null());

    let blob = build_minimal_dxbc();
    // Confirm the blob is well-formed via the public dxbc API too.
    let container = dxbc::parse(&blob).expect("DXBC parses");
    assert!(container.instructions_chunk().is_some());

    // Call CreateVertexShader via vtbl[12].
    let vs_fn_addr = unsafe { vtbl_slot(device, VS_SLOT) };
    type CreateVS = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        usize,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_vs: CreateVS = unsafe { core::mem::transmute(vs_fn_addr) };
    let mut shader: *mut c_void = core::ptr::null_mut();
    let hr_vs = unsafe {
        create_vs(
            device,
            blob.as_ptr() as *const c_void,
            blob.len(),
            core::ptr::null_mut(),
            &mut shader,
        )
    };
    assert_eq!(hr_vs, S_OK);
    assert!(!shader.is_null(), "S_OK should hand back a non-null shader pointer");

    // PS slot too.
    let ps_fn_addr = unsafe { vtbl_slot(device, PS_SLOT) };
    let create_ps: CreateVS = unsafe { core::mem::transmute(ps_fn_addr) };
    let mut ps_shader: *mut c_void = core::ptr::null_mut();
    let hr_ps = unsafe {
        create_ps(
            device,
            blob.as_ptr() as *const c_void,
            blob.len(),
            core::ptr::null_mut(),
            &mut ps_shader,
        )
    };
    assert_eq!(hr_ps, S_OK);
    assert!(!ps_shader.is_null());
}

#[repr(C)]
struct D3D11BufferDesc {
    byte_width: u32,
    usage: u32,
    bind_flags: u32,
    cpu_access_flags: u32,
    misc_flags: u32,
    structure_byte_stride: u32,
}

#[repr(C)]
struct D3D11SubresourceData {
    p_sys_mem: *const c_void,
    sys_mem_pitch: u32,
    sys_mem_slice_pitch: u32,
}

#[test]
fn create_buffer_allocates_metal_buffer_and_returns_handle() {
    if !quantum_kernel32::cocoa::metal_available() {
        eprintln!("Metal unavailable — skipping");
        return;
    }
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );

    let create_buffer_addr = unsafe { vtbl_slot(device, CREATE_BUFFER_SLOT) };
    type CreateBuf = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_buf: CreateBuf = unsafe { core::mem::transmute(create_buffer_addr) };

    let initial: [u32; 4] = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
    let desc = D3D11BufferDesc {
        byte_width: (initial.len() * 4) as u32,
        usage: 0,
        bind_flags: 0x1, // D3D11_BIND_VERTEX_BUFFER
        cpu_access_flags: 0,
        misc_flags: 0,
        structure_byte_stride: 0,
    };
    let initial_data = D3D11SubresourceData {
        p_sys_mem: initial.as_ptr() as *const c_void,
        sys_mem_pitch: 0,
        sys_mem_slice_pitch: 0,
    };
    let mut buffer: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        create_buf(
            device,
            &desc as *const _ as *const c_void,
            &initial_data as *const _ as *const c_void,
            &mut buffer,
        )
    };
    assert_eq!(hr, S_OK, "valid CreateBuffer should return S_OK");
    assert!(!buffer.is_null(), "S_OK should hand back a non-null buffer");
    // The handle is a real MTLBuffer pointer. We don't probe its
    // contents from Rust (would require a separate objc-msgSend path
    // for [buf contents]); the round-trip is exercised in the cocoa
    // module's metal_new_buffer behaviour.
    quantum_kernel32::cocoa::release(buffer);
}

#[repr(C)]
struct D3D11Texture2DDesc {
    width: u32,
    height: u32,
    mip_levels: u32,
    array_size: u32,
    format: u32,
    sample_count: u32,
    sample_quality: u32,
    usage: u32,
    bind_flags: u32,
    cpu_access_flags: u32,
    misc_flags: u32,
}

#[test]
fn create_texture_2d_allocates_metal_texture() {
    if !quantum_kernel32::cocoa::metal_available() {
        return;
    }
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );

    let create_tex_addr = unsafe { vtbl_slot(device, CREATE_TEXTURE_2D_SLOT) };
    type CreateTex = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_tex: CreateTex = unsafe { core::mem::transmute(create_tex_addr) };

    let desc = D3D11Texture2DDesc {
        width: 256,
        height: 256,
        mip_levels: 1,
        array_size: 1,
        format: 28, // DXGI_FORMAT_R8G8B8A8_UNORM
        sample_count: 1,
        sample_quality: 0,
        usage: 0,
        bind_flags: 0x08, // D3D11_BIND_SHADER_RESOURCE
        cpu_access_flags: 0,
        misc_flags: 0,
    };
    let mut tex: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        create_tex(
            device,
            &desc as *const _ as *const c_void,
            core::ptr::null(),
            &mut tex,
        )
    };
    assert_eq!(hr, S_OK);
    assert!(!tex.is_null());
    quantum_kernel32::cocoa::release(tex);
}

#[test]
fn create_texture_2d_rejects_zero_dimensions() {
    if !quantum_kernel32::cocoa::metal_available() {
        return;
    }
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );
    let create_tex_addr = unsafe { vtbl_slot(device, CREATE_TEXTURE_2D_SLOT) };
    type CreateTex = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_tex: CreateTex = unsafe { core::mem::transmute(create_tex_addr) };
    let desc = D3D11Texture2DDesc {
        width: 0,
        height: 0,
        mip_levels: 1,
        array_size: 1,
        format: 28,
        sample_count: 1,
        sample_quality: 0,
        usage: 0,
        bind_flags: 0x08,
        cpu_access_flags: 0,
        misc_flags: 0,
    };
    let mut tex: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        create_tex(
            device,
            &desc as *const _ as *const c_void,
            core::ptr::null(),
            &mut tex,
        )
    };
    assert_ne!(hr, S_OK);
    assert!(tex.is_null());
}

#[test]
fn device_context_state_setters_are_callable_no_ops() {
    // Walk the immediate-context vtable and call a few state setters
    // through it. They should accept any arguments and return without
    // crashing. This exercises the fact that the context has its own
    // vtable separate from the device's.
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );
    assert!(!ctx.is_null(), "immediate-context pointer must be non-null");
    assert_ne!(ctx, device, "context must be its own object, not aliased to device");

    // IASetPrimitiveTopology(ctx, topology) at slot 24.
    let slot_topo = 24usize;
    type SetTopo = unsafe extern "C" fn(*mut c_void, u32);
    let topo_fn: SetTopo = unsafe { core::mem::transmute(vtbl_slot(ctx, slot_topo)) };
    unsafe {
        topo_fn(ctx, 4); // D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST
    }

    // Draw(ctx, vertex_count, start_vertex_location) at slot 13.
    let slot_draw = 13usize;
    type Draw = unsafe extern "C" fn(*mut c_void, u32, u32);
    let draw_fn: Draw = unsafe { core::mem::transmute(vtbl_slot(ctx, slot_draw)) };
    unsafe {
        draw_fn(ctx, 3, 0);
    }

    // OMSetRenderTargets(ctx, count, ppRTVs, pDSV) at slot 33.
    let slot_om = 33usize;
    type OmSet =
        unsafe extern "C" fn(*mut c_void, u32, *const *mut c_void, *mut c_void);
    let om_fn: OmSet = unsafe { core::mem::transmute(vtbl_slot(ctx, slot_om)) };
    unsafe {
        om_fn(ctx, 0, core::ptr::null(), core::ptr::null_mut());
    }
}

#[test]
fn texture_dimensions_round_trip_via_cocoa_accessors() {
    if !quantum_kernel32::cocoa::metal_available() {
        return;
    }
    let tex = quantum_kernel32::cocoa::metal_new_texture_2d_with_usage(
        320, 240, 80, // BGRA8Unorm
        0x05,        // ShaderRead | RenderTarget
    );
    assert!(!tex.is_null());
    let w = unsafe { quantum_kernel32::cocoa::metal_texture_width(tex) };
    let h = unsafe { quantum_kernel32::cocoa::metal_texture_height(tex) };
    assert_eq!(w, 320);
    assert_eq!(h, 240);
    quantum_kernel32::cocoa::release(tex);
}

#[test]
fn create_buffer_rejects_zero_size() {
    if !quantum_kernel32::cocoa::metal_available() {
        return;
    }
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );
    let create_buffer_addr = unsafe { vtbl_slot(device, CREATE_BUFFER_SLOT) };
    type CreateBuf = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_buf: CreateBuf = unsafe { core::mem::transmute(create_buffer_addr) };

    let desc = D3D11BufferDesc {
        byte_width: 0,
        usage: 0,
        bind_flags: 0,
        cpu_access_flags: 0,
        misc_flags: 0,
        structure_byte_stride: 0,
    };
    let mut buffer: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        create_buf(
            device,
            &desc as *const _ as *const c_void,
            core::ptr::null(),
            &mut buffer,
        )
    };
    assert_ne!(hr, S_OK);
    assert!(buffer.is_null());
}

#[test]
fn create_vertex_shader_rejects_garbage_bytecode() {
    let mut device: *mut c_void = core::ptr::null_mut();
    let mut feature_level: u32 = 0;
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
        &mut feature_level,
        &mut ctx,
    );
    let vs_fn_addr = unsafe { vtbl_slot(device, VS_SLOT) };
    type CreateVS = unsafe extern "C" fn(
        *mut c_void,
        *const c_void,
        usize,
        *mut c_void,
        *mut *mut c_void,
    ) -> i32;
    let create_vs: CreateVS = unsafe { core::mem::transmute(vs_fn_addr) };

    let garbage = b"not a real dxbc blob :)";
    let mut shader: *mut c_void = core::ptr::null_mut();
    let hr = unsafe {
        create_vs(
            device,
            garbage.as_ptr() as *const c_void,
            garbage.len(),
            core::ptr::null_mut(),
            &mut shader,
        )
    };
    assert_ne!(hr, S_OK, "garbage bytecode must not return S_OK");
}
