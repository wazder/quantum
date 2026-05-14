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
