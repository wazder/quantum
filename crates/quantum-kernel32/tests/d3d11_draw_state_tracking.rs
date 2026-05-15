//! ID3D11DeviceContext state setters now record into a process-wide
//! DrawState; Draw / DrawIndexed bump an atomic counter. This test
//! exercises every setter through the vtable, then asserts the
//! snapshot reflects the most recent binding and the draw counter
//! incremented twice.

use core::ffi::c_void;

const VS_SET_SHADER_SLOT: usize = 11;
const PS_SET_SHADER_SLOT: usize = 9;
const IA_SET_INPUT_LAYOUT_SLOT: usize = 17;
const IA_SET_VERTEX_BUFFERS_SLOT: usize = 18;
const IA_SET_INDEX_BUFFER_SLOT: usize = 19;
const IA_SET_PRIMITIVE_TOPOLOGY_SLOT: usize = 24;
const OM_SET_RENDER_TARGETS_SLOT: usize = 33;
const RS_SET_VIEWPORTS_SLOT: usize = 44;
const DRAW_SLOT: usize = 13;
const DRAW_INDEXED_SLOT: usize = 12;

unsafe fn vtbl_slot(obj: *mut c_void, slot: usize) -> usize {
    let vtbl: *const *const usize = obj as *const *const usize;
    let table = unsafe { *vtbl };
    unsafe { *table.add(slot) }
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

#[test]
fn setters_update_draw_state_and_draw_counter_increments() {
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

    // Make-up handles. They aren't real ID3D11* pointers in this test
    // (state tracking just stores them as opaque usize), so anything
    // non-zero works.
    let vs: usize = 0x1111_0000_AAAA_0001;
    let ps: usize = 0x1111_0000_BBBB_0002;
    let il: usize = 0x1111_0000_CCCC_0003;
    let vb: usize = 0x1111_0000_DDDD_0004;
    let ib: usize = 0x1111_0000_EEEE_0005;

    // VSSetShader(ctx, vs, NULL, 0)
    let f = unsafe { vtbl_slot(ctx, VS_SET_SHADER_SLOT) };
    type SetShader = unsafe extern "C" fn(*mut c_void, usize, *mut c_void, u32);
    let set_vs: SetShader = unsafe { core::mem::transmute(f) };
    unsafe { set_vs(ctx, vs, core::ptr::null_mut(), 0) };
    let set_ps: SetShader =
        unsafe { core::mem::transmute(vtbl_slot(ctx, PS_SET_SHADER_SLOT)) };
    unsafe { set_ps(ctx, ps, core::ptr::null_mut(), 0) };

    // IASetInputLayout(ctx, il)
    type SetIL = unsafe extern "C" fn(*mut c_void, usize);
    let set_il: SetIL = unsafe { core::mem::transmute(vtbl_slot(ctx, IA_SET_INPUT_LAYOUT_SLOT)) };
    unsafe { set_il(ctx, il) };

    // IASetVertexBuffers(ctx, 0, 1, &vb, &stride, &offset)
    type SetVB = unsafe extern "C" fn(
        *mut c_void,
        u32,
        u32,
        *const usize,
        *const u32,
        *const u32,
    );
    let set_vb: SetVB = unsafe { core::mem::transmute(vtbl_slot(ctx, IA_SET_VERTEX_BUFFERS_SLOT)) };
    let stride: u32 = 32;
    let offset: u32 = 0;
    unsafe { set_vb(ctx, 0, 1, &vb, &stride, &offset) };

    // IASetIndexBuffer(ctx, ib, format=DXGI_FORMAT_R32_UINT, offset=0)
    type SetIB = unsafe extern "C" fn(*mut c_void, usize, u32, u32);
    let set_ib: SetIB = unsafe { core::mem::transmute(vtbl_slot(ctx, IA_SET_INDEX_BUFFER_SLOT)) };
    unsafe { set_ib(ctx, ib, 42, 0) };

    // IASetPrimitiveTopology(ctx, TRIANGLELIST=4)
    type SetTopo = unsafe extern "C" fn(*mut c_void, u32);
    let set_topo: SetTopo =
        unsafe { core::mem::transmute(vtbl_slot(ctx, IA_SET_PRIMITIVE_TOPOLOGY_SLOT)) };
    unsafe { set_topo(ctx, 4) };

    // RSSetViewports(ctx, 1, &vp)
    let vp = D3D11Viewport {
        top_left_x: 0.0,
        top_left_y: 0.0,
        width: 1920.0,
        height: 1080.0,
        min_depth: 0.0,
        max_depth: 1.0,
    };
    type SetVP = unsafe extern "C" fn(*mut c_void, u32, *const c_void);
    let set_vp: SetVP = unsafe { core::mem::transmute(vtbl_slot(ctx, RS_SET_VIEWPORTS_SLOT)) };
    unsafe { set_vp(ctx, 1, &vp as *const _ as *const c_void) };

    // OMSetRenderTargets(ctx, 0, NULL, NULL) — clears the binding
    // (no RT in this minimal test; we pass num=0 so no
    // ResourceView dereference happens).
    type OmSet = unsafe extern "C" fn(*mut c_void, u32, *const *mut c_void, *mut c_void);
    let om_set: OmSet = unsafe { core::mem::transmute(vtbl_slot(ctx, OM_SET_RENDER_TARGETS_SLOT)) };
    unsafe { om_set(ctx, 0, core::ptr::null(), core::ptr::null_mut()) };

    // Capture the baseline draw count, fire two draws, snapshot state.
    let baseline = quantum_kernel32::d3d11::draw_count();

    type Draw = unsafe extern "C" fn(*mut c_void, u32, u32);
    let draw: Draw = unsafe { core::mem::transmute(vtbl_slot(ctx, DRAW_SLOT)) };
    unsafe { draw(ctx, 3, 0) };

    type DrawIdx = unsafe extern "C" fn(*mut c_void, u32, u32, i32);
    let draw_idx: DrawIdx = unsafe { core::mem::transmute(vtbl_slot(ctx, DRAW_INDEXED_SLOT)) };
    unsafe { draw_idx(ctx, 6, 0, 0) };

    // Verify state.
    let state = quantum_kernel32::d3d11::snapshot_draw_state();
    assert_eq!(state.vs_shader, vs);
    assert_eq!(state.ps_shader, ps);
    assert_eq!(state.input_layout, il);
    assert_eq!(state.vertex_buffer, vb);
    assert_eq!(state.vertex_stride, stride);
    assert_eq!(state.index_buffer, ib);
    assert_eq!(state.index_format, 42);
    assert_eq!(state.primitive_topology, 4);
    assert_eq!(state.viewport_w, 1920.0);
    assert_eq!(state.viewport_h, 1080.0);

    let after = quantum_kernel32::d3d11::draw_count();
    assert_eq!(after - baseline, 2, "two Draw* calls must increment counter");
}
