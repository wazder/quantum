//! Whole-process orchestration: take a PE byte buffer (typically read
//! from disk), load it, wire its IAT to the kernel32 thunk table,
//! then drive the dispatcher loop until `ExitProcess` fires.
//!
//! This is the production path the `quantum run <file.exe>` command
//! takes; the test crates that built bespoke drivers will move over
//! to it once they have nothing exotic to express.

use core::ptr::NonNull;

use quantum_core::Error as CoreError;
use quantum_jit::block;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{LoadedImage, PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, GuestStack, MachVmManager, STOP_SENTINEL, invoke_block_with_ctx,
};

/// Reasons a quantum run can fail before guest code ever executes.
#[derive(Debug)]
pub enum RunError {
    Parse(CoreError),
    Load(CoreError),
    Reloc(CoreError),
    Imports(CoreError),
    WireIat(CoreError),
    Stack(CoreError),
    Dispatcher(CoreError),
    Translate(String),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "PE parse failed: {e}"),
            Self::Load(e) => write!(f, "image map failed: {e}"),
            Self::Reloc(e) => write!(f, "relocations failed: {e}"),
            Self::Imports(e) => write!(f, "import parse failed: {e}"),
            Self::WireIat(e) => write!(f, "IAT wiring failed: {e}"),
            Self::Stack(e) => write!(f, "guest stack alloc failed: {e}"),
            Self::Dispatcher(e) => write!(f, "dispatcher init failed: {e}"),
            Self::Translate(msg) => write!(f, "translation failed: {msg}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Run a guest PE from in-memory bytes. Returns the exit code the
/// guest passed to `ExitProcess`, or `u32::MAX` if the guest returned
/// without calling it.
pub fn run_pe(bytes: &[u8]) -> Result<u32, RunError> {
    let pe = PeFile::parse(bytes).map_err(RunError::Parse)?;
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).map_err(RunError::Load)?;
    apply_relocations(&mut image).map_err(RunError::Reloc)?;
    let imp = imports::parse(&image).map_err(RunError::Imports)?;
    imports::wire_iat(&mut image, &imp, resolve).map_err(RunError::WireIat)?;

    let stack = GuestStack::default_size().map_err(RunError::Stack)?;
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top();

    let mut disp = Dispatcher::new(1024 * 1024).map_err(RunError::Dispatcher)?;
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        let _ = run_dispatcher_loop(&mut disp, &image, &mut ctx, entry_va);
    });

    Ok(exit_code)
}

fn run_dispatcher_loop(
    disp: &mut Dispatcher,
    image: &LoadedImage,
    ctx: &mut GuestContext,
    start_rip: u64,
) -> Result<(), RunError> {
    let mut current_rip = start_rip;
    let mut iters = 0;
    loop {
        iters += 1;
        // 10M iterations is an upper bound for tonight; real game loops can
        // easily exceed that — replace with chained blocks (Phase 1.4) to
        // avoid the round-trip per block.
        if iters > 10_000_000 {
            return Err(RunError::Translate("dispatcher loop limit reached".into()));
        }

        let ptr: NonNull<u8> = if let Some(p) = disp.lookup(current_rip) {
            p
        } else {
            let rva = match current_rip.checked_sub(image.actual_base) {
                Some(off) if (off as usize) < image.len() => off as u32,
                _ => {
                    return Err(RunError::Translate(format!(
                        "guest RIP {current_rip:#x} outside image"
                    )));
                }
            };
            // 64 bytes is enough for any single basic block; the
            // translator walks until the first terminator.
            let bytes: Vec<u8> = image
                .rva_to_slice(rva, 64)
                .ok_or_else(|| RunError::Translate(format!("RVA {rva:#x} oob")))?
                .to_vec();
            let block = block::translate_for_dispatcher(&bytes, current_rip, None)
                .map_err(|e| RunError::Translate(format!("{e:?}")))?;
            disp.install(current_rip, &block.host_bytes)
                .map_err(RunError::Dispatcher)?
        };

        // SAFETY: block respects the dispatcher prologue/epilogue
        // contract — reads ctx for guest regs, runs, spills back, RETs
        // with next_rip in X0.
        let next_rip = unsafe { invoke_block_with_ctx(ptr, ctx) };
        if next_rip == STOP_SENTINEL {
            return Ok(());
        }
        current_rip = next_rip;
    }
}
