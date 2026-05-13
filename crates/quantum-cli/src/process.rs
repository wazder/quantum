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
use quantum_kernel32::process::{run_with_exit_trap, take_crash_info};
use quantum_kernel32::resolve;
use std::sync::atomic::{AtomicU64, Ordering};

/// Last guest RIP entered by the dispatcher loop. Updated immediately
/// before each `invoke_block_with_ctx` call so that if the guest faults
/// inside that block we can still surface the source RIP.
static LAST_ENTERED_RIP: AtomicU64 = AtomicU64::new(0);
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
    let trace = std::env::var("QUANTUM_TRACE").is_ok();
    if trace {
        eprintln!("[trace] parsing PE ({} bytes)", bytes.len());
    }
    let pe = PeFile::parse(bytes).map_err(RunError::Parse)?;
    if trace {
        eprintln!(
            "[trace] PE: entry={:#x} base={:#x} sections={}",
            pe.opt.address_of_entry_point,
            pe.opt.image_base,
            pe.coff.number_of_sections,
        );
    }
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).map_err(RunError::Load)?;
    if trace {
        eprintln!(
            "[trace] mapped at {:#x} (size {:#x})",
            image.actual_base,
            image.size_of_image,
        );
    }
    apply_relocations(&mut image).map_err(RunError::Reloc)?;
    let imp = imports::parse(&image).map_err(RunError::Imports)?;
    if trace {
        let mut unresolved = 0;
        for dll in &imp.dlls {
            for entry in &dll.entries {
                let n = match entry {
                    quantum_loader::ImportEntry::Name { name, .. } => name.clone(),
                    quantum_loader::ImportEntry::Ordinal { ordinal, .. } => format!("#{ordinal}"),
                };
                if resolve(&dll.name, &n).is_none() {
                    unresolved += 1;
                }
            }
        }
        eprintln!(
            "[trace] imports: {} DLLs, {} unresolved",
            imp.dlls.len(),
            unresolved,
        );
    }
    imports::wire_iat(&mut image, &imp, resolve).map_err(RunError::WireIat)?;

    let stack = GuestStack::default_size().map_err(RunError::Stack)?;
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.entry_rsp(STOP_SENTINEL);

    let mut disp = Dispatcher::new(1024 * 1024).map_err(RunError::Dispatcher)?;
    let entry_va = image.actual_base + image.entry_rva as u64;
    if trace {
        eprintln!("[trace] entering JIT at {entry_va:#x}");
    }

    let exit_code = run_with_exit_trap(|| {
        if let Err(e) = run_dispatcher_loop(&mut disp, &image, &mut ctx, entry_va) {
            eprintln!("[trace] dispatcher: {e}");
        }
    });

    if trace {
        if let Some(crash) = take_crash_info() {
            eprintln!(
                "[trace] FATAL signal {}: fault_addr={:#x}, host_pc={:#x}, last_guest_rip={:#x}",
                crash.sig,
                crash.fault_addr,
                crash.host_pc,
                LAST_ENTERED_RIP.load(Ordering::SeqCst),
            );
        }
        eprintln!("[trace] exited; code={exit_code:#x}");
    }
    Ok(exit_code)
}

fn run_dispatcher_loop(
    disp: &mut Dispatcher,
    image: &LoadedImage,
    ctx: &mut GuestContext,
    start_rip: u64,
) -> Result<(), RunError> {
    let trace = std::env::var("QUANTUM_TRACE_BLOCKS").is_ok();
    let mut current_rip = start_rip;
    let mut iters = 0;
    loop {
        iters += 1;
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
            // Grow the decode window — Sekiro's DRM has long basic blocks.
            let window = 256usize;
            let bytes: Vec<u8> = image
                .rva_to_slice(rva, window.min(image.len() - rva as usize))
                .ok_or_else(|| RunError::Translate(format!("RVA {rva:#x} oob")))?
                .to_vec();
            if trace {
                eprintln!(
                    "[block] translating @ {current_rip:#x} (rva {rva:#x}, first bytes: {:02x?})",
                    &bytes[..32.min(bytes.len())]
                );
            }
            let block = block::translate_for_dispatcher(&bytes, current_rip, None)
                .map_err(|e| RunError::Translate(format!("at {current_rip:#x}: {e:?}")))?;
            disp.install(current_rip, &block.host_bytes)
                .map_err(RunError::Dispatcher)?
        };

        LAST_ENTERED_RIP.store(current_rip, Ordering::SeqCst);
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
