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
use quantum_kernel32::seh::{
    self, Context as Win64Context, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, ExceptionPointers, ExceptionRecord,
};
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
/// One side DLL loaded alongside the main EXE. We keep the parsed
/// LoadedImage (whose memory backs the module's code/data) plus its
/// ExportTable so the IAT resolver can look up functions in it.
struct SideModule {
    name: String,
    image: LoadedImage,
    exports: quantum_loader::ExportTable,
}

impl SideModule {
    /// Resolve an export by name (or `"#NNN"` ordinal form) into the
    /// absolute host address of the function inside this module.
    /// Returns None if the export isn't found or is a forwarder.
    fn resolve(&self, function: &str) -> Option<u64> {
        if let Some(ord_str) = function.strip_prefix('#') {
            let ord: u32 = ord_str.parse().ok()?;
            let idx = ord.checked_sub(self.exports.ordinal_base)? as usize;
            let entry = self.exports.entries.get(idx)?;
            match &entry.target {
                quantum_loader::ExportTarget::Rva(rva) => {
                    Some(self.image.actual_base + *rva as u64)
                }
                quantum_loader::ExportTarget::Forwarded(_) => None,
            }
        } else {
            let named = self.exports.names.iter().find(|n| n.name == function)?;
            let idx = named.ordinal as usize;
            let entry = self.exports.entries.get(idx)?;
            match &entry.target {
                quantum_loader::ExportTarget::Rva(rva) => {
                    Some(self.image.actual_base + *rva as u64)
                }
                quantum_loader::ExportTarget::Forwarded(_) => None,
            }
        }
    }
}

/// Load and prepare every DLL the main image imports (that we don't
/// already stub) from `dll_dir`. Returns the list of side modules so
/// the caller can route IAT lookups through them.
fn load_side_dlls(
    main: &quantum_loader::ImportTable,
    dll_dir: &std::path::Path,
    mem: &MachVmManager,
    trace: bool,
) -> Vec<SideModule> {
    let mut out: Vec<SideModule> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut work: Vec<String> = main
        .dlls
        .iter()
        .map(|d| d.name.to_ascii_lowercase())
        .collect();

    while let Some(dll_name) = work.pop() {
        if !seen.insert(dll_name.clone()) {
            continue;
        }
        // Skip DLLs we already have a built-in resolver for.
        if has_builtin(&dll_name) {
            continue;
        }
        let path = dll_dir.join(&dll_name);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                if trace {
                    eprintln!("[trace] side-dll: {dll_name} not found at {path:?}");
                }
                continue;
            }
        };
        let pe = match PeFile::parse(&bytes) {
            Ok(p) => p,
            Err(e) => {
                if trace {
                    eprintln!("[trace] side-dll: {dll_name} parse failed: {e}");
                }
                continue;
            }
        };
        let mut image = match load(&pe, mem) {
            Ok(i) => i,
            Err(e) => {
                if trace {
                    eprintln!("[trace] side-dll: {dll_name} map failed: {e}");
                }
                continue;
            }
        };
        if let Err(e) = apply_relocations(&mut image) {
            if trace {
                eprintln!("[trace] side-dll: {dll_name} reloc failed: {e}");
            }
            continue;
        }
        let exports = match quantum_loader::exports::parse(&image) {
            Ok(Some(t)) => t,
            _ => {
                if trace {
                    eprintln!("[trace] side-dll: {dll_name} has no exports");
                }
                continue;
            }
        };
        // Also queue this DLL's own imports for loading.
        if let Ok(sub_imp) = imports::parse(&image) {
            for d in &sub_imp.dlls {
                let lc = d.name.to_ascii_lowercase();
                if !seen.contains(&lc) {
                    work.push(lc);
                }
            }
        }
        if trace {
            eprintln!(
                "[trace] side-dll: loaded {dll_name} @ {:#x} ({} exports)",
                image.actual_base,
                exports.entries.len()
            );
        }
        out.push(SideModule {
            name: dll_name,
            image,
            exports,
        });
    }
    out
}

/// True if `resolve()` in quantum-kernel32 recognises this DLL — i.e.
/// we have a built-in stub set and shouldn't try to side-load it.
fn has_builtin(dll: &str) -> bool {
    matches!(
        dll,
        "kernel32.dll"
            | "kernelbase.dll"
            | "user32.dll"
            | "gdi32.dll"
            | "advapi32.dll"
            | "winmm.dll"
            | "shell32.dll"
            | "ole32.dll"
            | "oleaut32.dll"
            | "imm32.dll"
            | "crypt32.dll"
            | "dinput8.dll"
            | "xinput1_3.dll"
            | "wldap32.dll"
            | "ws2_32.dll"
            | "dxgi.dll"
            | "d3d11.dll"
            | "d3d9.dll"
            | "d3dx11_43.dll"
            | "d3dcompiler_43.dll"
            | "steam_api64.dll"
            | "ntdll.dll"
    )
}

#[allow(dead_code)]
pub fn run_pe(bytes: &[u8]) -> Result<u32, RunError> {
    run_pe_with_dir(bytes, std::env::current_dir().ok().as_deref())
}

/// Variant that takes a directory used to discover bundled side DLLs
/// alongside the main executable.
pub fn run_pe_with_dir(bytes: &[u8], dll_dir: Option<&std::path::Path>) -> Result<u32, RunError> {
    let trace = std::env::var("QUANTUM_TRACE").is_ok();
    if trace {
        eprintln!("[trace] parsing PE ({} bytes)", bytes.len());
    }
    let pe = PeFile::parse(bytes).map_err(RunError::Parse)?;
    if trace {
        eprintln!(
            "[trace] PE: entry={:#x} base={:#x} sections={}",
            pe.opt.address_of_entry_point, pe.opt.image_base, pe.coff.number_of_sections,
        );
    }
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).map_err(RunError::Load)?;
    if trace {
        eprintln!(
            "[trace] mapped at {:#x} (size {:#x})",
            image.actual_base, image.size_of_image,
        );
    }
    apply_relocations(&mut image).map_err(RunError::Reloc)?;
    let imp = imports::parse(&image).map_err(RunError::Imports)?;

    // Discover and load any DLLs the main image imports that we don't
    // have built-in stubs for. fmodex / bink / oo2core etc. live next
    // to the main EXE; we map them into the same VM and tap their
    // exports.
    let side_modules = if let Some(dir) = dll_dir {
        load_side_dlls(&imp, dir, &mem, trace)
    } else {
        Vec::new()
    };

    let resolver = |dll: &str, function: &str| -> Option<u64> {
        if let Some(addr) = resolve(dll, function) {
            return Some(addr);
        }
        // Fall back to side modules (loaded fmodex / bink / etc).
        let lc = dll.to_ascii_lowercase();
        for sm in &side_modules {
            if sm.name == lc
                && let Some(addr) = sm.resolve(function)
            {
                return Some(addr);
            }
        }
        None
    };

    if trace {
        let mut unresolved = 0;
        for dll in &imp.dlls {
            for entry in &dll.entries {
                let n = match entry {
                    quantum_loader::ImportEntry::Name { name, .. } => name.clone(),
                    quantum_loader::ImportEntry::Ordinal { ordinal, .. } => format!("#{ordinal}"),
                };
                if resolver(&dll.name, &n).is_none() {
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
    imports::wire_iat(&mut image, &imp, resolver).map_err(RunError::WireIat)?;

    // Parse .pdata once. Static SEH dispatch (after the vectored
    // handler path fails) walks this to find a handler covering the
    // faulting RIP. 0 entries is fine — caller treats absence as
    // "no handler, propagate".
    let runtime_functions = quantum_loader::exception::parse(&image).map_err(RunError::Imports)?;
    if trace {
        eprintln!(
            "[trace] .pdata: {} RUNTIME_FUNCTION entries",
            runtime_functions.len()
        );
    }

    let stack = GuestStack::default_size().map_err(RunError::Stack)?;
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.entry_rsp(STOP_SENTINEL);

    let mut disp = Dispatcher::new(1024 * 1024).map_err(RunError::Dispatcher)?;
    let entry_va = image.actual_base + image.entry_rva as u64;
    if trace {
        eprintln!("[trace] entering JIT at {entry_va:#x}");
    }

    let mut exit_code = run_with_exit_trap(|| {
        if let Err(e) = run_dispatcher_loop(&mut disp, &image, &mut ctx, entry_va) {
            eprintln!("[trace] dispatcher: {e}");
        }
    });

    // If the guest faulted (sentinel exit code from the crash handler),
    // try dispatching to a registered SEH filter or vectored handler.
    // The dispatcher may loop here several times if a filter returns
    // EXCEPTION_CONTINUE_EXECUTION and execution faults again.
    let mut last_crash: Option<quantum_kernel32::process::CrashInfo> = None;
    let mut seh_attempts = 0;
    while exit_code == 0xFFFF_FFFE && seh_attempts < 16 {
        seh_attempts += 1;
        let crash = match take_crash_info() {
            Some(c) => c,
            None => break,
        };
        last_crash = Some(crash);
        if !dispatch_seh(
            &mut disp,
            &image,
            &mut ctx,
            &crash,
            &runtime_functions,
            trace,
        ) {
            break;
        }
        // A handler returned EXCEPTION_CONTINUE_EXECUTION. Resume the
        // dispatcher loop from the (possibly-mutated) ctx.rip.
        let resume_rip = ctx.rip;
        if trace {
            eprintln!("[trace] SEH resume @ {resume_rip:#x}");
        }
        exit_code = run_with_exit_trap(|| {
            if let Err(e) = run_dispatcher_loop(&mut disp, &image, &mut ctx, resume_rip) {
                eprintln!("[trace] dispatcher: {e}");
            }
        });
    }

    if trace {
        if let Some(crash) = last_crash.or_else(take_crash_info) {
            eprintln!(
                "[trace] FATAL signal {}: fault_addr={:#x}, host_pc={:#x}, last_guest_rip={:#x}",
                crash.sig,
                crash.fault_addr,
                crash.host_pc,
                LAST_ENTERED_RIP.load(Ordering::SeqCst),
            );
            let gprs = crash.to_guest_gprs();
            eprintln!(
                "[trace]   RAX={:#x} RCX={:#x} RDX={:#x} RBX={:#x}",
                gprs[0], gprs[1], gprs[2], gprs[3]
            );
            eprintln!(
                "[trace]   RSP={:#x} RBP={:#x} RSI={:#x} RDI={:#x}",
                gprs[4], gprs[5], gprs[6], gprs[7]
            );
            eprintln!(
                "[trace]   R8 ={:#x} R9 ={:#x} R10={:#x} R11={:#x}",
                gprs[8], gprs[9], gprs[10], gprs[11]
            );
            eprintln!(
                "[trace]   R12={:#x} R13={:#x} R14={:#x} R15={:#x}",
                gprs[12], gprs[13], gprs[14], gprs[15]
            );
        }
        eprintln!("[trace] exited; code={exit_code:#x}");
    }
    Ok(exit_code)
}

/// On a faulted dispatcher exit, walk vectored handlers + the
/// registered unhandled-exception filter. Each handler is called via
/// `invoke_guest_function` with `RCX = &EXCEPTION_POINTERS`. Returns
/// `true` if a handler returned `EXCEPTION_CONTINUE_EXECUTION` (caller
/// should resume); `false` otherwise (caller should propagate the
/// fault).
///
/// The CONTEXT structure is heap-allocated here and a mutable pointer
/// is handed to the guest. If the handler mutates fields (Rip / GPRs)
/// we copy them back into `ctx` so the resumed dispatcher sees the
/// requested state.
fn dispatch_seh(
    disp: &mut Dispatcher,
    image: &LoadedImage,
    ctx: &mut GuestContext,
    crash: &quantum_kernel32::process::CrashInfo,
    runtime_functions: &[quantum_loader::exception::RuntimeFunction],
    trace: bool,
) -> bool {
    let exception_code = match crash.sig {
        5 => EXCEPTION_BREAKPOINT, // SIGTRAP = int3
        11 | 10 => EXCEPTION_ACCESS_VIOLATION,
        4 => 0xC000_001D, // SIGILL -> EXCEPTION_ILLEGAL_INSTRUCTION
        _ => return false,
    };

    let crash_gprs = crash.to_guest_gprs();
    let mut record = Box::new(ExceptionRecord {
        exception_code,
        exception_address: crash.host_pc as *mut _,
        ..ExceptionRecord::default()
    });
    let mut context = Box::new(Win64Context::from_guest_gprs(
        &crash_gprs,
        // For int3 the saved RIP is one past the int3; for SIGSEGV the
        // host PC is the faulting JIT instruction which doesn't map
        // cleanly to a guest RIP. We use last_guest_rip as a best
        // approximation — vectored handlers typically read CONTEXT.Rip
        // to identify the trap site.
        LAST_ENTERED_RIP.load(Ordering::SeqCst),
        ctx.flags,
    ));
    let pointers = Box::new(ExceptionPointers {
        exception_record: &mut *record as *mut _,
        context_record: &mut *context as *mut _,
    });
    let pointers_ptr = &*pointers as *const ExceptionPointers as u64;

    // Refresh ctx GPRs from the trap state so the handler sees the
    // same values it would on real Windows.
    ctx.gprs = crash_gprs;
    ctx.rip = LAST_ENTERED_RIP.load(Ordering::SeqCst);

    // Walk vectored handlers first (Windows calls them before SEH frames).
    for handler in seh::vectored_handlers_snapshot() {
        if trace {
            eprintln!(
                "[trace] SEH: invoking vectored handler @ {:#x}",
                handler.callback
            );
        }
        // Set RCX = &EXCEPTION_POINTERS per Win64 ABI for the handler signature
        //   LONG (*)(EXCEPTION_POINTERS*)
        ctx.gprs[1] = pointers_ptr;
        let disposition = match invoke_guest_function(disp, image, ctx, handler.callback) {
            Ok(rax) => rax as i32,
            Err(e) => {
                if trace {
                    eprintln!("[trace] SEH: vectored handler errored: {e}");
                }
                return false;
            }
        };
        if disposition == EXCEPTION_CONTINUE_EXECUTION {
            if trace {
                eprintln!(
                    "[trace] SEH: vectored handler returned CONTINUE_EXECUTION (new Rip={:#x})",
                    context.rip
                );
            }
            let (rip, flags) = context.into_guest_gprs(&mut ctx.gprs);
            ctx.rip = rip;
            ctx.flags = flags;
            return true;
        }
        if disposition == EXCEPTION_CONTINUE_SEARCH {
            continue; // Try next handler.
        }
        // Any other return is treated as "stop dispatching".
        break;
    }

    // Then the unhandled-exception filter, if any.
    let filter = quantum_kernel32::stubs::registered_unhandled_filter();
    if filter != 0 {
        if trace {
            eprintln!("[trace] SEH: invoking unhandled filter @ {filter:#x}");
        }
        ctx.gprs[1] = pointers_ptr;
        let disposition = match invoke_guest_function(disp, image, ctx, filter) {
            Ok(rax) => rax as i32,
            Err(e) => {
                if trace {
                    eprintln!("[trace] SEH: unhandled filter errored: {e}");
                }
                return false;
            }
        };
        if disposition == EXCEPTION_CONTINUE_EXECUTION {
            if trace {
                eprintln!(
                    "[trace] SEH: unhandled filter returned CONTINUE_EXECUTION (new Rip={:#x})",
                    context.rip
                );
            }
            let (rip, flags) = context.into_guest_gprs(&mut ctx.gprs);
            ctx.rip = rip;
            ctx.flags = flags;
            return true;
        }
    }

    // Static .pdata SEH: find the RUNTIME_FUNCTION covering the
    // faulting RIP, resolve its UNWIND_INFO chain to the handler
    // address, and call it with the full 4-arg Win64 SEH signature:
    //   EXCEPTION_DISPOSITION (*)(EXCEPTION_RECORD*, PVOID, CONTEXT*, PVOID)
    //
    // Disposition values come from <excpt.h> EXCEPTION_DISPOSITION enum:
    //   ExceptionContinueExecution = 0
    //   ExceptionContinueSearch    = 1
    //   ExceptionNestedException   = 2
    //   ExceptionCollidedUnwind    = 3
    let fault_rva = LAST_ENTERED_RIP
        .load(Ordering::SeqCst)
        .saturating_sub(image.actual_base) as u32;
    if let Some(rf) =
        quantum_loader::exception::lookup_runtime_function(runtime_functions, fault_rva)
        && let Ok((ui, _source_rf)) = quantum_loader::exception::resolve_handler(image, rf)
        && let Some(handler_rva) = ui.handler_rva
    {
        let handler_va = image.actual_base + handler_rva as u64;
        if trace {
            eprintln!("[trace] SEH: .pdata handler @ {handler_va:#x} for fault rva {fault_rva:#x}");
        }
        // Win64 ABI: RCX, RDX, R8, R9 = arg0..arg3.
        //   arg0: EXCEPTION_RECORD*
        //   arg1: EstablisherFrame (the RSP at the SEH frame establishment)
        //   arg2: CONTEXT*
        //   arg3: DispatcherContext* (we pass NULL — most C++ EH frames ignore it)
        ctx.gprs[1] = &mut *record as *mut _ as u64;
        ctx.gprs[2] = ctx.gprs[4]; // EstablisherFrame ≈ current RSP
        ctx.gprs[8] = &mut *context as *mut _ as u64;
        ctx.gprs[9] = 0;
        let disposition = match invoke_guest_function(disp, image, ctx, handler_va) {
            Ok(rax) => rax as i32,
            Err(e) => {
                if trace {
                    eprintln!("[trace] SEH: .pdata handler errored: {e}");
                }
                return false;
            }
        };
        if disposition == 0 {
            // ExceptionContinueExecution.
            if trace {
                eprintln!(
                    "[trace] SEH: .pdata handler returned ContinueExecution (new Rip={:#x})",
                    context.rip
                );
            }
            let (rip, flags) = context.into_guest_gprs(&mut ctx.gprs);
            ctx.rip = rip;
            ctx.flags = flags;
            return true;
        }
        // ContinueSearch / NestedException / CollidedUnwind aren't
        // walked further here — a real implementation would unwind
        // and try the next frame's handler. We stop and propagate.
    }

    false
}

/// Run a guest function to completion and return its `rax` value.
///
/// Used by the future SEH dispatcher to invoke a registered exception
/// filter or vectored handler from outside the main dispatcher loop.
/// The caller must have set up `ctx.gprs[1..]` with the function's
/// Win64 arguments (RCX/RDX/R8/R9) before calling. `ctx.gprs[4]` (RSP)
/// is decremented by 8 here and the STOP_SENTINEL is pushed onto the
/// guest stack so the function's RET lands back at the dispatcher
/// exit. After return, RSP is naturally restored by the callee's RET.
pub fn invoke_guest_function(
    disp: &mut Dispatcher,
    image: &LoadedImage,
    ctx: &mut GuestContext,
    fn_rip: u64,
) -> Result<u64, RunError> {
    // Push a fake return address so the callee's RET pops STOP_SENTINEL
    // and exits the dispatcher cleanly.
    ctx.gprs[4] = ctx.gprs[4].wrapping_sub(8);
    // SAFETY: ctx.gprs[4] points into the guest stack which is real
    // host memory we allocated via MachVmManager.
    unsafe {
        *(ctx.gprs[4] as *mut u64) = STOP_SENTINEL;
    }
    run_dispatcher_loop(disp, image, ctx, fn_rip)?;
    Ok(ctx.gprs[0])
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
