# Quantum — Overnight Recap (2026-05-13)

Sabah çıkması gereken durum — bu doc'u önce oku, sonra README + docs/.

## Tek satırda

Hand-assembled Win64 PE'ler artık Apple Silicon'da JIT'lenip çalışıyor.
ExitProcess, WriteFile (gerçek stdout I/O), counter loop'lar (Jcc rel),
ve guest stack üzerinde PUSH/POP — hepsi gerçek silikonda doğrulanmış.

## Sayılar

* **12 commit**, hepsi local'de (`a343068` HEAD)
* **84 test**, hepsi green
* **0** üçüncü parti runtime crate (Wine, GPTK, MoltenVK yok; bağımlılık `std` + el yazısı FFI)
* **0** clippy warning (`cargo clippy --workspace --all-targets -- -D warnings`)

## Çalışan E2E senaryoları

Hepsi `cargo test --workspace` ile birlikte koşuyor. Hepsi gerçek
Win64 PE byte buffer'larını sıfırdan inşa ediyor.

| Test | Ne yapıyor |
|------|-----------|
| `e2e_exit_process` | mov ecx, 42; call ExitProcess; ud2 → exit code 42 |
| `e2e_write_then_exit` | WriteFile ile "hello, quantum\n" stdout'a basıyor, sonra ExitProcess(0) |
| `e2e_loop` | 10 kez döngü (jnz rel8), `r8d += 7`, exit code 70 |
| `e2e_push_pop` | mov→push→clobber→pop sıralaması, exit code 7 (gerçek guest stack'te yaşıyor) |

Hepsi gerçek mach_vm regions'larda mapped, base relocation'lar
uygulanmış, IAT slot'ları kernel32 thunk pointer'larıyla doldurulmuş,
JIT MAP_JIT codecache'e install edilmiş, W^X flip ile RX'e geçilmiş,
i-cache invalidate edilmiş, CPU gerçekten çalıştırmış.

## Bileşenler (commit sırasına göre)

1. **Workspace + 7 crate** — `quantum-core`, `quantum-runtime`,
   `quantum-loader`, `quantum-jit`, `quantum-ntdll`, `quantum-kernel32`,
   `quantum-cli`. Cargo workspace, edition 2024, Rust 1.95.

2. **`quantum-runtime`** — Darwin/Mach FFI sıfırdan: `mach_vm_allocate`,
   `mach_vm_protect`, `mmap(MAP_JIT)`, `pthread_jit_write_protect_np`,
   `sys_icache_invalidate`. `MachVmManager`, `CodeCache`,
   `GuestStack`. Hepsi `quantum_core::Error` döndürüyor — host
   syscalls için no `libc` crate, declared inline.

3. **`quantum-loader`** — PE/COFF parser sıfırdan: DOS header, COFF,
   PE32 + PE32+ optional, section table, 16 data directory parser
   (image map, reloc, imports, delay_imports, exports, exception,
   tls, load_config, debug, resources, peb types). `wire_iat` her
   IAT slot'una host thunk pointer'ı yazıyor.

4. **`quantum-jit::decoder`** — x86_64 decoder sıfırdan: tüm legacy
   prefix'ler (LOCK/REP/REPNE/OSIZE/ASIZE + FS/GS), full REX,
   ModRM+SIB+RIP-relative, single-byte primary table'ın
   integer+control-flow alt kümesi, 0F secondary'nin CMOVcc/SETcc/
   Jcc rel32/MOVZX/MOVSX/BSF/BSR/BT*/XADD/CMPXCHG kısmı.

5. **`quantum-jit::emitter`** — AArch64 gerçek assembler sıfırdan.
   Her encoder bit-pattern golden test'ler ile `clang -x assembler
   -target arm64-apple-darwin -c` çıktısına karşı doğrulanmış.
   MOVZ/MOVK/MOVN, ADD/SUB imm + shifted reg, AND/ORR/EOR/ANDS,
   MUL/MADD/UDIV/SDIV, CSEL/CSINC/CSINV/CSNEG, LDR/STR x/w/h/b,
   LDP/STP pre/post/signed, B/BL/B.cond/CBZ/TBZ/BR/BLR/RET, sistem
   (NOP/BRK/ISB/DMB ISH/MRS/MSR NZCV/MRS TPIDR_EL0). Label/fixup
   makinası 26/19/14-bit branch range'leri ile.

6. **`quantum-jit::lifter`** — `Inst` -> AArch64 düşürme. Pinning:
   RAX..R15 -> X0..X15, RSP -> X19, RBP -> X5. Karşılayan op'lar:
   MOV imm/reg/mem (B1/B2/B4/B8), ADD/SUB reg/imm (B4/B8), XOR (zero
   idiom optimize), LEA, CMP, PUSH/POP, RET (host RET'e), CallIndirect
   (IAT load + Win64→AAPCS64 4-arg shuffle + host frame save), NOP,
   INT3, UD2. x86 CF/ARM C polarity inversion `cond_x86_to_a64`'de.

7. **`quantum-jit::block`** — basic-block translator. Pre-pass: tüm
   instruction'ları decode et, her birine bir Label atan. Emit pass:
   her instruction'dan önce label'ını bind, sonra lift; Jcc/JMP rel
   için target RIP'i hesapla ve bloktaki Label'a branch et.
   `translate_with_stack` opsiyonel olarak X19'a guest stack top'u
   yüklüyor.

8. **`quantum-kernel32`** — `ExitProcess` (setjmp/longjmp trap ile
   panic'siz escape — Rust panic JIT frame'inden geçemiyor çünkü
   eh_frame yok). `GetStdHandle`, `WriteFile` (gerçek POSIX write).
   `resolve(dll, name) -> Option<u64>` IAT wirer için.

9. **Codesigning otomatik** — `build/jit.entitlements`,
   `scripts/test-runner.sh`, `.cargo/config.toml`. Her test binary'si
   `Apple Development: tatarhasan09@gmail.com (FD43D54MNN)` ile
   imzalanıyor; identity yoksa ad-hoc fallback. `com.apple.security.cs.
   allow-jit` entitlement MAP_JIT için gerekli.

10. **Belgeler** — `README.md`, `docs/architecture.md`, `docs/jit.md`,
    `docs/loader.md`, `docs/future-work.md`. Her crate ve modül
    docstring'i var.

## "Daha optimize" ipuçları

`docs/future-work.md` sonundaki "Why 'more optimised than Windows' is
plausible" bölümüne bakabilirsin. Kısaca: legacy bring-up yok (DOS,
16-bit, eski API timeline'ları), translator + ABI bridge co-design
edilmiş, Apple Silicon'un per-thread W^X mekanizması mprotect'ten
çok daha ucuz, IAT bridge load→marshal→BLR direct (shim ya da IPC
yok). Real workloads üzerinde benchmark gerçek bir uygulama
çalışınca yapılacak.

## Devam edersen, sırada en mantıklı

`docs/future-work.md`'deki "Near term" listesi öncelik sırasıyla:

1. **Dispatcher** — RET'i host RET değil, dispatcher'a return olarak
   düşür. Bu olunca block-to-block control flow ve gerçek guest
   function call'ları çalışır.
2. **PEB/TEB construction** — `quantum-loader::peb` tipler tanımlı,
   kimse build etmiyor. `gs:[0x60]` okuyabilen guest için lazım.
3. **DLL resolution** — `resolve()` sadece kernel32 biliyor. msvcrt
   ve user32 için minimal entry'ler eklenirse hello-world-class
   C programları çalışır.
4. **Real PE input** — `mingw-w64` Homebrew'dan veya `zig cc -target
   x86_64-windows-gnu` ile gerçek hello.exe üretip yüklersin.

## Hızlı yeniden doğrulama

```sh
cargo test --workspace             # 84 test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git log --oneline | head -15       # 12 commit
```

## Karar verilen iddiaları

* **Dil**: Rust 1.95, edition 2024
* **ISA stratejisi**: kendi x86_64 → AArch64 binary translator'ımız
  (Rosetta 2 değil)
* **Bağımlılık politikası**: `[dependencies]` boş — sadece `std`
  ve el yazısı FFI
* **ExitProcess escape**: setjmp/longjmp (Rust panic değil)
* **Codesigning**: developer identity + JIT entitlement, otomatik
  her test öncesi

Hepsi `docs/architecture.md`'de daha ayrıntılı.
