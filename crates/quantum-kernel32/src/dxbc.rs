//! DXBC (Direct3D shader bytecode) parser scaffold.
//!
//! Reads the container layout — header, chunk table, per-chunk fourcc
//! plus payload — so the eventual DXBC → MSL transpiler can navigate
//! to the chunks it needs: `SHEX`/`SHDR` (instruction stream),
//! `RDEF` (resource bindings), `ISGN`/`OSGN` (I/O signatures),
//! `STAT` (diagnostic counters).
//!
//! No third-party DXBC code is consulted; layout reconstructed from
//! Microsoft's public DXIL / FXC documentation plus by-hand round-trips
//! of `fxc.exe` output. The format has been stable since DX10.
//!
//! Container layout (little-endian throughout):
//!
//!   offset  size       field
//!   0x00    4          magic           = "DXBC"
//!   0x04    16         hash            (MD5 of the rest)
//!   0x14    4          one             (always 1)
//!   0x18    4          total_size      (bytes, including header)
//!   0x1C    4          chunk_count
//!   0x20    chunk_count*4   chunk_offsets[chunk_count]
//!   chunk_offsets[i]:  4    fourcc
//!                       4    chunk_size  (payload, excludes 8-byte hdr)
//!                       chunk_size  payload

#![allow(clippy::not_unsafe_ptr_arg_deref)]

/// Errors surfaced while parsing a DXBC container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DxbcError {
    /// Buffer too small to even hold the fixed header.
    TooShort,
    /// First four bytes aren't `"DXBC"`.
    BadMagic,
    /// Header's `one` field isn't 1 — file is from a different format
    /// (DXIL?) or corrupt.
    BadVersion,
    /// `total_size` doesn't match the buffer length.
    SizeMismatch,
    /// A chunk header / offset / size walks past the end of the buffer.
    ChunkOob {
        idx: usize,
        offset: u32,
        size: u32,
    },
    /// Chunk count claims more entries than the buffer can hold.
    TooManyChunks(u32),
}

/// One chunk inside the container. We keep raw offsets + sizes plus
/// the fourcc as `[u8; 4]` so callers can compare with byte literals
/// (`b"SHEX"`, `b"RDEF"`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub fourcc: [u8; 4],
    /// Byte offset within the container where the payload starts
    /// (after the 8-byte chunk header).
    pub payload_offset: usize,
    pub payload_size: usize,
}

impl Chunk {
    /// Slice the payload bytes out of the original container buffer.
    pub fn payload<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.payload_offset..self.payload_offset + self.payload_size]
    }
}

/// Parsed DXBC container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub total_size: usize,
    pub chunks: Vec<Chunk>,
}

impl Container {
    /// Find the first chunk with the given fourcc, if any. DXBC
    /// shouldn't contain duplicates of the well-known chunks so a
    /// "first match" lookup is sufficient.
    pub fn find(&self, fourcc: &[u8; 4]) -> Option<&Chunk> {
        self.chunks.iter().find(|c| c.fourcc == *fourcc)
    }

    /// Convenience: the SHEX (DX11) or SHDR (DX10) instruction stream
    /// chunk — whichever the container holds.
    pub fn instructions_chunk(&self) -> Option<&Chunk> {
        self.find(b"SHEX").or_else(|| self.find(b"SHDR"))
    }
}

const HEADER_FIXED_LEN: usize = 0x20;

/// Parse a DXBC container in place. Returns the chunk table; payload
/// bytes are read on demand via `Chunk::payload`.
pub fn parse(bytes: &[u8]) -> Result<Container, DxbcError> {
    if bytes.len() < HEADER_FIXED_LEN {
        return Err(DxbcError::TooShort);
    }
    if &bytes[0..4] != b"DXBC" {
        return Err(DxbcError::BadMagic);
    }
    let one = u32::from_le_bytes(bytes[0x14..0x18].try_into().unwrap());
    if one != 1 {
        return Err(DxbcError::BadVersion);
    }
    let total_size = u32::from_le_bytes(bytes[0x18..0x1C].try_into().unwrap()) as usize;
    if total_size != bytes.len() {
        return Err(DxbcError::SizeMismatch);
    }
    let chunk_count = u32::from_le_bytes(bytes[0x1C..0x20].try_into().unwrap());
    let chunks_table_end = HEADER_FIXED_LEN
        .checked_add(chunk_count as usize * 4)
        .ok_or(DxbcError::TooManyChunks(chunk_count))?;
    if chunks_table_end > bytes.len() {
        return Err(DxbcError::TooManyChunks(chunk_count));
    }

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for i in 0..chunk_count as usize {
        let entry_off = HEADER_FIXED_LEN + i * 4;
        let chunk_off =
            u32::from_le_bytes(bytes[entry_off..entry_off + 4].try_into().unwrap()) as usize;
        // Each chunk needs at least an 8-byte header.
        if chunk_off + 8 > bytes.len() {
            return Err(DxbcError::ChunkOob {
                idx: i,
                offset: chunk_off as u32,
                size: 0,
            });
        }
        let mut fourcc = [0u8; 4];
        fourcc.copy_from_slice(&bytes[chunk_off..chunk_off + 4]);
        let payload_size =
            u32::from_le_bytes(bytes[chunk_off + 4..chunk_off + 8].try_into().unwrap()) as usize;
        let payload_offset = chunk_off + 8;
        if payload_offset + payload_size > bytes.len() {
            return Err(DxbcError::ChunkOob {
                idx: i,
                offset: chunk_off as u32,
                size: payload_size as u32,
            });
        }
        chunks.push(Chunk {
            fourcc,
            payload_offset,
            payload_size,
        });
    }

    Ok(Container { total_size, chunks })
}

// ---------- Instruction stream decoder ----------
//
// A SHEX / SHDR payload starts with a 2-token program header:
//
//   word 0: version_token
//     bits 0..3   minor version
//     bits 4..7   major version (4 or 5)
//     bits 16..31 program type (0=PS, 1=VS, 2=GS, 3=HS, 4=DS, 5=CS)
//   word 1: total_token_count (including this header)
//
// After the header is a stream of variable-length instructions. Each
// instruction header token:
//   bits 0..10   opcode
//   bits 11..23  opcode-specific control bits
//   bits 24..30  instruction length in 32-bit tokens (header included)
//   bit 31       extended (next token is an extended-opcode token)

/// Program type encoded in the version token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    Pixel,
    Vertex,
    Geometry,
    Hull,
    Domain,
    Compute,
    Unknown(u16),
}

impl ProgramType {
    fn from_word(w: u16) -> Self {
        match w {
            0 => Self::Pixel,
            1 => Self::Vertex,
            2 => Self::Geometry,
            3 => Self::Hull,
            4 => Self::Domain,
            5 => Self::Compute,
            other => Self::Unknown(other),
        }
    }
}

/// Header of a SHEX payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaderProgramHeader {
    pub major: u8,
    pub minor: u8,
    pub program_type: ProgramType,
    /// Total number of 32-bit tokens in the shader, header included.
    pub total_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    HeaderTooShort,
    LengthMismatch { declared: u32, actual: usize },
    InstructionOob { word_offset: usize, length: u32 },
    ZeroLengthOpcode { word_offset: usize },
}

/// One decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction<'a> {
    pub opcode: u16,
    pub control: u16,
    pub extended: bool,
    pub tokens: &'a [u32],
}

/// Parse the 2-token SHEX/SHDR header.
pub fn parse_program_header(tokens: &[u32]) -> Result<ShaderProgramHeader, DecodeError> {
    if tokens.len() < 2 {
        return Err(DecodeError::HeaderTooShort);
    }
    let vt = tokens[0];
    let minor = (vt & 0x0F) as u8;
    let major = ((vt >> 4) & 0x0F) as u8;
    let prog = ((vt >> 16) & 0xFFFF) as u16;
    let total_tokens = tokens[1];
    if (total_tokens as usize) != tokens.len() {
        return Err(DecodeError::LengthMismatch {
            declared: total_tokens,
            actual: tokens.len(),
        });
    }
    Ok(ShaderProgramHeader {
        major,
        minor,
        program_type: ProgramType::from_word(prog),
        total_tokens,
    })
}

/// Iterator over instructions in a SHEX/SHDR token stream.
pub struct InstructionIter<'a> {
    body: &'a [u32],
    cursor: usize,
}

impl<'a> InstructionIter<'a> {
    /// Build the iterator from the full token stream — we skip the
    /// 2-token program header automatically.
    pub fn new(tokens: &'a [u32]) -> Self {
        let cursor = tokens.len().min(2);
        Self {
            body: tokens,
            cursor,
        }
    }

    /// Convert raw chunk bytes into a `Vec<u32>` (DXBC stores tokens
    /// little-endian). Returns None when the byte length isn't a
    /// multiple of 4.
    pub fn from_payload_bytes(bytes: &[u8]) -> Option<Vec<u32>> {
        if bytes.len() & 3 != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            out.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
        Some(out)
    }
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = Result<Instruction<'a>, DecodeError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.body.len() {
            return None;
        }
        let pos = self.cursor;
        let header = self.body[pos];
        let opcode = (header & 0x07FF) as u16;
        let control = ((header >> 11) & 0x1FFF) as u16;
        let length = (header >> 24) & 0x7F;
        let extended = (header & 0x8000_0000) != 0;
        if length == 0 {
            return Some(Err(DecodeError::ZeroLengthOpcode { word_offset: pos }));
        }
        let end = pos.checked_add(length as usize);
        match end {
            Some(e) if e <= self.body.len() => {
                let tokens = &self.body[pos..e];
                self.cursor = e;
                Some(Ok(Instruction {
                    opcode,
                    control,
                    extended,
                    tokens,
                }))
            }
            _ => Some(Err(DecodeError::InstructionOob {
                word_offset: pos,
                length,
            })),
        }
    }
}

/// A subset of D3D10/11 opcodes from `<d3d10_shader.h>`.
pub mod opcode {
    pub const ADD: u16 = 0x00;
    pub const AND: u16 = 0x01;
    pub const BREAK: u16 = 0x02;
    pub const BREAKC: u16 = 0x03;
    pub const DERIV_RTX: u16 = 0x0B;
    pub const DERIV_RTY: u16 = 0x0C;
    pub const DISCARD: u16 = 0x0D;
    pub const DIV: u16 = 0x0E;
    pub const DP2: u16 = 0x0F;
    pub const DP3: u16 = 0x10;
    pub const DP4: u16 = 0x11;
    pub const ELSE: u16 = 0x12;
    pub const ENDIF: u16 = 0x15;
    pub const ENDLOOP: u16 = 0x16;
    pub const EQ: u16 = 0x18;
    pub const EXP: u16 = 0x19;
    pub const FRC: u16 = 0x1A;
    pub const FTOI: u16 = 0x1B;
    pub const FTOU: u16 = 0x1C;
    pub const GE: u16 = 0x1D;
    pub const IADD: u16 = 0x1E;
    pub const IF: u16 = 0x1F;
    pub const IEQ: u16 = 0x20;
    pub const IGE: u16 = 0x21;
    pub const ILT: u16 = 0x22;
    pub const IMUL: u16 = 0x26;
    pub const INE: u16 = 0x27;
    pub const INEG: u16 = 0x28;
    pub const ISHL: u16 = 0x29;
    pub const ISHR: u16 = 0x2A;
    pub const ITOF: u16 = 0x2B;
    pub const LOG: u16 = 0x2F;
    pub const LOOP: u16 = 0x30;
    pub const LT: u16 = 0x31;
    pub const MAD: u16 = 0x32;
    pub const MIN: u16 = 0x33;
    pub const MAX: u16 = 0x34;
    pub const MOV: u16 = 0x36;
    pub const MOVC: u16 = 0x37;
    pub const MUL: u16 = 0x38;
    pub const NE: u16 = 0x39;
    pub const NOP: u16 = 0x3A;
    pub const NOT: u16 = 0x3B;
    pub const OR: u16 = 0x3C;
    pub const RESINFO: u16 = 0x3D;
    pub const RET: u16 = 0x3E;
    pub const RETC: u16 = 0x3F;
    pub const ROUND_NE: u16 = 0x40;
    pub const ROUND_NI: u16 = 0x41;
    pub const ROUND_PI: u16 = 0x42;
    pub const ROUND_Z: u16 = 0x43;
    pub const RSQ: u16 = 0x44;
    pub const SAMPLE: u16 = 0x45;
    pub const SAMPLE_C: u16 = 0x46;
    pub const SAMPLE_L: u16 = 0x48;
    pub const SAMPLE_D: u16 = 0x49;
    pub const SAMPLE_B: u16 = 0x4A;
    pub const SQRT: u16 = 0x4B;
    pub const SWITCH: u16 = 0x4C;
    pub const SINCOS: u16 = 0x4D;
    pub const UDIV: u16 = 0x4E;
    pub const ULT: u16 = 0x4F;
    pub const UGE: u16 = 0x50;
    pub const UMUL: u16 = 0x51;
    pub const USHR: u16 = 0x55;
    pub const UTOF: u16 = 0x56;
    pub const XOR: u16 = 0x57;
    /// Vertex shader output register declaration.
    pub const DCL_OUTPUT: u16 = 0x65;
    /// Pixel shader input register declaration.
    pub const DCL_INPUT_PS: u16 = 0x62;
}

// ---------- Operand decoder ----------
//
// Each operand starts with a 32-bit "operand token":
//   bits 0..1   number of components (0=0, 1=1, 2=4, 3=N)
//   bits 2..3   component selection mode (mask / swizzle / select-1)
//   bits 4..7   component values (mask/swizzle/select index)
//   bits 8..11  operand type (0=temp, 1=input, 2=output, 4=imm32, ...)
//   bits 12..19 index dimension (0=scalar, 1=1D, 2=2D, 3=3D) + per-dim
//               representation (immediate vs relative)
//   bits 20..30 reserved
//   bit  31     extended
//
// We decode the subset we need for vertex / pixel shader MOVs: temp,
// input, output, immediate. Other types (constant buffer, sampler,
// resource, ...) get reported as `OperandType::Unknown(raw)` so the
// emitter can pick them up later without re-walking the bytes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    Temp,
    Input,
    Output,
    IndexableTemp,
    Immediate32,
    ConstantBuffer,
    Sampler,
    Resource,
    NullObject,
    Unknown(u8),
}

impl OperandType {
    fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::Temp,
            1 => Self::Input,
            2 => Self::Output,
            3 => Self::IndexableTemp,
            4 => Self::Immediate32,
            8 => Self::ConstantBuffer,
            6 => Self::Sampler,
            7 => Self::Resource,
            13 => Self::NullObject,
            other => Self::Unknown(other),
        }
    }
}

/// Component selection / masking. A swizzle/mask is four 2-bit
/// values picking among `xyzw` (0..3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentSelect {
    /// All four components present (operand has 0 components — scalar).
    None,
    /// A 4-bit mask of which `xyzw` are written.
    Mask(u8),
    /// A 4-element swizzle (`[xyzw, xyzw, xyzw, xyzw]`).
    Swizzle([u8; 4]),
    /// A single-component select (one of `xyzw`).
    Select1(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operand {
    pub op_type: OperandType,
    pub selection: ComponentSelect,
    /// For Temp/Input/Output/IndexableTemp: the register index. For
    /// Immediate32: the first immediate word. For unknown / extended
    /// forms: 0.
    pub index0: u32,
    /// Immediate operands carry up to four 32-bit lanes (vec4); only
    /// `imm[..imm_len]` is valid.
    pub imm: [u32; 4],
    pub imm_len: u8,
}

/// Pull one operand out of `tokens` starting at `cursor`. Returns the
/// decoded operand and the new cursor position. Returns None when the
/// remaining tokens can't form a complete operand.
pub fn decode_operand(tokens: &[u32], cursor: usize) -> Option<(Operand, usize)> {
    let token = *tokens.get(cursor)?;
    let mut next = cursor + 1;

    let num_comp = (token & 0b11) as u8;
    let sel_mode = ((token >> 2) & 0b11) as u8;
    // Selection / swizzle field is 8 bits (4..11). For mask form only
    // the low 4 bits matter; for swizzle all 8 do.
    let sel_bits = ((token >> 4) & 0xFF) as u8;
    let op_type_raw = ((token >> 12) & 0xFF) as u8;
    let index_dim = ((token >> 20) & 0b11) as u8;
    let extended = (token & 0x8000_0000) != 0;

    // We accept and skip the extended-operand token but don't decode
    // its sub-fields yet.
    if extended {
        let _ext = *tokens.get(next)?;
        next += 1;
    }

    let selection = match (num_comp, sel_mode) {
        (0, _) => ComponentSelect::None,
        (1, _) => ComponentSelect::Select1(sel_bits & 0b11),
        (2, 0) => {
            // Mask form: low 4 bits of sel_bits = write mask.
            ComponentSelect::Mask(sel_bits & 0x0F)
        }
        (2, 1) => {
            // Swizzle form: 8 bits = four 2-bit component indices,
            // lane 0 in bits 4..5, lane 3 in bits 10..11.
            let s = [
                sel_bits & 0b11,
                (sel_bits >> 2) & 0b11,
                (sel_bits >> 4) & 0b11,
                (sel_bits >> 6) & 0b11,
            ];
            ComponentSelect::Swizzle(s)
        }
        (2, 2) => ComponentSelect::Select1(sel_bits & 0b11),
        _ => ComponentSelect::None,
    };

    let op_type = OperandType::from_raw(op_type_raw);

    let mut index0: u32 = 0;
    let mut imm = [0u32; 4];
    let mut imm_len = 0u8;

    if matches!(op_type, OperandType::Immediate32) {
        // imm32 operand: one 32-bit word per component the operand
        // declared (num_comp == 1 → 1 word; num_comp == 2 → 4 words).
        let count = match num_comp {
            1 => 1usize,
            2 => 4usize,
            _ => 0,
        };
        for slot in imm.iter_mut().take(count) {
            *slot = *tokens.get(next)?;
            next += 1;
        }
        imm_len = count as u8;
        index0 = imm[0];
    } else {
        // For temp/input/output etc., index_dim tokens follow. We
        // decode the simplest "1D immediate" form: one word giving the
        // register index. Anything more complex (relative addressing,
        // multi-dim indices) is recorded as 0 for now.
        if index_dim >= 1 {
            index0 = *tokens.get(next)?;
            next += 1;
        }
        // Skip any additional dim tokens we don't decode yet.
        for _ in 1..index_dim as usize {
            next += 1;
            if next > tokens.len() {
                return None;
            }
        }
    }

    Some((
        Operand {
            op_type,
            selection,
            index0,
            imm,
            imm_len,
        },
        next,
    ))
}

// ---------- ISGN / OSGN signature parser ----------
//
// `ISGN` and `OSGN` chunks describe the inputs / outputs each shader
// stage actually consumes / produces. The MSL emitter walks them to
// build `[[stage_in]]` / `[[stage_out]]` structs, pick `[[vertex]]`
// vs `[[fragment]]` function attributes, and route vertex-shader
// outputs into pixel-shader inputs.
//
// Chunk layout (little-endian throughout):
//   u32 element_count
//   u32 reserved        (usually 8 — offset of first element from
//                         the start of the chunk payload)
//   per element (24 bytes):
//     u32 name_offset   (from start of chunk payload)
//     u32 semantic_index
//     u32 system_value  (D3D_NAME_*)
//     u32 component_type (1=UINT32, 2=SINT32, 3=FLOAT32)
//     u32 register
//     u32 mask          (low 4 bits = which components present;
//                         next 4 bits = mask in use by the stage)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    Uint32,
    Sint32,
    Float32,
    Unknown(u32),
}

impl ComponentType {
    fn from_raw(v: u32) -> Self {
        match v {
            1 => Self::Uint32,
            2 => Self::Sint32,
            3 => Self::Float32,
            other => Self::Unknown(other),
        }
    }

    /// Map to a Metal Shading Language base type name (`int`, `uint`,
    /// `float`). Returns `"float"` for unknown — the most permissive
    /// default for unrecognised inputs.
    pub fn metal_base(&self) -> &'static str {
        match self {
            Self::Uint32 => "uint",
            Self::Sint32 => "int",
            Self::Float32 => "float",
            Self::Unknown(_) => "float",
        }
    }
}

/// One element of an ISGN / OSGN chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureElement {
    /// Semantic name (`SV_Position`, `COLOR`, `TEXCOORD`, ...).
    pub semantic_name: String,
    pub semantic_index: u32,
    /// D3D_NAME enum value; 0 = D3D_NAME_UNDEFINED (no system value).
    pub system_value: u32,
    pub component_type: ComponentType,
    pub register: u32,
    /// Low 4 bits are the components present (bit 0 = .x, bit 3 = .w).
    pub mask: u8,
    /// Next 4 bits of the mask DWORD — components actually
    /// read/written by the stage. Typically equals `mask` for VS
    /// outputs and PS inputs that are wired up.
    pub used_mask: u8,
}

/// Parse an ISGN / OSGN chunk payload into a list of signature elements.
pub fn parse_signature(chunk_payload: &[u8]) -> Result<Vec<SignatureElement>, DecodeError> {
    if chunk_payload.len() < 8 {
        return Err(DecodeError::HeaderTooShort);
    }
    let count = u32::from_le_bytes(chunk_payload[0..4].try_into().unwrap()) as usize;
    let elem_start =
        u32::from_le_bytes(chunk_payload[4..8].try_into().unwrap()) as usize;
    let elem_stride = 24usize;
    if elem_start + count * elem_stride > chunk_payload.len() {
        return Err(DecodeError::InstructionOob {
            word_offset: elem_start,
            length: (count * elem_stride) as u32,
        });
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = elem_start + i * elem_stride;
        let read_u32 = |off| u32::from_le_bytes(chunk_payload[base + off..base + off + 4].try_into().unwrap());
        let name_off = read_u32(0) as usize;
        let semantic_index = read_u32(4);
        let system_value = read_u32(8);
        let component_type = ComponentType::from_raw(read_u32(12));
        let register = read_u32(16);
        let mask_dword = read_u32(20);
        let mask = (mask_dword & 0x0F) as u8;
        let used_mask = ((mask_dword >> 8) & 0x0F) as u8;
        // Name strings are NUL-terminated ASCII inside the same chunk
        // payload, starting at `name_off` (an offset relative to the
        // payload).
        let mut name = String::new();
        if name_off < chunk_payload.len() {
            for &b in &chunk_payload[name_off..] {
                if b == 0 {
                    break;
                }
                name.push(b as char);
            }
        }
        out.push(SignatureElement {
            semantic_name: name,
            semantic_index,
            system_value,
            component_type,
            register,
            mask,
            used_mask,
        });
    }
    Ok(out)
}

// ---------- Minimal MSL emitter ----------
//
// Emits Metal Shading Language source for the handful of DXBC opcodes
// we want a real game's simplest shaders to compile through. The full
// transpiler will route every opcode here; for now MOV / ADD / MUL /
// MAD / RET cover passthrough VS and a trivial PS.

/// Render one operand as a Metal Shading Language expression. Only
/// supports the operand classes the emitter actively lowers; anything
/// else returns a `/* TODO */`-prefixed sentinel so callers can spot it
/// in generated source.
fn render_operand(op: &Operand) -> String {
    fn comp_char(c: u8) -> char {
        match c & 0b11 {
            0 => 'x',
            1 => 'y',
            2 => 'z',
            _ => 'w',
        }
    }
    fn select_suffix(s: ComponentSelect) -> String {
        match s {
            ComponentSelect::None => String::new(),
            ComponentSelect::Mask(m) => {
                let mut out = String::from(".");
                for (i, ch) in ['x', 'y', 'z', 'w'].iter().enumerate() {
                    if (m & (1 << i)) != 0 {
                        out.push(*ch);
                    }
                }
                if out == "." { String::new() } else { out }
            }
            ComponentSelect::Swizzle(sw) => {
                let mut out = String::from(".");
                for c in sw {
                    out.push(comp_char(c));
                }
                out
            }
            ComponentSelect::Select1(c) => format!(".{}", comp_char(c)),
        }
    }

    match op.op_type {
        OperandType::Temp => {
            format!("r{}{}", op.index0, select_suffix(op.selection))
        }
        OperandType::Input => format!("v{}{}", op.index0, select_suffix(op.selection)),
        OperandType::Output => format!("o{}{}", op.index0, select_suffix(op.selection)),
        OperandType::Immediate32 => match op.imm_len {
            1 => format!("float(as_type<float>(uint(0x{:08X})))", op.imm[0]),
            4 => format!(
                "float4(as_type<float>(uint(0x{:08X})), as_type<float>(uint(0x{:08X})), as_type<float>(uint(0x{:08X})), as_type<float>(uint(0x{:08X})))",
                op.imm[0], op.imm[1], op.imm[2], op.imm[3]
            ),
            _ => "/* imm-malformed */ 0.0".to_string(),
        },
        OperandType::ConstantBuffer => {
            // `cb<n>[m]` in DXBC notation — n is the constant-buffer
            // slot (set via VSSetConstantBuffers / PSSetConstantBuffers)
            // and m is the dword index inside the buffer. Our minimal
            // operand decoder only captures the first index; a full
            // implementation walks the 2-D index decode and produces
            // a real Metal [[buffer(n)]] access. For now emit a stable
            // reference the transpiler can later substitute.
            format!(
                "cb{}[{}]{}",
                op.index0,
                op.imm[0], // placeholder: real second dim index
                select_suffix(op.selection)
            )
        }
        OperandType::Sampler => format!("s{}{}", op.index0, select_suffix(op.selection)),
        OperandType::Resource => format!("t{}{}", op.index0, select_suffix(op.selection)),
        OperandType::IndexableTemp => {
            format!("x{}{}", op.index0, select_suffix(op.selection))
        }
        OperandType::NullObject => "/* null-object */ 0.0".to_string(),
        OperandType::Unknown(raw) => format!("/* TODO operand Unknown({raw}) */ 0.0"),
    }
}

/// Emit Metal Shading Language for `tokens` (the SHEX/SHDR token
/// stream including its 2-token program header). Returns the MSL
/// source as a `String` or a `DecodeError`.
pub fn emit_msl(tokens: &[u32]) -> Result<String, DecodeError> {
    let hdr = parse_program_header(tokens)?;
    let mut out = String::new();
    out.push_str("// generated by quantum-kernel32::dxbc::emit_msl\n");
    out.push_str(&format!(
        "// shader major={} minor={} type={:?}\n",
        hdr.major, hdr.minor, hdr.program_type
    ));
    out.push_str("#include <metal_stdlib>\nusing namespace metal;\n\n");

    // Emit a *compilable* signature per stage. Real `[[stage_in]]` /
    // `[[stage_out]]` structs from ISGN/OSGN are still a follow-up;
    // until then we use minimal valid prototypes so that even a
    // trivial shader produces a non-null MTLLibrary:
    //   vertex   → returns a struct with a [[position]] field
    //   fragment → returns float4 (the colour)
    //   compute  → kernel void (always valid)
    // The body works on r0..r3 locals; the stage-appropriate value is
    // returned at the end (r0 by convention — most DX shaders leave
    // their output there after the final mov to o0).
    #[derive(PartialEq)]
    enum Stage {
        Vertex,
        Fragment,
        Compute,
    }
    let stage = match hdr.program_type {
        ProgramType::Vertex
        | ProgramType::Geometry
        | ProgramType::Hull
        | ProgramType::Domain => Stage::Vertex,
        ProgramType::Pixel => Stage::Fragment,
        ProgramType::Compute | ProgramType::Unknown(_) => Stage::Compute,
    };
    match stage {
        Stage::Vertex => {
            out.push_str("struct VsOut { float4 pos [[position]]; };\n\n");
            out.push_str("vertex VsOut main_vs() {\n");
        }
        Stage::Fragment => {
            out.push_str("fragment float4 main_ps() {\n");
        }
        Stage::Compute => {
            out.push_str("kernel void main_cs() {\n");
        }
    }
    out.push_str("    float4 r0 = float4(0);\n");
    out.push_str("    float4 r1 = float4(0);\n");
    out.push_str("    float4 r2 = float4(0);\n");
    out.push_str("    float4 r3 = float4(0);\n");

    for inst in InstructionIter::new(tokens) {
        let inst = inst?;
        // Skip the instruction header word (idx 0) and decode operands
        // from idx 1 onward. We accept best-effort failure here so a
        // malformed shader doesn't poison the rest of the emit.
        let body = &inst.tokens[1..];
        let ops = decode_all_operands(body, 2);
        match inst.opcode {
            opcode::MOV if ops.len() == 2 => {
                out.push_str(&format!(
                    "    {} = {};\n",
                    render_operand(&ops[0]),
                    render_operand(&ops[1])
                ));
            }
            opcode::ADD if ops.len() == 3 => {
                out.push_str(&format!(
                    "    {} = {} + {};\n",
                    render_operand(&ops[0]),
                    render_operand(&ops[1]),
                    render_operand(&ops[2])
                ));
            }
            opcode::MUL if ops.len() == 3 => {
                out.push_str(&format!(
                    "    {} = {} * {};\n",
                    render_operand(&ops[0]),
                    render_operand(&ops[1]),
                    render_operand(&ops[2])
                ));
            }
            opcode::MAD if ops.len() == 4 => {
                out.push_str(&format!(
                    "    {} = fma({}, {}, {});\n",
                    render_operand(&ops[0]),
                    render_operand(&ops[1]),
                    render_operand(&ops[2]),
                    render_operand(&ops[3])
                ));
            }
            opcode::RET => {
                // DXBC RET ends the function. We don't honour early
                // returns yet (most shaders RET once at the end);
                // the stage-appropriate return is emitted after the
                // loop so the signature stays valid.
                out.push_str("    // ret\n");
            }
            other => {
                out.push_str(&format!("    // unsupported opcode 0x{other:02X}\n"));
            }
        }
    }
    // Stage-appropriate terminal return so the (typed) signature
    // compiles. r0 holds the shader's last-written output by
    // convention.
    match stage {
        Stage::Vertex => {
            out.push_str("    VsOut _o; _o.pos = r0; return _o;\n");
        }
        Stage::Fragment => {
            out.push_str("    return r0;\n");
        }
        Stage::Compute => {
            // void — nothing to return.
        }
    }
    out.push_str("}\n");
    Ok(out)
}

/// Drain up to `max` operands from `body`. Stops on the first decode
/// failure or when the slice runs out. Returns whatever was parsed.
fn decode_all_operands(body: &[u32], max: usize) -> Vec<Operand> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while out.len() < max {
        match decode_operand(body, cursor) {
            Some((op, next)) => {
                out.push(op);
                cursor = next;
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DXBC container with the requested chunks.
    fn build_container(chunks: &[([u8; 4], &[u8])]) -> Vec<u8> {
        let table_len = chunks.len() * 4;
        let mut data_off = HEADER_FIXED_LEN + table_len;
        let mut chunk_offsets = Vec::with_capacity(chunks.len());
        for (_, payload) in chunks {
            chunk_offsets.push(data_off);
            data_off += 8 + payload.len();
        }
        let total_size = data_off;

        let mut out = Vec::with_capacity(total_size);
        out.extend_from_slice(b"DXBC");
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(total_size as u32).to_le_bytes());
        out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
        for &off in &chunk_offsets {
            out.extend_from_slice(&(off as u32).to_le_bytes());
        }
        for (fcc, payload) in chunks {
            out.extend_from_slice(fcc);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        debug_assert_eq!(out.len(), total_size);
        out
    }

    /// Build an `instr_header_token(opcode, length, control=0)`.
    fn ihdr(opcode: u16, length: u32) -> u32 {
        (opcode as u32 & 0x7FF) | ((length & 0x7F) << 24)
    }

    #[test]
    fn parses_zero_chunk_container() {
        let blob = build_container(&[]);
        let c = parse(&blob).unwrap();
        assert_eq!(c.total_size, blob.len());
        assert!(c.chunks.is_empty());
    }

    #[test]
    fn parses_two_chunk_container_with_lookup() {
        let shex = b"\x40\x00\x01\x00deadbeef";
        let rdef = b"\x10\x20\x30\x40";
        let blob = build_container(&[(*b"SHEX", shex), (*b"RDEF", rdef)]);
        let c = parse(&blob).unwrap();
        assert_eq!(c.chunks.len(), 2);

        let shx = c.find(b"SHEX").unwrap();
        assert_eq!(shx.payload(&blob), shex);

        let rd = c.find(b"RDEF").unwrap();
        assert_eq!(rd.payload(&blob), rdef);

        assert_eq!(c.instructions_chunk().unwrap().payload(&blob), shex);
        assert!(c.find(b"ZZZZ").is_none());
    }

    #[test]
    fn falls_back_to_shdr_when_no_shex() {
        let shdr = b"\x99\x88\x77\x66";
        let blob = build_container(&[(*b"SHDR", shdr)]);
        let c = parse(&blob).unwrap();
        assert_eq!(c.instructions_chunk().unwrap().payload(&blob), shdr);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = build_container(&[]);
        blob[0] = b'X';
        assert_eq!(parse(&blob), Err(DxbcError::BadMagic));
    }

    #[test]
    fn rejects_truncated_buffer() {
        assert_eq!(parse(&[0u8; 16]), Err(DxbcError::TooShort));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut blob = build_container(&[]);
        blob[0x14] = 2;
        assert_eq!(parse(&blob), Err(DxbcError::BadVersion));
    }

    #[test]
    fn rejects_size_mismatch() {
        let mut blob = build_container(&[]);
        let lie = (blob.len() - 1) as u32;
        blob[0x18..0x1C].copy_from_slice(&lie.to_le_bytes());
        assert_eq!(parse(&blob), Err(DxbcError::SizeMismatch));
    }

    #[test]
    fn rejects_chunk_offset_past_end() {
        let blob = build_container(&[(*b"SHEX", b"payload")]);
        let mut bad = blob.clone();
        bad[HEADER_FIXED_LEN..HEADER_FIXED_LEN + 4]
            .copy_from_slice(&((blob.len() + 16) as u32).to_le_bytes());
        match parse(&bad) {
            Err(DxbcError::ChunkOob { idx: 0, .. }) => {}
            other => panic!("expected ChunkOob at idx 0, got {other:?}"),
        }
    }

    #[test]
    fn instruction_iter_walks_a_two_instr_pixel_shader() {
        // PS 4.0, total 6 tokens: 2-token header + MOV(len=2) + RET(len=2).
        let prog_type_ps: u32 = 0;
        let major: u32 = 4;
        let version_token = (major << 4) | (prog_type_ps << 16);
        let total: u32 = 6;
        let mov = ihdr(opcode::MOV, 2);
        let mov_operand: u32 = 0xDEAD_BEEF;
        let ret = ihdr(opcode::RET, 2);
        let ret_operand: u32 = 0;
        let tokens = [version_token, total, mov, mov_operand, ret, ret_operand];

        let hdr = parse_program_header(&tokens).unwrap();
        assert_eq!(hdr.major, 4);
        assert_eq!(hdr.minor, 0);
        assert_eq!(hdr.program_type, ProgramType::Pixel);
        assert_eq!(hdr.total_tokens, 6);

        let mut iter = InstructionIter::new(&tokens);
        let i0 = iter.next().unwrap().unwrap();
        assert_eq!(i0.opcode, opcode::MOV);
        assert_eq!(i0.tokens.len(), 2);
        assert_eq!(i0.tokens[1], mov_operand);
        assert!(!i0.extended);

        let i1 = iter.next().unwrap().unwrap();
        assert_eq!(i1.opcode, opcode::RET);
        assert_eq!(i1.tokens.len(), 2);

        assert!(iter.next().is_none(), "no more instructions");
    }

    #[test]
    fn instruction_iter_flags_zero_length() {
        // Two-token shader where the instruction header has length=0.
        let bad_hdr = opcode::MOV as u32; // length field cleared
        let tokens = [
            (4u32 << 4) | (1u32 << 16),
            3,
            bad_hdr,
        ];
        // Lie about total_tokens so parse_program_header accepts the
        // 3-token buffer for this corner-case test.
        let mut t = tokens.to_vec();
        t[1] = 3;
        let mut iter = InstructionIter::new(&t);
        match iter.next() {
            Some(Err(DecodeError::ZeroLengthOpcode { .. })) => {}
            other => panic!("expected ZeroLengthOpcode, got {other:?}"),
        }
    }

    #[test]
    fn instruction_iter_flags_oob_length() {
        // header claims length=5 but only 1 word follows.
        let oob = (opcode::MOV as u32) | (5u32 << 24);
        let tokens = [(4u32 << 4) | (1u32 << 16), 3, oob];
        let mut iter = InstructionIter::new(&tokens);
        match iter.next() {
            Some(Err(DecodeError::InstructionOob { length: 5, .. })) => {}
            other => panic!("expected InstructionOob, got {other:?}"),
        }
    }

    #[test]
    fn render_constant_buffer_operand_emits_cb_index() {
        let op = Operand {
            op_type: OperandType::ConstantBuffer,
            selection: ComponentSelect::Swizzle([0, 1, 2, 3]),
            index0: 2,
            imm: [5, 0, 0, 0],
            imm_len: 0,
        };
        let s = render_operand(&op);
        assert!(s.contains("cb2["), "expected cb2[…] prefix, got {s}");
        assert!(s.contains(".xyzw"), "expected swizzle suffix");
    }

    #[test]
    fn render_sampler_and_resource_operands() {
        let s = render_operand(&Operand {
            op_type: OperandType::Sampler,
            selection: ComponentSelect::None,
            index0: 1,
            imm: [0; 4],
            imm_len: 0,
        });
        assert_eq!(s, "s1");
        let t = render_operand(&Operand {
            op_type: OperandType::Resource,
            selection: ComponentSelect::Select1(2),
            index0: 3,
            imm: [0; 4],
            imm_len: 0,
        });
        assert_eq!(t, "t3.z");
    }

    #[test]
    fn payload_bytes_round_trip_to_tokens() {
        let words: Vec<u32> = vec![1, 2, 3, 4];
        let mut bytes = Vec::new();
        for w in &words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let parsed = InstructionIter::from_payload_bytes(&bytes).unwrap();
        assert_eq!(parsed, words);

        // Misaligned length is rejected.
        assert!(InstructionIter::from_payload_bytes(&[1, 2, 3]).is_none());
    }

    /// Build an operand token for `r<index>` with a write mask of `wxyz`.
    fn op_temp_mask(_index: u32, mask: u8) -> u32 {
        // num_comp=2 (4-comp), sel_mode=0 (mask), sel_bits=mask
        // op_type=0 (temp), index_dim=1 (1D)
        0b10 | ((mask as u32) << 4) | (1 << 20)
    }

    #[test]
    fn decode_operand_handles_temp_register_with_mask() {
        let op_tok = op_temp_mask(2, 0b1111);
        let index_tok = 2u32;
        let tokens = [op_tok, index_tok];
        let (op, next) = decode_operand(&tokens, 0).unwrap();
        assert_eq!(next, 2);
        assert_eq!(op.op_type, OperandType::Temp);
        assert_eq!(op.index0, 2);
        match op.selection {
            ComponentSelect::Mask(m) => assert_eq!(m, 0b1111),
            other => panic!("expected Mask, got {other:?}"),
        }
    }

    #[test]
    fn decode_operand_handles_imm32_scalar() {
        // num_comp=1 (one component), op_type=4 (Immediate32),
        // index_dim=0 (scalar), one immediate word.
        let op_tok: u32 = 1 | (4 << 12);
        let tokens = [op_tok, 0x4080_0000]; // 4.0f
        let (op, next) = decode_operand(&tokens, 0).unwrap();
        assert_eq!(next, 2);
        assert_eq!(op.op_type, OperandType::Immediate32);
        assert_eq!(op.imm_len, 1);
        assert_eq!(op.imm[0], 0x4080_0000);
    }

    /// Build a temp operand with a 4-bit write mask (destination form).
    fn op_temp_mask_tok(mask: u8) -> u32 {
        0b10 | (((mask & 0x0F) as u32) << 4) | (1 << 20)
    }

    /// Build a temp operand with an 8-bit swizzle (source form). The
    /// swizzle is packed as four 2-bit lanes (little-endian).
    fn op_temp_swizzle_tok(swizzle: u8) -> u32 {
        0b10 | (1u32 << 2) | ((swizzle as u32) << 4) | (1u32 << 20)
    }

    #[test]
    fn decode_operand_handles_source_swizzle() {
        // xyzw = lanes 0,1,2,3 packed = 0b11_10_01_00 = 0xE4.
        let op = op_temp_swizzle_tok(0xE4);
        let (decoded, _) = decode_operand(&[op, 7], 0).unwrap();
        assert_eq!(decoded.index0, 7);
        match decoded.selection {
            ComponentSelect::Swizzle(s) => assert_eq!(s, [0, 1, 2, 3]),
            other => panic!("expected Swizzle, got {other:?}"),
        }
    }

    #[test]
    fn emit_msl_renders_mov_between_temps() {
        // Shader: MOV r0.xyzw, r1.xyzw ; RET
        // Layout (8 tokens):
        //   [0]  version_token (VS 4.0)
        //   [1]  total_tokens = 8
        //   [2]  MOV header (len = 5)
        //   [3]  dst_op = r0.mask(xyzw)
        //   [4]  dst register index = 0
        //   [5]  src_op = r1.swizzle(xyzw)
        //   [6]  src register index = 1
        //   [7]  RET header (len = 1, no operands)
        let prog = (4u32 << 4) | (1u32 << 16);
        let dst = op_temp_mask_tok(0b1111);
        let src = op_temp_swizzle_tok(0xE4);
        let mov_hdr = (opcode::MOV as u32) | (5u32 << 24);
        let ret_hdr = (opcode::RET as u32) | (1u32 << 24);
        let total = 8u32;
        let tokens = [prog, total, mov_hdr, dst, 0, src, 1, ret_hdr];
        let msl = emit_msl(&tokens).unwrap();
        assert!(
            msl.contains("r0.xyzw = r1.xyzw;"),
            "MOV should lower to assignment; got:\n{msl}"
        );
        // VS 4.0 → vertex stage: typed return of a [[position]] struct.
        assert!(msl.contains("VsOut _o; _o.pos = r0; return _o;"), "got:\n{msl}");
    }

    /// Build a hand-crafted ISGN/OSGN chunk payload with the given
    /// elements. Names are concatenated NUL-terminated after the
    /// fixed-size element records.
    fn build_signature_payload(elements: &[(&str, u32, u32, ComponentType, u32, u8, u8)]) -> Vec<u8> {
        let count = elements.len();
        let elem_start = 8u32 + (count as u32 * 24);
        let mut out = Vec::new();
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&8u32.to_le_bytes());
        // Compute name offsets.
        let mut name_offsets: Vec<u32> = Vec::with_capacity(count);
        let mut name_blob: Vec<u8> = Vec::new();
        for (name, _, _, _, _, _, _) in elements {
            name_offsets.push(elem_start + name_blob.len() as u32);
            name_blob.extend_from_slice(name.as_bytes());
            name_blob.push(0);
        }
        for (i, (_, sem_idx, sys_val, comp_ty, reg, mask, used)) in elements.iter().enumerate() {
            out.extend_from_slice(&name_offsets[i].to_le_bytes());
            out.extend_from_slice(&sem_idx.to_le_bytes());
            out.extend_from_slice(&sys_val.to_le_bytes());
            let comp_raw: u32 = match comp_ty {
                ComponentType::Uint32 => 1,
                ComponentType::Sint32 => 2,
                ComponentType::Float32 => 3,
                ComponentType::Unknown(v) => *v,
            };
            out.extend_from_slice(&comp_raw.to_le_bytes());
            out.extend_from_slice(&reg.to_le_bytes());
            let mask_dword: u32 = (*mask as u32) | ((*used as u32) << 8);
            out.extend_from_slice(&mask_dword.to_le_bytes());
        }
        out.extend_from_slice(&name_blob);
        out
    }

    #[test]
    fn parse_signature_decodes_single_position_input() {
        let blob = build_signature_payload(&[(
            "SV_Position",
            0,
            1, // D3D_NAME_POSITION
            ComponentType::Float32,
            0,
            0b1111,
            0b1111,
        )]);
        let sig = parse_signature(&blob).expect("sig parses");
        assert_eq!(sig.len(), 1);
        let e = &sig[0];
        assert_eq!(e.semantic_name, "SV_Position");
        assert_eq!(e.semantic_index, 0);
        assert_eq!(e.system_value, 1);
        assert_eq!(e.component_type, ComponentType::Float32);
        assert_eq!(e.register, 0);
        assert_eq!(e.mask, 0b1111);
        assert_eq!(e.used_mask, 0b1111);
    }

    #[test]
    fn parse_signature_decodes_two_inputs() {
        let blob = build_signature_payload(&[
            ("POSITION", 0, 0, ComponentType::Float32, 0, 0b1111, 0b1111),
            ("COLOR", 0, 0, ComponentType::Float32, 1, 0b1111, 0b1111),
        ]);
        let sig = parse_signature(&blob).unwrap();
        assert_eq!(sig.len(), 2);
        assert_eq!(sig[0].semantic_name, "POSITION");
        assert_eq!(sig[1].semantic_name, "COLOR");
        assert_eq!(sig[1].register, 1);
    }

    #[test]
    fn parse_signature_rejects_truncated_blob() {
        // 4 bytes is shorter than the 8-byte header.
        assert!(matches!(
            parse_signature(&[0; 4]),
            Err(DecodeError::HeaderTooShort)
        ));
    }

    #[test]
    fn component_type_maps_to_metal_base() {
        assert_eq!(ComponentType::Uint32.metal_base(), "uint");
        assert_eq!(ComponentType::Sint32.metal_base(), "int");
        assert_eq!(ComponentType::Float32.metal_base(), "float");
        assert_eq!(ComponentType::Unknown(99).metal_base(), "float");
    }

    #[test]
    fn emit_msl_passthrough_ret_only_shader() {
        // PS 4.0, total 4 tokens: 2-token header + RET (len=2).
        let prog_type_ps: u32 = 0;
        let major: u32 = 4;
        let version_token = (major << 4) | (prog_type_ps << 16);
        let total: u32 = 4;
        let ret = (opcode::RET as u32) | (2u32 << 24);
        let tokens = [version_token, total, ret, 0];
        let msl = emit_msl(&tokens).unwrap();
        assert!(msl.contains("metal_stdlib"));
        // PS 4.0 → fragment stage returns float4 (the colour).
        assert!(msl.contains("fragment float4 main_ps"), "got:\n{msl}");
        assert!(msl.contains("return r0;"), "got:\n{msl}");
    }

    #[test]
    fn emitted_msl_compiles_to_a_real_metal_library() {
        // The end-to-end proof: a trivial vertex shader's emitted MSL
        // is now valid enough that Metal actually compiles it into an
        // MTLLibrary. (Pre-this-commit emit_msl produced `vertex void`
        // which Metal rejects.)
        if !crate::cocoa::metal_available() {
            eprintln!("Metal unavailable; skipping");
            return;
        }
        // VS 4.0, 4 tokens: header + RET.
        let prog = (4u32 << 4) | (1u32 << 16); // major=4, type=VS(1)
        let total = 4u32;
        let ret = (opcode::RET as u32) | (2u32 << 24);
        let tokens = [prog, total, ret, 0];
        let msl = emit_msl(&tokens).expect("emit");
        let lib = crate::cocoa::metal_new_library(&msl);
        assert!(
            !lib.is_null(),
            "emitted vertex MSL must compile to a non-null MTLLibrary; \
             source:\n{msl}"
        );
        let f = crate::cocoa::metal_library_function(lib, "main_vs");
        assert!(!f.is_null(), "main_vs must resolve in the library");
        crate::cocoa::release(f);
        crate::cocoa::release(lib);
    }
}
