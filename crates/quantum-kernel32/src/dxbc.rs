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
}
