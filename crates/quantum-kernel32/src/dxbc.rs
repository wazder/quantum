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
//! Layout (little-endian throughout):
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
//!
//! Chunks come in any order but the offsets in the table are absolute
//! from the start of the container.

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
        let payload_size = u32::from_le_bytes(
            bytes[chunk_off + 4..chunk_off + 8].try_into().unwrap(),
        ) as usize;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DXBC container with the requested chunks.
    /// Each `chunks` entry is `(fourcc, payload_bytes)`.
    fn build_container(chunks: &[([u8; 4], &[u8])]) -> Vec<u8> {
        // Compute the size: fixed header + chunk offset table + each
        // chunk's (8-byte header + payload).
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
        out.extend_from_slice(&[0u8; 16]); // hash (skipped in our parser)
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
        // Pretend the total size is one byte short of reality.
        let lie = (blob.len() - 1) as u32;
        blob[0x18..0x1C].copy_from_slice(&lie.to_le_bytes());
        assert_eq!(parse(&blob), Err(DxbcError::SizeMismatch));
    }

    #[test]
    fn rejects_chunk_offset_past_end() {
        let blob = build_container(&[(*b"SHEX", b"payload")]);
        let mut bad = blob.clone();
        // Stomp the first chunk offset with something past EOF.
        bad[HEADER_FIXED_LEN..HEADER_FIXED_LEN + 4]
            .copy_from_slice(&((blob.len() + 16) as u32).to_le_bytes());
        match parse(&bad) {
            Err(DxbcError::ChunkOob { idx: 0, .. }) => {}
            other => panic!("expected ChunkOob at idx 0, got {other:?}"),
        }
    }
}
