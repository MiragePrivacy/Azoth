/// Module for stripping EVM bytecode to extract the runtime blob and prepare it for
/// obfuscation.
///
/// This module implements the second step of BOSC preprocessing by isolating the runtime
/// bytecode, recording removal details, preserving library placeholders, and providing
/// utilities for re-mapping and reassembly. It aligns with Wroblewski’s focus on measuring
/// obfuscation potency against the true runtime and BOSC’s gas efficiency considerations.
///
/// # Usage
/// ```rust,ignore
/// let bytes = hex::decode("60016002a165627a7a72").unwrap();
/// let sections = detection::locate_sections(&bytes, &vec![], &DecodeInfo { byte_length: bytes.len(), keccak_hash: [0; 32], source: SourceType::HexString }).unwrap();
/// let (clean_runtime, report) = strip_bytecode(&bytes, &sections).unwrap();
/// let rebuilt = report.reassemble(&clean_runtime).unwrap();
/// assert_eq!(bytes, rebuilt);
/// ```
use crate::detection::{Section, SectionKind};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Represents a runtime section with its original offset and length.
#[derive(Debug, Clone)]
pub struct RuntimeSpan {
    pub offset: usize,
    pub len: usize,
}

/// Represents a removed section with its original data.
#[derive(Debug, Clone)]
pub struct Removed {
    pub offset: usize,
    pub kind: SectionKind,
    pub data: Vec<u8>,
}

/// Report detailing the stripping process and enabling reassembly.
#[derive(Debug)]
pub struct CleanReport {
    /// Layout of runtime spans with their original offsets and lengths.
    pub runtime_layout: Vec<RuntimeSpan>,
    /// List of removed sections with their original data.
    pub removed: Vec<Removed>,
    /// Optional Keccak-256 hash of the original Swarm data (if Auxdata provides it).
    pub swarm_hash: Option<[u8; 32]>,
    /// Number of bytes saved by removing non-runtime sections.
    pub bytes_saved: usize,
    /// Length of the cleaned runtime bytecode.
    pub clean_len: usize,
    /// Keccak-256 hash of the cleaned runtime bytecode.
    pub clean_keccak: [u8; 32],
    /// Mapping of old PCs to new PCs after stripping.
    pub pc_map: Vec<(usize, usize)>,
}

/// Custom error type for stripping operations.
#[derive(Debug, Error)]
pub enum StripError {
    #[error("section out of bounds at offset {0}")]
    OutOfBounds(usize),
    #[error("invalid section configuration")]
    InvalidConfig,
    #[error("no runtime found")]
    NoRuntimeFound,
}

/// Strips the bytecode to extract the runtime blob and generates a report.
///
/// # Arguments
/// * `bytes` - Raw bytecode bytes.
/// * `sections` - Detected sections from `detection.rs`.
///
/// # Returns
/// A tuple of (cleaned runtime bytecode, CleanReport), or an error if stripping fails.
pub fn strip_bytecode(
    bytes: &[u8],
    sections: &[Section],
) -> Result<(Vec<u8>, CleanReport), StripError> {
    let mut runtime_spans = Vec::new();
    let mut removed = Vec::new();
    let mut pc_map = Vec::new();
    let mut old_pc = 0;
    let mut new_pc = 0;

    // Collect runtime spans and removed sections in one pass
    for section in sections {
        match section.kind {
            SectionKind::Runtime => runtime_spans.push((section.offset, section.len)),
            _ => {
                if section.offset + section.len > bytes.len() {
                    return Err(StripError::OutOfBounds(section.offset));
                }
                removed.push(Removed {
                    offset: section.offset,
                    kind: section.kind,
                    data: bytes[section.offset..section.offset + section.len].to_vec(),
                });
            }
        }
    }

    // Validate and sort runtime spans
    if runtime_spans.is_empty() {
        return Err(StripError::NoRuntimeFound);
    }
    runtime_spans.sort_unstable_by_key(|&(o, _)| o);

    // Convert runtime spans to layout
    let runtime_layout: Vec<_> = runtime_spans
        .iter()
        .map(|&(o, l)| RuntimeSpan { offset: o, len: l })
        .collect();

    // Concatenate runtime bytes in one allocation
    let mut clean_runtime = Vec::with_capacity(runtime_spans.iter().map(|&(_, l)| l).sum());
    let mut prev_end = 0;
    for &(offset, len) in &runtime_spans {
        if prev_end > 0 && offset > prev_end {
            return Err(StripError::InvalidConfig); // Gap between runtime spans
        }
        if offset + len > bytes.len() {
            return Err(StripError::OutOfBounds(offset));
        }
        clean_runtime.extend_from_slice(&bytes[offset..offset + len]);
        // Update PC mapping
        for _i in 0..len {
            if old_pc < bytes.len() {
                pc_map.push((old_pc, new_pc));
                old_pc += 1;
                new_pc += 1;
            }
        }
        prev_end = offset + len;
    }

    // Compute bytes saved and digest
    let bytes_saved = removed.iter().map(|r| r.data.len()).sum();
    let clean_len = clean_runtime.len();
    let mut hasher = Keccak256::new();
    hasher.update(&clean_runtime);
    let clean_keccak = {
        let mut result = [0u8; 32];
        hasher.finalize_into(result.as_mut().into());
        result
    };

    // Compute Swarm hash (placeholder)
    let swarm_hash = None;

    let report = CleanReport {
        runtime_layout,
        removed,
        swarm_hash,
        bytes_saved,
        clean_len,
        clean_keccak,
        pc_map,
    };

    Ok((clean_runtime, report))
}

impl CleanReport {
    /// Reassembles the original bytecode from the cleaned runtime and removal map.
    ///
    /// # Arguments
    /// * `clean` - Cleaned runtime bytecode.
    ///
    /// # Returns
    /// The reassembled original bytecode.
    pub fn reassemble(&self, clean: &[u8]) -> Vec<u8> {
        if self.removed.is_empty()
            && self.runtime_layout.len() == 1
            && self.runtime_layout[0].offset == 0
        {
            return clean.to_vec();
        }
        let mut out = vec![0u8; clean.len() + self.bytes_saved];

        // Cursor into the concatenated runtime blob
        let mut src_idx = 0;

        // Merge runtime and removed slices in offset order
        let mut all_spans: Vec<_> = self
            .runtime_layout
            .iter()
            .map(|r| (r.offset, r.len, true)) // true = runtime
            .chain(self.removed.iter().map(|r| (r.offset, r.data.len(), false))) // false = removed
            .collect();
        all_spans.sort_unstable_by_key(|&(o, _, _)| o);

        for (off, len, is_rt) in all_spans {
            if is_rt {
                out[off..off + len].copy_from_slice(&clean[src_idx..src_idx + len]);
                src_idx += len;
            } else {
                let rem = self.removed.iter().find(|r| r.offset == off).unwrap();
                out[off..off + len].copy_from_slice(&rem.data);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection;

    #[tokio::test]
    async fn test_round_trip() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        // Fixture: Init (6 bytes) + Runtime (2 bytes) + Auxdata (6 bytes)
        let bytecode = hex::decode("600a600e600039600af3deadbeef6001a165627a7a72").unwrap();
        let (instructions, info, _) =
            crate::decoder::decode_bytecode(&format!("0x{}", hex::encode(&bytecode)), false)
                .await
                .unwrap();
        let sections = detection::locate_sections(&bytecode, &instructions, &info).unwrap();

        let (clean_runtime, report) = strip_bytecode(&bytecode, &sections).unwrap();
        let rebuilt = report.reassemble(&clean_runtime);

        assert_eq!(bytecode, rebuilt, "Round-trip failed");
        assert_eq!(report.clean_len, 2, "Clean runtime length mismatch");
        assert_eq!(
            report.bytes_saved,
            bytecode.len() - clean_runtime.len(),
            "Bytes saved mismatch"
        );
    }

    #[tokio::test]
    async fn test_runtime_only() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        // Fixture: Runtime-only bytecode (2 bytes)
        let bytecode = hex::decode("6001").unwrap();
        let (instructions, info, _) =
            crate::decoder::decode_bytecode(&format!("0x{}", hex::encode(&bytecode)), false)
                .await
                .unwrap();
        let sections = detection::locate_sections(&bytecode, &instructions, &info).unwrap();

        let (clean_runtime, report) = strip_bytecode(&bytecode, &sections).unwrap();
        let rebuilt = report.reassemble(&clean_runtime);

        assert_eq!(bytecode, rebuilt, "Round-trip failed");
        assert_eq!(report.clean_len, 2, "Clean runtime length mismatch");
        assert_eq!(report.bytes_saved, 0, "Bytes saved should be 0");
        assert!(report.removed.is_empty(), "Removed should be empty");
    }
}
