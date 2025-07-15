/// Module for the `obfuscate` subcommand, which applies obfuscation transforms to EVM
/// bytecode.
///
/// This module processes input bytecode, constructs a CFG, applies specified transforms (e.g.,
/// shuffle, jump_transform, opaque-predicates), and outputs the obfuscated bytecode. It also
/// generates a gas and size report if requested.
use async_trait::async_trait;
use azoth_core::{
    cfg_ir::Block,
    decoder::{decode_bytecode, Instruction},
    detection::locate_sections,
    encoder::{encode_with_original, rebuild},
    strip::strip_bytecode,
};
use azoth_transform::{
    pass,
    util::{PassConfig, Transform},
};
use azoth_utils::errors::ObfuscateError;
use clap::Args;
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Arguments for the `obfuscate` subcommand.
#[derive(Args)]
pub struct ObfuscateArgs {
    /// Input bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
    pub input: String,
    /// Random seed for transform application (default: 42).
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Comma-separated list of transforms (default: shuffle,jump_transform,opaque_pred).
    #[arg(long, default_value = "shuffle,jump_transform,opaque_pred")]
    passes: String,
    /// Minimum quality threshold for accepting transforms (default: 0.0).
    #[arg(long, default_value_t = 0.0)]
    accept_threshold: f64,
    /// Maximum allowable size increase as a fraction (default: 0.1).
    #[arg(long, default_value_t = 0.1)]
    max_size_delta: f32,
    /// Path to emit gas/size report as JSON (optional).
    #[arg(long)]
    emit: Option<String>,
}

/// Analyzes instructions to count unknown opcodes and provide feedback.
fn analyze_instructions(instructions: &[Instruction]) -> (usize, usize, Vec<String>) {
    let total_count = instructions.len();
    let mut unknown_count = 0;
    let mut unknown_types = HashSet::new();

    for instr in instructions {
        if instr.opcode == "unknown" || instr.opcode.starts_with("UNKNOWN_") {
            unknown_count += 1;
            unknown_types.insert(instr.opcode.clone());
        }
    }

    (
        total_count,
        unknown_count,
        unknown_types.into_iter().collect(),
    )
}

/// Executes the `obfuscate` subcommand to apply transforms and output obfuscated bytecode.
#[async_trait]
impl super::Command for ObfuscateArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let (bytes, decode_input, is_file) = {
            if self.input.trim_start().starts_with("0x") {
                let clean = normalise_hex(&self.input)?;
                let raw = hex::decode(&clean)?;
                (raw, self.input.to_string(), false)
            } else if Path::new(&self.input).extension().and_then(|s| s.to_str()) == Some("hex") {
                let s = fs::read_to_string(&self.input)?;
                let clean = normalise_hex(&s)?;
                let raw = hex::decode(&clean)?;
                (raw, clean.clone(), false)
            } else {
                let raw = fs::read(&self.input)?;
                (raw, self.input.to_string(), true)
            }
        };

        let (instructions, info, _) = decode_bytecode(&decode_input, is_file).await?;

        // Analyze and report unknown opcodes
        let (total_instructions, unknown_count, unknown_types) =
            analyze_instructions(&instructions);
        if unknown_count > 0 {
            println!("Input Analysis:");
            println!("Total instructions: {total_instructions}");
            println!(
                "Unknown opcodes: {} ({:.1}%)",
                unknown_count,
                100.0 * unknown_count as f64 / total_instructions as f64
            );
            println!("Unknown types found: {unknown_types:?}");
            println!("   → These will be preserved as raw bytes in the output.");
            println!("   → If the original contract works, the obfuscated version should too.");
            println!();
        }

        let sections = locate_sections(&bytes, &instructions, &info)?;
        let (clean_runtime, clean_report) = strip_bytecode(&bytes, &sections)?;
        let original_len = clean_runtime.len();
        let mut cfg_ir = azoth_core::cfg_ir::build_cfg_ir(
            &instructions,
            &sections,
            &bytes,
            clean_report.clone(),
        )?;

        let passes = build_passes(&self.passes)?;
        let cfg = PassConfig {
            accept_threshold: self.accept_threshold,
            aggressive: false,
            max_size_delta: self.max_size_delta,
            max_opaque_ratio: 0.5,
        };

        // Track size before transforms
        let initial_size = {
            let mut initial_instructions = Vec::new();
            for node in cfg_ir.cfg.node_indices() {
                if let Block::Body {
                    instructions: block_ins,
                    ..
                } = &cfg_ir.cfg[node]
                {
                    initial_instructions.extend(block_ins.iter().cloned());
                }
            }
            let initial_bytes = encode_with_original(&initial_instructions, Some(&bytes))?;
            initial_bytes.len()
        };

        println!("Transform Analysis:");
        println!("Original size: {} bytes", original_len);
        println!("Pre-transform size: {} bytes", initial_size);
        println!("Applying {} transforms...", passes.len());

        // Apply all transforms at once (original behavior)
        pass::run(&mut cfg_ir, &passes, &cfg, self.seed).await?;

        let mut instructions = Vec::new();
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body {
                instructions: block_ins,
                ..
            } = &cfg_ir.cfg[node]
            {
                instructions.extend(block_ins.iter().cloned());
            }
        }

        // Encode with unknown opcode handling - pass original bytecode for PC lookup
        let obf_runtime = encode_with_original(&instructions, Some(&bytes))?;
        let final_bytecode = rebuild(&obf_runtime, &clean_report);
        let new_len = obf_runtime.len();

        let allowable = (original_len as f32 * (1.0 + self.max_size_delta)).ceil() as usize;
        if new_len > allowable {
            return Err(format!(
                "Obfuscated bytecode grew {:.1}%, exceeds --max-size-delta {:.1}%",
                100.0 * (new_len as f32 / original_len as f32 - 1.0),
                self.max_size_delta * 100.0
            )
            .into());
        }

        if let Some(path) = self.emit {
            let report = gas_report(original_len, new_len, unknown_count);
            fs::write(&path, serde_json::to_string_pretty(&report)?)?;
            println!("📊 Wrote gas/size report to {}", &path);
        }

        // Success summary
        if unknown_count > 0 {
            println!("✅ Obfuscation complete with {unknown_count} unknown opcodes preserved",);
        } else {
            println!("✅ Obfuscation complete");
        }
        println!(
            "📈 Size change: {} → {} bytes ({:+.1}%)",
            original_len,
            new_len,
            100.0 * (new_len as f32 / original_len as f32 - 1.0)
        );
        println!();

        println!("0x{}", hex::encode(final_bytecode));
        Ok(())
    }
}

/// Normalizes a hex string by removing prefixes and underscores.
fn normalise_hex(s: &str) -> Result<String, ObfuscateError> {
    let stripped = s.trim().trim_start_matches("0x").replace('_', "");
    if stripped.len() % 2 != 0 {
        return Err(ObfuscateError::OddLength(stripped.len()));
    }
    Ok(stripped)
}

/// Builds a list of transform passes from a comma-separated string.
fn build_passes(list: &str) -> Result<Vec<Box<dyn Transform>>, Box<dyn Error>> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(|name| match name.trim() {
            "shuffle" => Ok(Box::new(azoth_transform::shuffle::Shuffle) as Box<dyn Transform>),
            "opaque_pred" | "opaque_predicate" => Ok(Box::new(
                azoth_transform::opaque_predicate::OpaquePredicate::new(PassConfig {
                    max_opaque_ratio: 0.5,
                    ..Default::default()
                }),
            ) as Box<dyn Transform>),
            "jump_transform" | "jump_addr" => Ok(Box::new(
                azoth_transform::jump_address_transformer::JumpAddressTransformer::new(
                    PassConfig::default(),
                ),
            ) as Box<dyn Transform>),
            _ => Err(ObfuscateError::InvalidPass(name.to_string()).into()),
        })
        .collect()
}

/// Generates a JSON report comparing original and obfuscated bytecode sizes and gas costs.
///
/// # Arguments
/// * `original_len` - The length of the original runtime bytecode.
/// * `new_len` - The length of the obfuscated runtime bytecode.
/// * `unknown_count` - Number of unknown opcodes preserved.
///
/// # Returns
/// A `serde_json::Value` containing the report.
fn gas_report(original_len: usize, new_len: usize, unknown_count: usize) -> serde_json::Value {
    let gas = |bytes| 32_000 + 200 * bytes as u64;
    json!({
        "original_bytes": original_len,
        "obfuscated_bytes": new_len,
        "size_delta_bytes": (new_len as i64 - original_len as i64),
        "original_deploy_gas": gas(original_len),
        "obfuscated_deploy_gas": gas(new_len),
        "gas_delta": (gas(new_len) as i64 - gas(original_len) as i64),
        "percent_size": (new_len as f64 / original_len as f64 - 1.0) * 100.0,
        "unknown_opcodes_preserved": unknown_count,
        "notes": if unknown_count > 0 {
            "Unknown opcodes were preserved as raw bytes to maintain functionality"
        } else {
            "All opcodes were standard and successfully obfuscated"
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Command;
    use std::env;
    use std::fs;

    #[ignore]
    #[tokio::test]
    async fn test_obfuscate_pipeline() {
        let input = "0x6001600155aabb"; // PUSH1 0x01, PUSH1 0x02, MSTORE, dummy auxdata
        let dir = env::temp_dir();
        let path = dir.join("test_obfuscate.hex");
        fs::write(&path, input).unwrap();
        let temp_report = dir.join("report.json");

        let args = ObfuscateArgs {
            input: path.to_str().unwrap().to_string(),
            seed: 42,
            passes: "shuffle,jump_transform,opaque_pred".to_string(),
            accept_threshold: 0.0,
            max_size_delta: 10.0,
            emit: Some(temp_report.to_str().unwrap().to_string()),
        };

        let result = args.execute().await;
        if let Err(e) = result {
            panic!("CLI errored: {:?}", e);
        }

        let report = fs::read_to_string(&temp_report).unwrap();
        let report_json: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert!(report_json["original_bytes"].is_number());
        assert!(report_json["percent_size"].is_f64());
        assert!(report_json["unknown_opcodes_preserved"].is_number());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&temp_report).unwrap();
    }

    #[test]
    fn test_analyze_instructions() {
        let instructions = vec![
            Instruction {
                pc: 0,
                opcode: "PUSH1".to_string(),
                imm: Some("01".to_string()),
            },
            Instruction {
                pc: 2,
                opcode: "unknown".to_string(),
                imm: None,
            },
            Instruction {
                pc: 3,
                opcode: "UNKNOWN_0xfe".to_string(),
                imm: None,
            },
            Instruction {
                pc: 4,
                opcode: "SSTORE".to_string(),
                imm: None,
            },
        ];

        let (total, unknown, types) = analyze_instructions(&instructions);
        assert_eq!(total, 4);
        assert_eq!(unknown, 2);
        assert!(types.contains(&"unknown".to_string()));
        assert!(types.contains(&"UNKNOWN_0xfe".to_string()));
    }
}
