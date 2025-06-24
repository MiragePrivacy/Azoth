/// Module for the `obfuscate` subcommand, which applies obfuscation transforms to EVM
/// bytecode.
///
/// This module processes input bytecode, constructs a CFG, applies specified transforms (e.g.,
/// shuffle, stack-noise, opaque-predicates), and outputs the obfuscated bytecode. It also
/// generates a gas and size report if requested.
use async_trait::async_trait;
use bytecloak_core::cfg_ir::Block;
use bytecloak_core::decoder::decode_bytecode;
use bytecloak_core::detection::locate_sections;
use bytecloak_core::encoder::{encode, rebuild};
use bytecloak_core::strip::strip_bytecode;
use bytecloak_transform::{
    pass,
    util::{PassConfig, Transform},
};
use clap::Args;
use serde_json::json;
use std::error::Error;
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during obfuscation.
#[derive(Debug, Error)]
pub enum ObfuscateError {
    /// The hex string has an odd length, making it invalid.
    #[error("hex string has odd length: {0}")]
    OddLength(usize),
    /// Failed to decode hex string to bytes.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// File read/write error.
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    /// Transform application failed.
    #[error("transform error: {0}")]
    Transform(#[from] bytecloak_transform::util::TransformError),
    /// Invalid transform pass specified.
    #[error("invalid pass: {0}")]
    InvalidPass(String),
    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Arguments for the `obfuscate` subcommand.
#[derive(Args)]
pub struct ObfuscateArgs {
    /// Random seed for transform application (default: 42).
    #[arg(long, default_value_t = 42)]
    seed: u64,
    /// Comma-separated list of transforms (default: shuffle,stack_noise,opaque_pred).
    #[arg(long, default_value = "shuffle,stack_noise,opaque_pred")]
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

/// Executes the `obfuscate` subcommand to apply transforms and output obfuscated bytecode.
///
/// # Arguments
/// * `input` - A hex string, .hex file, or binary file containing EVM bytecode.
///
/// # Returns
/// A `Result` indicating success or an error if processing fails.
#[async_trait]
impl super::Command for ObfuscateArgs {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>> {
        let (bytes, decode_input, is_file) = {
            if input.trim_start().starts_with("0x") {
                let clean = normalise_hex(input)?;
                let raw = hex::decode(&clean)?;
                (raw, input.to_string(), false)
            } else if Path::new(input).extension().and_then(|s| s.to_str()) == Some("hex") {
                let s = fs::read_to_string(input)?;
                let clean = normalise_hex(&s)?;
                let raw = hex::decode(&clean)?;
                (raw, clean.clone(), false)
            } else {
                let raw = fs::read(input)?;
                (raw, input.to_string(), true)
            }
        };

        let (instructions, info, _) = decode_bytecode(&decode_input, is_file).await?;
        let sections = locate_sections(&bytes, &instructions, &info)?;
        let (clean_runtime, clean_report) = strip_bytecode(&bytes, &sections)?;
        let original_len = clean_runtime.len();
        let mut cfg_ir = bytecloak_core::cfg_ir::build_cfg_ir(
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
            max_noise_ratio: 0.5,
            max_opaque_ratio: 0.5,
        };
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
        let obf_runtime = encode(&instructions)?;
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
            let report = gas_report(original_len, new_len);
            fs::write(&path, serde_json::to_string_pretty(&report)?)?;
            println!("Wrote gas/size report to {}", &path);
        }

        println!("0x{}", hex::encode(final_bytecode));
        Ok(())
    }
}

/// Normalizes a hex string by removing prefixes and underscores.
///
/// # Arguments
/// * `s` - The input hex string (e.g., "0x1234", "12_34").
///
/// # Returns
/// A `Result` containing the cleaned hex string or an `ObfuscateError` if invalid.
fn normalise_hex(s: &str) -> Result<String, ObfuscateError> {
    let stripped = s.trim().trim_start_matches("0x").replace('_', "");

    if stripped.len() % 2 != 0 {
        return Err(ObfuscateError::OddLength(stripped.len()));
    }
    Ok(stripped)
}

/// Builds a list of transform passes from a comma-separated string.
///
/// # Arguments
/// * `list` - A string of transform names (e.g., "shuffle,stack_noise").
///
/// # Returns
/// A `Result` containing a vector of `Box<dyn Transform>` or an error if a pass is invalid.
fn build_passes(list: &str) -> Result<Vec<Box<dyn Transform>>, Box<dyn Error>> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(|name| match name.trim() {
            "shuffle" => Ok(Box::new(bytecloak_transform::shuffle::Shuffle) as Box<dyn Transform>),
            "stack_noise" => Ok(Box::new(bytecloak_transform::stack_noise::StackNoise::new(
                PassConfig {
                    max_noise_ratio: 0.5,
                    ..Default::default()
                },
            )) as Box<dyn Transform>),
            "opaque_pred" | "opaque_predicate" => Ok(Box::new(
                bytecloak_transform::opaque_predicate::OpaquePredicate::new(PassConfig {
                    max_opaque_ratio: 0.5,
                    ..Default::default()
                }),
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
///
/// # Returns
/// A `serde_json::Value` containing the report.
fn gas_report(original_len: usize, new_len: usize) -> serde_json::Value {
    let gas = |bytes| 32_000 + 200 * bytes as u64;
    json!({
        "original_bytes": original_len,
        "obfuscated_bytes": new_len,
        "size_delta_bytes": (new_len as i64 - original_len as i64),
        "original_deploy_gas": gas(original_len),
        "obfuscated_deploy_gas": gas(new_len),
        "gas_delta": (gas(new_len) as i64 - gas(original_len) as i64),
        "percent_size": (new_len as f64 / original_len as f64 - 1.0) * 100.0
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
            seed: 42,
            passes: "shuffle,stack_noise,opaque_pred".to_string(),
            accept_threshold: 0.0,
            max_size_delta: 10.0,
            emit: Some(temp_report.to_str().unwrap().to_string()),
        };

        let result = args.execute(path.to_str().unwrap()).await;
        if let Err(e) = result {
            panic!("CLI errored: {:?}", e);
        }

        let report = fs::read_to_string(&temp_report).unwrap();
        let report_json: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert!(report_json["original_bytes"].is_number());
        assert!(report_json["percent_size"].is_f64());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&temp_report).unwrap();
    }

    #[tokio::test]
    async fn test_obfuscate_size_limit() {
        let input = "0x6001600155aabb"; // PUSH1 0x01, PUSH1 0x02, MSTORE, dummy auxdata
        let dir = env::temp_dir();
        let path = dir.join("test_obfuscate_size_limit.hex");
        fs::write(&path, input).unwrap();

        let args = ObfuscateArgs {
            seed: 42,
            passes: "stack_noise".to_string(),
            accept_threshold: 0.0,
            max_size_delta: 0.0001, // 0.01% threshold
            emit: None,
        };

        let result = args.execute(path.to_str().unwrap()).await;
        assert!(result.is_err(), "should reject when growth > 0.01 %");
        fs::remove_file(&path).unwrap();
    }
}
