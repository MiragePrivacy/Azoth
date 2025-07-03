use crate::util::Transform;
use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle};
use bytecloak_core::decoder::Instruction;
use bytecloak_core::encoder;
use bytecloak_core::Opcode;
use bytecloak_utils::errors::TransformError;
use rand::{rngs::StdRng, seq::SliceRandom};
use std::collections::HashMap;
use tracing::debug;

pub struct Shuffle;

#[async_trait]
impl Transform for Shuffle {
    fn name(&self) -> &'static str {
        "Shuffle"
    }

    async fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        let mut blocks: Vec<(usize, &Block)> = ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body { start_pc, .. } = &ir.cfg[n] {
                    Some((*start_pc, &ir.cfg[n]))
                } else {
                    None
                }
            })
            .collect();

        if blocks.len() <= 1 {
            debug!("Not enough blocks to shuffle");
            return Ok(false);
        }

        let original_order: Vec<usize> = blocks.iter().map(|(pc, _)| *pc).collect();
        blocks.shuffle(rng);
        let new_order: Vec<usize> = blocks.iter().map(|(pc, _)| *pc).collect();
        if original_order == new_order {
            debug!("Shuffle produced no change");
            return Ok(false);
        }

        let mut new_instrs = Vec::new();
        let mut pc_map = HashMap::new();
        let mut current_pc = 0;

        for (_, block) in blocks {
            if let Block::Body { instructions, .. } = block {
                for instr in instructions {
                    pc_map.insert(instr.pc, current_pc);
                    let mut new_instr = instr.clone();
                    new_instr.pc = current_pc;
                    new_instrs.push(new_instr);
                    current_pc += self.instruction_size(instr);
                }
            }
        }

        for instr in &mut new_instrs {
            if instr.opcode == "JUMP" || instr.opcode == "JUMPI" {
                if let Some(imm) = &instr.imm {
                    if let Ok(old_target) = usize::from_str_radix(imm, 16) {
                        if let Some(new_target) = pc_map.get(&old_target) {
                            instr.imm = Some(format!("{new_target:x}"));
                        } else {
                            return Err(TransformError::InvalidJumpTarget(old_target));
                        }
                    }
                }
            }
        }

        let new_bytecode = encoder::encode(&new_instrs)
            .map_err(|e| TransformError::EncodingError(e.to_string()))?;
        ir.replace_body(new_bytecode, &[]).await?;
        Ok(true)
    }
}

impl Shuffle {
    fn instruction_size(&self, instr: &Instruction) -> usize {
        let (_opcode, imm_size) = match instr.opcode.as_str() {
            "PUSH1" => Opcode::parse(0x60),
            "PUSH2" => Opcode::parse(0x61),
            "PUSH3" => Opcode::parse(0x62),
            "PUSH4" => Opcode::parse(0x63),
            "PUSH5" => Opcode::parse(0x64),
            "PUSH6" => Opcode::parse(0x65),
            "PUSH7" => Opcode::parse(0x66),
            "PUSH8" => Opcode::parse(0x67),
            "PUSH9" => Opcode::parse(0x68),
            "PUSH10" => Opcode::parse(0x69),
            "PUSH11" => Opcode::parse(0x6a),
            "PUSH12" => Opcode::parse(0x6b),
            "PUSH13" => Opcode::parse(0x6c),
            "PUSH14" => Opcode::parse(0x6d),
            "PUSH15" => Opcode::parse(0x6e),
            "PUSH16" => Opcode::parse(0x6f),
            "PUSH17" => Opcode::parse(0x70),
            "PUSH18" => Opcode::parse(0x71),
            "PUSH19" => Opcode::parse(0x72),
            "PUSH20" => Opcode::parse(0x73),
            "PUSH21" => Opcode::parse(0x74),
            "PUSH22" => Opcode::parse(0x75),
            "PUSH23" => Opcode::parse(0x76),
            "PUSH24" => Opcode::parse(0x77),
            "PUSH25" => Opcode::parse(0x78),
            "PUSH26" => Opcode::parse(0x79),
            "PUSH27" => Opcode::parse(0x7a),
            "PUSH28" => Opcode::parse(0x7b),
            "PUSH29" => Opcode::parse(0x7c),
            "PUSH30" => Opcode::parse(0x7d),
            "PUSH31" => Opcode::parse(0x7e),
            "PUSH32" => Opcode::parse(0x7f),
            _ => (Opcode::UNKNOWN(0), 0),
        };
        1 + imm_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytecloak_analysis::collect_metrics;
    use bytecloak_core::{cfg_ir, decoder, detection, strip};
    use rand::SeedableRng;
    use tokio;

    #[tokio::test]
    async fn test_shuffle_reorders_blocks() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x60015b6002"; // PUSH1 0x01, JUMPDEST, PUSH1 0x02
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report).unwrap();

        let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let transform = Shuffle;
        let changed = transform.apply(&mut cfg_ir, &mut rng).await.unwrap();
        let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
        assert!(changed, "Shuffle should reorder blocks");
        assert_eq!(
            before.byte_len, after.byte_len,
            "Byte length should not change"
        );
    }
}
