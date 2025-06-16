use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle, EdgeType, build_cfg_ir};
use bytecloak_core::decoder::decode_bytecode;
use bytecloak_core::detection::locate_sections;
use clap::Args;
use hex::FromHex;
use std::error::Error;
use std::fs;

#[derive(Args)]
pub struct CfgArgs {
    /// Output file for Graphviz .dot (default: stdout)
    #[arg(short, long)]
    output: Option<String>,
}

#[async_trait]
impl super::Command for CfgArgs {
    async fn execute(self, input: &str) -> Result<(), Box<dyn Error>> {
        let (bytes, is_file) = if let Some(path) = input.strip_prefix('@') {
            (fs::read(path)?, true)
        } else {
            let clean = input.strip_prefix("0x").unwrap_or(input);
            (Vec::from_hex(clean)?, false)
        };

        let (instructions, info, _) = decode_bytecode(input, is_file).await?;
        let sections = locate_sections(&bytes, &instructions, &info)?;
        let cfg_ir = build_cfg_ir(&instructions, &sections, &bytes)?;

        let dot = generate_dot(&cfg_ir);
        if let Some(out_path) = self.output {
            fs::write(out_path, &dot)?;
        } else {
            println!("{}", dot);
        }
        Ok(())
    }
}

fn generate_dot(cfg_ir: &CfgIrBundle) -> String {
    let mut dot = String::from("digraph CFG {\n");

    // Add nodes
    for node in cfg_ir.cfg.node_indices() {
        let block = cfg_ir.cfg.node_weight(node).unwrap();
        let label = match block {
            Block::Entry => "Entry".to_string(),
            Block::Exit => "Exit".to_string(),
            Block::Body {
                start_pc,
                instructions,
                ..
            } => {
                let instrs: Vec<String> = instructions.iter().map(|i| i.to_string()).collect();
                format!("Block_{}\\n{}", start_pc, instrs.join("\\n"))
            }
        };
        dot.push_str(&format!("    {} [label=\"{}\"];\n", node.index(), label));
    }

    // Add edges
    for edge in cfg_ir.cfg.edge_indices() {
        let (src, dst) = cfg_ir.cfg.edge_endpoints(edge).unwrap();
        let edge_type = cfg_ir.cfg.edge_weight(edge).unwrap();
        let label = match edge_type {
            EdgeType::Fallthrough => "Fallthrough",
            EdgeType::Jump => "Jump",
            EdgeType::BranchTrue => "BranchTrue",
            EdgeType::BranchFalse => "BranchFalse",
        };
        dot.push_str(&format!(
            "    {} -> {} [label=\"{}\"];\n",
            src.index(),
            dst.index(),
            label
        ));
    }

    dot.push_str("}\n");
    dot
}
