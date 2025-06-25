/// Module for the `cfg` subcommand, which visualizes the control flow graph (CFG) of EVM
/// bytecode.
///
/// This module processes input bytecode, constructs a CFG using the `cfg_ir` module, and
/// generates a Graphviz .dot file representing the CFG. The output can be written to a file or
/// printed to stdout.
use async_trait::async_trait;
use bytecloak_core::cfg_ir::{Block, CfgIrBundle, EdgeType, build_cfg_ir};
use bytecloak_core::decoder::{decode_bytecode, input_to_bytes};
use bytecloak_core::detection::locate_sections;
use bytecloak_core::strip::strip_bytecode;
use clap::Args;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Arguments for the `cfg` subcommand.
#[derive(Args)]
pub struct CfgArgs {
    /// Input bytecode as a hex string (0x...) or file path containing EVM bytecode.
    pub input: String,
    /// Output file for Graphviz .dot (default: stdout)
    #[arg(short, long)]
    output: Option<String>,
}

/// Executes the `cfg` subcommand to generate a CFG visualization.
#[async_trait]
impl super::Command for CfgArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let is_file = !self.input.starts_with("0x") && Path::new(&self.input).is_file();
        let bytes = input_to_bytes(&self.input, is_file)?;
        let (instructions, info, _) = decode_bytecode(&self.input, is_file).await?;
        let sections = locate_sections(&bytes, &instructions, &info)?;
        let (_clean_runtime, clean_report) = strip_bytecode(&bytes, &sections)?;
        let cfg_ir = build_cfg_ir(&instructions, &sections, &bytes, clean_report)?;

        let dot = generate_dot(&cfg_ir);
        if let Some(out_path) = self.output {
            fs::write(out_path, &dot)?;
        } else {
            println!("{}", dot);
        }
        Ok(())
    }
}

/// Generates a Graphviz .dot representation of the CFG.
///
/// # Arguments
/// * `cfg_ir` - The `CfgIrBundle` containing the CFG to visualize.
///
/// # Returns
/// A `String` containing the .dot file content.
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
