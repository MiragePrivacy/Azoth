/// Module for computing analytical metrics to evaluate EVM bytecode obfuscation transforms.
///
/// Implements a minimal set of metrics quantified by bytecode size, control flow complexity,
/// stack usage, and dominator overlap to assess transform potency (analyst effort) and gas
/// efficiency. The module provides functions to collect metrics from a `CfgIrBundle` and
/// `CleanReport`, compare pre- and post-obfuscation states, and compute
/// dominator/post-dominator pairs for control flow analysis.
///
/// # Usage
/// ```rust,ignore
/// let (instructions, info, _) = decoder::decode_bytecode("0x600160015601", false).await.unwrap();
/// let bytes = hex::decode("600160015601").unwrap();
/// let &sections = detection::locate_&sections(&bytes, &instructions, &info).unwrap();
/// let (clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
/// let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes).unwrap();
/// let metrics = metrics::collect_metrics(&cfg_ir, &report).unwrap();
/// println!("{}", serde_json::to_string_pretty(&metrics).unwrap());
/// ```
use azoth_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
use azoth_core::strip::CleanReport;
use azoth_utils::errors::MetricsError;
use petgraph::{
    algo::dominators::simple_fast,
    graph::{DiGraph, NodeIndex},
    stable_graph::IndexType,
    visit::Reversed,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

/// Represents a set of analytical metrics for evaluating bytecode obfuscation.
///
/// Metrics include bytecode size, control flow complexity (block and edge counts), stack usage,
/// dominator overlap, and a composite potency score. Used to compare pre- and post-obfuscation
/// states and guide transform selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Size of the cleaned runtime bytecode in bytes.
    pub byte_len: usize,
    /// Number of basic blocks in the CFG (excluding Entry/Exit).
    pub block_cnt: usize,
    /// Number of edges in the CFG.
    pub edge_cnt: usize,
    /// Maximum stack height across all body blocks.
    pub max_stack_peak: usize,
    /// Fraction of nodes that are both dominators and post-dominators.
    pub dom_overlap: f64,
    /// Composite potency score (heuristic based on nodes, edges, and overlap).
    pub potency: f64,
}

/// Collects metrics from the cleaned runtime bytecode and CFG.
///
/// Computes bytecode size, block and edge counts, maximum stack height, dominator overlap, and
/// potency score. Uses the `CleanReport` for size and `CfgIrBundle` for control flow and stack
/// data. The potency score balances complexity (nodes, edges) against overlap to estimate analyst
/// effort, with adjustments for gas efficiency.
///
/// # Arguments
/// * `ir` - The CFG and IR bundle from `cfg_ir::build_cfg_ir`.
/// * `report` - The stripping report from `strip::strip_bytecode`.
///
/// # Returns
/// A `Metrics` struct with computed metrics, or an error if the CFG is invalid.
pub fn collect_metrics(ir: &CfgIrBundle, report: &CleanReport) -> Result<Metrics, MetricsError> {
    if ir.cfg.node_count() < 2 {
        return Err(MetricsError::EmptyCfg);
    }

    let (doms, post_doms) = dominator_pairs(&ir.cfg);
    let overlap = dom_overlap(&doms, &post_doms);

    let block_cnt = ir
        .cfg
        .node_indices()
        .filter(|&n| matches!(ir.cfg[n], Block::Body { .. }))
        .count();
    if block_cnt == 0 {
        return Err(MetricsError::NoBodyBlocks);
    }

    let max_stack_peak = max_stack_per_block(ir).values().max().copied().unwrap_or(0);

    Ok(Metrics {
        byte_len: report.clean_len,
        block_cnt,
        edge_cnt: ir.cfg.edge_count(),
        max_stack_peak,
        dom_overlap: overlap,
        potency: score(overlap, block_cnt, ir.cfg.edge_count()),
    })
}

/// Computes the maximum stack height for each block in the CFG.
///
/// Iterates through the CFG nodes, extracting the `max_stack` field from `Block::Body` instances
/// and mapping it to the block’s starting program counter. Used to determine the overall maximum
/// stack height across all blocks.
///
/// # Arguments
/// * `ir` - The CFG and IR bundle from `cfg_ir::build_cfg_ir`.
///
/// # Returns
/// A map of block starting PCs to their maximum stack heights.
pub fn max_stack_per_block(ir: &CfgIrBundle) -> HashMap<usize, usize> {
    let mut map = HashMap::new();
    for node in ir.cfg.node_indices() {
        if let Some(Block::Body {
            start_pc,
            max_stack,
            ..
        }) = ir.cfg.node_weight(node)
        {
            map.insert(*start_pc, *max_stack);
        }
    }
    map
}

// Define a type alias for the HashMap used in dominator pairs
type DominatorMap<Ix> = HashMap<NodeIndex<Ix>, NodeIndex<Ix>>;

/// Computes dominator and post-dominator pairs for the CFG.
///
/// Uses `petgraph`’s `simple_fast` algorithm to compute immediate dominators and post-dominators,
/// mapping nodes to their immediate dominator/post-dominator. The entry node (index 0) and exit
/// node (last index) are used as roots for the respective analyses.
///
/// # Arguments
/// * `g` - The CFG graph from `CfgIrBundle`.
///
/// # Returns
/// A tuple of two hash maps: (dominators, post-dominators), mapping node indices to their immediate
/// dominator/post-dominator.
fn dominator_pairs<Ix>(g: &DiGraph<Block, EdgeType, Ix>) -> (DominatorMap<Ix>, DominatorMap<Ix>)
where
    Ix: IndexType,
{
    let entry = NodeIndex::<Ix>::new(0);
    let exit = NodeIndex::<Ix>::new(g.node_count() - 1);

    let doms = simple_fast(g, entry);
    let mut dom_map = HashMap::new();
    for n in g.node_indices() {
        if let Some(idom) = doms.immediate_dominator(n) {
            dom_map.insert(n, idom);
        }
    }

    let post = simple_fast(Reversed(g), exit);
    let mut pdom_map = HashMap::new();
    for n in g.node_indices() {
        if let Some(ipdom) = post.immediate_dominator(n) {
            pdom_map.insert(n, ipdom);
        }
    }

    (dom_map, pdom_map)
}

/// Computes the fraction of nodes that are both dominators and post-dominators.
///
/// Measures overlap between dominator and post-dominator sets, indicating critical control
/// flow points that resist simplification. A higher overlap suggests a more linear CFG, reducing
/// obfuscation potency.
///
/// # Arguments
/// * `doms` - Map of nodes to their immediate dominators.
/// * `pdoms` - Map of nodes to their immediate post-dominators.
///
/// # Returns
/// The fraction of nodes where the dominator and post-dominator are the same.
fn dom_overlap<Ix>(doms: &DominatorMap<Ix>, pdoms: &DominatorMap<Ix>) -> f64
where
    Ix: IndexType + Hash + Eq,
{
    let common = doms
        .iter()
        .filter(|(n, d)| pdoms.get(*n) == Some(*d))
        .count();
    if doms.is_empty() {
        0.0
    } else {
        common as f64 / doms.len() as f64
    }
}

/// Computes a composite potency score for the CFG.
///
/// Combines block count, edge count, and dominator overlap into a heuristic score estimating
/// analyst effort (Wroblewski’s potency). The formula emphasizes control flow complexity (nodes,
/// edges) while penalizing high overlap, which indicates simpler CFGs. Weights are tuned for
/// prototype use and can be adjusted based on testing.
///
/// # Arguments
/// * `overlap` - Fraction of dominator/post-dominator overlap.
/// * `nodes` - Number of body blocks in the CFG.
/// * `edges` - Number of edges in the CFG.
///
/// # Returns
/// A potency score (higher indicates greater complexity).
fn score(overlap: f64, nodes: usize, edges: usize) -> f64 {
    5.0 * (nodes as f64).log2() + edges as f64 + 30.0 * (1.0 - overlap)
}

/// Compares two sets of metrics to evaluate an obfuscation transform.
///
/// Computes the difference in potency scores, adjusted for byte length changes to account for gas
/// costs. A positive result indicates the transform increases complexity without excessive size
/// growth.
///
/// # Arguments
/// * `before` - Metrics before the transform.
/// * `after` - Metrics after the transform.
///
/// # Returns
/// A score representing the transform’s effectiveness (positive is better).
pub fn compare(before: &Metrics, after: &Metrics) -> f64 {
    after.potency - before.potency - 0.25 * (after.byte_len as f64 - before.byte_len as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::{cfg_ir, decoder, detection, strip};
    use azoth_utils::errors::DecodeError;
    use petgraph::graph::NodeIndex;
    use tokio;

    /// Tests metrics computation for a simple bytecode with linear control flow.
    #[tokio::test]
    async fn test_collect_metrics_simple() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();

        let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
        assert_eq!(metrics.byte_len, 6, "Byte length mismatch");
        assert_eq!(metrics.block_cnt, 2, "Block count mismatch");
        assert!(
            metrics.max_stack_peak > 0,
            "Max stack peak should be positive"
        );
        assert!(metrics.potency > 0.0, "Potency score should be positive");
        assert!(
            metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
            "Invalid overlap"
        );
    }

    /// Tests metrics computation for a single-block bytecode.
    #[tokio::test]
    async fn test_collect_metrics_single_block() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x600050"; // PUSH1 0x00, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();

        let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
        assert_eq!(metrics.byte_len, 3, "Byte length mismatch");
        assert_eq!(metrics.block_cnt, 1, "Block count mismatch");
        assert_eq!(metrics.edge_cnt, 2, "Edge count mismatch");
        assert_eq!(metrics.max_stack_peak, 1, "Max stack peak mismatch");
        assert!(
            metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
            "Invalid overlap"
        );
    }

    /// Tests metrics computation for a bytecode with conditional branching.
    #[tokio::test]
    async fn test_collect_metrics_branching() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();

        let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
        assert_eq!(metrics.byte_len, 8, "Byte length mismatch");
        assert_eq!(metrics.block_cnt, 2, "Block count mismatch");
        assert_eq!(metrics.edge_cnt, 2, "Edge count mismatch");
        assert!(
            metrics.max_stack_peak >= 1,
            "Max stack peak should be positive"
        );
        assert!(
            metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
            "Invalid overlap"
        );
    }

    /// Tests that decoding an empty bytecode fails with a parse error.
    #[tokio::test]
    async fn test_collect_metrics_empty_input() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let err = decoder::decode_bytecode("0x", false)
            .await
            .expect_err("empty blob must fail to decode");
        assert!(matches!(err, DecodeError::Parse { .. }));
    }

    /// Tests metrics computation for a CFG with no body blocks.
    #[tokio::test]
    async fn test_collect_metrics_no_body_blocks() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x00"; // STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();

        let m = collect_metrics(&cfg_ir, &report).expect("single STOP is still code");
        assert_eq!(m.block_cnt, 1, "Single STOP should form one body block");
    }

    /// Tests the compare function for metrics.
    #[tokio::test]
    async fn test_compare_metrics() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode_before = "0x600050"; // PUSH1 0x00, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode_before, false)
            .await
            .unwrap();
        let bytes = hex::decode(bytecode_before.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();
        let metrics_before = collect_metrics(&cfg_ir, &report).unwrap();

        let bytecode_after = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
        let (instructions, info, _) = decoder::decode_bytecode(bytecode_after, false)
            .await
            .unwrap();
        let bytes = hex::decode(bytecode_after.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();
        let metrics_after = collect_metrics(&cfg_ir, &report).unwrap();

        let score = compare(&metrics_before, &metrics_after);
        assert!(score > 0.0, "Transform should increase potency");
    }

    /// Tests invariant: potency score increases with more edges.
    #[tokio::test]
    async fn test_potency_edge_increase() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode_simple = "0x600050"; // PUSH1 0x00, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode_simple, false)
            .await
            .unwrap();
        let bytes = hex::decode(bytecode_simple.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();
        let metrics_simple = collect_metrics(&cfg_ir, &report).unwrap();

        let bytecode_complex = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode_complex, false)
            .await
            .unwrap();
        let bytes = hex::decode(bytecode_complex.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();
        let metrics_complex = collect_metrics(&cfg_ir, &report).unwrap();

        assert!(
            metrics_complex.potency > metrics_simple.potency,
            "More edges should increase potency"
        );
    }

    /// Tests dominator and post-dominator computation for a branching CFG.
    #[tokio::test]
    async fn test_dominator_computation() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let bytecode = "0x6000600157600256"; // PUSH1 0x00, PUSH1 0x01, JUMPI, PUSH1 0x02, JUMP
        let (instructions, info, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();
        let bytes = hex::decode(bytecode.trim_start_matches("0x")).unwrap();
        let sections = detection::locate_sections(&bytes, &instructions, &info).unwrap();
        let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
        let cfg_ir =
            cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report.clone()).unwrap();

        let (doms, post_doms) = dominator_pairs(&cfg_ir.cfg);
        let overlap = dom_overlap(&doms, &post_doms);

        // Verify dominators
        let entry = NodeIndex::<u32>::new(0);
        let first_body = NodeIndex::<u32>::new(2); // First body block is at index 2
        assert!(
            doms.contains_key(&first_body),
            "First body block should have a dominator"
        );
        assert_eq!(
            doms.get(&first_body).copied(),
            Some(entry),
            "First body block’s dominator should be Entry"
        );

        // Verify post-dominators
        let _exit = NodeIndex::<u32>::new(1); // Exit is at index 1
        let second_body = NodeIndex::<u32>::new(3); // Second body block is at index 3
        assert!(
            post_doms.contains_key(&first_body),
            "First body block should have a post-dominator"
        );
        assert!(
            post_doms.get(&second_body).is_none(),
            "Second body block should have no post-dominator due to potential loop"
        );
        assert_eq!(
            post_doms.get(&first_body).copied(),
            Some(second_body),
            "In this graph every path from first body block goes through second body block, not Exit"
        );

        // Verify overlap bounds
        assert!(
            overlap >= 0.0 && overlap <= 1.0,
            "Dominator overlap should be between 0 and 1"
        );

        // Verify metrics integration
        let metrics = collect_metrics(&cfg_ir, &report).unwrap();
        assert_eq!(
            metrics.dom_overlap, overlap,
            "Metrics overlap should match computed overlap"
        );
    }
}
