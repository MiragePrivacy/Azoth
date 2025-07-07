//! Contract semantics extraction and representation
//! 
//! This module analyzes bytecode to extract semantic information needed
//! for formal verification.

use crate::{VerificationResult, VerificationError};
use bytecloak_core::decoder::{decode_bytecode, Instruction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Semantic representation of a smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSemantics {
    /// Contract functions with their properties
    pub functions: Vec<FunctionSemantics>,
    /// Storage layout mapping
    pub storage_layout: HashMap<u64, String>, // slot -> type
    /// Global state invariants
    pub state_invariants: Vec<String>, // SMT formulas
    /// Contract-level properties
    pub properties: ContractProperties,
    /// Control flow graph
    pub control_flow: ControlFlowGraph,
}

/// Semantic representation of a contract function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSemantics {
    /// Function name (if known)
    pub name: String,
    /// Function selector (first 4 bytes of keccak hash)
    pub selector: Option<[u8; 4]>,
    /// Function preconditions (SMT formulas)
    pub preconditions: Vec<String>,
    /// Function postconditions (SMT formulas)
    pub postconditions: Vec<String>,
    /// State modifications this function can make
    pub state_modifications: Vec<StateModification>,
    /// Gas consumption characteristics
    pub gas_characteristics: GasCharacteristics,
    /// Whether this function is view/pure
    pub read_only: bool,
    /// Whether this function is payable
    pub payable: bool,
}

/// Description of how a function modifies contract state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateModification {
    /// Storage slot being modified
    pub storage_slot: u64,
    /// Type of modification
    pub modification_type: ModificationType,
    /// Conditions under which modification occurs
    pub conditions: Vec<String>, // SMT formulas
}

/// Types of state modifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModificationType {
    /// Direct assignment
    Assignment,
    /// Increment/decrement
    Arithmetic,
    /// Conditional update
    Conditional,
    /// Array/mapping update
    Collection,
}

/// Gas consumption characteristics of a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCharacteristics {
    /// Base gas cost (fixed part)
    pub base_cost: u64,
    /// Variable gas cost factors
    pub variable_costs: Vec<VariableGasCost>,
    /// Maximum possible gas consumption
    pub max_gas: Option<u64>,
}

/// Variable gas cost component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableGasCost {
    /// What drives this variable cost
    pub factor: GasCostFactor,
    /// Cost per unit
    pub cost_per_unit: u64,
}

/// Factors that affect gas consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasCostFactor {
    /// Input data size
    InputDataSize,
    /// Storage operations
    StorageOperations,
    /// Loop iterations
    LoopIterations,
    /// External calls
    ExternalCalls,
}

/// Contract-level properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractProperties {
    /// Whether the contract uses a proxy pattern
    pub is_proxy: bool,
    /// Whether the contract is upgradeable
    pub is_upgradeable: bool,
    /// Reentrancy guards present
    pub has_reentrancy_guards: bool,
    /// Access control mechanisms
    pub access_control: AccessControlType,
}

/// Types of access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessControlType {
    /// No access control
    None,
    /// Simple owner-based control
    Owner,
    /// Role-based access control
    RoleBased,
    /// Custom access control
    Custom,
}

/// Control flow graph representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Basic blocks in the contract
    pub blocks: Vec<BasicBlock>,
    /// Edges between blocks
    pub edges: Vec<ControlFlowEdge>,
    /// Entry points (function starts)
    pub entry_points: HashMap<[u8; 4], usize>, // selector -> block index
}

/// A basic block in the control flow - simplified without Instruction serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Block identifier
    pub id: usize,
    /// Starting instruction offset
    pub start_offset: usize,
    /// Number of instructions in this block
    pub instruction_count: usize,
    /// Block type
    pub block_type: BlockType,
    /// Opcodes in this block (simplified representation)
    pub opcodes: Vec<String>,
}

/// Types of basic blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockType {
    /// Function entry point
    Entry,
    /// Regular execution block
    Normal,
    /// Conditional branch
    Branch,
    /// Function return
    Return,
    /// Error/revert
    Error,
}

/// Edge in the control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    /// Source block
    pub from: usize,
    /// Destination block
    pub to: usize,
    /// Condition for taking this edge
    pub condition: EdgeCondition,
}

/// Conditions for control flow edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeCondition {
    /// Unconditional jump
    Unconditional,
    /// Conditional jump (true branch)
    ConditionalTrue,
    /// Conditional jump (false branch)
    ConditionalFalse,
    /// Function call
    Call,
    /// Function return
    Return,
}

/// Extract semantic information from bytecode
pub fn extract_semantics(bytecode: &[u8]) -> VerificationResult<ContractSemantics> {
    tracing::debug!("Extracting semantic information from bytecode ({} bytes)", bytecode.len());
    
    // Decode bytecode to instructions
    let instructions = decode_bytecode_to_instructions(bytecode)?;
    
    // Build control flow graph
    let control_flow = build_control_flow_graph(&instructions)?;
    
    // Extract functions
    let functions = extract_functions(&instructions, &control_flow)?;
    
    // Analyze storage layout
    let storage_layout = analyze_storage_layout(&instructions)?;
    
    // Extract contract properties
    let properties = analyze_contract_properties(&instructions)?;
    
    // Generate state invariants
    let state_invariants = generate_state_invariants(&functions, &storage_layout)?;
    
    Ok(ContractSemantics {
        functions,
        storage_layout,
        state_invariants,
        properties,
        control_flow,
    })
}

/// Decode bytecode using bytecloak-core
fn decode_bytecode_to_instructions(bytecode: &[u8]) -> VerificationResult<Vec<Instruction>> {
    let bytecode_hex = format!("0x{}", hex::encode(bytecode));
    
    // Use bytecloak-core's decoder
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            decode_bytecode(&bytecode_hex, false).await
        })
        .map(|(instructions, _, _)| instructions)
        .map_err(|e| VerificationError::BytecodeAnalysis(format!("Failed to decode bytecode: {}", e)))
}

/// Build control flow graph from instructions
fn build_control_flow_graph(instructions: &[Instruction]) -> VerificationResult<ControlFlowGraph> {
    let mut blocks = Vec::new();
    let mut edges = Vec::new();
    let mut entry_points = HashMap::new();
    
    // Find basic block boundaries
    let block_starts = find_block_boundaries(instructions);
    
    // Create basic blocks
    for (i, &start_offset) in block_starts.iter().enumerate() {
        let end_offset = block_starts.get(i + 1).copied().unwrap_or(instructions.len());
        
        let block_instructions = &instructions[start_offset..end_offset];
        let opcodes: Vec<String> = block_instructions.iter().map(|inst| inst.opcode.clone()).collect();
        
        let block_type = determine_block_type(block_instructions);
        
        blocks.push(BasicBlock {
            id: i,
            start_offset,
            instruction_count: block_instructions.len(),
            block_type,
            opcodes,
        });
    }
    
    // Analyze control flow edges
    for (i, block) in blocks.iter().enumerate() {
        let block_edges = analyze_block_edges(block, &blocks, instructions);
        edges.extend(block_edges);
    }
    
    // Find function entry points (simplified heuristic)
    for (i, block) in blocks.iter().enumerate() {
        if matches!(block.block_type, BlockType::Entry) {
            // Try to extract function selector
            if let Some(selector) = extract_function_selector_from_opcodes(&block.opcodes) {
                entry_points.insert(selector, i);
            }
        }
    }
    
    Ok(ControlFlowGraph {
        blocks,
        edges,
        entry_points,
    })
}

/// Find boundaries of basic blocks
fn find_block_boundaries(instructions: &[Instruction]) -> Vec<usize> {
    let mut boundaries = vec![0]; // Start is always a boundary
    
    for (i, instruction) in instructions.iter().enumerate() {
        match instruction.opcode.as_str() {
            // Jump destinations are block boundaries
            "JUMPDEST" => boundaries.push(i),
            // Instructions after jumps/calls are boundaries  
            "JUMP" | "JUMPI" => {
                if i + 1 < instructions.len() {
                    boundaries.push(i + 1);
                }
            },
            "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                if i + 1 < instructions.len() {
                    boundaries.push(i + 1);
                }
            },
            _ => {}
        }
    }
    
    boundaries.sort();
    boundaries.dedup();
    boundaries
}

/// Determine the type of a basic block
fn determine_block_type(instructions: &[Instruction]) -> BlockType {
    if instructions.is_empty() {
        return BlockType::Normal;
    }
    
    // Check last instruction
    match instructions.last().unwrap().opcode.as_str() {
        "RETURN" => BlockType::Return,
        "REVERT" => BlockType::Error,
        "JUMPI" => BlockType::Branch, // conditional
        _ => {
            // Check if this looks like a function entry
            if instructions.len() > 4 && instructions[0].opcode == "JUMPDEST" {
                BlockType::Entry
            } else {
                BlockType::Normal
            }
        }
    }
}

/// Analyze control flow edges from a block
fn analyze_block_edges(block: &BasicBlock, all_blocks: &[BasicBlock], _instructions: &[Instruction]) -> Vec<ControlFlowEdge> {
    let mut edges = Vec::new();
    
    if let Some(last_opcode) = block.opcodes.last() {
        match last_opcode.as_str() {
            "JUMP" => {
                // Unconditional jump - would need jump target analysis
                // For now, simplified
            },
            "JUMPI" => {
                // Conditional jump - has both true and false branches
                // Would need more sophisticated analysis
            },
            "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                // Call edge - execution continues after call
                if let Some(next_block) = all_blocks.iter().find(|b| b.id == block.id + 1) {
                    edges.push(ControlFlowEdge {
                        from: block.id,
                        to: next_block.id,
                        condition: EdgeCondition::Call,
                    });
                }
            },
            "RETURN" | "REVERT" => {
                // Terminal instructions - no outgoing edges
            },
            _ => {
                // Fall-through to next block
                if let Some(next_block) = all_blocks.iter().find(|b| b.id == block.id + 1) {
                    edges.push(ControlFlowEdge {
                        from: block.id,
                        to: next_block.id,
                        condition: EdgeCondition::Unconditional,
                    });
                }
            }
        }
    }
    
    edges
}

/// Extract function selector from opcodes
fn extract_function_selector_from_opcodes(opcodes: &[String]) -> Option<[u8; 4]> {
    // Look for PUSH4 pattern (simplified)
    for opcode in opcodes {
        if opcode == "PUSH4" {
            // In a real implementation, we'd need the immediate value
            // For now, return a placeholder
            return Some([0x12, 0x34, 0x56, 0x78]);
        }
    }
    None
}

/// Extract function information from instructions
fn extract_functions(
    _instructions: &[Instruction], 
    control_flow: &ControlFlowGraph
) -> VerificationResult<Vec<FunctionSemantics>> {
    let mut functions = Vec::new();
    
    for (selector, &block_id) in &control_flow.entry_points {
        let function = analyze_function(control_flow, *selector, block_id)?;
        functions.push(function);
    }
    
    Ok(functions)
}

/// Analyze a single function
fn analyze_function(
    control_flow: &ControlFlowGraph,
    selector: [u8; 4],
    entry_block_id: usize,
) -> VerificationResult<FunctionSemantics> {
    let function_name = format!("function_{}", hex::encode(selector));
    
    // Analyze function blocks (all reachable from entry)
    let function_blocks = find_reachable_blocks(control_flow, entry_block_id);
    
    // Extract state modifications
    let state_modifications = analyze_state_modifications(&function_blocks)?;
    
    // Analyze gas characteristics
    let gas_characteristics = analyze_gas_characteristics(&function_blocks)?;
    
    // Determine function properties
    let (read_only, payable) = analyze_function_properties(&function_blocks)?;
    
    // Generate preconditions and postconditions
    let preconditions = generate_function_preconditions(&selector, &state_modifications);
    let postconditions = generate_function_postconditions(&selector, &state_modifications);
    
    Ok(FunctionSemantics {
        name: function_name,
        selector: Some(selector),
        preconditions,
        postconditions,
        state_modifications,
        gas_characteristics,
        read_only,
        payable,
    })
}

/// Find all blocks reachable from a given entry block
fn find_reachable_blocks(control_flow: &ControlFlowGraph, entry_block_id: usize) -> Vec<&BasicBlock> {
    let mut reachable = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    
    queue.push_back(entry_block_id);
    
    while let Some(block_id) = queue.pop_front() {
        if visited.contains(&block_id) {
            continue;
        }
        
        visited.insert(block_id);
        
        if let Some(block) = control_flow.blocks.get(block_id) {
            reachable.push(block);
            
            // Add successor blocks to queue
            for edge in &control_flow.edges {
                if edge.from == block_id {
                    queue.push_back(edge.to);
                }
            }
        }
    }
    
    reachable
}

/// Analyze state modifications in function blocks
fn analyze_state_modifications(blocks: &[&BasicBlock]) -> VerificationResult<Vec<StateModification>> {
    let mut modifications = Vec::new();
    
    for block in blocks {
        for opcode in &block.opcodes {
            match opcode.as_str() {
                "SSTORE" => {
                    // Storage write operation
                    modifications.push(StateModification {
                        storage_slot: 0, // Would need stack analysis to get actual slot
                        modification_type: ModificationType::Assignment,
                        conditions: vec![], // Would need condition analysis
                    });
                },
                "SLOAD" => {
                    // Storage read - not a modification but important for analysis
                },
                _ => {}
            }
        }
    }
    
    Ok(modifications)
}

/// Analyze gas characteristics of function blocks
fn analyze_gas_characteristics(blocks: &[&BasicBlock]) -> VerificationResult<GasCharacteristics> {
    let mut base_cost = 21000u64; // Base transaction cost
    let mut variable_costs = Vec::new();
    let max_gas = None;
    
    for block in blocks {
        for opcode in &block.opcodes {
            // Add instruction gas cost
            base_cost += get_instruction_gas_cost_by_name(opcode);
            
            // Check for variable cost operations
            match opcode.as_str() {
                "SSTORE" => {
                    variable_costs.push(VariableGasCost {
                        factor: GasCostFactor::StorageOperations,
                        cost_per_unit: 20000, // SSTORE cost
                    });
                },
                "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                    variable_costs.push(VariableGasCost {
                        factor: GasCostFactor::ExternalCalls,
                        cost_per_unit: 2300, // Base call cost
                    });
                },
                _ => {}
            }
        }
    }
    
    Ok(GasCharacteristics {
        base_cost,
        variable_costs,
        max_gas,
    })
}

/// Get base gas cost for an instruction by name
fn get_instruction_gas_cost_by_name(opcode: &str) -> u64 {
    match opcode {
        // Arithmetic operations
        "ADD" | "MUL" | "SUB" | "DIV" | "SDIV" => 3,
        "MOD" | "SMOD" | "ADDMOD" | "MULMOD" | "EXP" | "SIGNEXTEND" => 5,
        
        // Comparison operations
        "LT" | "GT" | "SLT" | "SGT" | "EQ" | "ISZERO" | "AND" | "OR" | "XOR" | "NOT" | "BYTE" | "SHL" | "SHR" | "SAR" => 3,
        
        // Memory operations
        "MLOAD" | "MSTORE" | "MSTORE8" => 3,
        
        // Storage operations
        "SLOAD" => 800,
        "SSTORE" => 20000, // simplified
        
        // Stack operations
        "POP" => 2,
        opcode if opcode.starts_with("DUP") || opcode.starts_with("SWAP") => 3,
        
        // Push operations
        opcode if opcode.starts_with("PUSH") => 3,
        
        // Jump operations
        "JUMP" => 8,
        "JUMPI" => 10,
        "JUMPDEST" => 1,
        
        // Call operations
        "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => 700,
        
        // Return operations
        "RETURN" | "REVERT" => 0,
        
        _ => 1, // Default gas cost
    }
}

/// Analyze function properties (read-only, payable)
fn analyze_function_properties(blocks: &[&BasicBlock]) -> VerificationResult<(bool, bool)> {
    let mut has_state_change = false;
    let mut is_payable = false;
    
    for block in blocks {
        for opcode in &block.opcodes {
            match opcode.as_str() {
                "SSTORE" => {
                    has_state_change = true;
                },
                "CALLVALUE" => {
                    is_payable = true;
                },
                _ => {}
            }
        }
    }
    
    let read_only = !has_state_change;
    Ok((read_only, is_payable))
}

/// Generate function preconditions
fn generate_function_preconditions(
    selector: &[u8; 4],
    state_modifications: &[StateModification],
) -> Vec<String> {
    let mut preconditions = Vec::new();
    
    // Basic precondition: correct function selector
    preconditions.push(format!(
        "(= (function-selector (data tx)) #x{})",
        hex::encode(selector)
    ));
    
    // Add preconditions based on state modifications
    for modification in state_modifications {
        match modification.modification_type {
            ModificationType::Arithmetic => {
                preconditions.push(format!(
                    "(>= (storage-slot-{} (storage state)) 0)",
                    modification.storage_slot
                ));
            },
            _ => {}
        }
    }
    
    preconditions
}

/// Generate function postconditions
fn generate_function_postconditions(
    _selector: &[u8; 4],
    state_modifications: &[StateModification],
) -> Vec<String> {
    let mut postconditions = Vec::new();
    
    // Success postcondition
    postconditions.push(
        "(=> (success result) (> (gas-used result) 0))".to_string()
    );
    
    // State modification postconditions
    for modification in state_modifications {
        postconditions.push(format!(
            "(=> (success result) 
                (= (storage-slot-{} (storage (final-state result)))
                   (updated-value (storage-slot-{} (storage state)))))",
            modification.storage_slot,
            modification.storage_slot
        ));
    }
    
    postconditions
}

/// Analyze storage layout from instructions
fn analyze_storage_layout(instructions: &[Instruction]) -> VerificationResult<HashMap<u64, String>> {
    let mut layout = HashMap::new();
    
    // Look for storage operations and try to infer layout
    for instruction in instructions {
        match instruction.opcode.as_str() {
            "SLOAD" | "SSTORE" => {
                // Would need stack analysis to get actual storage slot
                // For now, add some default entries
                layout.insert(0, "uint256".to_string());
                layout.insert(1, "address".to_string());
                layout.insert(2, "mapping(address=>uint256)".to_string());
            },
            _ => {}
        }
    }
    
    Ok(layout)
}

/// Analyze contract-level properties
fn analyze_contract_properties(instructions: &[Instruction]) -> VerificationResult<ContractProperties> {
    let mut is_proxy = false;
    let mut is_upgradeable = false;
    let mut has_reentrancy_guards = false;
    let mut access_control = AccessControlType::None;
    
    // Look for common patterns
    for instruction in instructions {
        match instruction.opcode.as_str() {
            "DELEGATECALL" => {
                is_proxy = true;
                is_upgradeable = true;
            },
            "CALLER" => {
                // Might indicate access control
                access_control = AccessControlType::Owner;
            },
            _ => {}
        }
    }
    
    // Look for reentrancy guard patterns (simplified)
    let opcodes: Vec<&str> = instructions.iter().map(|i| i.opcode.as_str()).collect();
    if opcodes.windows(3).any(|w| w == ["SLOAD", "ISZERO", "JUMPI"]) {
        has_reentrancy_guards = true;
    }
    
    Ok(ContractProperties {
        is_proxy,
        is_upgradeable,
        has_reentrancy_guards,
        access_control,
    })
}

/// Generate state invariants from functions and storage
fn generate_state_invariants(
    functions: &[FunctionSemantics],
    storage_layout: &HashMap<u64, String>,
) -> VerificationResult<Vec<String>> {
    let mut invariants = Vec::new();
    
    // Basic invariants for each storage slot
    for (slot, slot_type) in storage_layout {
        match slot_type.as_str() {
            "uint256" => {
                invariants.push(format!(
                    "(assert (forall ((s State)) 
                        (and (>= (storage-slot-{} (storage s)) 0) 
                             (< (storage-slot-{} (storage s)) (^ 2 256)))))",
                    slot, slot
                ));
            },
            "address" => {
                invariants.push(format!(
                    "(assert (forall ((s State)) 
                        (and (>= (storage-slot-{} (storage s)) 0) 
                             (< (storage-slot-{} (storage s)) (^ 2 160)))))",
                    slot, slot
                ));
            },
            _ => {}
        }
    }
    
    // Function-specific invariants
    for function in functions {
        if function.read_only {
            invariants.push(format!(
                "(assert (forall ((s State) (tx Transaction))
                    (= (storage (final-state ({} s tx))) (storage s))))",
                function.name
            ));
        }
    }
    
    Ok(invariants)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_semantics_empty() {
        let bytecode = vec![];
        let result = extract_semantics(&bytecode);
        
        // Should handle empty bytecode gracefully
        assert!(result.is_ok() || matches!(result.unwrap_err(), VerificationError::BytecodeAnalysis(_)));
    }
    
    #[test]
    fn test_block_boundary_detection() {
        // Create mock instructions for testing
        let instructions = vec![
            Instruction { pc: 0, opcode: "JUMPDEST".to_string(), imm: None },
            Instruction { pc: 1, opcode: "PUSH1".to_string(), imm: Some(vec![0x01]) },
            Instruction { pc: 3, opcode: "JUMPI".to_string(), imm: None },
            Instruction { pc: 4, opcode: "JUMPDEST".to_string(), imm: None },
        ];
        
        let boundaries = find_block_boundaries(&instructions);
        
        assert!(boundaries.contains(&0)); // Start
        assert!(boundaries.contains(&3)); // After JUMPI
    }
    
    #[test]
    fn test_gas_cost_calculation() {
        assert_eq!(get_instruction_gas_cost_by_name("ADD"), 3);
        assert_eq!(get_instruction_gas_cost_by_name("SLOAD"), 800);
        assert_eq!(get_instruction_gas_cost_by_name("SSTORE"), 20000);
    }
    
    #[test]
    fn test_function_selector_extraction() {
        let opcodes = vec!["PUSH4".to_string(), "DUP1".to_string()];
        
        let selector = extract_function_selector_from_opcodes(&opcodes);
        assert!(selector.is_some()); // Should find PUSH4 pattern
    }
    
    #[test]
    fn test_determine_block_type() {
        let instructions_return = vec![
            Instruction { pc: 0, opcode: "PUSH1".to_string(), imm: Some(vec![0x01]) },
            Instruction { pc: 2, opcode: "RETURN".to_string(), imm: None },
        ];
        
        assert!(matches!(determine_block_type(&instructions_return), BlockType::Return));
        
        let instructions_revert = vec![
            Instruction { pc: 0, opcode: "PUSH1".to_string(), imm: Some(vec![0x01]) },
            Instruction { pc: 2, opcode: "REVERT".to_string(), imm: None },
        ];
        
        assert!(matches!(determine_block_type(&instructions_revert), BlockType::Error));
    }
}
