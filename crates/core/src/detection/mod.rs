/// Module for detecting and classifying bytecode regions (Init, Runtime, ConstructorArgs,
/// Auxdata, Padding) as part of BOSC Step 1 preprocessing.
///
/// This module implements the structural analysis of EVM bytecode to extract runtime bytecode,
/// remove deployment and auxdata bytecode, and provide exact byte-ranges for subsequent stages
/// (e.g., stripping and recovery). It uses raw bytes, decoded instructions, and metadata from
/// `decoder.rs` to identify logical regions based on opcode patterns and byte-level
/// signatures.
///
/// # Usage
/// ```rust,ignore
/// use detection::sections::locate_sections;
/// use detection::dispatcher::detect_function_dispatcher;
///
/// let (instructions, _, _) = decoder::decode_bytecode("0x60016002", false).await.unwrap();
/// let sections = locate_sections(&hex::decode("60016002").unwrap(), &instructions).unwrap();
/// assert!(!sections.is_empty());
/// ```
pub mod dispatcher;
pub mod sections;

pub use dispatcher::{
    DispatcherInfo, ExtractionPattern, FunctionSelector, detect_function_dispatcher, has_dispatcher,
};

pub use sections::{
    Section, SectionKind, extract_runtime_instructions, locate_sections, validate_sections,
};
