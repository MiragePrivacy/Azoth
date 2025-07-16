use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use azoth_core::{cfg_ir, decoder, detection, strip};
use azoth_transform::{
    jump_address_transformer::JumpAddressTransformer, opaque_predicate::OpaquePredicate, pass::run,
    shuffle::Shuffle, PassConfig, Transform,
};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info};

#[derive(Debug, Deserialize, Serialize)]
struct ObfuscateRequest {
    /// Raw bytecode as hex string (with or without 0x prefix)
    bytecode: String,
    /// Optional obfuscation options
    options: Option<ObfuscationOptions>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ObfuscationOptions {
    /// Enable instruction shuffling
    shuffle: Option<bool>,
    /// Enable opaque predicates
    opaque_predicates: Option<bool>,
    /// Enable jump address transformation
    jump_address_transform: Option<bool>,
    /// Custom seed for deterministic obfuscation
    seed: Option<u64>,
    /// Obfuscation intensity (0.0 to 1.0)
    intensity: Option<f32>,
}

impl Default for ObfuscationOptions {
    fn default() -> Self {
        Self {
            shuffle: Some(true),
            opaque_predicates: Some(true),
            jump_address_transform: Some(true),
            seed: None,
            intensity: Some(0.5),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ObfuscateResponse {
    /// Obfuscated bytecode as hex string
    obfuscated_bytecode: String,
    /// Original bytecode length in bytes
    original_size: usize,
    /// Obfuscated bytecode length in bytes
    obfuscated_size: usize,
    /// Size increase percentage
    size_increase_percentage: f64,
    /// Gas cost analysis (if available)
    gas_analysis: Option<GasAnalysis>,
    /// Obfuscation metadata
    metadata: ObfuscationMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct GasAnalysis {
    original_gas_estimate: Option<u64>,
    obfuscated_gas_estimate: Option<u64>,
    gas_overhead_percentage: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ObfuscationMetadata {
    transforms_applied: Vec<String>,
    execution_time_ms: u64,
    seed_used: u64,
    blocks_created: usize,
    instructions_added: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let app = Router::new()
        .route("/", get(health_check))
        .route("/obfuscate", post(obfuscate_bytecode))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("azoth API server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> ResponseJson<serde_json::Value> {
    ResponseJson(serde_json::json!({
        "status": "healthy",
        "service": "azoth-api",
        "version": env!("CARGO_PKG_VERSION"),
        "features": {
            "shuffle": true,
            "opaque_predicates": true,
            "jump_address_transform": true
        }
    }))
}

async fn obfuscate_bytecode(
    Json(request): Json<ObfuscateRequest>,
) -> Result<ResponseJson<ObfuscateResponse>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let start_time = std::time::Instant::now();

    info!(
        "Received obfuscation request for bytecode: {}",
        &request.bytecode[..std::cmp::min(20, request.bytecode.len())]
    );

    // Normalize bytecode input
    let bytecode = request.bytecode.trim_start_matches("0x");

    // Validate hex input
    if hex::decode(bytecode).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                error: "Invalid hex bytecode".to_string(),
                details: Some("Bytecode must be valid hexadecimal".to_string()),
            }),
        ));
    }

    let options = request.options.unwrap_or_default();

    match perform_obfuscation(bytecode, &options).await {
        Ok(result) => {
            let execution_time = start_time.elapsed();
            let size_increase = if result.original_size > 0 {
                ((result.obfuscated_size as f64 - result.original_size as f64)
                    / result.original_size as f64)
                    * 100.0
            } else {
                0.0
            };

            let response = ObfuscateResponse {
                obfuscated_bytecode: result.obfuscated_bytecode,
                original_size: result.original_size,
                obfuscated_size: result.obfuscated_size,
                size_increase_percentage: size_increase,
                gas_analysis: result.gas_analysis,
                metadata: ObfuscationMetadata {
                    transforms_applied: result.transforms_applied,
                    execution_time_ms: execution_time.as_millis() as u64,
                    seed_used: result.seed_used,
                    blocks_created: result.blocks_created,
                    instructions_added: result.instructions_added,
                },
            };

            info!(
                "Obfuscation completed in {}ms, size: {} -> {} bytes ({:.1}% increase)",
                execution_time.as_millis(),
                result.original_size,
                result.obfuscated_size,
                size_increase
            );
            Ok(ResponseJson(response))
        }
        Err(e) => {
            error!("Obfuscation failed: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(ErrorResponse {
                    error: "Obfuscation failed".to_string(),
                    details: Some(e.to_string()),
                }),
            ))
        }
    }
}

struct ObfuscationResult {
    obfuscated_bytecode: String,
    original_size: usize,
    obfuscated_size: usize,
    gas_analysis: Option<GasAnalysis>,
    transforms_applied: Vec<String>,
    seed_used: u64,
    blocks_created: usize,
    instructions_added: usize,
}

async fn perform_obfuscation(
    bytecode_hex: &str,
    options: &ObfuscationOptions,
) -> Result<ObfuscationResult, Box<dyn std::error::Error + Send + Sync>> {
    // Generate seed
    let seed = options.seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    // Step 1: Decode bytecode
    let input = format!("0x{bytecode_hex}");
    let (instructions, info, _) = decoder::decode_bytecode(&input, false).await?;
    let bytes = hex::decode(bytecode_hex)?;
    let original_size = bytes.len();

    // Step 2: Detect sections
    let sections = detection::locate_sections(&bytes, &instructions, &info)?;

    // Step 3: Strip to get runtime
    let (clean_runtime, report) = strip::strip_bytecode(&bytes, &sections)?;

    // Step 4: Build CFG-IR
    let mut cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report)?;
    let original_block_count = cfg_ir.cfg.node_count();
    let original_instruction_count: usize = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|n| {
            if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[n] {
                Some(instructions.len())
            } else {
                None
            }
        })
        .sum();

    // Step 5: Configure transformation parameters
    let intensity = options.intensity.unwrap_or(0.5).clamp(0.0, 1.0);
    let config = PassConfig {
        accept_threshold: 0.0, // Accept all transforms for now
        aggressive: intensity > 0.7,
        max_size_delta: intensity, // Allow more size increase with higher intensity
        max_opaque_ratio: intensity * 0.5, // Scale opaque predicates with intensity
    };

    // Step 6: Create transform pipeline
    let mut transforms: Vec<Box<dyn Transform>> = Vec::new();
    let mut transforms_applied = Vec::new();

    // Add enabled transforms
    if options.shuffle.unwrap_or(true) {
        transforms.push(Box::new(Shuffle));
        transforms_applied.push("instruction_shuffle".to_string());
    }

    if options.opaque_predicates.unwrap_or(true) {
        transforms.push(Box::new(OpaquePredicate::new(config.clone())));
        transforms_applied.push("opaque_predicates".to_string());
    }

    if options.jump_address_transform.unwrap_or(true) {
        transforms.push(Box::new(JumpAddressTransformer::new(config.clone())));
        transforms_applied.push("jump_address_transform".to_string());
    }

    // Step 7: Apply transforms
    if !transforms.is_empty() {
        run(&mut cfg_ir, &transforms, &config, seed).await?;
    }

    // Calculate transformation metrics
    let final_block_count = cfg_ir.cfg.node_count();
    let final_instruction_count: usize = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|n| {
            if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[n] {
                Some(instructions.len())
            } else {
                None
            }
        })
        .sum();

    let blocks_created = final_block_count.saturating_sub(original_block_count);
    let instructions_added = final_instruction_count.saturating_sub(original_instruction_count);

    // Step 8: Extract instructions and encode back to bytecode
    let mut all_instructions = Vec::new();

    // Collect all instructions from the CFG in execution order
    let mut visited = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();

    // Find entry block
    if let Some(entry_idx) = cfg_ir
        .cfg
        .node_indices()
        .find(|&n| matches!(cfg_ir.cfg[n], azoth_core::cfg_ir::Block::Entry))
    {
        queue.push_back(entry_idx);
    }

    // BFS traversal to collect instructions in execution order
    while let Some(current) = queue.pop_front() {
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);

        if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[current] {
            all_instructions.extend(instructions.clone());
        }

        // Add children to queue
        for edge in cfg_ir.cfg.edges(current) {
            if !visited.contains(&edge.target()) {
                queue.push_back(edge.target());
            }
        }
    }

    // If BFS didn't work (shouldn't happen), fall back to collecting all instructions
    if all_instructions.is_empty() {
        for node_idx in cfg_ir.cfg.node_indices() {
            if let azoth_core::cfg_ir::Block::Body { instructions, .. } = &cfg_ir.cfg[node_idx] {
                all_instructions.extend(instructions.clone());
            }
        }
    }

    // Encode instructions back to bytecode
    let obfuscated_bytes = if all_instructions.is_empty() {
        // Fallback to original clean runtime if no instructions were collected
        clean_runtime
    } else {
        azoth_core::encoder::encode(&all_instructions)
            .map_err(|e| format!("Failed to encode obfuscated instructions: {e}"))?
    };

    // Step 9: Reassemble with non-runtime sections if needed
    let final_bytecode = cfg_ir.clean_report.reassemble(&obfuscated_bytes);
    let obfuscated_bytecode = format!("0x{}", hex::encode(&final_bytecode));

    Ok(ObfuscationResult {
        obfuscated_bytecode,
        original_size,
        obfuscated_size: final_bytecode.len(),
        gas_analysis: None, // TODO: Implement gas analysis
        transforms_applied,
        seed_used: seed,
        blocks_created,
        instructions_added,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_check() {
        let app = Router::new().route("/health", get(health_check));
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<serde_json::Value>();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["service"], "azoth-api");
    }

    #[tokio::test]
    async fn test_obfuscate_simple_bytecode() {
        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode));
        let server = TestServer::new(app).unwrap();

        let request = ObfuscateRequest {
            bytecode: "0x6001600255".to_string(), // PUSH1 1, PUSH1 2, SSTORE
            options: Some(ObfuscationOptions {
                shuffle: Some(false),           // Disable shuffle for predictable test
                opaque_predicates: Some(false), // Disable for simpler test
                jump_address_transform: Some(false),
                seed: Some(42), // Fixed seed for reproducibility
                intensity: Some(0.1),
            }),
        };

        let response = server.post("/obfuscate").json(&request).await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<ObfuscateResponse>();
        assert!(body.obfuscated_bytecode.starts_with("0x"));
        assert!(body.original_size > 0);
    }

    #[tokio::test]
    async fn test_invalid_bytecode() {
        let app = Router::new().route("/obfuscate", post(obfuscate_bytecode));
        let server = TestServer::new(app).unwrap();

        let request = ObfuscateRequest {
            bytecode: "0xZZZZ".to_string(), // Invalid hex
            options: None,
        };

        let response = server.post("/obfuscate").json(&request).await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        let body = response.json::<ErrorResponse>();
        assert!(body.error.contains("Invalid hex bytecode"));
    }
}
