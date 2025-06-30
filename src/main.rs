use axum::{
    http::StatusCode,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;
use tower_http::cors::CorsLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use base64::Engine;

// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        generate_keypair,
        create_token,
        mint_token,
        sign_message,
        verify_message,
        send_sol,
        send_token
    ),
    components(schemas(
        KeypairResponse,
        CreateTokenRequest,
        MintTokenRequest,
        SignMessageRequest,
        VerifyMessageRequest,
        SendSolRequest,
        SendTokenRequest,
        InstructionResponse,
        AccountInfo,
        SignatureResponse,
        VerificationResponse,
        SolTransferResponse,
        TokenTransferResponse,
        TokenTransferAccountInfo
    )),
    tags((name = "Solana API", description = "Solana blockchain operations"))
)]
struct ApiDoc;

// Base response structures
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// Specific response data structures
#[derive(Debug, Serialize, ToSchema)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountInfo>,
    pub instruction_data: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountInfo {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignatureResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerificationResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

// SOL transfer response with simplified accounts format
#[derive(Debug, Serialize, ToSchema)]
pub struct SolTransferResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}

// Token transfer response with different account format
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenTransferResponse {
    pub program_id: String,
    pub accounts: Vec<TokenTransferAccountInfo>,
    pub instruction_data: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenTransferAccountInfo {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

// Request structures
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

// Application state
#[derive(Clone)]
pub struct AppState;

impl AppState {
    pub fn new() -> Self {
        Self
    }
}

// Utility functions
fn keypair_from_secret(secret: &str) -> Result<Keypair, String> {
    let secret_bytes = bs58::decode(secret)
        .into_vec()
        .map_err(|_| "Invalid base58 secret key")?;
    
    if secret_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    
    Keypair::from_bytes(&secret_bytes)
        .map_err(|_| "Invalid secret key format".to_string())
}

fn pubkey_from_str(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str)
        .map_err(|_| "Invalid public key format".to_string())
}

fn account_meta_to_info(account: &AccountMeta) -> AccountInfo {
    AccountInfo {
        pubkey: account.pubkey.to_string(),
        is_signer: account.is_signer,
        is_writable: account.is_writable,
    }
}

fn account_meta_to_token_info(account: &AccountMeta) -> TokenTransferAccountInfo {
    TokenTransferAccountInfo {
        pubkey: account.pubkey.to_string(),
        is_signer: account.is_signer,
    }
}

// Validation functions
fn validate_required_fields_sign_message(payload: &SignMessageRequest) -> Result<(), String> {
    if payload.message.trim().is_empty() || payload.secret.trim().is_empty() {
        return Err("Missing required fields".to_string());
    }
    Ok(())
}

fn validate_required_fields_verify_message(payload: &VerifyMessageRequest) -> Result<(), String> {
    if payload.message.trim().is_empty() || payload.signature.trim().is_empty() || payload.pubkey.trim().is_empty() {
        return Err("Missing required fields".to_string());
    }
    Ok(())
}

fn validate_sol_transfer_inputs(payload: &SendSolRequest) -> Result<(), String> {
    if payload.from.trim().is_empty() || payload.to.trim().is_empty() {
        return Err("Invalid addresses provided".to_string());
    }
    
    if payload.lamports == 0 {
        return Err("Amount must be greater than 0".to_string());
    }
    
    // Validate that from and to are different
    if payload.from == payload.to {
        return Err("Cannot send SOL to the same address".to_string());
    }
    
    Ok(())
}

fn validate_token_transfer_inputs(payload: &SendTokenRequest) -> Result<(), String> {
    if payload.destination.trim().is_empty() || payload.mint.trim().is_empty() || payload.owner.trim().is_empty() {
        return Err("Invalid addresses provided".to_string());
    }
    
    if payload.amount == 0 {
        return Err("Amount must be greater than 0".to_string());
    }
    
    Ok(())
}

// Endpoint handlers
#[utoipa::path(
    post,
    path = "/keypair",
    responses(
        (status = 200, description = "Keypair generated successfully", body = ApiResponse<KeypairResponse>)
    )
)]
async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.to_bytes()).into_string(),
    };
    
    Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    })
}

#[utoipa::path(
    post,
    path = "/token/create",
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "Token creation instruction", body = ApiResponse<InstructionResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    // Validate mint authority
    let mint_authority = match pubkey_from_str(&payload.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid mint authority public key format".to_string()),
            })));
        }
    };

    // Validate mint address
    let mint = match pubkey_from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid mint public key format".to_string()),
            })));
        }
    };

    // Validate decimals (SPL tokens support 0-9 decimals typically)
    if payload.decimals > 9 {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Decimals must be between 0 and 9".to_string()),
        })));
    }

    // Create the initialize mint instruction
    let instruction = match initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority), // Using mint_authority as freeze_authority too
        payload.decimals,
    ) {
        Ok(instruction) => instruction,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create mint instruction: {}", e)),
            })));
        }
    };

    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(account_meta_to_info)
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    }))
}

#[utoipa::path(
    post,
    path = "/token/mint",
    request_body = MintTokenRequest,
    responses(
        (status = 200, description = "Token mint instruction", body = ApiResponse<InstructionResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    let mint = match pubkey_from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid mint public key format".to_string()),
            })));
        }
    };
    
    let destination = match pubkey_from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid destination public key format".to_string()),
            })));
        }
    };
    
    let authority = match pubkey_from_str(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid authority public key format".to_string()),
            })));
        }
    };

    let instruction = match mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(instruction) => instruction,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create mint instruction: {}", e)),
            })));
        }
    };

    let accounts: Vec<AccountInfo> = instruction.accounts
        .iter()
        .map(account_meta_to_info)
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    }))
}

#[utoipa::path(
    post,
    path = "/message/sign",
    request_body = SignMessageRequest,
    responses(
        (status = 200, description = "Message signed successfully", body = ApiResponse<SignatureResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<Json<ApiResponse<SignatureResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    // Validate required fields
    if let Err(e) = validate_required_fields_sign_message(&payload) {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })));
    }

    match keypair_from_secret(&payload.secret) {
        Ok(keypair) => {
            let message_bytes = payload.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);
            
            let response = SignatureResponse {
                signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
                public_key: keypair.pubkey().to_string(),
                message: payload.message,
            };
            
            Ok(Json(ApiResponse {
                success: true,
                data: Some(response),
                error: None,
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })))
    }
}

#[utoipa::path(
    post,
    path = "/message/verify",
    request_body = VerifyMessageRequest,
    responses(
        (status = 200, description = "Message verification result", body = ApiResponse<VerificationResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<Json<ApiResponse<VerificationResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    // Validate required fields
    if let Err(e) = validate_required_fields_verify_message(&payload) {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })));
    }

    let result = (|| -> Result<bool, String> {
        let pubkey = pubkey_from_str(&payload.pubkey)?;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&payload.signature)
            .map_err(|_| "Invalid signature format")?;
        
        if signature_bytes.len() != 64 {
            return Err("Invalid signature length".to_string());
        }
        
        let signature = Signature::from(<[u8; 64]>::try_from(signature_bytes)
            .map_err(|_| "Invalid signature format")?);
        
        let message_bytes = payload.message.as_bytes();
        Ok(signature.verify(&pubkey.to_bytes(), message_bytes))
    })();
    
    match result {
        Ok(valid) => {
            let response = VerificationResponse {
                valid,
                message: payload.message,
                pubkey: payload.pubkey,
            };
            
            Ok(Json(ApiResponse {
                success: true,
                data: Some(response),
                error: None,
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })))
    }
}

#[utoipa::path(
    post,
    path = "/send/sol",
    request_body = SendSolRequest,
    responses(
        (status = 200, description = "SOL transfer instruction", body = ApiResponse<SolTransferResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<Json<ApiResponse<SolTransferResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    // Validate inputs
    if let Err(e) = validate_sol_transfer_inputs(&payload) {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })));
    }

    let from = match pubkey_from_str(&payload.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid from address format".to_string()),
            })));
        }
    };
    
    let to = match pubkey_from_str(&payload.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid to address format".to_string()),
            })));
        }
    };

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    // Convert accounts to simplified string format as per specification
    let accounts: Vec<String> = instruction.accounts
        .iter()
        .map(|account| account.pubkey.to_string())
        .collect();

    let response = SolTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    }))
}

#[utoipa::path(
    post,
    path = "/send/token",
    request_body = SendTokenRequest,
    responses(
        (status = 200, description = "Token transfer instruction", body = ApiResponse<TokenTransferResponse>),
        (status = 400, description = "Invalid request", body = ApiResponse<String>)
    )
)]
async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<Json<ApiResponse<TokenTransferResponse>>, (StatusCode, Json<ApiResponse<String>>)> {
    // Validate inputs
    if let Err(e) = validate_token_transfer_inputs(&payload) {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
            success: false,
            data: None,
            error: Some(e),
        })));
    }

    let mint = match pubkey_from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid mint address format".to_string()),
            })));
        }
    };
    
    let owner = match pubkey_from_str(&payload.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid owner address format".to_string()),
            })));
        }
    };
    
    let destination = match pubkey_from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some("Invalid destination address format".to_string()),
            })));
        }
    };

    // Get associated token accounts
    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = match transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    ) {
        Ok(instruction) => instruction,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Failed to create transfer instruction: {}", e)),
            })));
        }
    };

    // Convert accounts to token transfer format (with isSigner field)
    let accounts: Vec<TokenTransferAccountInfo> = instruction.accounts
        .iter()
        .map(account_meta_to_token_info)
        .collect();

    let response = TokenTransferResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(Json(ApiResponse {
        success: true,
        data: Some(response),
        error: None,
    }))
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // Load .env file if it exists
    dotenv::dotenv().ok();
    
    // Get port from environment variable or use default
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    
    let app_state = AppState::new();

    // Build the router with Swagger UI
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let addr = format!("{}:{}", host, port);
    log::info!("Solana API Server running on http://{}", addr);
    log::info!("Swagger UI available at http://{}/swagger-ui/", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app).await.unwrap();
}