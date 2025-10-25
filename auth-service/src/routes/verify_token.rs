use crate::app_state::AppState;
use crate::domain::AuthAPIError;
use crate::utils::auth;
use auth::validate_token;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError> {
    match validate_token(&request.token, state.banned_token_store.clone()).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
#[derive(Deserialize, Debug)]
pub struct VerifyTokenRequest {
    pub token: String,
}
