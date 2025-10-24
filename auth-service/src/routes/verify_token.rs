use crate::domain::AuthAPIError;
use crate::utils::auth;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = request.token;
    let claims = match auth::validate_token(&token).await {
        Ok(claims) => claims,
        Err(_) => return Err(AuthAPIError::InvalidToken),
    };

    println!("{}", claims.sub);

    Ok(StatusCode::OK.into_response())
}
#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
