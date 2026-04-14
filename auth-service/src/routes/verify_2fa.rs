use crate::app_state::AppState;
use crate::domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode};
use crate::utils::auth::generate_auth_cookie;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>, // New!
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    }; // Validate the email in `request`

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(two_fa_code) => two_fa_code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    // New!
    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    // Call `two_fa_code_store.get_code`. If the call fails,
    // return a `AuthAPIError::IncorrectCredentials`.
    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok(code_tuple) => code_tuple,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };
    // Validate that the `login_attempt_id` and `two_fa_code`
    // in the request body matches values in the `code_tuple`.
    // If not, return an `AuthAPIError::IncorrectCredentials`.
    if !code_tuple.0.eq(&login_attempt_id) || !code_tuple.1.eq(&two_fa_code) {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    if let Err(e) = two_fa_code_store.remove_code(&email).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(()))
}

#[derive(Deserialize, Debug)]
pub struct Verify2FARequest {
    pub email: SecretString,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: SecretString,
    #[serde(rename = "2FACode")]
    pub two_fa_code: SecretString,
}
