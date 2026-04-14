use crate::app_state::AppState;
use crate::domain::{AuthAPIError, Email, HashedPassword, LoginAttemptId, TwoFACode};
use crate::utils::auth;
use auth::generate_auth_cookie;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email: Email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    match HashedPassword::parse(request.password.clone()).await {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = &state.user_store.read().await;

    if user_store
        .validate_user(&email, &request.password)
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    };

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Handle request based on the user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

// New!
#[tracing::instrument(name = "Handle 2FA flow", skip_all)]
async fn handle_2fa(
    email: &Email,    // New!
    state: &AppState, // New!
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    if let Err(e) = state
        .two_fa_code_store
        .write()
        .await
        .add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    // send 2FA code via the email client. Return `AuthAPIError::UnexpectedError` if the operation fails.
    if let Err(e) = state
        .email_client
        .send_email(
            email,
            "2FA Authentication Code",
            two_fa_code.as_ref().expose_secret(),
        )
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e)));
    }

    // Finally, we need to return the login attempt ID to the client
    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().expose_secret().to_owned(), // Add the generated login attempt ID
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

// New!
#[tracing::instrument(name = "Handle non-2FA flow", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    let updated_jar = jar.add(auth_cookie);

    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: SecretString,
    password: SecretString,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}
