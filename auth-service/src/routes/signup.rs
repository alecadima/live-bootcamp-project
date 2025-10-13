use crate::{app_state::AppState,
            domain::{error::AuthAPIError, user::User}};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

pub async fn signup(
    // TODO: Use Axum's state extractor to pass in AppState
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    // TODO: early return AuthAPIError::InvalidCredentials if:
    // - email is empty or does not contain '@'
    // - password is less than 8 characters
    if email.is_empty() || !email.contains('@') || password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }
    // Create a new `User` instance using data in the `request`
    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // TODO: early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    if user_store.get_user(user.email.as_ref()).is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // TODO: Add `user` to the `user_store`. Simply unwrap the returned `Result` enum type for now.
    // TODO: instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    user_store.add_user(user).map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
