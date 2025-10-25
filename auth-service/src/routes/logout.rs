use crate::app_state::AppState;
use crate::{
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};
use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie, CookieJar};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken if the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // If the token is valid, you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.
    let _ = match validate_token(&token, state.banned_token_store.clone()).await {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };

    if state
        .banned_token_store
        .write()
        .await
        .add_token(token.to_owned())
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    // Remove JWT cookie from the CookieJar
    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));

    (jar, Ok(StatusCode::OK))
}
