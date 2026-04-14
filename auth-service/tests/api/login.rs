use crate::helpers::{get_random_email, TestApp};
use auth_service::domain::Email;
use auth_service::routes::TwoFactorAuthResponse;
use auth_service::utils::constants::JWT_COOKIE_NAME;
use auth_service::ErrorResponse;
use secrecy::{ExposeSecret, SecretString};
use test_helpers::api_test;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[api_test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[api_test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/emails"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    // assert that `json_body.login_attempt_id` is stored inside `app.two_fa_code_store`
    let two_fa_code_store = app.two_fa_code_store.read().await;

    let code_tuple = two_fa_code_store
        .get_code(&Email::parse(SecretString::new(random_email.into_boxed_str())).unwrap())
        .await
        .expect("Failed to get 2FA code");

    assert_eq!(
        code_tuple.0.as_ref().expose_secret(),
        &json_body.login_attempt_id
    );
}

#[api_test]
async fn should_return_422_if_malformed_credentials() {

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
                        "password": "password123",
        }),
        serde_json::json!({
                        "email": random_email,
        }),
    ];

    for test_case in test_cases {
        let response = app.post_login(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[api_test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.

    let email = "@test.com".to_string();

    let test_cases = [
        serde_json::json!({
                        "email": "teste#gmail.com",
                        "password": "password123",
        }),
        serde_json::json!({
                        "email": "test@test.com",
                        "password": "1234",
        }),
        serde_json::json!({
                        "email": "test#test.com",
                        "password": "1234",
        }),
    ];

    for test_case in test_cases {
        let response = app.post_login(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
    let response = app
        .post_login(&serde_json::json!({
            "email": email,
            "password": "password123",
        }))
        .await;

    assert_eq!(response.status().as_u16(), 400);
}

#[api_test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.

    let random_email = get_random_email();

    let response = app
        .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": false
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app
        .post_login(&serde_json::json!({
            "email": random_email,
            "password": "wrong password",
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}
