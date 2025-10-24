use crate::helpers::TestApp;
use auth_service::domain::Email;
use auth_service::utils::generate_auth_cookie;
use auth_service::ErrorResponse;

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let random_email = Email::parse(TestApp::get_random_email()).unwrap();

    let token = match generate_auth_cookie(&random_email) {
        Ok(cookie) => cookie.value().to_owned(),
        Err(_) => panic!("Failed to generate auth cookie"),
    };

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let body = serde_json::json!({
        "token": "invalid-token",
    });

    let response = app.post_verify_token(&body).await;
    assert_eq!(response.status().as_u16(), 401);

    let body = response.json::<ErrorResponse>().await.unwrap();
    assert_eq!(body.error, "Invalid token");
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
                        "token": 1234,
        }),
        serde_json::json!({
                        "not-token": "not-token",
        }),
    ];

    for test_case in test_cases {
        let response = app.post_verify_token(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}
