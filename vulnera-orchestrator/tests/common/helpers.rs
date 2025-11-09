//! Test helper functions for vulnera-orchestrator

use axum::http::StatusCode;
use axum_test::TestResponse;

/// Assert HTTP response is successful
pub fn assert_success(response: &TestResponse) {
    assert!(
        response.status_code().is_success(),
        "Expected success, got: {}",
        response.status_code()
    );
}

/// Assert HTTP response has specific status code
pub fn assert_status(response: &TestResponse, expected: StatusCode) {
    assert_eq!(
        response.status_code(),
        expected,
        "Expected status {}, got {}",
        expected,
        response.status_code()
    );
}

