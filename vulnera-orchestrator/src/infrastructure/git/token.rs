use std::future::Future;

tokio::task_local! {
    static GIT_REQUEST_TOKEN: String;
}

/// Scope a request-scoped Git token for the lifetime of the provided future.
pub async fn with_request_git_token<F, T>(token: String, fut: F) -> T
where
    F: Future<Output = T>,
{
    GIT_REQUEST_TOKEN.scope(token, fut).await
}

/// Retrieve the Git token, if one has been scoped for the current task.
pub fn current_request_git_token() -> Option<String> {
    GIT_REQUEST_TOKEN.try_with(|token| token.clone()).ok()
}
