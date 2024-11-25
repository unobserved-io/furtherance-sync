use axum::{
    async_trait,
    body::Body,
    extract::{FromRequestParts, State},
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::CookieJar;

use crate::{auth::verify_access_token, database, models::AppState};

pub async fn web_auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for public routes
    let path = request.uri().path();
    if is_public_route(path) {
        return next.run(request).await;
    }

    // Check for valid session
    if let Some(session_cookie) = jar.get("session") {
        if let Ok(user_id) = session_cookie.value().parse::<i32>() {
            // For official version, check subscription status
            #[cfg(feature = "official")]
            if let Ok(is_active) = database::is_subscription_active(&state.db, user_id).await {
                if !is_active {
                    return axum::response::Redirect::to("/login").into_response();
                }
            }
            return next.run(request).await;
        }
    }

    axum::response::Redirect::to("/login").into_response()
}

// In middleware.rs
pub async fn api_auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for public API routes
    let path = request.uri().path();
    if is_public_api_route(path) {
        return next.run(request).await;
    }

    // Check for valid Bearer token
    let auth_result = if let Some(auth_header) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            let token = auth_str.replace("Bearer ", "");
            verify_access_token(&token).ok()
        } else {
            None
        }
    } else {
        None
    };

    match auth_result {
        Some(user_id) => {
            // For official version, check subscription status
            #[cfg(feature = "official")]
            if let Ok(is_active) = database::is_subscription_active(&state.db, user_id).await {
                if !is_active {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": "inactive_subscription",
                            "message": "Your subscription is not active"
                        })),
                    )
                        .into_response();
                }
            }
            next.run(request).await
        }
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

// Helper functions to determine which routes should skip auth
fn is_public_route(path: &str) -> bool {
    matches!(
        path,
        "/login" | "/register" | "/forgot-password" | "/reset-password" | "/static"
    )
}

fn is_public_api_route(path: &str) -> bool {
    matches!(path, "/api/login" | "/api/register")
}

// Extractor for getting authenticated user ID
pub struct AuthUser(pub i32);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // First try web session
        let jar = CookieJar::from_headers(&parts.headers);
        if let Some(session_cookie) = jar.get("session") {
            if let Ok(user_id) = session_cookie.value().parse::<i32>() {
                return Ok(AuthUser(user_id));
            }
        }

        // Then try API token
        if let Some(auth_header) = parts.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                let token = auth_str.replace("Bearer ", "");
                if let Ok(user_id) = verify_access_token(&token) {
                    return Ok(AuthUser(user_id));
                }
            }
        }

        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}
