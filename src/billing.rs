// Furtherance Sync
// Copyright (C) 2024  Ricky Kresslein <rk@unobserved.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use stripe::Webhook;
use tracing::error;

use crate::{database, models::AppState};

pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // Get Stripe signature from headers
    let stripe_signature = match headers.get("Stripe-Signature") {
        Some(sig) => match sig.to_str() {
            Ok(sig) => sig,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Get webhook secret from environment
    let webhook_secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            error!("STRIPE_WEBHOOK_SECRET not set");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Verify webhook signature
    let event = match Webhook::construct_event(&body, stripe_signature, &webhook_secret) {
        Ok(event) => event,
        Err(e) => {
            error!("Failed to verify webhook signature: {}", e);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Handle different event types
    match event.type_ {
        stripe::EventType::CheckoutSessionCompleted => {
            let session = match event.data.object {
                stripe::EventObject::CheckoutSession(session) => session,
                _ => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Extract customer ID and client reference (verification token)
            let customer_id = match session.customer {
                Some(customer) => customer.id(),
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            let customer_email = match session.customer_email {
                Some(email) => email,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            let verification_token = match session.client_reference_id {
                Some(token) => token,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            let temp_reg =
                match database::get_temporary_registration(&state.db, &verification_token).await {
                    Ok(Some(reg)) => reg,
                    Ok(None) => {
                        error!(
                            "No temporary registration found for token: {}",
                            verification_token
                        );
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    Err(e) => {
                        error!("Database error: {}", e);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };

            if let Err(e) = database::create_user_with_stripe(
                &state.db,
                &temp_reg.email,
                &temp_reg.password_hash,
                &customer_id,
            )
            .await
            {
                error!("Failed to create user: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            if let Err(e) =
                database::mark_temp_registration_used(&state.db, &verification_token).await
            {
                error!("Failed to mark registration as used: {}", e);
                // Continue since user was created
            }

            StatusCode::OK.into_response()
        }
        _ => StatusCode::OK.into_response(),
    }
}
