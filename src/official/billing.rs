// Furtherance Sync
// Copyright (C) 2025  Ricky Kresslein <rk@unobserved.io>
//
// This code is licensed under the Elastic License 2.0.
// For details: https://www.elastic.co/licensing/elastic-license

use std::str::FromStr;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use stripe::{CustomerId, Webhook};
use tracing::{debug, error};

use crate::{database, middleware::AuthUser, models::AppState};

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
            // More specific error logging
            if body.is_empty() {
                error!("Empty webhook body received");
            } else {
                error!("Failed to verify webhook signature: {}", e);
                debug!("Webhook body preview: {:.100}...", body);
            }
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

            let verification_token = match session.client_reference_id {
                Some(token) => token,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            let subscription_id = match session.subscription {
                Some(stripe::Expandable::Id(id)) => id,
                Some(stripe::Expandable::Object(sub)) => sub.id,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Fetch the subscription to get its status and details
            let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
                Ok(key) => key,
                Err(_) => {
                    error!("STRIPE_SECRET_KEY not set");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let client = stripe::Client::new(stripe_key);

            let subscription =
                match stripe::Subscription::retrieve(&client, &subscription_id, &[]).await {
                    Ok(sub) => sub,
                    Err(e) => {
                        error!("Failed to retrieve subscription: {}", e);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
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

            // Create user with subscription details
            if let Err(e) = database::create_user_with_subscription(
                &state.db,
                &temp_reg.email,
                &temp_reg.password_hash,
                &customer_id,
                &subscription.status.to_string(),
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
        stripe::EventType::CustomerSubscriptionDeleted
        | stripe::EventType::CustomerSubscriptionUpdated => {
            let subscription = match event.data.object {
                stripe::EventObject::Subscription(subscription) => subscription,
                _ => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Get the customer ID from the subscription
            let customer_id = match subscription.customer {
                stripe::Expandable::Id(id) => id,
                stripe::Expandable::Object(customer) => customer.id,
            };

            // Update subscription status in database
            let status = subscription.status.to_string();

            if let Err(e) =
                database::update_subscription_status(&state.db, &customer_id, status).await
            {
                error!("Failed to update subscription status: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            StatusCode::OK.into_response()
        }
        _ => StatusCode::OK.into_response(),
    }
}

pub async fn redirect_to_customer_portal(
    State(state): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Response {
    let customer_id = match database::get_stripe_customer_id(&state.db, user_id).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            error!("Failed to get customer_id: (Ok(None))");
            return Redirect::to("/encryption").into_response();
        }
        Err(e) => {
            error!("Failed to get customer_id: {}", e);
            return Redirect::to("/encryption").into_response();
        }
    };

    let stripe_secret_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => return Redirect::to("/encryption").into_response(),
    };
    let client = stripe::Client::new(stripe_secret_key);

    // Create customer portal session
    let return_url = "https://sync.furtherance.app/encryption";
    let customer_id = match CustomerId::from_str(&customer_id) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid Stripe customer ID format: {}", e);
            return Redirect::to("/encryption").into_response();
        }
    };

    match stripe::BillingPortalSession::create(
        &client,
        stripe::CreateBillingPortalSession {
            customer: customer_id,
            return_url: Some(return_url),
            configuration: None,
            expand: &[],
            flow_data: None,
            locale: None,
            on_behalf_of: None,
        },
    )
    .await
    {
        Ok(session) => Redirect::to(&session.url).into_response(),
        Err(e) => {
            error!("Failed to create Stripe portal session: {}", e);
            Redirect::to("/encryption").into_response()
        }
    }
}
