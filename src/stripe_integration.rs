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

// use std::error::Error;
// use std::str::FromStr;

// use stripe::{CheckoutSessionMode, Client, CreateCheckoutSession, PriceId};

// pub async fn create_stripe_checkout_session(
//     email: &str,
//     verification_token: &str,
// ) -> Result<String, Box<dyn Error>> {
//     let client = Client::new(std::env::var("STRIPE_SECRET_KEY")?);

//     let mut session = CreateCheckoutSession::new();
//     session.mode = Some(CheckoutSessionMode::Subscription);
//     session.success_url = Some(&format!(
//         "https://sync.furtherance.app/register/complete?token={}",
//         verification_token
//     ));
//     session.cancel_url = Some("https://sync.furtherance.app/register");
//     session.customer_email = Some(email);
//     session.line_items = Some(vec![stripe::CreateCheckoutSessionLineItems {
//         price: PriceId::from_str("price_YOUR_PRICE_ID_HERE").unwrap(),
//         quantity: Some(1),
//         ..Default::default()
//     }]);

//     let session = session.create(&client).await?;
//     Ok(session.url.unwrap_or_default())
// }
