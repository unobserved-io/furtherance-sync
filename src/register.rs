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

use std::collections::HashMap;

use actix_web::{http::header, web, HttpResponse, Responder};
use askama::Template;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Deserialize;

use crate::{
    create_user,
    login::{Claims, FUR_SECRET_KEY},
    AppState,
};

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    error_msg: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
}

pub async fn show_register(query: web::Query<HashMap<String, String>>) -> impl Responder {
    let error_msg = query.get("error").map(|e| e.to_string());
    let html = RegisterTemplate { error_msg }.render().unwrap();
    HttpResponse::Ok().content_type("text/html").body(html)
}

pub async fn handle_register_form(
    data: web::Data<AppState>,
    form: web::Form<RegisterForm>,
) -> impl Responder {
    match create_user(&data.db, &form.email, &form.password).await {
        Ok(user_id) => {
            let claims = Claims {
                sub: user_id,
                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };

            match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(FUR_SECRET_KEY),
            ) {
                Ok(_) => HttpResponse::Found()
                    .append_header((header::LOCATION, "/login?message=Registration successful"))
                    .finish(),
                Err(_) => HttpResponse::Found()
                    .append_header((header::LOCATION, "/register?error=Internal server error"))
                    .finish(),
            }
        }
        Err(_) => HttpResponse::Found()
            .append_header((header::LOCATION, "/register?error=Could not create user"))
            .finish(),
    }
}
