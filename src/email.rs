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

use lettre::{
    transport::smtp::authentication::Credentials, transport::smtp::PoolConfig, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};

pub struct EmailConfig {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    from_email: String,
    from_name: String,
}

impl EmailConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            smtp_host: std::env::var("SMTP_HOST")?,
            smtp_port: std::env::var("SMTP_PORT")?.parse().unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME")?,
            smtp_password: std::env::var("SMTP_PASSWORD")?,
            from_email: std::env::var("FROM_EMAIL")?,
            from_name: std::env::var("FROM_NAME")?,
        })
    }

    pub fn create_transport(&self) -> AsyncSmtpTransport<Tokio1Executor> {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)
            .unwrap()
            .port(self.smtp_port)
            .credentials(Credentials::new(
                self.smtp_username.clone(),
                self.smtp_password.clone(),
            ))
            .pool_config(PoolConfig::new().max_size(20))
            .build()
    }
}

pub async fn send_password_reset_email(
    config: &EmailConfig,
    to_email: &str,
    reset_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reset_url = format!(
        "https://sync.furtherance.app/reset-password?token={}",
        reset_token
    );

    let email = Message::builder()
        .from(format!("{} <{}>", config.from_name, config.from_email).parse()?)
        .to(to_email.parse()?)
        .subject("Reset Your Furtherance Password")
        .body(format!(
            "Hello,\n\n\
            You recently requested to reset your password for your Furtherance account. \
            Click the link below to reset it:\n\n\
            {}\n\n\
            This link will expire in 1 hour.\n\n\
            If you did not request a password reset, please ignore this email.\n\n\
            Sincerely,\n\
            The Furtherance Team",
            reset_url
        ))?;

    let mailer = config.create_transport();
    mailer.send(email).await?;

    Ok(())
}
