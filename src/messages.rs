use serde::{Deserialize, Serialize};
use axum::extract::ws::Message as WsMessage;

#[derive(Debug, Clone)]
pub enum AppMessage {
    Text(String),
    Close,
}

impl From<AppMessage> for WsMessage {
    fn from(app_msg: AppMessage) -> Self {
        match app_msg {
            AppMessage::Text(s) => WsMessage::Text(s.into()),
            AppMessage::Close => WsMessage::Close(None),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum ClientMessage {
    #[serde(rename = "auth")]
    Auth { token: String },

    #[serde(rename = "text")]
    Text { to: String, text: String },
    File { to: String, url: String },
}
