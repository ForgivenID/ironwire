use rand_core::{RngCore, OsRng};
use ed25519_dalek::{VerifyingKey, Signature, PUBLIC_KEY_LENGTH, Verifier};
use hex;
use serde_json::json;
use axum::extract::ws::{Message, Utf8Bytes};

pub struct AuthChallenge {
    pub challenge: [u8; 32],
    pub public_key: VerifyingKey,
}

#[derive(Debug)]
pub enum AuthError {
    InvalidPublicKey,
    InvalidSignatureLength,
    InvalidSignatureFormat,
    VerificationFailed,
}

impl AuthChallenge {
    pub fn new(public_key_bytes: &[u8]) -> Result<(Self, Message), AuthError> {
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(AuthError::InvalidPublicKey);
        }

        let public_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|_| AuthError::InvalidPublicKey)?;

        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);

        let auth_challenge = AuthChallenge {
            challenge,
            public_key,
        };

        let msg = json!({
            "type": "auth_challenge",
            "challenge": hex::encode(challenge)
        });
        let ws_msg = Message::Text(Utf8Bytes::from(msg.to_string()));

        Ok((auth_challenge, ws_msg))
    }

    pub fn verify(&self, sig_bytes: &[u8]) -> Result<(), AuthError> {
        if sig_bytes.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(AuthError::InvalidSignatureLength);
        }

        let sig_array: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| AuthError::InvalidSignatureFormat)?;

        let signature = Signature::from(sig_array);

        self.public_key.verify(&self.challenge, &signature)
            .map_err(|_| AuthError::VerificationFailed)
    }

    pub fn client_id(&self) -> String {
        hex::encode(self.public_key.as_bytes())
    }
}