#![allow(dead_code)]
use std::time::Duration;
use bluer::{Adapter, Address, Device, gatt::remote::Characteristic};
use anyhow::{Result, bail, Context};
use futures::StreamExt;

use crate::constants::{
    KEY_BASED_PAIRING_CHAR_UUID, MODEL_ID_CHAR_UUID,
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_NOTIFICATION_TIMEOUT,
};
use crate::crypto::{aes_128_encrypt, aes_128_decrypt, generate_random_salt};
use crate::protocol::{
    KeyBasedPairingRequest, KeyBasedPairingResponse,
    parse_bluetooth_address, parse_kbp_response_multi_strategy,
};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success: bool,
    pub provider_address: Option<String>,
    pub error: Option<String>,
    pub raw_response: Option<Vec<u8>>,
    pub response_received: bool,
}

pub struct FastPairClient {
    adapter: Adapter,
    address: Address,
    connection_timeout: Duration,
    notification_timeout: Duration,
}

impl FastPairClient {
    pub fn new(
        adapter: Adapter,
        address: Address,
        connection_timeout: Option<Duration>,
        notification_timeout: Option<Duration>,
    ) -> Self {
        Self {
            adapter,
            address,
            connection_timeout: connection_timeout
                .unwrap_or_else(|| Duration::from_secs_f64(DEFAULT_CONNECTION_TIMEOUT)),
            notification_timeout: notification_timeout
                .unwrap_or_else(|| Duration::from_secs_f64(DEFAULT_NOTIFICATION_TIMEOUT)),
        }
    }

    pub fn address_str(&self) -> String {
        self.address.to_string()
    }

    async fn get_device(&self) -> Result<Device> {
        self.adapter.device(self.address).context("Failed to get device")
    }

    async fn connect_device(&self) -> Result<Device> {
        let device = self.get_device().await?;
        if !device.is_connected().await? {
            tokio::time::timeout(self.connection_timeout, device.connect())
                .await
                .context("Connection timed out")?
                .context("Failed to connect to device")?;
        }
        Ok(device)
    }

    async fn find_characteristic(
        device: &Device,
        char_uuid_str: &str,
    ) -> Result<Characteristic> {
        let target_uuid: uuid::Uuid = char_uuid_str.parse()
            .context("Invalid characteristic UUID")?;

        for service in device.services().await? {
            for char in service.characteristics().await? {
                if char.uuid().await? == target_uuid {
                    return Ok(char);
                }
            }
        }
        bail!("Characteristic {} not found", char_uuid_str)
    }

    pub async fn read_model_id(&self) -> Result<Option<u32>> {
        let device = self.connect_device().await?;
        let char = Self::find_characteristic(&device, MODEL_ID_CHAR_UUID).await?;
        let data = char.read().await?;
        if data.len() >= 3 {
            let model_id = u32::from_be_bytes([0, data[0], data[1], data[2]]);
            return Ok(Some(model_id));
        }
        Ok(None)
    }

    pub async fn send_raw_pairing_probe(&self, encrypted_data: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        let device = self.connect_device().await?;
        let char = Self::find_characteristic(&device, KEY_BASED_PAIRING_CHAR_UUID).await?;

        let notify_stream = char.notify().await
            .context("Failed to start notifications")?;
        futures::pin_mut!(notify_stream);

        char.write(encrypted_data).await
            .context("Failed to write to KBP characteristic")?;

        let response = tokio::time::timeout(
            self.notification_timeout,
            notify_stream.next(),
        )
        .await
        .ok()
        .flatten();

        Ok(response)
    }

    pub async fn send_key_based_pairing_request(
        &self,
        request: &KeyBasedPairingRequest,
        aes_key: &[u8; 16],
    ) -> Result<Option<KeyBasedPairingResponse>> {
        let plaintext = request.build();
        let encrypted = aes_128_encrypt(aes_key, &plaintext);
        let raw_response = self.send_raw_pairing_probe(&encrypted).await?;

        if let Some(resp_bytes) = raw_response {
            if resp_bytes.len() == 16 {
                let mut ct = [0u8; 16];
                ct.copy_from_slice(&resp_bytes);
                let decrypted = aes_128_decrypt(aes_key, &ct);
                return Ok(Some(KeyBasedPairingResponse::parse(&decrypted)?));
            }
        }
        Ok(None)
    }

    pub async fn verify_pairing_behavior(
        &self,
        aes_key: Option<&[u8; 16]>,
        seeker_address: Option<[u8; 6]>,
    ) -> VerificationResult {
        let provider_addr_bytes = match parse_bluetooth_address(&self.address_str()) {
            Ok(b) => b,
            Err(e) => return VerificationResult {
                success: false,
                provider_address: None,
                error: Some(e.to_string()),
                raw_response: None,
                response_received: false,
            },
        };

        let salt = generate_random_salt(8);
        let mut request = KeyBasedPairingRequest::for_verification(provider_addr_bytes, seeker_address);
        request.salt = Some(salt.clone());

        let zero_key = [0u8; 16];
        let key = aes_key.unwrap_or(&zero_key);
        let plaintext = request.build();
        let encrypted_request = aes_128_encrypt(key, &plaintext);

        let mut salt_based_secret = [0u8; 16];
        salt_based_secret[..8.min(salt.len())].copy_from_slice(&salt[..8.min(salt.len())]);

        match self.send_raw_pairing_probe(&encrypted_request).await {
            Ok(Some(raw_response)) => {
                let secret_slice: &[u8] = aes_key
                    .map(|k| k as &[u8])
                    .unwrap_or(&salt_based_secret);

                let provider_address_str = parse_kbp_response_multi_strategy(
                    &raw_response,
                    Some(secret_slice),
                );

                VerificationResult {
                    success: true,
                    response_received: true,
                    provider_address: provider_address_str,
                    raw_response: Some(raw_response),
                    error: None,
                }
            }
            Ok(None) => VerificationResult {
                success: false,
                response_received: false,
                provider_address: None,
                error: Some("No response from device (not vulnerable or not reachable)".to_string()),
                raw_response: None,
            },
            Err(e) => VerificationResult {
                success: false,
                response_received: false,
                provider_address: None,
                error: Some(e.to_string()),
                raw_response: None,
            },
        }
    }
}
