#![allow(dead_code)]

use anyhow::{Result, bail, Context};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;

const NEARBY_API_BASE: &str = "https://nearbydevices-pa.googleapis.com/v1/device";
const NEARBY_API_KEY: &str = "AIzaSyDZNqlAMsRFsWBvSBfoFJgFzNtQkGxkVOw";

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    device: Option<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo {
    anti_spoofing_key_pair: Option<AntiSpoofingKeyPair>,
    name: Option<String>,
    #[serde(rename = "type")]
    device_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AntiSpoofingKeyPair {
    public_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceAntiSpoofingInfo {
    pub public_key_bytes: [u8; 64],
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub model_id: u32,
}

pub async fn fetch_anti_spoofing_key(model_id: u32) -> Result<DeviceAntiSpoofingInfo> {
    let url = format!(
        "{}?key={}&fields=device.antiSpoofingKeyPair.publicKey,device.name,device.type",
        format!("{}/{}", NEARBY_API_BASE, model_id),
        NEARBY_API_KEY,
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Failed to reach Google Nearby API")?;

    let status = response.status();
    if !status.is_success() {
        bail!(
            "Google API returned HTTP {}: model 0x{:06X} may not be registered",
            status,
            model_id
        );
    }

    let body: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse Google API response as JSON")?;

    let public_key_b64 = body
        .get("device")
        .and_then(|d| d.get("antiSpoofingKeyPair"))
        .and_then(|k| k.get("publicKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!(
            "No Anti-Spoofing public key in response for model 0x{:06X}. \
             Device may not support Fast Pair or key is not public.",
            model_id
        ))?;

    let key_bytes = BASE64
        .decode(public_key_b64)
        .context("Failed to base64-decode Anti-Spoofing public key")?;

    if key_bytes.len() != 64 {
        bail!(
            "Anti-Spoofing public key is {} bytes, expected 64 (P-256 uncompressed X||Y)",
            key_bytes.len()
        );
    }

    let mut public_key_bytes = [0u8; 64];
    public_key_bytes.copy_from_slice(&key_bytes);

    let device_name = body
        .get("device")
        .and_then(|d| d.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let device_type = body
        .get("device")
        .and_then(|d| d.get("type"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DeviceAntiSpoofingInfo {
        public_key_bytes,
        device_name,
        device_type,
        model_id,
    })
}

pub async fn fetch_anti_spoofing_key_cached(
    model_id: u32,
    cache: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<u32, DeviceAntiSpoofingInfo>>>,
) -> Result<DeviceAntiSpoofingInfo> {
    {
        let guard = cache.lock().await;
        if let Some(info) = guard.get(&model_id) {
            return Ok(info.clone());
        }
    }

    let info = fetch_anti_spoofing_key(model_id).await?;

    {
        let mut guard = cache.lock().await;
        guard.insert(model_id, info.clone());
    }

    Ok(info)
}
