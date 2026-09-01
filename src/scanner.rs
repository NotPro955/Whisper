use std::collections::HashMap;
use std::time::Duration;
use bluer::{Adapter, Address};
use anyhow::Result;
use futures::StreamExt;
use uuid::Uuid;

use crate::constants::known_model_ids;

#[derive(Debug, Clone)]
pub struct FastPairDevice {
    pub address: Address,
    pub name: Option<String>,
    pub model_id: Option<u32>,
    pub model_name: String,
    pub rssi: Option<i16>,
    pub is_in_pairing_mode: bool,
    pub has_account_key_filter: bool,
    pub raw_service_data: Vec<u8>,
}

impl FastPairDevice {
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.model_name.clone())
    }

    pub fn address_str(&self) -> String {
        self.address.to_string()
    }
}

impl std::fmt::Display for FastPairDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = if self.is_in_pairing_mode { "PAIRING" } else { "paired/idle" };
        let model_hex = self.model_id.map(|id| format!("0x{:06X}", id)).unwrap_or_else(|| "N/A".to_string());
        write!(
            f,
            "FastPairDevice({}, addr={}, model={}, rssi={:?}dBm, mode={})",
            self.display_name(), self.address_str(), model_hex, self.rssi, mode
        )
    }
}

pub struct ParsedServiceData {
    pub model_id: Option<u32>,
    pub is_pairing_mode: bool,
    pub has_account_key_filter: bool,
    pub salt: Option<Vec<u8>>,
    pub battery: Option<Vec<u8>>,
}

pub fn parse_fast_pair_service_data(data: &[u8]) -> ParsedServiceData {
    let mut result = ParsedServiceData {
        model_id: None,
        is_pairing_mode: false,
        has_account_key_filter: false,
        salt: None,
        battery: None,
    };

    if data.len() < 3 {
        return result;
    }

    let first_byte = data[0];

    if first_byte == 0x00 && data.len() >= 3 {
        let model_id = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        result.model_id = Some(model_id);
        result.is_pairing_mode = true;
    } else if data.len() == 3 && (first_byte & 0x80) == 0 {
        let model_id = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        result.model_id = Some(model_id);
        result.is_pairing_mode = true;
    } else if (first_byte & 0x60) != 0 {
        result.has_account_key_filter = true;
        result.is_pairing_mode = false;
        let filter_length = ((first_byte >> 4) & 0x0F) as usize;
        if data.len() > 1 + filter_length {
            let remaining = &data[1 + filter_length..];
            let mut i = 0;
            while i + 1 < remaining.len() {
                let field_id = remaining[i];
                let field_len = remaining[i + 1] as usize;
                if field_id == 0x11 && field_len >= 1 && i + 2 + field_len <= remaining.len() {
                    result.salt = Some(remaining[i + 2..i + 2 + field_len].to_vec());
                } else if field_id == 0x03 && field_len >= 1 && i + 2 + field_len <= remaining.len() {
                    result.battery = Some(remaining[i + 2..i + 2 + field_len].to_vec());
                }
                i += 2 + field_len;
            }
        }
    } else if data.len() == 3 {
        let model_id = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        result.model_id = Some(model_id);
        result.is_pairing_mode = true;
    }

    result
}

pub async fn find_fast_pair_devices(
    adapter: &Adapter,
    timeout_secs: f64,
) -> Result<Vec<FastPairDevice>> {
    let fp_uuid = Uuid::parse_str(crate::constants::FAST_PAIR_SERVICE_UUID).unwrap();
    let models = known_model_ids();
    let mut devices: HashMap<Address, FastPairDevice> = HashMap::new();

    adapter.set_powered(true).await?;

    let discover = adapter.discover_devices().await?;
    let timeout = Duration::from_secs_f64(timeout_secs);

    let collect = async {
        futures::pin_mut!(discover);
        while let Some(event) = discover.next().await {
            use bluer::AdapterEvent;
            match event {
                AdapterEvent::DeviceAdded(addr) => {
                    if let Ok(device) = adapter.device(addr) {
                        if let Ok(Some(uuids)) = device.uuids().await {
                            let has_fp = uuids.iter().any(|u| *u == fp_uuid);
                            if has_fp {
                                let name = device.name().await.ok().flatten();
                                let rssi = device.rssi().await.ok().flatten();
                                let service_data = device.service_data().await.ok().flatten();
                                
                                let (raw_data, parsed) = if let Some(ref sd) = service_data {
                                    let fp_entry = sd.iter().find(|(k, _)| {
                                        k.to_string().to_lowercase().contains("fe2c")
                                    });
                                    if let Some((_, data)) = fp_entry {
                                        let parsed = parse_fast_pair_service_data(data);
                                        (data.clone(), parsed)
                                    } else {
                                        (vec![], parse_fast_pair_service_data(&[]))
                                    }
                                } else {
                                    (vec![], parse_fast_pair_service_data(&[]))
                                };

                                let model_name = parsed
                                    .model_id
                                    .and_then(|id| models.get(&id).map(|s| s.to_string()))
                                    .unwrap_or_else(|| "Unknown".to_string());

                                let fp_device = FastPairDevice {
                                    address: addr,
                                    name,
                                    model_id: parsed.model_id,
                                    model_name,
                                    rssi,
                                    is_in_pairing_mode: parsed.is_pairing_mode,
                                    has_account_key_filter: parsed.has_account_key_filter,
                                    raw_service_data: raw_data,
                                };
                                devices.insert(addr, fp_device);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(timeout, collect).await.ok();

    Ok(devices.into_values().collect())
}

pub async fn find_vulnerable_devices(
    adapter: &Adapter,
    timeout_secs: f64,
) -> Result<Vec<FastPairDevice>> {
    let all = find_fast_pair_devices(adapter, timeout_secs).await?;
    Ok(all.into_iter().filter(|d| !d.is_in_pairing_mode).collect())
}
