#![allow(dead_code)]
use std::collections::HashMap;
use uuid::Uuid;

pub const FAST_PAIR_SERVICE_UUID_16: u16 = 0xFE2C;
pub const FAST_PAIR_SERVICE_UUID: &str = "0000fe2c-0000-1000-8000-00805f9b34fb";
pub const MODEL_ID_CHAR_UUID: &str = "fe2c1233-8366-4814-8eb0-01de32100bea";
pub const KEY_BASED_PAIRING_CHAR_UUID: &str = "fe2c1234-8366-4814-8eb0-01de32100bea";
pub const PASSKEY_CHAR_UUID: &str = "fe2c1235-8366-4814-8eb0-01de32100bea";
pub const ACCOUNT_KEY_CHAR_UUID: &str = "fe2c1236-8366-4814-8eb0-01de32100bea";
pub const FIRMWARE_REVISION_CHAR_UUID: &str = "fe2c1237-8366-4814-8eb0-01de32100bea";
pub const ADDITIONAL_DATA_CHAR_UUID: &str = "fe2c1238-8366-4814-8eb0-01de32100bea";

pub const DEFAULT_SCAN_TIMEOUT: f64 = 10.0;
pub const DEFAULT_CONNECTION_TIMEOUT: f64 = 10.0;
pub const DEFAULT_NOTIFICATION_TIMEOUT: f64 = 1.5;
pub const MAX_ACCOUNT_KEYS: usize = 10;
pub const ACCOUNT_KEY_SIZE: usize = 16;

pub mod message_type {
    pub const KEY_BASED_PAIRING_REQUEST: u8 = 0x00;
    pub const KEY_BASED_PAIRING_RESPONSE: u8 = 0x01;
    pub const KEY_BASED_PAIRING_EXTENDED_RESPONSE: u8 = 0x02;
    pub const SEEKER_PASSKEY: u8 = 0x02;
    pub const PROVIDER_PASSKEY: u8 = 0x03;
    pub const ACTION_REQUEST: u8 = 0x10;
}

pub mod pairing_flags {
    pub const INITIATE_BONDING: u8 = 0x01;
    pub const SEEKER_ADDRESS_PRESENT: u8 = 0x02;
    pub const RESERVED_BIT_2: u8 = 0x04;
    pub const ALT_SEEKER_ADDRESS_PRESENT: u8 = 0x08;
    pub const REQUEST_EXTENDED_RESPONSE: u8 = 0x10;
    pub const SUBSEQUENT_PAIRING: u8 = 0x20;
    pub const RETROACTIVE_ACCOUNT_KEY: u8 = 0x40;
    pub const RESERVED_BIT_7: u8 = 0x80;
}

pub fn known_model_ids() -> HashMap<u32, &'static str> {
    let mut m = HashMap::new();
    m.insert(0x0600FC, "Google Pixel Buds");
    m.insert(0x0600FD, "Google Pixel Buds");
    m.insert(0xD800AA, "Google Pixel Buds Pro");
    m.insert(0x30018E, "Google Pixel Buds Pro 2");
    m.insert(0xCD8256, "Sony WF-1000XM4");
    m.insert(0x0E30C3, "Sony WH-1000XM5");
    m.insert(0x821F66, "Sony LinkBuds S");
    m.insert(0xF52494, "JBL Tune Buds");
    m.insert(0x718FA4, "JBL Live Pro 2");
    m.insert(0x9D3F8A, "Anker Soundcore Liberty 4");
    m.insert(0x1312F3, "Samsung Galaxy Buds2 Pro");
    m
}

pub fn get_device_name(model_id: u32) -> String {
    known_model_ids()
        .get(&model_id)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("Unknown Device (0x{:06X})", model_id))
}

pub fn fast_pair_service_uuid() -> Uuid {
    FAST_PAIR_SERVICE_UUID.parse().unwrap()
}

pub fn key_based_pairing_char_uuid() -> Uuid {
    KEY_BASED_PAIRING_CHAR_UUID.parse().unwrap()
}

pub fn model_id_char_uuid() -> Uuid {
    MODEL_ID_CHAR_UUID.parse().unwrap()
}
