#![allow(dead_code)]
use anyhow::{Result, bail};
use crate::constants::message_type;
use crate::crypto::aes_128_decrypt;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PairingRequestFlags: u8 {
        const NONE                  = 0x00;
        const INITIATE_BONDING      = 0x01;
        const SEEKER_ADDRESS_PRESENT = 0x02;
        const RESERVED_2            = 0x04;
        const ALT_SEEKER_ADDRESS    = 0x08;
        const EXTENDED_RESPONSE     = 0x10;
        const SUBSEQUENT_PAIRING    = 0x20;
        const RETROACTIVE_ACCOUNT_KEY = 0x40;
        const RESERVED_7            = 0x80;
    }
}

#[derive(Debug, Clone)]
pub struct KeyBasedPairingRequest {
    pub provider_address: [u8; 6],
    pub seeker_address: Option<[u8; 6]>,
    pub flags: PairingRequestFlags,
    pub salt: Option<Vec<u8>>,
}

impl KeyBasedPairingRequest {
    pub fn new(
        provider_address: [u8; 6],
        seeker_address: Option<[u8; 6]>,
        flags: PairingRequestFlags,
    ) -> Self {
        Self { provider_address, seeker_address, flags, salt: None }
    }

    pub fn for_verification(
        provider_address: [u8; 6],
        seeker_address: Option<[u8; 6]>,
    ) -> Self {
        Self {
            provider_address,
            seeker_address,
            flags: PairingRequestFlags::INITIATE_BONDING | PairingRequestFlags::EXTENDED_RESPONSE,
            salt: None,
        }
    }

    pub fn strategy_raw_kbp(provider_address: [u8; 6]) -> Self {
        Self {
            provider_address,
            seeker_address: None,
            flags: PairingRequestFlags::INITIATE_BONDING | PairingRequestFlags::EXTENDED_RESPONSE,
            salt: None,
        }
    }

    pub fn strategy_with_seeker(provider_address: [u8; 6], seeker_address: [u8; 6]) -> Self {
        Self {
            provider_address,
            seeker_address: Some(seeker_address),
            flags: PairingRequestFlags::SEEKER_ADDRESS_PRESENT,
            salt: None,
        }
    }

    pub fn strategy_retroactive(provider_address: [u8; 6], seeker_address: [u8; 6]) -> Self {
        Self {
            provider_address,
            seeker_address: Some(seeker_address),
            flags: PairingRequestFlags::SEEKER_ADDRESS_PRESENT | PairingRequestFlags::ALT_SEEKER_ADDRESS,
            salt: None,
        }
    }

    pub fn strategy_extended(provider_address: [u8; 6]) -> Self {
        Self {
            provider_address,
            seeker_address: None,
            flags: PairingRequestFlags::EXTENDED_RESPONSE,
            salt: None,
        }
    }

    pub fn build(&self) -> [u8; 16] {
        let mut packet = [0u8; 16];
        packet[0] = message_type::KEY_BASED_PAIRING_REQUEST;
        let mut flags = self.flags;
        if self.seeker_address.is_some() {
            flags |= PairingRequestFlags::SEEKER_ADDRESS_PRESENT;
        }
        packet[1] = flags.bits();
        packet[2..8].copy_from_slice(&self.provider_address);
        if let Some(seeker) = &self.seeker_address {
            packet[8..14].copy_from_slice(seeker);
            let salt = self.salt.clone().unwrap_or_else(|| crate::crypto::generate_random_salt(2));
            packet[14..16].copy_from_slice(&salt[..2.min(salt.len())]);
        } else {
            let salt = self.salt.clone().unwrap_or_else(|| crate::crypto::generate_random_salt(8));
            let len = 8.min(salt.len());
            packet[8..8 + len].copy_from_slice(&salt[..len]);
        }
        packet
    }
}

#[derive(Debug, Clone)]
pub struct KeyBasedPairingResponse {
    pub message_type: u8,
    pub provider_address: [u8; 6],
    pub salt: [u8; 9],
}

impl KeyBasedPairingResponse {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 16 {
            bail!("Response must be 16 bytes");
        }
        let mut provider_address = [0u8; 6];
        provider_address.copy_from_slice(&data[1..7]);
        let mut salt = [0u8; 9];
        salt.copy_from_slice(&data[7..16]);
        Ok(Self {
            message_type: data[0],
            provider_address,
            salt,
        })
    }

    pub fn provider_address_str(&self) -> String {
        self.provider_address
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyBlock {
    pub message_type: u8,
    pub passkey: u32,
    pub salt: [u8; 12],
}

impl PasskeyBlock {
    pub fn build(&self) -> [u8; 16] {
        let mut packet = [0u8; 16];
        packet[0] = self.message_type;
        let pk_bytes = self.passkey.to_be_bytes();
        packet[1..4].copy_from_slice(&pk_bytes[1..4]);
        packet[4..16].copy_from_slice(&self.salt);
        packet
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != 16 {
            bail!("Passkey block must be 16 bytes");
        }
        let passkey = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let mut salt = [0u8; 12];
        salt.copy_from_slice(&data[4..16]);
        Ok(Self { message_type: data[0], passkey, salt })
    }

    pub fn create_seeker_passkey(passkey: u32) -> Self {
        use rand::RngCore;
        let mut salt = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self { message_type: 0x02, passkey, salt }
    }
}

pub fn parse_bluetooth_address(address_str: &str) -> Result<[u8; 6]> {
    let normalized = address_str.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        bail!("Invalid Bluetooth address: {}", address_str);
    }
    let mut result = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        result[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow::anyhow!("Invalid hex in address: {}", part))?;
    }
    Ok(result)
}

pub fn format_bluetooth_address(bytes: &[u8; 6]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

pub fn parse_kbp_response_multi_strategy(
    data: &[u8],
    shared_secret: Option<&[u8]>,
) -> Option<String> {
    if data.len() < 7 {
        return None;
    }

    let extract_address = |d: &[u8], offset: usize| -> Option<String> {
        if offset + 6 > d.len() {
            return None;
        }
        Some(d[offset..offset + 6].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":"))
    };

    let is_valid_address = |addr: &str| -> bool {
        if addr == "00:00:00:00:00:00" || addr == "FF:FF:FF:FF:FF:FF" {
            return false;
        }
        let parts: Vec<&str> = addr.split(':').collect();
        parts.len() == 6 && parts.iter().all(|p| p.len() == 2)
    };

    if data[0] == 0x01 || data[0] == message_type::KEY_BASED_PAIRING_RESPONSE {
        if let Some(addr) = extract_address(data, 1) {
            if is_valid_address(&addr) {
                return Some(addr);
            }
        }
    }

    if data[0] == 0x02 && data.len() >= 9 {
        let addr_count = data[2] as usize;
        if addr_count >= 1 {
            if let Some(addr) = extract_address(data, 3) {
                if is_valid_address(&addr) {
                    return Some(addr);
                }
            }
        }
    }

    if let Some(secret) = shared_secret {
        if secret.len() >= 16 {
            let mut key = [0u8; 16];
            key.copy_from_slice(&secret[..16]);
            if data.len() == 16 {
                let mut ct = [0u8; 16];
                ct.copy_from_slice(data);
                let decrypted = aes_128_decrypt(&key, &ct);
                if decrypted[0] == message_type::KEY_BASED_PAIRING_RESPONSE {
                    if let Some(addr) = extract_address(&decrypted, 1) {
                        if is_valid_address(&addr) {
                            return Some(addr);
                        }
                    }
                }
            }
        }
    }

    for offset in 0..data.len().saturating_sub(5) {
        if let Some(addr) = extract_address(data, offset) {
            if is_valid_address(&addr) {
                return Some(addr);
            }
        }
    }

    None
}
