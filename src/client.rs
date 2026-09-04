#![allow(dead_code)]
use std::time::Duration;
use bluer::{Adapter, Address, Device, gatt::remote::Characteristic};
use anyhow::{Result, bail, Context};
use futures::StreamExt;

use crate::constants::{
    KEY_BASED_PAIRING_CHAR_UUID, MODEL_ID_CHAR_UUID,
    DEFAULT_CONNECTION_TIMEOUT, DEFAULT_NOTIFICATION_TIMEOUT,
};
use crate::crypto::{
    aes_128_encrypt, aes_128_decrypt, generate_random_salt,
    generate_secp256r1_keypair, derive_shared_secret_from_provider_public_key,
};
use crate::protocol::{
    KeyBasedPairingRequest, PairingRequestFlags,
    parse_bluetooth_address, format_bluetooth_address,
    parse_kbp_response_multi_strategy,
};
use crate::google_api::{fetch_anti_spoofing_key, DeviceAntiSpoofingInfo};
use crate::hci::{HciMonitor, HciEvent, att_error_name, hci_index_for_adapter};

const NOTIFY_STABILISE_MS: u64 = 300;
const RETRY_DELAY_MS: u64 = 800;
const MAX_RETRIES: usize = 3;
const EXTENDED_TIMEOUT_SECS: f64 = 10.0;

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyMethod {
    ZeroKey,
    AccountKey,
    AntiSpoofing,
}

impl std::fmt::Display for VerifyMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyMethod::ZeroKey      => write!(f, "zero-key (unreliable)"),
            VerifyMethod::AccountKey   => write!(f, "account key"),
            VerifyMethod::AntiSpoofing => write!(f, "ECDH + Anti-Spoofing key (Google API)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HciDiagnostic {
    pub att_error: Option<(u8, String)>,
    pub write_ack: bool,
    pub raw_notifications: Vec<Vec<u8>>,
    pub disconnected: bool,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success: bool,
    pub provider_address: Option<String>,
    pub error: Option<String>,
    pub raw_response: Option<Vec<u8>>,
    pub response_received: bool,
    pub method_used: VerifyMethod,
    pub anti_spoofing_info: Option<DeviceAntiSpoofingInfo>,
    pub strategy_used: Option<String>,
    pub hci_diagnostic: Option<HciDiagnostic>,
    pub attempts: usize,
}

impl VerificationResult {
    fn fail(method: VerifyMethod, error: impl Into<String>) -> Self {
        Self {
            success: false,
            provider_address: None,
            error: Some(error.into()),
            raw_response: None,
            response_received: false,
            method_used: method,
            anti_spoofing_info: None,
            strategy_used: None,
            hci_diagnostic: None,
            attempts: 0,
        }
    }
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
                .context("Failed to connect")?;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        Ok(device)
    }

    async fn disconnect_device(&self) {
        if let Ok(device) = self.get_device().await {
            let _ = device.disconnect().await;
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    async fn find_characteristic(
        device: &Device,
        char_uuid_str: &str,
    ) -> Result<Characteristic> {
        let target_uuid: uuid::Uuid = char_uuid_str.parse()
            .context("Invalid UUID")?;
        for service in device.services().await? {
            for ch in service.characteristics().await? {
                if ch.uuid().await? == target_uuid {
                    return Ok(ch);
                }
            }
        }
        bail!("Characteristic {} not found", char_uuid_str)
    }

    pub async fn read_model_id(&self) -> Result<Option<u32>> {
        let device = self.connect_device().await?;
        let ch = Self::find_characteristic(&device, MODEL_ID_CHAR_UUID).await?;
        let data = ch.read().await?;
        if data.len() >= 3 {
            return Ok(Some(u32::from_be_bytes([0, data[0], data[1], data[2]])));
        }
        Ok(None)
    }

    async fn probe_once(
        &self,
        encrypted_data: &[u8; 16],
        hci_monitor: Option<&HciMonitor>,
    ) -> Result<(Option<Vec<u8>>, Option<HciDiagnostic>)> {
        let device = self.connect_device().await?;
        let ch = Self::find_characteristic(&device, KEY_BASED_PAIRING_CHAR_UUID).await?;

        let notify_stream = ch.notify().await
            .context("Failed to subscribe to notifications")?;
        futures::pin_mut!(notify_stream);

        tokio::time::sleep(Duration::from_millis(NOTIFY_STABILISE_MS)).await;

        ch.write(encrypted_data).await
            .context("Failed to write KBP characteristic")?;

        let gatt_response = tokio::time::timeout(
            self.notification_timeout,
            notify_stream.next(),
        )
        .await
        .ok()
        .flatten();

        let hci_diag = if let Some(mon) = hci_monitor {
            let pkts = mon.drain_att_notifications(Duration::from_millis(500));
            let mut diag = HciDiagnostic {
                att_error: None,
                write_ack: false,
                raw_notifications: vec![],
                disconnected: false,
            };
            for pkt in &pkts {
                match &pkt.event {
                    HciEvent::AttError { error_code, .. } => {
                        diag.att_error = Some((*error_code, att_error_name(*error_code).to_string()));
                    }
                    HciEvent::AttWriteRsp => { diag.write_ack = true; }
                    HciEvent::AttNotification { data, .. } => {
                        diag.raw_notifications.push(data.clone());
                    }
                    HciEvent::Disconnected { .. } => { diag.disconnected = true; }
                    _ => {}
                }
            }
            Some(diag)
        } else {
            None
        };

        Ok((gatt_response, hci_diag))
    }

    async fn try_strategy(
        &self,
        request: &KeyBasedPairingRequest,
        aes_key: &[u8; 16],
        _strategy_name: &str,
        hci_monitor: Option<&HciMonitor>,
    ) -> Option<(Vec<u8>, Option<HciDiagnostic>)> {
        let plaintext = request.build();
        let encrypted = aes_128_encrypt(aes_key, &plaintext);

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                self.disconnect_device().await;
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            }

            match self.probe_once(&encrypted, hci_monitor).await {
                Ok((Some(response), diag)) => {
                    return Some((response, diag));
                }
                Ok((None, Some(ref diag))) if diag.att_error.is_some() => {
                    return None;
                }
                Ok((None, diag)) => {
                    let _ = diag;
                }
                Err(_) => {}
            }
        }
        None
    }

    fn build_all_strategies(
        &self,
        provider_addr: [u8; 6],
        adapter_addr: Option<[u8; 6]>,
    ) -> Vec<(String, KeyBasedPairingRequest)> {
        let mut strategies = vec![];

        strategies.push((
            "standard (initiate+extended)".into(),
            KeyBasedPairingRequest::for_verification(provider_addr, None),
        ));

        strategies.push((
            "raw KBP minimal".into(),
            KeyBasedPairingRequest::strategy_raw_kbp(provider_addr),
        ));

        strategies.push((
            "extended only".into(),
            KeyBasedPairingRequest::strategy_extended(provider_addr),
        ));

        if let Some(seeker) = adapter_addr {
            strategies.push((
                "with seeker address".into(),
                KeyBasedPairingRequest::strategy_with_seeker(provider_addr, seeker),
            ));
            strategies.push((
                "retroactive".into(),
                KeyBasedPairingRequest::strategy_retroactive(provider_addr, seeker),
            ));
        }

        let mut req_no_bond = KeyBasedPairingRequest::for_verification(provider_addr, None);
        req_no_bond.flags = PairingRequestFlags::EXTENDED_RESPONSE
            | PairingRequestFlags::SUBSEQUENT_PAIRING;
        strategies.push(("subsequent pairing".into(), req_no_bond));

        strategies
    }

    fn address_variants(ble_addr: [u8; 6]) -> Vec<[u8; 6]> {
        let mut variants = vec![ble_addr];

        let mut reversed = ble_addr;
        reversed.reverse();
        if reversed != ble_addr {
            variants.push(reversed);
        }

        let mut incremented = ble_addr;
        let last = incremented[5];
        if last < 0xFF {
            incremented[5] = last + 1;
            variants.push(incremented);
        }
        if last > 0x00 {
            incremented[5] = last - 1;
            variants.push(incremented);
        }

        variants
    }

    async fn get_adapter_address(&self) -> Option<[u8; 6]> {
        if let Ok(addr_str) = self.adapter.address().await {
            parse_bluetooth_address(&addr_str.to_string()).ok()
        } else {
            None
        }
    }

    async fn probe_with_key_full(
        &self,
        aes_key: &[u8; 16],
        ble_addr: [u8; 6],
        method: VerifyMethod,
        anti_spoofing_info: Option<DeviceAntiSpoofingInfo>,
        hci_monitor: Option<&HciMonitor>,
    ) -> VerificationResult {
        let adapter_addr = self.get_adapter_address().await;
        let addr_variants = Self::address_variants(ble_addr);
        let mut total_attempts = 0;
        let mut last_hci_diag: Option<HciDiagnostic> = None;

        for provider_addr in &addr_variants {
            let strategies = self.build_all_strategies(*provider_addr, adapter_addr);

            for (strategy_name, request) in &strategies {
                total_attempts += 1;

                if let Some((raw_response, hci_diag)) = self
                    .try_strategy(request, aes_key, strategy_name, hci_monitor)
                    .await
                {
                    last_hci_diag = hci_diag;

                    let provider_address_str = parse_kbp_response_multi_strategy(
                        &raw_response,
                        Some(aes_key as &[u8]),
                    );

                    return VerificationResult {
                        success: true,
                        response_received: true,
                        provider_address: provider_address_str,
                        raw_response: Some(raw_response),
                        error: None,
                        method_used: method,
                        anti_spoofing_info,
                        strategy_used: Some(format!(
                            "{} (addr variant: {})",
                            strategy_name,
                            format_bluetooth_address(provider_addr)
                        )),
                        hci_diagnostic: last_hci_diag,
                        attempts: total_attempts,
                    };
                } else if let Some(Some(ref diag)) = Some(hci_monitor.map(|_| HciDiagnostic {
                    att_error: None,
                    write_ack: false,
                    raw_notifications: vec![],
                    disconnected: false,
                })) {
                    last_hci_diag = Some(diag.clone());
                }

                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }

        VerificationResult {
            success: false,
            response_received: false,
            provider_address: None,
            error: Some(format!(
                "No response after {} attempts across {} strategies and {} address variants",
                total_attempts,
                self.build_all_strategies(ble_addr, adapter_addr).len(),
                addr_variants.len(),
            )),
            raw_response: None,
            method_used: method,
            anti_spoofing_info,
            strategy_used: None,
            hci_diagnostic: last_hci_diag,
            attempts: total_attempts,
        }
    }

    pub async fn verify_pairing_behavior(
        &self,
        account_key: Option<&[u8; 16]>,
        seeker_address: Option<[u8; 6]>,
    ) -> VerificationResult {
        let ble_addr = match parse_bluetooth_address(&self.address_str()) {
            Ok(b) => b,
            Err(e) => return VerificationResult::fail(VerifyMethod::ZeroKey, e.to_string()),
        };

        let hci_monitor = {
            let name = self.adapter.name();
            hci_index_for_adapter(name)
                .and_then(|idx| HciMonitor::open(idx).ok())
        };

        if let Some(key) = account_key {
            return self.probe_with_key_full(
                key, ble_addr,
                VerifyMethod::AccountKey,
                None,
                hci_monitor.as_ref(),
            ).await;
        }

        let model_id = self.read_model_id().await.ok().flatten();

        if let Some(mid) = model_id {
            match fetch_anti_spoofing_key(mid).await {
                Ok(info) => {
                    let keypair = generate_secp256r1_keypair();
                    match derive_shared_secret_from_provider_public_key(keypair, &info.public_key_bytes) {
                        Ok(aes_key) => {
                            let result = self.probe_with_key_full(
                                &aes_key, ble_addr,
                                VerifyMethod::AntiSpoofing,
                                Some(info),
                                hci_monitor.as_ref(),
                            ).await;

                            if result.response_received {
                                return result;
                            }

                            eprintln!(
                                "Anti-Spoofing ECDH probe returned no response after {} attempt(s). \
                                 Falling back to zero-key probe.",
                                result.attempts
                            );
                        }
                        Err(e) => eprintln!("ECDH derivation failed: {}", e),
                    }
                }
                Err(e) => eprintln!("Google API failed: {} — falling back to zero-key", e),
            }
        } else {
            eprintln!("Could not read Model ID — skipping Anti-Spoofing path");
        }

        let zero_key = [0u8; 16];
        self.probe_with_key_full(
            &zero_key, ble_addr,
            VerifyMethod::ZeroKey,
            None,
            hci_monitor.as_ref(),
        ).await
    }
}
