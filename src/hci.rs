#![allow(dead_code)]

use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};
use anyhow::{Result, bail};
use tokio::sync::mpsc;

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCI_DEV_NONE: libc::c_uint = 0xffff;
const HCI_CHANNEL_RAW: libc::c_int = 0;
const HCI_CHANNEL_MONITOR: libc::c_int = 2;
const HCI_FILTER_SIZE: usize = 14;

const HCI_EVENT_PKT: u8 = 0x04;
const HCI_ACLDATA_PKT: u8 = 0x02;
const EVT_DISCONN_COMPLETE: u8 = 0x05;
const EVT_LE_META: u8 = 0x3E;
const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;

const ATT_OP_ERROR: u8 = 0x01;
const ATT_OP_HANDLE_NOTIFY: u8 = 0x1B;
const ATT_OP_HANDLE_IND: u8 = 0x1D;
const ATT_OP_WRITE_RSP: u8 = 0x13;

#[derive(Debug, Clone)]
pub enum HciEvent {
    AttNotification { handle: u16, data: Vec<u8> },
    AttError { request_op: u8, handle: u16, error_code: u8 },
    AttWriteRsp,
    Disconnected { reason: u8 },
    RawAcl(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct HciPacket {
    pub event: HciEvent,
    pub timestamp: Instant,
    pub raw: Vec<u8>,
}

pub struct HciMonitor {
    fd: RawFd,
    hci_index: u16,
}

impl HciMonitor {
    pub fn open(hci_index: u16) -> Result<Self> {
        let fd = unsafe {
            libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, BTPROTO_HCI)
        };
        if fd < 0 {
            bail!("Failed to open HCI socket: {}", std::io::Error::last_os_error());
        }

        #[repr(C)]
        struct SockaddrHci {
            hci_family: libc::sa_family_t,
            hci_dev: u16,
            hci_channel: u16,
        }

        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as libc::sa_family_t,
            hci_dev: hci_index,
            hci_channel: HCI_CHANNEL_RAW as u16,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd); }
            bail!("Failed to bind HCI socket: {}", std::io::Error::last_os_error());
        }

        let mut filter = [0u8; HCI_FILTER_SIZE];
        filter[0] = 0xFF;
        filter[1] = 0xFF;
        filter[2] = 0xFF;
        filter[3] = 0xFF;
        filter[4] = 0xFF;
        filter[5] = 0xFF;

        const SOL_HCI: libc::c_int = 0;
        const HCI_FILTER: libc::c_int = 2;

        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_HCI,
                HCI_FILTER,
                filter.as_ptr() as *const libc::c_void,
                HCI_FILTER_SIZE as libc::socklen_t,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd); }
            bail!("Failed to set HCI filter: {}", std::io::Error::last_os_error());
        }

        Ok(Self { fd, hci_index })
    }

    pub fn read_packet(&self) -> Option<HciPacket> {
        let mut buf = [0u8; 1024];
        let n = unsafe {
            libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };

        if n <= 0 {
            return None;
        }

        let data = buf[..n as usize].to_vec();
        parse_hci_packet(&data)
    }

    pub fn read_packet_timeout(&self, timeout: Duration) -> Option<HciPacket> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }

            let mut pollfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let ms = remaining.as_millis().min(100) as libc::c_int;
            let ret = unsafe { libc::poll(&mut pollfd, 1, ms) };

            if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                if let Some(pkt) = self.read_packet() {
                    return Some(pkt);
                }
            }

            if Instant::now() >= deadline {
                return None;
            }
        }
    }

    pub fn drain_att_notifications(&self, timeout: Duration) -> Vec<HciPacket> {
        let deadline = Instant::now() + timeout;
        let mut results = Vec::new();

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(pkt) = self.read_packet_timeout(remaining.min(Duration::from_millis(100))) {
                match &pkt.event {
                    HciEvent::AttNotification { .. } |
                    HciEvent::AttError { .. } |
                    HciEvent::Disconnected { .. } => {
                        results.push(pkt);
                    }
                    _ => {}
                }
            }
        }

        results
    }
}

impl Drop for HciMonitor {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

fn parse_hci_packet(data: &[u8]) -> Option<HciPacket> {
    if data.is_empty() {
        return None;
    }

    let raw = data.to_vec();
    let timestamp = Instant::now();

    let event = match data[0] {
        HCI_EVENT_PKT => parse_hci_event(&data[1..])?,
        HCI_ACLDATA_PKT => parse_acl_data(&data[1..])?,
        _ => return None,
    };

    Some(HciPacket { event, timestamp, raw })
}

fn parse_hci_event(data: &[u8]) -> Option<HciEvent> {
    if data.len() < 2 {
        return None;
    }
    let event_code = data[0];
    let _param_len = data[1] as usize;
    let params = &data[2..];

    match event_code {
        EVT_DISCONN_COMPLETE => {
            if params.len() >= 3 {
                Some(HciEvent::Disconnected { reason: params[2] })
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_acl_data(data: &[u8]) -> Option<HciEvent> {
    if data.len() < 4 {
        return None;
    }

    let total_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + total_len {
        return None;
    }

    let payload = &data[4..4 + total_len];
    if payload.len() < 4 {
        return None;
    }

    let l2cap_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let cid = u16::from_le_bytes([payload[2], payload[3]]);

    if cid != 0x0004 {
        return None;
    }

    let att_data = &payload[4..];
    if att_data.is_empty() {
        return None;
    }

    match att_data[0] {
        ATT_OP_HANDLE_NOTIFY | ATT_OP_HANDLE_IND => {
            if att_data.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([att_data[1], att_data[2]]);
            let notification_data = att_data[3..].to_vec();
            Some(HciEvent::AttNotification { handle, data: notification_data })
        }
        ATT_OP_ERROR => {
            if att_data.len() < 5 {
                return None;
            }
            Some(HciEvent::AttError {
                request_op: att_data[1],
                handle: u16::from_le_bytes([att_data[2], att_data[3]]),
                error_code: att_data[4],
            })
        }
        ATT_OP_WRITE_RSP => Some(HciEvent::AttWriteRsp),
        _ => Some(HciEvent::RawAcl(att_data.to_vec())),
    }
}

pub fn att_error_name(code: u8) -> &'static str {
    match code {
        0x01 => "Invalid Handle",
        0x02 => "Read Not Permitted",
        0x03 => "Write Not Permitted",
        0x04 => "Invalid PDU",
        0x05 => "Insufficient Authentication",
        0x06 => "Request Not Supported",
        0x07 => "Invalid Offset",
        0x08 => "Insufficient Authorization",
        0x09 => "Prepare Queue Full",
        0x0A => "Attribute Not Found",
        0x0B => "Attribute Not Long",
        0x0C => "Insufficient Encryption Key Size",
        0x0D => "Invalid Attribute Length",
        0x0E => "Unlikely Error",
        0x0F => "Insufficient Encryption",
        0x10 => "Unsupported Group Type",
        0x11 => "Insufficient Resources",
        0x80 => "Application Error (device-specific)",
        0x81 => "Application Error (device-specific)",
        0x82 => "Application Error (device-specific)",
        _ => "Unknown Error",
    }
}

pub fn hci_index_for_adapter(adapter_name: &str) -> Option<u16> {
    let name = adapter_name.trim_start_matches("hci");
    name.parse::<u16>().ok()
}
