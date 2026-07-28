//! Standalone probe: try to read Logitech HID++ Device Serial Number (feature 0x0003).
//!
//! Reuses the same HID++ long-report protocol as kbshare_flow. Run with:
//!   cargo run -p kbshare-flow --bin sn-probe
//!   KBSHARE_FLOW_DEBUG=1 cargo run -p kbshare-flow --bin sn-probe

#![cfg(windows)]

use anyhow::{bail, Context, Result};
use hidapi::HidApi;
use std::time::{Duration, Instant};

const LOGITECH_VENDOR_ID: u16 = 0x046d;
const BOLT_RECEIVER_PID: u16 = 0xc548;
const UNIFYING_RECEIVER_PIDS: [u16; 2] = [0xc52b, 0xc532];
const FEATURE_ROOT: u16 = 0x0000;
const FEATURE_DEVICE_FW_VERSION: u16 = 0x0002;
const FEATURE_DEVICE_TYPE_AND_NAME: u16 = 0x0005;
const FEATURE_CHANGE_HOST: u16 = 0x1814;
const REPORT_LONG: u8 = 0x11;
const SOFTWARE_ID: u8 = 0x08;
const DIRECT_DEVICE_INDEX: u8 = 0xff;

const HIDPP_USAGE_PAGES: [u16; 3] = [0xff00, 0xff43, 0xff0c];
const HIDPP_LONG_USAGES: [u16; 2] = [0x0002, 0x0202];

fn is_receiver(product_id: u16) -> bool {
    product_id == BOLT_RECEIVER_PID || UNIFYING_RECEIVER_PIDS.contains(&product_id)
}

fn is_candidate(usage_page: u16, usage: u16) -> bool {
    HIDPP_USAGE_PAGES.contains(&usage_page) && HIDPP_LONG_USAGES.contains(&usage)
}

fn debug_enabled() -> bool {
    std::env::var_os("KBSHARE_FLOW_DEBUG").is_some()
}

fn build_message(device_index: u8, request_id: u16, params: &[u8]) -> Result<[u8; 20]> {
    if params.len() > 16 {
        bail!("HID++ long report accepts at most 16 parameter bytes");
    }
    let mut message = [0u8; 20];
    message[0] = REPORT_LONG;
    message[1] = device_index;
    message[2] = (request_id >> 8) as u8;
    message[3] = (request_id as u8 & 0xf0) | SOFTWARE_ID;
    message[4..4 + params.len()].copy_from_slice(params);
    Ok(message)
}

fn request(
    device: &hidapi::HidDevice,
    device_index: u8,
    request_id: u16,
    params: &[u8],
) -> Result<Option<Vec<u8>>> {
    let message = build_message(device_index, request_id, params)?;
    let expected = [message[2], message[3]];
    let mut stale = [0u8; 32];
    while device.read_timeout(&mut stale, 0)? > 0 {}
    let written = device.write(&message).context("write HID++ report")?;
    if debug_enabled() {
        eprintln!("hid++ write slot={device_index:02x} bytes={written} {message:02x?}");
    }

    let deadline = Instant::now() + Duration::from_millis(600);
    let mut response = [0u8; 32];
    while Instant::now() < deadline {
        let read = device
            .read_timeout(&mut response, 100)
            .context("read HID++ report")?;
        if debug_enabled() && read > 0 {
            eprintln!("hid++ read bytes={read} {:02x?}", &response[..read]);
        }
        if read < 4 || response[0] != REPORT_LONG {
            continue;
        }
        let response_index = response[1];
        if response_index != device_index && response_index != (device_index ^ 0xff) {
            continue;
        }
        if response[2] == 0xff && read >= 6 && response[3..5] == expected {
            return Ok(None);
        }
        if response[2..4] == expected {
            return Ok(Some(response[4..read].to_vec()));
        }
    }
    Ok(None)
}

fn resolve_feature(device: &hidapi::HidDevice, slot: u8, feature: u16) -> Result<Option<u8>> {
    let params = [(feature >> 8) as u8, feature as u8, 0];
    Ok(request(device, slot, FEATURE_ROOT << 8, &params)?
        .and_then(|reply| reply.first().copied())
        .filter(|index| *index != 0))
}

fn read_unit_id(device: &hidapi::HidDevice, slot: u8, feature_index: u8) -> Result<Option<String>> {
    // Feature 0x0002 (DEVICE_FW_VERSION) func 0x00 returns:
    // count(1) + for each: level(1) + name(3) + version_major(1) + version_minor(1) + build(2) + extras...
    // But the first 5 bytes after count are: level, name[3], transport_bits
    // Solaar reads unitId = bytes[1:5], modelId = bytes[7:13]
    let Some(reply) = request(device, slot, (feature_index as u16) << 8, &[])? else {
        return Ok(None);
    };
    if reply.len() < 13 {
        return Ok(None);
    }
    let unit_id = &reply[1..5];
    let model_id = &reply[7..13];
    let transport_bits = reply[6];
    let unit_hex = unit_id
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    let model_hex = model_id
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    Ok(Some(format!(
        "unitId={} modelId={} transport=0x{:02X}",
        unit_hex, model_hex, transport_bits
    )))
}

fn read_name(device: &hidapi::HidDevice, slot: u8, feature_index: u8) -> Result<Option<String>> {
    let Some(reply) = request(device, slot, (feature_index as u16) << 8, &[])? else {
        return Ok(None);
    };
    let Some(&name_len) = reply.first() else {
        return Ok(None);
    };
    let mut name = Vec::with_capacity(name_len as usize);
    while name.len() < name_len as usize {
        let Some(chunk) = request(
            device,
            slot,
            ((feature_index as u16) << 8) | 0x10,
            &[name.len() as u8],
        )?
        else {
            break;
        };
        let remaining = name_len as usize - name.len();
        name.extend(chunk.into_iter().take(remaining));
    }
    Ok((!name.is_empty()).then(|| String::from_utf8_lossy(&name).into_owned()))
}

fn main() -> Result<()> {
    let api = HidApi::new().context("initialize hidapi")?;
    let mut found = 0;

    for info in api.device_list() {
        if info.vendor_id() != LOGITECH_VENDOR_ID {
            continue;
        }
        // Print every Logitech device's USB descriptor serial for comparison.
        let usb_sn = info.serial_number().unwrap_or("None");
        let pid = info.product_id();
        let usage_page = info.usage_page();
        let usage = info.usage();
        let candidate = is_candidate(usage_page, usage);
        println!(
            "[enumerate] pid={:04x} usage_page={:04x} usage={:04x} candidate={} usb_serial={:?} path={}",
            pid, usage_page, usage, candidate, usb_sn,
            info.path().to_string_lossy(),
        );
    }
    println!("---");

    for info in api.device_list() {
        if info.vendor_id() != LOGITECH_VENDOR_ID || !is_candidate(info.usage_page(), info.usage())
        {
            continue;
        }
        let product_id = info.product_id();
        let receiver = is_receiver(product_id);
        let path = info.path().to_string_lossy().into_owned();
        let device = match info.open_device(&api) {
            Ok(device) => device,
            Err(error) => {
                if debug_enabled() {
                    eprintln!("hid++ open failed path={path}: {error}");
                }
                continue;
            }
        };
        let slots: Vec<u8> = if receiver {
            (1..=6).collect()
        } else {
            vec![DIRECT_DEVICE_INDEX]
        };
        for slot in slots {
            let Some(ch_feature) = resolve_feature(&device, slot, FEATURE_CHANGE_HOST)? else {
                continue;
            };
            let host_info = match request(&device, slot, (ch_feature as u16) << 8, &[])? {
                Some(reply) => reply,
                None => continue,
            };
            if host_info.len() < 2 {
                continue;
            }
            let name_feature = resolve_feature(&device, slot, FEATURE_DEVICE_TYPE_AND_NAME)?;
            let device_type = match name_feature {
                Some(index) => request(&device, slot, ((index as u16) << 8) | 0x20, &[])?
                    .and_then(|reply| reply.first().copied()),
                None => None,
            };
            let name = match name_feature {
                Some(index) => read_name(&device, slot, index)?,
                None => None,
            };

            // Read unitId/modelId from DEVICE_FW_VERSION (feature 0x0002).
            let fw_feature = resolve_feature(&device, slot, FEATURE_DEVICE_FW_VERSION)?;
            let unit_id = match fw_feature {
                Some(index) => read_unit_id(&device, slot, index)?,
                None => None,
            };

            // Feature 0x0003 on this device returns stable binary data.
            // For standard HID++ 2.0 it's DEVICE_NAME, but this device
            // (MX Master 3S via Bolt) maps it differently. Use the full
            // response as a device fingerprint if name length doesn't match.
            let feat_0003 = resolve_feature(&device, slot, 0x0003)?;
            let feat_0003_raw = match feat_0003 {
                Some(index) => request(&device, slot, (index as u16) << 8, &[])?,
                None => None,
            };

            // Also try feature 0x0005 func 0x00 (getCount for DEVICE_TYPE_AND_NAME)
            // and func 0x30 which might return serial on some devices.
            let feat_0005 = resolve_feature(&device, slot, FEATURE_DEVICE_TYPE_AND_NAME)?;
            let feat_0005_count = match feat_0005 {
                Some(index) => request(&device, slot, (index as u16) << 8, &[])?,
                None => None,
            };

            found += 1;
            println!(
                "slot={} pid={:04x} type={:?} name={:?} hosts={} current={} ch_feature={:02x}",
                slot, product_id, device_type, name, host_info[0], host_info[1], ch_feature,
            );
            println!("  fw_feature={:?} unit_id={:?}", fw_feature, unit_id);
            println!("  feat_0003={:?} raw={:02x?}", feat_0003, feat_0003_raw);
            println!(
                "  feat_0005={:?} count_raw={:02x?}",
                feat_0005, feat_0005_count
            );
        }
    }

    if found == 0 {
        eprintln!("no ChangeHost-capable Logitech devices found");
    }
    Ok(())
}
