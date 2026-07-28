use anyhow::{bail, Result};
pub use kbshare_core::protocol::{FlowLayout, FlowLayoutDevice};
use serde::{Deserialize, Serialize};
use std::path::Path;

const LOGITECH_VENDOR_ID: u16 = 0x046d;
const BOLT_RECEIVER_PID: u16 = 0xc548;
const UNIFYING_RECEIVER_PIDS: [u16; 2] = [0xc52b, 0xc532];
const FEATURE_ROOT: u16 = 0x0000;
const FEATURE_DEVICE_FINGERPRINT: u16 = 0x0003;
const FEATURE_DEVICE_TYPE_AND_NAME: u16 = 0x0005;
const FEATURE_CHANGE_HOST: u16 = 0x1814;
const REPORT_LONG: u8 = 0x11;
const SOFTWARE_ID: u8 = 0x08;
const DIRECT_DEVICE_INDEX: u8 = 0xff;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowLiteConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub slot: Option<u8>,
    #[serde(default)]
    pub fingerprint: Option<[u8; 16]>,
    #[serde(default = "default_local_host")]
    pub local_host: u8,
    #[serde(default = "default_remote_host")]
    pub remote_host: u8,
    #[serde(default = "default_edge_px")]
    pub edge_px: i32,
    #[serde(default)]
    pub layout: FlowLayout,
}

impl Default for FlowLiteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slot: None,
            fingerprint: None,
            local_host: default_local_host(),
            remote_host: default_remote_host(),
            edge_px: default_edge_px(),
            layout: FlowLayout::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowRole {
    Host,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEdge {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTarget {
    pub edge: FlowEdge,
    pub host_index: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutReconcile {
    AppliedRemote,
    SendLocal(FlowLayout),
    Equal,
}

impl FlowLiteConfig {
    pub fn ensure_layout(&mut self, local_id: &str, remote_id: &str, role: FlowRole) {
        if !self.layout.devices.is_empty() {
            return;
        }
        let (local_host, local_x, remote_host, remote_x) = match role {
            FlowRole::Host => (self.local_host, 180, self.remote_host, 820),
            FlowRole::Client => (self.remote_host, 820, self.local_host, 180),
        };
        self.layout.devices = vec![
            FlowLayoutDevice {
                id: local_id.to_string(),
                label: local_id.to_string(),
                host_index: local_host,
                x: local_x,
                y: 500,
            },
            FlowLayoutDevice {
                id: remote_id.to_string(),
                label: remote_id.to_string(),
                host_index: remote_host,
                x: remote_x,
                y: 500,
            },
        ];
    }

    pub fn target_for_peer(&self, local_id: &str, peer_id: &str) -> Option<FlowTarget> {
        let local = self
            .layout
            .devices
            .iter()
            .find(|device| device.id == local_id)?;
        let peer = self
            .layout
            .devices
            .iter()
            .find(|device| device.id == peer_id)?;
        let dx = peer.x - local.x;
        let dy = peer.y - local.y;
        if dx == 0 && dy == 0 {
            return None;
        }
        let edge = if dx.abs() >= dy.abs() {
            if dx > 0 {
                FlowEdge::Right
            } else {
                FlowEdge::Left
            }
        } else if dy > 0 {
            FlowEdge::Bottom
        } else {
            FlowEdge::Top
        };
        Some(FlowTarget {
            edge,
            host_index: peer.host_index,
        })
    }
}

pub fn reconcile_layout(local: &mut FlowLayout, incoming: &FlowLayout) -> LayoutReconcile {
    if incoming.is_newer_than(local) {
        *local = incoming.clone();
        LayoutReconcile::AppliedRemote
    } else if local.is_newer_than(incoming) {
        LayoutReconcile::SendLocal(local.clone())
    } else {
        LayoutReconcile::Equal
    }
}

pub fn persist_layout(config_path: &Path, layout: &FlowLayout) -> Result<()> {
    let bytes = std::fs::read(config_path)?;
    let mut root: serde_json::Value = serde_json::from_slice(&bytes)?;
    let object = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("configuration root must be an object"))?;
    let flow = object
        .entry("flow_lite")
        .or_insert_with(|| serde_json::json!({}));
    let flow_object = flow
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("flow_lite must be an object"))?;
    flow_object.insert("layout".into(), serde_json::to_value(layout)?);
    let mut output = serde_json::to_vec_pretty(&root)?;
    output.push(b'\n');
    std::fs::write(config_path, output)?;
    Ok(())
}

pub fn persist_flow_lite(config_path: &Path, config: &FlowLiteConfig) -> Result<()> {
    let bytes = std::fs::read(config_path)?;
    let mut root: serde_json::Value = serde_json::from_slice(&bytes)?;
    let object = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("configuration root must be an object"))?;
    let flow = object
        .entry("flow_lite")
        .or_insert_with(|| serde_json::json!({}));
    let flow_object = flow
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("flow_lite must be an object"))?;
    let serialized = serde_json::to_value(config)?;
    for (key, value) in serialized
        .as_object()
        .expect("FlowLiteConfig serializes as an object")
    {
        flow_object.insert(key.clone(), value.clone());
    }
    let mut output = serde_json::to_vec_pretty(&root)?;
    output.push(b'\n');
    std::fs::write(config_path, output)?;
    Ok(())
}

fn default_local_host() -> u8 {
    0
}
fn default_remote_host() -> u8 {
    2
}
fn default_edge_px() -> i32 {
    2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Receiver,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDevice {
    pub path: String,
    pub product_id: u16,
    pub connection: ConnectionType,
    pub slot: u8,
    pub device_type: Option<u8>,
    pub name: Option<String>,
    pub feature_index: u8,
    pub host_count: u8,
    pub current_host: u8,
    pub fingerprint: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidCollection {
    pub path: String,
    pub product_id: u16,
    pub usage_page: u16,
    pub usage: u16,
    pub interface_number: i32,
    pub candidate: bool,
}

impl FlowDevice {
    pub fn is_mouse(&self) -> bool {
        matches!(self.device_type, Some(3..=5))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use anyhow::{anyhow, Context};
    use hidapi::{HidApi, HidDevice};
    use std::sync::{Mutex as StdMutex, OnceLock};
    use std::time::{Duration, Instant};

    const HIDPP_USAGE_PAGES: [u16; 3] = [0xff00, 0xff43, 0xff0c];
    const HIDPP_LONG_USAGES: [u16; 2] = [0x0002, 0x0202];
    static SWITCH_CACHE: OnceLock<StdMutex<Option<FlowDevice>>> = OnceLock::new();

    fn switch_cache() -> &'static StdMutex<Option<FlowDevice>> {
        SWITCH_CACHE.get_or_init(|| StdMutex::new(None))
    }

    fn remember_switch_device(device: &FlowDevice) {
        if let Ok(mut cache) = switch_cache().lock() {
            *cache = Some(device.clone());
        }
    }

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
        device: &HidDevice,
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

    fn write_only(
        device: &HidDevice,
        device_index: u8,
        request_id: u16,
        params: &[u8],
    ) -> Result<()> {
        let message = build_message(device_index, request_id, params)?;
        device.write(&message).context("write ChangeHost report")?;
        Ok(())
    }

    fn resolve_feature(device: &HidDevice, slot: u8, feature: u16) -> Result<Option<u8>> {
        let params = [(feature >> 8) as u8, feature as u8, 0];
        Ok(request(device, slot, FEATURE_ROOT << 8, &params)?
            .and_then(|reply| reply.first().copied())
            .filter(|index| *index != 0))
    }

    fn read_name(device: &HidDevice, slot: u8, feature_index: u8) -> Result<Option<String>> {
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

    fn read_fingerprint(device: &HidDevice, slot: u8) -> Result<Option<[u8; 16]>> {
        let Some(feature_index) = resolve_feature(device, slot, FEATURE_DEVICE_FINGERPRINT)? else {
            return Ok(None);
        };
        for attempt in 0..3 {
            if let Some(reply) = request(device, slot, (feature_index as u16) << 8, &[])? {
                if let Ok(fingerprint) = <[u8; 16]>::try_from(reply.as_slice()) {
                    return Ok(Some(fingerprint));
                }
            }
            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(75));
            }
        }
        Ok(None)
    }

    fn inspect_slot(
        device: &HidDevice,
        path: String,
        product_id: u16,
        connection: ConnectionType,
        slot: u8,
    ) -> Result<Option<FlowDevice>> {
        let Some(feature_index) = resolve_feature(device, slot, FEATURE_CHANGE_HOST)? else {
            return Ok(None);
        };
        let Some(host_info) = request(device, slot, (feature_index as u16) << 8, &[])? else {
            return Ok(None);
        };
        if host_info.len() < 2 {
            return Ok(None);
        }
        let name_feature = resolve_feature(device, slot, FEATURE_DEVICE_TYPE_AND_NAME)?;
        let device_type = match name_feature {
            Some(index) => request(device, slot, ((index as u16) << 8) | 0x20, &[])?
                .and_then(|reply| reply.first().copied()),
            None => None,
        };
        let name = match name_feature {
            Some(index) => read_name(device, slot, index)?,
            None => None,
        };
        let fingerprint = read_fingerprint(device, slot)?;
        Ok(Some(FlowDevice {
            path,
            product_id,
            connection,
            slot,
            device_type,
            name,
            feature_index,
            host_count: host_info[0],
            current_host: host_info[1],
            fingerprint,
        }))
    }

    fn inspect_matching(selected_slot: Option<u8>) -> Result<Vec<FlowDevice>> {
        let api = HidApi::new().context("initialize hidapi")?;
        let mut devices = Vec::new();
        for info in api.device_list() {
            if info.vendor_id() != LOGITECH_VENDOR_ID
                || !is_candidate(info.usage_page(), info.usage())
            {
                continue;
            }
            let product_id = info.product_id();
            let receiver = is_receiver(product_id);
            let connection = if receiver {
                ConnectionType::Receiver
            } else {
                ConnectionType::Direct
            };
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
                selected_slot.map_or_else(|| (1..=6).collect(), |slot| vec![slot])
            } else {
                vec![DIRECT_DEVICE_INDEX]
            };
            for slot in slots {
                if let Some(found) =
                    inspect_slot(&device, path.clone(), product_id, connection, slot)?
                {
                    devices.push(found);
                }
            }
        }
        Ok(devices)
    }

    pub fn inspect() -> Result<Vec<FlowDevice>> {
        inspect_with_fingerprint()
    }

    pub fn inspect_with_fingerprint() -> Result<Vec<FlowDevice>> {
        let devices = inspect_matching(None)?;
        if !devices.is_empty() {
            if let Some(mouse) = devices.iter().find(|device| device.is_mouse()) {
                remember_switch_device(mouse);
            }
            return Ok(devices);
        }
        // The first query can also wake a sleeping mouse. Retry the complete
        // scan once so transient HID++ timeouts do not disable auto-setup.
        std::thread::sleep(Duration::from_millis(150));
        let devices = inspect_matching(None)?;
        if let Some(mouse) = devices.iter().find(|device| device.is_mouse()) {
            remember_switch_device(mouse);
        }
        Ok(devices)
    }

    pub fn collections() -> Result<Vec<HidCollection>> {
        let api = HidApi::new().context("initialize hidapi")?;
        Ok(api
            .device_list()
            .filter(|info| info.vendor_id() == LOGITECH_VENDOR_ID)
            .map(|info| HidCollection {
                path: info.path().to_string_lossy().into_owned(),
                product_id: info.product_id(),
                usage_page: info.usage_page(),
                usage: info.usage(),
                interface_number: info.interface_number(),
                candidate: is_candidate(info.usage_page(), info.usage()),
            })
            .collect())
    }

    pub fn switch_host(slot: Option<u8>, target_host: u8) -> Result<FlowDevice> {
        let cached = switch_cache()
            .lock()
            .ok()
            .and_then(|cache| cache.clone())
            .filter(|device| slot.is_none() || slot == Some(device.slot));
        if let Some(selected) = cached {
            if target_host < selected.host_count {
                let api = HidApi::new().context("initialize hidapi")?;
                if let Ok(path) = std::ffi::CString::new(selected.path.clone()) {
                    if let Ok(device) = api.open_path(&path) {
                        if write_only(
                            &device,
                            selected.slot,
                            ((selected.feature_index as u16) << 8) | 0x10,
                            &[target_host],
                        )
                        .is_ok()
                        {
                            return Ok(selected);
                        }
                    }
                }
            }
            if let Ok(mut cache) = switch_cache().lock() {
                *cache = None;
            }
        }
        let candidates = inspect_matching(slot)?;
        let selected = candidates
            .iter()
            .find(|device| slot == Some(device.slot))
            .or_else(|| candidates.iter().find(|device| device.is_mouse()))
            .ok_or_else(|| anyhow!("no ChangeHost-capable Logitech mouse found"))?;
        if target_host >= selected.host_count {
            bail!(
                "host index {} is invalid for {} hosts",
                target_host,
                selected.host_count
            );
        }

        let api = HidApi::new().context("initialize hidapi")?;
        let path = std::ffi::CString::new(selected.path.clone()).context("invalid HID path")?;
        let device = api.open_path(&path).context("reopen selected HID device")?;
        write_only(
            &device,
            selected.slot,
            ((selected.feature_index as u16) << 8) | 0x10,
            &[target_host],
        )?;
        remember_switch_device(selected);
        Ok(selected.clone())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn flow_config_defaults_are_disabled_and_target_device_three() {
            let config = FlowLiteConfig::default();
            assert!(!config.enabled);
            assert_eq!(config.local_host, 0);
            assert_eq!(config.remote_host, 2);
        }

        #[test]
        fn layout_position_selects_edge_and_peer_channel() {
            let mut config = FlowLiteConfig::default();
            config.ensure_layout("host", "client", FlowRole::Host);
            let target = config.target_for_peer("host", "client").unwrap();
            assert_eq!(target.edge, FlowEdge::Right);
            assert_eq!(target.host_index, 2);

            config.layout.devices[1].x = 180;
            config.layout.devices[1].y = 50;
            assert_eq!(
                config.target_for_peer("host", "client").unwrap().edge,
                FlowEdge::Top
            );
        }

        #[test]
        fn reconcile_keeps_newest_complete_layout() {
            let mut local = FlowLayout {
                version: 10,
                updated_by: "host".into(),
                devices: vec![],
            };
            let incoming = FlowLayout {
                version: 11,
                updated_by: "client".into(),
                devices: vec![FlowLayoutDevice {
                    id: "offline".into(),
                    label: "Saved device".into(),
                    host_index: 1,
                    x: 500,
                    y: 100,
                }],
            };
            assert_eq!(
                reconcile_layout(&mut local, &incoming),
                LayoutReconcile::AppliedRemote
            );
            assert_eq!(local.devices, incoming.devices);
        }

        #[test]
        fn persist_layout_preserves_unrelated_config_fields() {
            let path = std::env::temp_dir().join(format!(
                "kbshare-flow-layout-{}-{}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::write(
                &path,
                br#"{"local_id":"host","remote_id":"client","custom":17,"flow_lite":{"enabled":true}}"#,
            )
            .unwrap();
            let layout = FlowLayout {
                version: 9,
                updated_by: "client".into(),
                devices: vec![FlowLayoutDevice {
                    id: "offline".into(),
                    label: "Offline".into(),
                    host_index: 1,
                    x: 300,
                    y: 700,
                }],
            };
            persist_layout(&path, &layout).unwrap();
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["custom"], 17);
            assert_eq!(saved["flow_lite"]["enabled"], true);
            assert_eq!(saved["flow_lite"]["layout"]["version"], 9);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn persist_flow_lite_preserves_unknown_flow_fields() {
            let path = std::env::temp_dir().join(format!(
                "kbshare-flow-config-{}-{}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::write(
                &path,
                br#"{"local_id":"host","flow_lite":{"vendor_extension":17}}"#,
            )
            .unwrap();
            let config = FlowLiteConfig {
                enabled: true,
                fingerprint: Some([3; 16]),
                ..FlowLiteConfig::default()
            };
            persist_flow_lite(&path, &config).unwrap();
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["flow_lite"]["vendor_extension"], 17);
            assert_eq!(saved["flow_lite"]["enabled"], true);
            assert_eq!(saved["flow_lite"]["fingerprint"][0], 3);
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn two_peers_converge_on_the_newer_layout() {
            let mut host = FlowLayout {
                version: 20,
                updated_by: "host".into(),
                devices: vec![],
            };
            let mut client = FlowLayout {
                version: 21,
                updated_by: "client".into(),
                devices: vec![FlowLayoutDevice {
                    id: "offline".into(),
                    label: "Offline".into(),
                    host_index: 1,
                    x: 700,
                    y: 200,
                }],
            };
            assert_eq!(
                reconcile_layout(&mut host, &client),
                LayoutReconcile::AppliedRemote
            );
            assert_eq!(reconcile_layout(&mut client, &host), LayoutReconcile::Equal);
            assert_eq!(host, client);
        }

        #[test]
        fn change_host_report_uses_zero_based_host_id() {
            let report = build_message(2, 0x0710, &[2]).unwrap();
            assert_eq!(&report[..5], &[0x11, 0x02, 0x07, 0x18, 0x02]);
            assert_eq!(report.len(), 20);
        }

        #[test]
        fn root_query_contains_feature_code() {
            let report = build_message(1, 0, &[0x18, 0x14, 0]).unwrap();
            assert_eq!(&report[..7], &[0x11, 0x01, 0x00, 0x08, 0x18, 0x14, 0x00]);
        }
    }
}

#[cfg(windows)]
pub use platform::{collections, inspect, inspect_with_fingerprint, switch_host};

#[cfg(not(windows))]
pub fn inspect() -> Result<Vec<FlowDevice>> {
    bail!("kbshare-flow HID++ access is currently implemented for Windows")
}

#[cfg(not(windows))]
pub fn inspect_with_fingerprint() -> Result<Vec<FlowDevice>> {
    inspect()
}

#[cfg(not(windows))]
pub fn collections() -> Result<Vec<HidCollection>> {
    bail!("kbshare-flow HID++ access is currently implemented for Windows")
}

#[cfg(not(windows))]
pub fn switch_host(_slot: Option<u8>, _target_host: u8) -> Result<FlowDevice> {
    bail!("kbshare-flow HID++ access is currently implemented for Windows")
}
