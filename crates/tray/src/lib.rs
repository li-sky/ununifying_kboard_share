//! System tray integration for kbshare.
//!
//! On Windows the tray owns the main thread's event loop. The engine (TCP,
//! TLS, capture/inject, heartbeats) runs on a spawned worker thread and
//! signals mode changes to the tray via a shared atomic.
//!
//! Windows uses its native notification area and Linux uses the
//! freedesktop StatusNotifierItem protocol. Other targets keep a headless
//! compatibility shim.
//! The browser-based configuration editor is available on every platform.

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

pub const MODE_LOCAL: u8 = 0;
pub const MODE_REMOTE: u8 = 1;

#[path = "platform/editor.rs"]
mod editor;
pub use editor::{launch as launch_config_editor, EditorEvent as ConfigEditorEvent};

#[derive(Debug, Clone)]
pub enum TrayExit {
    Quit,
    ReloadConfig(PathBuf),
}

#[derive(Debug, Clone)]
pub struct TrayConfig {
    /// Shown at the top of the menu and in the tooltip, e.g. "kbshare".
    pub app_name: String,
    /// Our local identifier (from config).
    pub local_id: String,
    /// SHA256 certificate fingerprint, to display for manual trust setup.
    pub fingerprint: String,
    /// Configuration file currently used by the process.
    pub config_path: Option<PathBuf>,
    /// Directory of the config file (used by "Open config folder").
    pub config_dir: Option<PathBuf>,
    /// Directory containing runtime log files.
    pub log_dir: Option<PathBuf>,
    /// The node is registered but no peer has been selected yet.
    pub waiting_for_peer: bool,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::editor;
    use image::ImageFormat;
    use std::io::Cursor;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::time::{Duration, Instant};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};
    use windows_sys::Win32::UI::Controls::Dialogs::{
        CommDlgExtendedError, GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST,
        OPENFILENAMEW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    fn to_wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn load_icon(mode: u8) -> Icon {
        let bytes: &[u8] = match mode {
            MODE_REMOTE => include_bytes!("icon_remote.png"),
            _ => include_bytes!("icon_local.png"),
        };
        if let Ok(img) = image::load(Cursor::new(bytes), ImageFormat::Png) {
            let rgba = img.into_rgba8();
            let (w, h) = rgba.dimensions();
            if let Ok(icon) = Icon::from_rgba(rgba.into_raw(), w, h) {
                return icon;
            }
        }
        let color: [u8; 4] = if mode == MODE_REMOTE {
            [60, 180, 75, 255]
        } else {
            [128, 128, 128, 255]
        };
        let rgba: Vec<u8> = std::iter::repeat(color).take(16 * 16).flatten().collect();
        Icon::from_rgba(rgba, 16, 16).expect("solid fallback icon")
    }

    fn show_message(title: &str, body: &str) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
        let t = to_wide(title);
        let b = to_wide(body);
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                b.as_ptr(),
                t.as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            );
        }
    }

    fn choose_config_file(
        config_dir: Option<&std::path::Path>,
        app_name: &str,
    ) -> Result<Option<PathBuf>> {
        let mut file_buf = vec![0u16; 4096];
        let filter = to_wide("JSON files\0*.json\0All files\0*.*\0\0");
        let title = to_wide(&format!("Load {} config", app_name));
        let initial_dir = config_dir.map(|dir| {
            dir.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });
        let default_ext = to_wide("json");

        let mut ofn = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: std::ptr::null_mut(),
            hInstance: std::ptr::null_mut(),
            lpstrFilter: filter.as_ptr(),
            lpstrCustomFilter: std::ptr::null_mut(),
            nMaxCustFilter: 0,
            nFilterIndex: 1,
            lpstrFile: file_buf.as_mut_ptr(),
            nMaxFile: file_buf.len() as u32,
            lpstrFileTitle: std::ptr::null_mut(),
            nMaxFileTitle: 0,
            lpstrInitialDir: initial_dir
                .as_ref()
                .map(|dir| dir.as_ptr())
                .unwrap_or(std::ptr::null()),
            lpstrTitle: title.as_ptr(),
            Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
            nFileOffset: 0,
            nFileExtension: 0,
            lpstrDefExt: default_ext.as_ptr(),
            lCustData: 0,
            lpfnHook: None,
            lpTemplateName: std::ptr::null(),
            pvReserved: std::ptr::null_mut(),
            dwReserved: 0,
            FlagsEx: 0,
        };

        let picked = unsafe { GetOpenFileNameW(&mut ofn) };
        if picked == 0 {
            let err = unsafe { CommDlgExtendedError() };
            if err == 0 {
                return Ok(None);
            }
            anyhow::bail!("file dialog failed with Win32 common-dialog error {}", err);
        }

        let end = file_buf
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(file_buf.len());
        let path = std::ffi::OsString::from_wide(&file_buf[..end]);
        Ok(Some(PathBuf::from(path)))
    }

    pub fn run_tray(
        cfg: TrayConfig,
        mode: Arc<AtomicU8>,
        session_active: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<TrayExit> {
        let config_dir = cfg.config_dir.clone();
        let config_path = cfg.config_path.clone();
        let log_dir = cfg.log_dir.clone();
        let menu = Menu::new();
        let initial_label = if cfg.waiting_for_peer {
            "Registered · Waiting"
        } else {
            "Local"
        };
        let status_item = MenuItem::new(
            format!("● {} — {}", cfg.app_name, initial_label),
            false,
            None,
        );
        let id_item = MenuItem::new(format!("id: {}", cfg.local_id), false, None);
        let fp_item = MenuItem::new("Show fingerprint…", true, None);
        let log_item = MenuItem::new("Open log folder", log_dir.is_some(), None);
        let load_cfg_item = MenuItem::new("Load config file…", true, None);
        let edit_cfg_item = MenuItem::new("Edit configuration…", config_path.is_some(), None);
        let cfg_item = MenuItem::new("Open config folder", config_dir.is_some(), None);
        let quit_item = MenuItem::new("Quit", true, None);
        menu.append(&status_item)?;
        menu.append(&id_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&fp_item)?;
        menu.append(&log_item)?;
        menu.append(&load_cfg_item)?;
        menu.append(&edit_cfg_item)?;
        menu.append(&cfg_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit_item)?;

        let fp_id = fp_item.id().clone();
        let log_id = log_item.id().clone();
        let load_cfg_id = load_cfg_item.id().clone();
        let edit_cfg_id = edit_cfg_item.id().clone();
        let cfg_id = cfg_item.id().clone();
        let quit_id = quit_item.id().clone();

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(format!("{} — {}", cfg.app_name, initial_label))
            .with_icon(load_icon(MODE_LOCAL))
            .build()?;

        let menu_channel = MenuEvent::receiver();
        let mut shown_mode: u8 = MODE_LOCAL;
        let app_name = cfg.app_name.clone();
        let fingerprint = cfg.fingerprint.clone();
        let local_id = cfg.local_id.clone();
        let mut exit_action = TrayExit::Quit;
        let mut editor_events = None;

        let poll_interval = Duration::from_millis(100);
        let mut last_poll = Instant::now();

        // Windows message pump + event polling loop.
        loop {
            // Drain any pending window messages (tray-icon uses a hidden
            // window internally to receive tray events).
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            // Drain menu events.
            while let Ok(me) = menu_channel.try_recv() {
                if me.id == quit_id {
                    shutdown.store(true, Ordering::Relaxed);
                } else if me.id == fp_id {
                    show_message(
                        &format!("{} fingerprint", app_name),
                        &format!("id: {}\nSHA256: {}", local_id, fingerprint),
                    );
                } else if me.id == log_id {
                    if let Some(dir) = &log_dir {
                        let _ = open::that_detached(dir);
                    }
                } else if me.id == load_cfg_id {
                    match choose_config_file(config_dir.as_deref(), &app_name) {
                        Ok(Some(path)) => {
                            exit_action = TrayExit::ReloadConfig(path);
                            shutdown.store(true, Ordering::Relaxed);
                        }
                        Ok(None) => {}
                        Err(error) => {
                            show_message(
                                &format!("{} config", app_name),
                                &format!("Failed to choose config file:\n{}", error),
                            );
                        }
                    }
                } else if me.id == edit_cfg_id {
                    if editor_events.is_none() {
                        if let Some(path) = &config_path {
                            match editor::launch(
                                path.clone(),
                                app_name.clone(),
                                session_active.clone(),
                            ) {
                                Ok(events) => editor_events = Some(events),
                                Err(error) => show_message(
                                    &format!("{} config", app_name),
                                    &format!("Failed to open configuration editor:\n{}", error),
                                ),
                            }
                        }
                    } else {
                        show_message(
                            &format!("{} config", app_name),
                            "The configuration editor is already open in your browser.",
                        );
                    }
                } else if me.id == cfg_id {
                    if let Some(dir) = &config_dir {
                        let _ = open::that_detached(dir);
                    }
                }
            }

            if let Some(events) = &editor_events {
                match events.try_recv() {
                    Ok(editor::EditorEvent::Saved(path)) => {
                        exit_action = TrayExit::ReloadConfig(path);
                        shutdown.store(true, Ordering::Relaxed);
                    }
                    Ok(editor::EditorEvent::Failed(error)) => {
                        show_message(
                            &format!("{} config", app_name),
                            &format!("Failed to save configuration:\n{}", error),
                        );
                        editor_events = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        editor_events = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }

            // Poll mode (cheap atomic) and update UI on change.
            let m = mode.load(Ordering::Relaxed);
            if m != shown_mode {
                shown_mode = m;
                let label = if m == MODE_REMOTE { "Remote" } else { "Local" };
                let _ = tray.set_tooltip(Some(format!("{} — {}", app_name, label)));
                let _ = tray.set_icon(Some(load_icon(m)));
                let _ = status_item.set_text(format!("● {} — {}", app_name, label));
            }

            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Sleep until next poll.
            let elapsed = last_poll.elapsed();
            if elapsed < poll_interval {
                std::thread::sleep(poll_interval - elapsed);
            }
            last_poll = Instant::now();
        }

        drop(tray);
        Ok(exit_action)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use crate::editor;
    use ksni::menu::{MenuItem, StandardItem};
    use std::process::Command;
    use std::sync::mpsc::{self, Receiver, TryRecvError};
    use std::time::Duration;

    #[derive(Debug, Clone, Copy)]
    enum Action {
        ShowFingerprint,
        OpenLogs,
        LoadConfig,
        EditConfig,
        OpenConfigDir,
        Quit,
    }

    struct LinuxTray {
        cfg: TrayConfig,
        mode: u8,
        actions: mpsc::Sender<Action>,
    }

    impl LinuxTray {
        fn status_label(&self) -> &'static str {
            if self.cfg.waiting_for_peer {
                "Registered · Waiting"
            } else if self.mode == MODE_REMOTE {
                "Remote"
            } else {
                "Local"
            }
        }

        fn item(&self, label: impl Into<String>, enabled: bool, action: Action) -> MenuItem<Self> {
            StandardItem {
                label: label.into(),
                enabled,
                activate: Box::new(move |tray: &mut Self| {
                    let _ = tray.actions.send(action);
                }),
                ..Default::default()
            }
            .into()
        }
    }

    impl ksni::Tray for LinuxTray {
        fn id(&self) -> String {
            self.cfg.app_name.clone()
        }

        fn title(&self) -> String {
            format!("{} — {}", self.cfg.app_name, self.status_label())
        }

        fn icon_name(&self) -> String {
            if self.cfg.waiting_for_peer {
                "network-idle".into()
            } else if self.mode == MODE_REMOTE {
                "network-transmit-receive".into()
            } else {
                "input-keyboard".into()
            }
        }

        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip {
                icon_name: self.icon_name(),
                title: self.title(),
                description: format!("id: {}", self.cfg.local_id),
                ..Default::default()
            }
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            let _ = self.actions.send(Action::EditConfig);
        }

        fn menu(&self) -> Vec<MenuItem<Self>> {
            vec![
                StandardItem {
                    label: format!("● {} — {}", self.cfg.app_name, self.status_label()),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: format!("id: {}", self.cfg.local_id),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                self.item("Show fingerprint…", true, Action::ShowFingerprint),
                self.item(
                    "Open log folder",
                    self.cfg.log_dir.is_some(),
                    Action::OpenLogs,
                ),
                self.item("Load config file…", true, Action::LoadConfig),
                self.item(
                    "Edit configuration…",
                    self.cfg.config_path.is_some(),
                    Action::EditConfig,
                ),
                self.item(
                    "Open config folder",
                    self.cfg.config_dir.is_some(),
                    Action::OpenConfigDir,
                ),
                MenuItem::Separator,
                self.item("Quit", true, Action::Quit),
            ]
        }
    }

    fn show_message(app_name: &str, title: &str, body: &str) {
        let notified = Command::new("notify-send")
            .arg("--app-name")
            .arg(app_name)
            .arg(title)
            .arg(body)
            .status()
            .is_ok_and(|status| status.success());
        if !notified {
            eprintln!("{title}\n{body}");
        }
    }

    fn open_path(app_name: &str, path: &std::path::Path, description: &str) {
        if let Err(error) = open::that_detached(path) {
            show_message(
                app_name,
                &format!("Could not open {description}"),
                &error.to_string(),
            );
        }
    }

    fn receive_editor_event(
        events: &mut Option<Receiver<editor::EditorEvent>>,
        app_name: &str,
    ) -> Option<PathBuf> {
        let Some(receiver) = events else {
            return None;
        };
        match receiver.try_recv() {
            Ok(editor::EditorEvent::Saved(path)) => Some(path),
            Ok(editor::EditorEvent::Failed(error)) => {
                show_message(app_name, "Configuration editor failed", &error);
                *events = None;
                None
            }
            Err(TryRecvError::Disconnected) => {
                *events = None;
                None
            }
            Err(TryRecvError::Empty) => None,
        }
    }

    pub fn run_tray(
        cfg: TrayConfig,
        mode: Arc<AtomicU8>,
        session_active: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<TrayExit> {
        let (action_sender, action_receiver) = mpsc::channel();
        let initial_mode = mode.load(Ordering::Relaxed);
        let service = ksni::TrayService::new(LinuxTray {
            cfg: cfg.clone(),
            mode: initial_mode,
            actions: action_sender,
        });
        let handle = service.handle();
        let tray_thread = std::thread::Builder::new()
            .name("linux-status-notifier".into())
            .spawn(move || {
                if let Err(error) = service.run() {
                    tracing::warn!(error = %error, "Linux status notifier unavailable");
                }
            })?;

        tracing::info!("Linux status notifier started");
        let mut shown_mode = initial_mode;
        let mut exit_action = TrayExit::Quit;
        let mut editor_events = None;

        while !shutdown.load(Ordering::Relaxed) {
            while let Ok(action) = action_receiver.try_recv() {
                match action {
                    Action::ShowFingerprint => show_message(
                        &cfg.app_name,
                        &format!("{} fingerprint", cfg.app_name),
                        &format!("id: {}\nSHA256: {}", cfg.local_id, cfg.fingerprint),
                    ),
                    Action::OpenLogs => {
                        if let Some(dir) = &cfg.log_dir {
                            open_path(&cfg.app_name, dir, "log folder");
                        }
                    }
                    Action::LoadConfig => {
                        if editor_events.is_none() {
                            if let Some(path) = &cfg.config_path {
                                match editor::launch_import(
                                    path.clone(),
                                    cfg.app_name.clone(),
                                    session_active.clone(),
                                ) {
                                    Ok(events) => editor_events = Some(events),
                                    Err(error) => show_message(
                                        &cfg.app_name,
                                        "Could not open configuration importer",
                                        &format!("{error:#}"),
                                    ),
                                }
                            }
                        } else {
                            show_message(
                                &cfg.app_name,
                                "Configuration editor",
                                "The configuration editor is already open. Use “Load config file…” there.",
                            );
                        }
                    }
                    Action::EditConfig => {
                        if editor_events.is_none() {
                            if let Some(path) = &cfg.config_path {
                                match editor::launch(
                                    path.clone(),
                                    cfg.app_name.clone(),
                                    session_active.clone(),
                                ) {
                                    Ok(events) => editor_events = Some(events),
                                    Err(error) => show_message(
                                        &cfg.app_name,
                                        "Could not open configuration editor",
                                        &format!("{error:#}"),
                                    ),
                                }
                            }
                        } else {
                            show_message(
                                &cfg.app_name,
                                "Configuration editor",
                                "The configuration editor is already open in your browser.",
                            );
                        }
                    }
                    Action::OpenConfigDir => {
                        if let Some(dir) = &cfg.config_dir {
                            open_path(&cfg.app_name, dir, "config folder");
                        }
                    }
                    Action::Quit => shutdown.store(true, Ordering::Relaxed),
                }
            }

            if let Some(path) = receive_editor_event(&mut editor_events, &cfg.app_name) {
                exit_action = TrayExit::ReloadConfig(path);
                shutdown.store(true, Ordering::Relaxed);
            }

            let current_mode = mode.load(Ordering::Relaxed);
            if current_mode != shown_mode {
                shown_mode = current_mode;
                handle.update(|tray| tray.mode = current_mode);
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        handle.shutdown();
        let _ = tray_thread.join();
        Ok(exit_action)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ksni::Tray;

        #[test]
        fn menu_exposes_the_windows_baseline_actions() {
            let (actions, _) = mpsc::channel();
            let tray = LinuxTray {
                cfg: TrayConfig {
                    app_name: "kbshare".into(),
                    local_id: "desktop".into(),
                    fingerprint: "abc123".into(),
                    config_path: Some(PathBuf::from("config.json")),
                    config_dir: Some(PathBuf::from(".")),
                    log_dir: Some(PathBuf::from("logs")),
                    waiting_for_peer: false,
                },
                mode: MODE_LOCAL,
                actions,
            };
            let labels = tray
                .menu()
                .into_iter()
                .filter_map(|item| match item {
                    MenuItem::Standard(item) => Some(item.label),
                    _ => None,
                })
                .collect::<Vec<_>>();

            for expected in [
                "Show fingerprint…",
                "Open log folder",
                "Load config file…",
                "Edit configuration…",
                "Open config folder",
                "Quit",
            ] {
                assert!(labels.iter().any(|label| label == expected), "{expected}");
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::*;
    use std::time::Duration;

    pub fn run_tray(
        _cfg: TrayConfig,
        _mode: Arc<AtomicU8>,
        _session_active: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<TrayExit> {
        tracing::info!("tray unsupported on this platform; running headless");
        while !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(TrayExit::Quit)
    }
}

pub use platform::run_tray;
