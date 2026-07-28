//! System tray integration for kbshare.
//!
//! On Windows the tray owns the main thread's event loop. The engine (TCP,
//! TLS, capture/inject, heartbeats) runs on a spawned worker thread and
//! signals mode changes to the tray via a shared atomic.
//!
//! On non-Windows targets `run_tray` is a no-op shim that blocks until
//! `shutdown` is set, so binaries that link this crate still build.

use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

pub const MODE_LOCAL: u8 = 0;
pub const MODE_REMOTE: u8 = 1;

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
    mod editor;
    pub use editor::{launch as launch_config_editor, EditorEvent as ConfigEditorEvent};
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

#[cfg(not(windows))]
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
#[cfg(windows)]
pub use platform::{launch_config_editor, ConfigEditorEvent};
