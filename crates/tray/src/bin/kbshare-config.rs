#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let mut args = std::env::args_os().skip(1);
    let config = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("usage: kbshare-config <config.json> [app-name]"))?,
    );
    let app_name = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "kbshare".to_string());
    let session_active = Arc::new(AtomicBool::new(false));
    let events = kbshare_tray::launch_config_editor(config, app_name, session_active)?;
    match events.recv()? {
        kbshare_tray::ConfigEditorEvent::Saved(path) => println!("saved {}", path.display()),
        kbshare_tray::ConfigEditorEvent::Failed(error) => anyhow::bail!(error),
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kbshare-config is currently available on Windows");
}
