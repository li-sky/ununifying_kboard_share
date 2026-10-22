//! Daily UTC logs with age-based retention, including while the app is idle.

use anyhow::Result;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use time::{Date, OffsetDateTime};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

const RETENTION_DAYS: i64 = 7;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

pub struct LogGuard {
    _cleanup: CleanupGuard,
    _writer: WorkerGuard,
}

pub fn init(directory: &Path) -> Result<LogGuard> {
    let (writer, guard) = tracing_appender::non_blocking(daily_appender(directory)?);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize logging: {error}"))?;
    cleanup_or_warn(directory);
    Ok(LogGuard {
        _cleanup: CleanupGuard::start(directory.to_path_buf(), CLEANUP_INTERVAL)?,
        _writer: guard,
    })
}

fn daily_appender(directory: &Path) -> Result<RollingFileAppender> {
    Ok(RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("kbshare")
        .filename_suffix("log")
        .build(directory)?)
}

struct CleanupGuard {
    stop: SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl CleanupGuard {
    fn start(directory: PathBuf, interval: Duration) -> io::Result<Self> {
        let (stop, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("log-retention".into())
            .spawn(move || {
                while receiver.recv_timeout(interval) == Err(RecvTimeoutError::Timeout) {
                    cleanup_or_warn(&directory);
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn cleanup_or_warn(directory: &Path) {
    if let Err(error) = remove_expired_logs(directory, OffsetDateTime::now_utc()) {
        // Retention failures must not prevent input forwarding or new log writes.
        tracing::warn!(error = %error, "could not remove expired log files; will retry");
    }
}

fn log_date(name: &str) -> Option<Date> {
    let date = name.strip_prefix("kbshare.")?.strip_suffix(".log")?;
    let format = time::format_description::parse("[year]-[month]-[day]").ok()?;
    let parsed = Date::parse(date, &format).ok()?;
    (parsed.to_string() == date).then_some(parsed)
}

fn remove_expired_logs(directory: &Path, now: OffsetDateTime) -> io::Result<()> {
    let cutoff = now.date() - time::Duration::days(RETENTION_DAYS);
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        // Never follow symlinks or remove directories/unrelated files.
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let expired = if let Some(date) = log_date(name) {
            date <= cutoff
        } else if name == "kbshare.log" {
            // Migrate the old unrotated file without deleting recent diagnostics.
            let modified = OffsetDateTime::from(entry.metadata()?.modified()?);
            modified <= now - time::Duration::days(RETENTION_DAYS)
        } else {
            false
        };
        if expired {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                // Another instance may have cleaned the shared directory first.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Instant, SystemTime};

    fn now() -> OffsetDateTime {
        Date::from_calendar_date(2026, time::Month::January, 3)
            .unwrap()
            .with_hms(12, 0, 0)
            .unwrap()
            .assume_utc()
    }

    #[test]
    fn retention_uses_calendar_age_not_number_of_files() {
        let dir = tempfile::tempdir().unwrap();
        let expired = ["kbshare.2025-12-27.log", "kbshare.2020-01-01.log"];
        let kept = [
            "kbshare.2025-12-28.log", // Six days ago: retained.
            "kbshare.2026-01-03.log", // Today.
            "kbshare.2026-01-04.log", // Clock rollback: don't delete future logs.
            "other.2020-01-01.log",
            "kbshare.2020-01-01.log.bak",
            "kbshare.2020-99-01.log",
        ];
        for name in expired.iter().chain(&kept) {
            fs::write(dir.path().join(name), "diagnostics").unwrap();
        }
        let subdir = dir.path().join("kbshare.2019-01-01.log");
        fs::create_dir(&subdir).unwrap();
        remove_expired_logs(dir.path(), now()).unwrap();
        for name in expired {
            assert!(!dir.path().join(name).exists(), "{name}");
        }
        for name in kept {
            assert!(dir.path().join(name).exists(), "{name}");
        }
        assert!(subdir.is_dir());
    }

    #[test]
    fn legacy_log_expires_seven_days_after_last_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kbshare.log");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"legacy diagnostics").unwrap();
        file.set_modified(SystemTime::from(now() - time::Duration::days(6)))
            .unwrap();
        remove_expired_logs(dir.path(), now()).unwrap();
        assert!(path.exists());
        file.set_modified(SystemTime::from(now() - time::Duration::days(7)))
            .unwrap();
        drop(file);
        remove_expired_logs(dir.path(), now()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn idle_app_still_cleans_expired_logs_and_worker_stops_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kbshare.2020-01-01.log");
        let guard =
            CleanupGuard::start(dir.path().to_path_buf(), Duration::from_millis(10)).unwrap();
        fs::write(&path, "expired").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!path.exists());
        drop(guard);
        // Drop joins the worker; a new expired file must now be left alone.
        fs::write(&path, "expired").unwrap();
        thread::sleep(Duration::from_millis(30));
        assert!(path.exists());
    }

    #[test]
    fn restarting_on_the_same_day_appends_to_daily_log() {
        let dir = tempfile::tempdir().unwrap();
        let before = OffsetDateTime::now_utc().date();
        for line in ["first run\n", "second run\n"] {
            let mut appender = daily_appender(dir.path()).unwrap();
            appender.write_all(line.as_bytes()).unwrap();
            appender.flush().unwrap();
        }
        let after = OffsetDateTime::now_utc().date();
        let mut paths: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        for path in &paths {
            let date = log_date(path.file_name().unwrap().to_str().unwrap()).unwrap();
            assert!(date >= before && date <= after);
        }
        let contents: String = paths
            .iter()
            .map(|path| fs::read_to_string(path).unwrap())
            .collect();
        assert_eq!(contents, "first run\nsecond run\n");
        if before == after {
            assert_eq!(paths.len(), 1);
        }
    }
}
