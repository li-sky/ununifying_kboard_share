//! Native clipboard promises. Describing files never reads their contents.
use super::files::FileMeta;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[cfg(target_os = "linux")]
#[path = "clipboard_deferred/linux.rs"]
mod native;
#[cfg(windows)]
#[path = "clipboard_deferred/windows.rs"]
mod native;

pub(super) struct Ticket {
    pub id: u64,
    pub files: Vec<FileMeta>,
    pub requested: AtomicBool,
    pub owned: AtomicBool,
    pub stopped: AtomicBool,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub owner: AtomicUsize,
    result: Mutex<Option<Result<Vec<PathBuf>, String>>>,
    changed: Condvar,
}
impl Ticket {
    pub fn wait(&self) -> Result<Vec<PathBuf>> {
        let mut result = self.result.lock().unwrap();
        if result.is_none() {
            self.requested.store(true, Ordering::Release);
        }
        while result.is_none() && !self.stopped.load(Ordering::Acquire) {
            result = self.changed.wait(result).unwrap();
        }
        match result.as_ref() {
            Some(Ok(paths)) => Ok(paths.clone()),
            Some(Err(error)) => Err(anyhow!(error.clone())),
            None => Err(anyhow!("clipboard file promise was cancelled")),
        }
    }
    pub fn cancel(&self) {
        let _result = self.result.lock().unwrap();
        self.stopped.store(true, Ordering::Release);
        self.changed.notify_all();
    }
}

pub(super) struct Provider {
    ticket: Arc<Ticket>,
}
impl Provider {
    pub fn new(id: u64, files: Vec<FileMeta>) -> Result<Self> {
        let ticket = Arc::new(Ticket {
            id,
            files,
            requested: AtomicBool::new(false),
            owned: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
            result: Mutex::new(None),
            changed: Condvar::new(),
        });
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker_ticket = ticket.clone();
        std::thread::Builder::new()
            .name("clipboard-promises".into())
            .spawn(move || {
                #[cfg(any(windows, target_os = "linux"))]
                let result = native::run(worker_ticket.clone(), &tx);
                #[cfg(not(any(windows, target_os = "linux")))]
                let result: Result<()> = Err(anyhow!(
                    "native deferred files unsupported on this platform"
                ));
                if let Err(error) = result {
                    let _ = tx.try_send(Err(format!("{error:#}")));
                    tracing::warn!(error = %error, "native clipboard provider stopped");
                }
                worker_ticket.owned.store(false, Ordering::Release);
                worker_ticket.cancel();
            })?;
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self { ticket }),
            result => {
                ticket.cancel();
                Err(anyhow!(
                    "could not publish deferred clipboard files: {result:?}"
                ))
            }
        }
    }
    pub fn owns(&self) -> bool {
        #[cfg(windows)]
        {
            return native::owns(&self.ticket);
        }
        #[cfg(not(windows))]
        {
            self.ticket.owned.load(Ordering::Acquire)
        }
    }
    pub fn take_request(&self) -> Option<u64> {
        self.ticket
            .requested
            .swap(false, Ordering::AcqRel)
            .then_some(self.ticket.id)
    }
    pub fn complete(&self, paths: Vec<PathBuf>) {
        *self.ticket.result.lock().unwrap() = Some(if paths.len() == self.ticket.files.len() {
            Ok(paths)
        } else {
            Err("received file count does not match promise".into())
        });
        self.ticket.changed.notify_all();
    }
    pub fn id(&self) -> u64 {
        self.ticket.id
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.ticket.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ticket() -> Arc<Ticket> {
        Arc::new(Ticket {
            id: 1,
            files: vec![FileMeta {
                name: "downloaded".into(),
                size: 0,
            }],
            requested: AtomicBool::new(false),
            owned: AtomicBool::new(true),
            stopped: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
            result: Mutex::new(None),
            changed: Condvar::new(),
        })
    }
    #[test]
    fn dropping_provider_wakes_all_pending_readers() {
        let ticket = ticket();
        let provider = Provider {
            ticket: ticket.clone(),
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(|| ticket.wait());
            let second = scope.spawn(|| ticket.wait());
            drop(provider);
            assert!(first.join().unwrap().is_err());
            assert!(second.join().unwrap().is_err());
        });
    }
    #[test]
    fn promise_requests_once_and_wakes_on_completion() {
        let ticket = ticket();
        let provider = Provider {
            ticket: ticket.clone(),
        };
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| ticket.wait().unwrap());
            let until = std::time::Instant::now() + Duration::from_secs(2);
            while !ticket.requested.load(Ordering::Acquire) {
                assert!(std::time::Instant::now() < until);
                std::thread::yield_now();
            }
            assert_eq!(provider.take_request(), Some(1));
            assert_eq!(provider.take_request(), None);
            provider.complete(vec![PathBuf::from("downloaded")]);
            assert_eq!(waiter.join().unwrap(), vec![PathBuf::from("downloaded")]);
        });
    }
}
