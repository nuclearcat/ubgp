use anyhow::{Context, Result};
use std::{
    ffi::CString,
    io::{self, Write},
};
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

/// Call only from the single-threaded startup path, before Tokio or tracing.
pub fn detach() -> Result<()> {
    // SAFETY: no runtime, worker threads, or logging locks exist at this point.
    // libc daemon forks, calls setsid, changes cwd to /, and redirects 0/1/2
    // to /dev/null. The original process exits after a successful fork.
    if unsafe { libc::daemon(0, 0) } != 0 {
        return Err(io::Error::last_os_error()).context("detaching daemon");
    }
    Ok(())
}

pub fn init_logging(background: bool, debug: bool) {
    let filter = if debug {
        "ubgp=debug".into()
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "ubgp=info".into())
    };
    if background {
        // SAFETY: openlog retains the static, NUL-terminated identifier.
        unsafe {
            libc::openlog(
                c"ubgp".as_ptr(),
                libc::LOG_PID | libc::LOG_NDELAY,
                libc::LOG_DAEMON,
            );
        }
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .without_time()
            .with_writer(Syslog)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

struct Syslog;
struct Event {
    bytes: Vec<u8>,
    priority: i32,
}
impl<'a> MakeWriter<'a> for Syslog {
    type Writer = Event;
    fn make_writer(&'a self) -> Event {
        Event {
            bytes: Vec::new(),
            priority: libc::LOG_INFO,
        }
    }
    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Event {
        let priority = match *meta.level() {
            Level::ERROR => libc::LOG_ERR,
            Level::WARN => libc::LOG_WARNING,
            Level::INFO => libc::LOG_INFO,
            _ => libc::LOG_DEBUG,
        };
        Event {
            bytes: Vec::new(),
            priority,
        }
    }
}
impl Write for Event {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes
            .extend(bytes.iter().map(|b| if *b == 0 { b'?' } else { *b }));
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        let message = CString::new(self.bytes.as_slice()).expect("NUL bytes sanitized in write");
        // SAFETY: the fixed format consumes exactly one live C string. Log
        // messages are data, never format strings (including any '%' characters).
        unsafe {
            libc::syslog(self.priority, c"%s".as_ptr(), message.as_ptr());
        }
    }
}
