//! `tracing-core` caches, per callsite, whether any subscriber is interested in it — once a
//! callsite's very first hit in the whole test-binary process resolves that cache (its
//! `has_just_one` fast path), the result sticks for the rest of the process. Tests that each
//! install their own scoped `tracing::subscriber::set_default` guard race on this: if a
//! shared production callsite (e.g. a `debug!` in a handler) is first hit — anywhere in the
//! process, on any thread — while no guard is active on that thread, the cache can disable the
//! callsite forever, silently dropping events for every guard installed afterwards, on any
//! thread.
//!
//! Installing exactly one `set_global_default` subscriber for the whole process closes that
//! fast path: a global dispatch is always "the" dispatch, so the cache's assumption holds and
//! never mis-fires. This module supplies that single subscriber and demultiplexes its output
//! back to whichever test is currently running on the calling thread via a thread-local
//! buffer, so concurrently running tests never see each other's captured log lines.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, Mutex, Once};

thread_local! {
    static ACTIVE_BUFFER: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

static INSTALL: Once = Once::new();

/// Installs the single process-global `tracing_subscriber::fmt` subscriber shared by every
/// debug-capturing test in this crate. Idempotent — only the first call across the whole test
/// binary actually installs anything, so every test can call this unconditionally without
/// coordinating over who "owns" the install.
pub fn install_global_test_subscriber() {
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(ThreadLocalMakeWriter)
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect(
            "install_global_test_subscriber must be the only code installing a global \
             tracing subscriber in this test binary",
        );
    });
}

#[derive(Clone, Default)]
struct ThreadLocalMakeWriter;

impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for ThreadLocalMakeWriter {
    type Writer = ThreadLocalWriter;

    fn make_writer(&'w self) -> Self::Writer {
        ThreadLocalWriter
    }
}

struct ThreadLocalWriter;

impl io::Write for ThreadLocalWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        ACTIVE_BUFFER.with(|active| {
            if let Some(target) = active.borrow().as_ref() {
                target.lock().unwrap().extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Routes the global subscriber's output on the calling thread into `buf` for as long as the
/// guard is alive, and stops routing on drop. `#[must_use]` so a guard bound to `_` (dropped
/// immediately, before the test body runs) fails to compile silently into "captures nothing."
#[must_use]
pub struct TestBufferGuard {
    _private: (),
}

impl TestBufferGuard {
    pub fn new(buf: Arc<Mutex<Vec<u8>>>) -> Self {
        ACTIVE_BUFFER.with(|active| *active.borrow_mut() = Some(buf));
        Self { _private: () }
    }
}

impl Drop for TestBufferGuard {
    fn drop(&mut self) {
        ACTIVE_BUFFER.with(|active| *active.borrow_mut() = None);
    }
}
