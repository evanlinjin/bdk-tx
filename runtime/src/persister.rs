//! Internal persisters used to bridge payjoin's `SessionPersister` trait into
//! the runtime's sans-IO `Step::Save` surface.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use payjoin::persist::SessionPersister;

/// Records every event passed to `save_event` into a shared buffer. The
/// runtime constructs one of these on demand, hands it to payjoin's `.save()`
/// flow, and later drains the buffer into a [`Step::Save`](crate::Step::Save).
///
/// `load` always returns an empty iterator — capture-only.
pub(crate) struct Capturing<E> {
    pub(crate) events: Arc<Mutex<Vec<E>>>,
}

impl<E> Capturing<E> {
    pub(crate) fn new(events: Arc<Mutex<Vec<E>>>) -> Self {
        Self { events }
    }
}

impl<E: Send + 'static> SessionPersister for Capturing<E> {
    type InternalStorageError = Infallible;
    type SessionEvent = E;

    fn save_event(&self, event: E) -> Result<(), Self::InternalStorageError> {
        self.events.lock().expect("captured-events mutex poisoned").push(event);
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        Ok(Box::new(core::iter::empty()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }
}

/// Replays a fixed event log when payjoin's `replay_event_log` asks the
/// persister to `load()`. Used by `*Session::resume_from_events` to feed a
/// pre-existing event sequence back into payjoin's state-machine constructors.
///
/// `save_event` on this persister is a no-op — replay is read-only.
pub(crate) struct Replay<E> {
    pub(crate) events: Mutex<Option<Vec<E>>>,
}

impl<E> Replay<E> {
    pub(crate) fn new(events: Vec<E>) -> Self {
        Self {
            events: Mutex::new(Some(events)),
        }
    }
}

impl<E: Send + 'static> SessionPersister for Replay<E> {
    type InternalStorageError = Infallible;
    type SessionEvent = E;

    fn save_event(&self, _event: E) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let taken = self
            .events
            .lock()
            .expect("replay-events mutex poisoned")
            .take()
            .unwrap_or_default();
        Ok(Box::new(taken.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }
}
