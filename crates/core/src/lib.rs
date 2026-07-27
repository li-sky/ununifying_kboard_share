//! kbshare-core
//!
//! Pure logic layer. No I/O, no threads, no OS calls. Everything here is
//! deterministic and unit-testable.

pub mod codec;
pub mod keycode;
pub mod pressed;
pub mod protocol;
pub mod runtime;
pub mod state;

pub use keycode::Key;
pub use pressed::PressedKeys;
pub use protocol::{Message, MouseState};
pub use state::{Event, Mode, SideEffect, StateMachine};
