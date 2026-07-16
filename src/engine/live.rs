//! Self-referential holder for a Frida `Session` and the `Script` created from it.
//!
//! `Session::create_script(&self, ..) -> Script<'_>` ties the `Script` to a borrow
//! of the `Session`, and dropping the `Session` detaches (tearing down the running
//! `Script`). So the two must live and die together. [`self_cell`] stores them in a
//! single stable heap allocation and guarantees the dependent (`Script`) is dropped
//! **before** the owner (`Session`) — the order frida-core requires
//! (`frida_unref(script)` then `frida_unref(session)`).
//!
//! The owner is `Session<'static>`: the engine leaks the `Frida`/`DeviceManager`/
//! `Device` singletons so `Device::attach` yields a `Session<'static>`.

use frida::{Script, Session};
use self_cell::self_cell;

self_cell!(
    pub struct LiveScript {
        owner: Session<'static>,

        #[covariant]
        dependent: Script,
    }
);
