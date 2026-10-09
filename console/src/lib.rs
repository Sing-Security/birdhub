//! The console's library half — the shell, the backend, the view data and
//! the pages — so the screenshot tests can build the real `ConsoleApp`
//! through `eframe` without a window, and drive its action layer the way a
//! click would. The binary (`main.rs`) is one thin caller; the tests are
//! another.

pub mod app;
pub mod backend;
pub mod data;
pub mod theme;
pub mod ui;
