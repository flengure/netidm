pub mod alloc;
pub mod backend;
pub mod hooks;
pub mod manager;
pub mod types;

pub use backend::{detect_backend, BackendKind};
pub use manager::WgManager;
